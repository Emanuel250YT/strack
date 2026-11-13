<#
.SYNOPSIS
  Starts a complete local demo of Strack with fresh state: the challenge simulator (sped up), the
  demo licensed platform, the demo pirate restream and Strack itself. Stop it with demo-stop.ps1.
  With -Standalone there is no simulator: the match comes from config/match.example.json on the wall
  clock (kick-off one minute ago) and four `strack provider` receivers take the orders.
  -Live is the standalone demo with nothing scripted: the pirate restreams on its own address
  (127.0.0.2:8200), Strack reads the mark from it when it is loaded, the Aurora provider also runs its
  network edge (HTTP proxy on 127.0.0.1:9180) that enforces the orders, and a browser window of an
  Aurora subscriber watches the pirate through it. With -Video the match clock follows the recording.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts/demo.ps1
  powershell -ExecutionPolicy Bypass -File scripts/demo.ps1 -Speed 10 -TwoMatches
  powershell -ExecutionPolicy Bypass -File scripts/demo.ps1 -Standalone
  powershell -ExecutionPolicy Bypass -File scripts/demo.ps1 -Live -Video D:\match.mp4 -VideoStart 600
#>
param(
  # Folder of the challenge repository (holds simulador/ and datos/).
  [string]$Challenge = "var/challenge",
  # Simulator speed-up: 6 plays the 105-minute match in 17.5 minutes.
  [double]$Speed = 6,
  # Follow a second match at the same time (a copy of the practice scenario with other teams).
  [switch]$TwoMatches,
  # Use the binary already built in target/release.
  [switch]$NoBuild,
  # No simulator: a configured match on the wall clock and four provider receivers.
  [switch]$Standalone,
  # A local match recording the licensed platform broadcasts instead of its synthetic match. It is read
  # from disk only and must never be copied into the repository.
  [string]$Video,
  # Optional copy of the same recording that carries the sound (same timeline as -Video).
  [string]$Audio,
  # Second of the recording to start from.
  [double]$VideoStart = 0,
  # Real end-to-end demo (implies -Standalone): see the synopsis.
  [switch]$Live,
  # Match name shown everywhere (standalone and live); the example config's name by default.
  [string]$MatchName
)
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
$run = Join-Path $root "var/demo"
$exe = Join-Path $root "target/release/strack.exe"
if ($Live) { $Standalone = [switch]$true }
$pirateAddress = if ($Live) { "127.0.0.2:8200" } else { "127.0.0.1:8200" }
$edgeAddress = "127.0.0.1:9180"

if (-not $Standalone) {
  if (-not (Test-Path (Join-Path $Challenge "simulador/servidor.py"))) {
    throw "Challenge repository not found in '$Challenge' (expected simulador/servidor.py). Pass -Challenge <folder> or use -Standalone."
  }
  $challengeDir = (Resolve-Path $Challenge).Path
}

& (Join-Path $PSScriptRoot "demo-stop.ps1") -Quiet

$ports = if ($Standalone) { @(3000, 8100, 8200, 9101, 9102, 9103, 9104, 9180) } else { @(3000, 8090, 8091, 8100, 8200) }
foreach ($port in $ports) {
  if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) {
    throw "Port $port is in use. Stop whatever listens there (or a previous demo with demo-stop.ps1)."
  }
}

if (-not $NoBuild) {
  Write-Host "Building the release binary..."
  cargo build --release
  if ($LASTEXITCODE -ne 0) { throw "cargo build --release failed" }
}
if (-not (Test-Path $exe)) { throw "Missing ${exe}: run without -NoBuild." }

if (Test-Path $run) { Remove-Item -Recurse -Force $run }
New-Item -ItemType Directory -Force (Join-Path $run "var") | Out-Null
Copy-Item (Join-Path $root "config/accounts.json"), (Join-Path $root "config/platforms.json") $run

$pids = @()
function Start-Part([string]$name, [string]$file, [string[]]$arguments, [string]$dir = $root) {
  $p = Start-Process -FilePath $file -ArgumentList $arguments -WorkingDirectory $dir -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput (Join-Path $run "$name.log") -RedirectStandardError (Join-Path $run "$name.err.log")
  $script:pids += $p.Id
  Write-Host ("  started {0,-10} pid {1}" -f $name, $p.Id)
}

$sources = @()
if ($Standalone) {
  # The example match, kicked off a minute ago (live: as far back as the recording starts, so the
  # match clock follows the picture); each provider's receiver keeps its orders in var/demo.
  $text = Get-Content (Join-Path $root "config/match.example.json") -Raw -Encoding UTF8
  if ($Live) { $text = $text -replace ' \(ficticio\)', '' }
  $config = $text | ConvertFrom-Json
  $offset = if ($Live -and $Video) { [Math]::Max(60, $VideoStart) } else { 60 }
  $kickoff = (Get-Date).AddSeconds(-$offset).ToString("yyyy-MM-ddTHH:mm:sszzz")
  $config.partido.inicio_iso = $kickoff
  if ($MatchName) { $config.partido.nombre = $MatchName }
  $matchFile = Join-Path $run "match.json"
  [System.IO.File]::WriteAllText($matchFile, ($config | ConvertTo-Json -Depth 12), (New-Object System.Text.UTF8Encoding $false))
  foreach ($p in $config.proveedores) {
    $listen = ([uri]$p.api_url).Authority
    $receiverArgs = @("provider", "--id", $p.id, "--name", "`"$($p.nombre)`"", "--listen", $listen, "--kickoff", $kickoff,
      "--accepts", ($p.capacidades -join ","), "--data", (Join-Path $run "provider-$($p.id).json"))
    # Aurora also runs its network edge: its subscribers browse through it and its blocks really cut.
    if ($Live -and $p.id -eq "aurora") { $receiverArgs += @("--gateway", $edgeAddress) }
    Start-Part "isp-$($p.id)" $exe $receiverArgs
  }
  $sources = @("--config", $matchFile)
} else {
$simulators = @("http://127.0.0.1:8090")
Start-Part "match-1" "python" @("-X", "utf8", "simulador/servidor.py", "--escenario", "datos/escenario_practica.json",
  "--datos", "datos", "--acelerar", "$Speed", "--puerto", "8090", "--log", (Join-Path $run "match-1.jsonl")) $challengeDir
if ($TwoMatches) {
  $second = Join-Path $challengeDir "datos/escenario_practica_2.json"
  if (-not (Test-Path $second)) {
    python -X utf8 -c "import json,sys; d=json.load(open(sys.argv[1],encoding='utf-8')); d['id']+='-b'; d['partido']['id']='practica-02'; d['partido']['nombre']='Partido de pr'+chr(225)+'ctica '+chr(8212)+' Atl'+chr(233)+'tico Muestra vs. Sportivo Prueba'; json.dump(d,open(sys.argv[2],'w',encoding='utf-8'),ensure_ascii=False)" (Join-Path $challengeDir "datos/escenario_practica.json") $second
  }
  Start-Part "match-2" "python" @("-X", "utf8", "simulador/servidor.py", "--escenario", "datos/escenario_practica_2.json",
    "--datos", "datos", "--acelerar", "$Speed", "--puerto", "8091", "--log", (Join-Path $run "match-2.jsonl")) $challengeDir
  $simulators += "http://127.0.0.1:8091"
}
$sources = @("--simulator", ($simulators -join ","))
}
# H.264 on the GPU when there is an NVIDIA card and ffmpeg has NVENC: the CPU stays free for the rest.
$env:STRACK_H264_ENCODER = $null
if ((Get-Command nvidia-smi -ErrorAction SilentlyContinue) -and (Get-Command ffmpeg -ErrorAction SilentlyContinue) -and ((ffmpeg -hide_banner -encoders 2>$null) -match "h264_nvenc")) {
  $env:STRACK_H264_ENCODER = "h264_nvenc"
  Write-Host "  video encoding on the NVIDIA GPU (h264_nvenc)"
}
# The licensed platform draws a synthetic match unless -Video points at a local recording.
$platformArgs = @("demo", "platform", "--data", (Join-Path $run "subscribers.json"))
if ($Video) {
  if (-not (Test-Path $Video)) { throw "Video not found: $Video" }
  $platformArgs += @("--video", "`"$((Resolve-Path $Video).Path)`"", "--video-start", "$VideoStart", "--loop")
  if ($Audio) {
    if (-not (Test-Path $Audio)) { throw "Audio not found: $Audio" }
    $platformArgs += @("--audio", "`"$((Resolve-Path $Audio).Path)`"")
  }
}
Start-Part "platform" $exe $platformArgs
Start-Part "pirate" $exe @("demo", "pirate", "--listen", $pirateAddress)
Start-Part "strack" $exe (@("serve") + $sources + @("--state-dir", (Join-Path $run "var"),
  "--accounts", (Join-Path $run "accounts.json"), "--platforms", (Join-Path $run "platforms.json"),
  "--intake-token", "token-demo-2026", "--allow-private-streams"))
$pids | Set-Content (Join-Path $run "pids.txt")

Write-Host "Waiting for Strack..."
$ready = $false
for ($i = 0; $i -lt 60 -and -not $ready; $i++) {
  try { $ready = (Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 "http://127.0.0.1:3000/login").StatusCode -eq 200 } catch { Start-Sleep -Milliseconds 500 }
}
if (-not $ready) { throw "Strack did not answer on http://127.0.0.1:3000 (see var/demo/strack.err.log)" }

if ($Live) {
  # An Aurora subscriber: a separate browser profile whose traffic goes through Aurora's network edge,
  # loopback included, so the provider's blocks apply to it like to any of its customers.
  $chrome = @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
    "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
  if ($chrome) {
    $viewer = Start-Process -FilePath $chrome -PassThru -ArgumentList @("--user-data-dir=`"$(Join-Path $run 'viewer')`"",
      "--proxy-server=http://$edgeAddress", "--proxy-bypass-list=`"<-loopback>`"", "--no-first-run",
      "--no-default-browser-check", "--autoplay-policy=no-user-gesture-required", "--new-window", "http://$pirateAddress/")
    $pids += $viewer.Id
    $pids | Set-Content (Join-Path $run "pids.txt")
    Write-Host "  started viewer     pid $($viewer.Id) (Aurora subscriber watching the pirate)"
  } else {
    Write-Host "  Chrome not found: open http://$pirateAddress/ in a browser that uses the proxy $edgeAddress"
  }
}

Write-Host ""
if ($Live) {
  Write-Host "Strack LIVE demo: nothing scripted. Match clock started $([int]($offset / 60)) min ago."
  Write-Host "As fiscalia, Cargar sitios: paste http://$pirateAddress/ (Strack reads the mark itself)."
  Write-Host "Aurora's network edge (HTTP proxy): http://$edgeAddress  - the viewer window browses through it."
} elseif ($Standalone) {
  Write-Host "Strack demo is running WITHOUT the simulator (wall clock, kick-off a minute ago)."
  Write-Host "Load the pirate streams as fiscalia in Cargar sitios: upload docs/demo-streams.csv,"
  Write-Host "or paste http://$pirateAddress/ and Strack reads the mark from the pirate stream itself."
  Write-Host "Provider receivers: http://127.0.0.1:9101..9104, orders kept in var/demo/provider-*.json"
} else {
  Write-Host "Strack demo is running (match at ${Speed}x). Walkthrough: docs/demo.md"
}
Write-Host ""
Write-Host "  Strack              http://127.0.0.1:3000"
Write-Host "  Licensed platform   http://127.0.0.1:8100   (staff: personal / personal-demo-2026)"
Write-Host "  Pirate site         http://$pirateAddress"
Write-Host ""
Write-Host "  laura    / laura-demo-2026      judge on duty until minute 50"
Write-Host "  martin   / martin-demo-2026     judge from minute 50"
Write-Host "  fiscalia / fiscalia-demo-2026   operations, loads pirate sites"
Write-Host "  tvf      / tvf-demo-2026        TV Ficticia Play's portal"
Write-Host "  admin    / admin-demo-2026      administration"
Write-Host ""
Write-Host "Stop everything: powershell -ExecutionPolicy Bypass -File scripts/demo-stop.ps1"
