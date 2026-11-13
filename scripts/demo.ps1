<#
.SYNOPSIS
  Starts a complete local demo of Strack with fresh state: the challenge simulator (sped up), the
  demo licensed platform, the demo pirate restream and Strack itself. Stop it with demo-stop.ps1.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts/demo.ps1
  powershell -ExecutionPolicy Bypass -File scripts/demo.ps1 -Speed 10 -TwoMatches
#>
param(
  # Folder of the challenge repository (holds simulador/ and datos/).
  [string]$Challenge = "var/challenge",
  # Simulator speed-up: 6 plays the 105-minute match in 17.5 minutes.
  [double]$Speed = 6,
  # Follow a second match at the same time (a copy of the practice scenario with other teams).
  [switch]$TwoMatches,
  # Use the binary already built in target/release.
  [switch]$NoBuild
)
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
$run = Join-Path $root "var/demo"
$exe = Join-Path $root "target/release/strack.exe"

if (-not (Test-Path (Join-Path $Challenge "simulador/servidor.py"))) {
  throw "Challenge repository not found in '$Challenge' (expected simulador/servidor.py). Pass -Challenge <folder>."
}
$challengeDir = (Resolve-Path $Challenge).Path

& (Join-Path $PSScriptRoot "demo-stop.ps1") -Quiet

foreach ($port in 3000, 8090, 8091, 8100, 8200) {
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
# The licensed platform draws a synthetic match: no third-party footage in the demo.
Start-Part "platform" $exe @("demo", "platform", "--data", (Join-Path $run "subscribers.json"))
Start-Part "pirate" $exe @("demo", "pirate")
Start-Part "strack" $exe @("serve", "--simulator", ($simulators -join ","), "--state-dir", (Join-Path $run "var"),
  "--accounts", (Join-Path $run "accounts.json"), "--platforms", (Join-Path $run "platforms.json"),
  "--intake-token", "token-demo-2026")
$pids | Set-Content (Join-Path $run "pids.txt")

Write-Host "Waiting for Strack..."
$ready = $false
for ($i = 0; $i -lt 60 -and -not $ready; $i++) {
  try { $ready = (Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 "http://127.0.0.1:3000/login").StatusCode -eq 200 } catch { Start-Sleep -Milliseconds 500 }
}
if (-not $ready) { throw "Strack did not answer on http://127.0.0.1:3000 (see var/demo/strack.err.log)" }

Write-Host ""
Write-Host "Strack demo is running (match at ${Speed}x). Walkthrough: docs/demo.md"
Write-Host ""
Write-Host "  Strack              http://127.0.0.1:3000"
Write-Host "  Licensed platform   http://127.0.0.1:8100   (staff: personal / personal-demo-2026)"
Write-Host "  Pirate site         http://127.0.0.1:8200"
Write-Host ""
Write-Host "  laura    / laura-demo-2026      judge on duty until minute 50"
Write-Host "  martin   / martin-demo-2026     judge from minute 50"
Write-Host "  fiscalia / fiscalia-demo-2026   operations, loads pirate sites"
Write-Host "  tvf      / tvf-demo-2026        TV Ficticia Play's portal"
Write-Host "  admin    / admin-demo-2026      administration"
Write-Host ""
Write-Host "Stop everything: powershell -ExecutionPolicy Bypass -File scripts/demo-stop.ps1"
