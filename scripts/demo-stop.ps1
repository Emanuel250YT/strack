<#
.SYNOPSIS
  Stops the processes demo.ps1 started (and their children, such as ffmpeg).
#>
param([switch]$Quiet)
$root = Split-Path $PSScriptRoot -Parent
$file = Join-Path $root "var/demo/pids.txt"
if (-not (Test-Path $file)) {
  if (-not $Quiet) { Write-Host "No demo is running." }
  return
}
foreach ($id in Get-Content $file) {
  if ($id -and (Get-Process -Id $id -ErrorAction SilentlyContinue)) {
    taskkill /PID $id /T /F | Out-Null
    if (-not $Quiet) { Write-Host "  stopped pid $id" }
  }
}
Remove-Item $file
if (-not $Quiet) { Write-Host "Demo stopped. Its state stays in var/demo for review." }
