# Network & Telemetry Inspector - end-to-end Block/Unblock workflow test.
# Launch -> detect connections -> select application -> inspect details -> Block -> verify firewall
# rule -> verify traffic is really blocked -> Unblock -> verify rule removal -> verify traffic restored.
#
# The probe is a private COPY of curl.exe under artifacts\probe, so no real application on this PC is
# ever blocked. When run without elevation, Windows shows two UAC prompts (Block, Unblock).
# ASCII only: Windows PowerShell 5.1 reads a BOM-less .ps1 as ANSI.
[CmdletBinding()]
param([string]$Exe)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $Exe) { $Exe = Join-Path $root 'release\NetworkTelemetryInspector.exe' }
$art = Join-Path $root 'artifacts'
$probeDir = Join-Path $art 'probe'
New-Item -ItemType Directory -Force -Path $probeDir | Out-Null
$probe = Join-Path $probeDir 'nti-probe-curl.exe'
Copy-Item (Join-Path $env:WINDIR 'System32\curl.exe') $probe -Force

$out = Join-Path $art 'workflow-test.txt'
$data = Join-Path $art 'workflow-data'
if (Test-Path $data) { Remove-Item $data -Recurse -Force }
$p = Start-Process $Exe -ArgumentList '--workflow-test', '--target', $probe, '--out', $out, '--data', $data -PassThru -Wait
Get-Content $out
Write-Host "exit $($p.ExitCode)"
exit $p.ExitCode
