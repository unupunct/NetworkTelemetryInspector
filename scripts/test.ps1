# Network & Telemetry Inspector - run every verification that needs no administrator rights.
#   1. unit tests (dependency-free console harness)
#   2. --selftest  : engine against the live connection table
#   3. --verify-ui : real window rendered off screen, every page, zero binding errors
# The Block/Unblock workflow needs UAC and is run separately:  scripts\workflow-test.ps1
# ASCII only: Windows PowerShell 5.1 reads a BOM-less .ps1 as ANSI.
[CmdletBinding()]
param([string]$Exe, [string]$Shots)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$art = Join-Path $root 'artifacts'
New-Item -ItemType Directory -Force -Path $art | Out-Null
$failed = 0

dotnet build (Join-Path $root 'tests\NetworkTelemetryInspector.Tests\NetworkTelemetryInspector.Tests.csproj') -c Debug --nologo -v q
if ($LASTEXITCODE -ne 0) { exit 1 }
& (Join-Path $root 'tests\NetworkTelemetryInspector.Tests\bin\Debug\net8.0-windows\NetworkTelemetryInspector.Tests.exe')
if ($LASTEXITCODE -ne 0) { $failed++ }

if (-not $Exe) { $Exe = Join-Path $root 'src\NetworkTelemetryInspector\bin\Debug\net8.0-windows\NetworkTelemetryInspector.exe' }

foreach ($mode in @('--selftest', '--verify-ui')) {
    $name = $mode.TrimStart('-')
    $out = Join-Path $art "$name.txt"
    $data = Join-Path $art "$name-data"
    if (Test-Path $data) { Remove-Item $data -Recurse -Force }
    $argsList = @($mode, '--out', $out, '--data', $data)
    if ($mode -eq '--verify-ui' -and $Shots) { $argsList += @('--shots', $Shots) }
    $p = Start-Process $Exe -ArgumentList $argsList -PassThru -Wait
    Write-Host "== $mode (exit $($p.ExitCode))" -ForegroundColor Cyan
    Get-Content $out | Where-Object { $_ -match 'FAIL|RESULT' }
    if ($p.ExitCode -ne 0) { $failed++ }
}

if ($failed -eq 0) { Write-Host 'ALL VERIFICATION PASSED' -ForegroundColor Green } else { Write-Host "$failed STAGE(S) FAILED" -ForegroundColor Red }
exit $failed
