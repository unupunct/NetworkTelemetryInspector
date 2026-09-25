# Network & Telemetry Inspector - release publish
# Produces release\NetworkTelemetryInspector.exe : one self-contained single-file win-x64 executable.
# ASCII only: Windows PowerShell 5.1 reads a BOM-less .ps1 as ANSI.
[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$SkipSelfTest
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$project = Join-Path $root 'src\NetworkTelemetryInspector\NetworkTelemetryInspector.csproj'
$tests = Join-Path $root 'tests\NetworkTelemetryInspector.Tests\NetworkTelemetryInspector.Tests.csproj'
$staging = Join-Path $root 'artifacts\publish'
$release = Join-Path $root 'release'

if (-not $SkipTests) {
    Write-Host 'Building and running unit tests' -ForegroundColor Cyan
    dotnet build $tests -c Release --nologo -v q
    if ($LASTEXITCODE -ne 0) { Write-Host 'TEST BUILD FAILED' -ForegroundColor Red; exit 1 }
    $testExe = Join-Path $root 'tests\NetworkTelemetryInspector.Tests\bin\Release\net8.0-windows\NetworkTelemetryInspector.Tests.exe'
    & $testExe
    if ($LASTEXITCODE -ne 0) { Write-Host "TESTS FAILED (exit $LASTEXITCODE). Publish aborted." -ForegroundColor Red; exit $LASTEXITCODE }
}

Write-Host 'Publishing self-contained single-file win-x64 Release build' -ForegroundColor Cyan
if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }

# Trimming stays off: WPF, COM late binding (Windows Firewall API) and reflection-based
# bindings are not trim safe. ReadyToRun lowers startup time and JIT memory.
dotnet publish $project `
    -c Release `
    -r win-x64 `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:EnableCompressionInSingleFile=false `
    -p:PublishReadyToRun=true `
    -p:PublishTrimmed=false `
    -p:DebugType=none `
    -p:SatelliteResourceLanguages=en `
    -o $staging `
    --nologo

if ($LASTEXITCODE -ne 0) { Write-Host "PUBLISH FAILED (exit $LASTEXITCODE)" -ForegroundColor Red; exit $LASTEXITCODE }

$published = Join-Path $staging 'NetworkTelemetryInspector.exe'
if (-not (Test-Path $published)) { Write-Host "PUBLISH FAILED: $published was not produced" -ForegroundColor Red; exit 1 }

New-Item -ItemType Directory -Force -Path $release | Out-Null
$target = Join-Path $release 'NetworkTelemetryInspector.exe'
Copy-Item $published $target -Force

$extras = Get-ChildItem $staging -File | Where-Object { $_.Name -ne 'NetworkTelemetryInspector.exe' }
if ($extras) {
    Write-Host 'Additional files produced by publish (not needed, not copied):' -ForegroundColor Yellow
    $extras | ForEach-Object { Write-Host ('  ' + $_.Name) }
}

if (-not $SkipSelfTest) {
    Write-Host 'Running the published exe headless self-test' -ForegroundColor Cyan
    $data = Join-Path $root 'artifacts\selftest-data'
    $out = Join-Path $root 'artifacts\selftest.txt'
    if (Test-Path $data) { Remove-Item $data -Recurse -Force }
    $p = Start-Process $target -ArgumentList '--selftest', '--out', $out, '--data', $data -PassThru -Wait
    Get-Content $out | Where-Object { $_ -match 'PASS|FAIL|RESULT|info' }
    if ($p.ExitCode -ne 0) { Write-Host "SELF-TEST FAILED (exit $($p.ExitCode))" -ForegroundColor Red; exit 1 }
}

$hash = (Get-FileHash $target -Algorithm SHA256).Hash
$mb = [math]::Round((Get-Item $target).Length / 1MB, 1)
Set-Content -Path (Join-Path $release 'SHA256SUMS.txt') -Value "$hash  NetworkTelemetryInspector.exe" -Encoding ascii
Write-Host ''
Write-Host "Release: $target ($mb MB)" -ForegroundColor Green
Write-Host "SHA-256: $hash" -ForegroundColor Green
