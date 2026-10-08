#requires -version 5.1
[CmdletBinding()]
param(
    [string]$Root = "D:\Program\Serpium\SerpiumVPN",
    [ValidateSet("Release","Debug")]
    [string]$Configuration = "Release",
    [switch]$Start,
    [switch]$Stop,
    [switch]$Smoke
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$package = Join-Path $Root (
    "Native\Serpium.SFP\artifacts\x64\" +
    $Configuration +
    "\package")

$runtime = Join-Path $package "Serpium.SFP.Runtime.exe"
$sys = Join-Path $package "Serpium.SFP.Kernel.sys"

if (-not (Test-Path -LiteralPath $runtime -PathType Leaf)) {
    throw "Runtime controller not found: $runtime"
}

if (-not (Test-Path -LiteralPath $sys -PathType Leaf)) {
    throw "Kernel SYS not found: $sys"
}

Write-Host "=== SFP Runtime Gate ===" -ForegroundColor Cyan
Write-Host ("SYS: " + $sys)

& $runtime signature $sys
$signatureExit = $LASTEXITCODE

if ($signatureExit -ne 0) {
    Write-Host ""
    Write-Host "SERPIUM_SFP_RUNTIME_SIGNATURE_GATE_BLOCKED" -ForegroundColor Yellow
    Write-Host "No driver service was created or started." -ForegroundColor Yellow
    exit $signatureExit
}

if ($Stop) {
    & $runtime stop
    exit $LASTEXITCODE
}

if ($Smoke) {
    & $runtime smoke $sys
    exit $LASTEXITCODE
}

if ($Start) {
    & $runtime start $sys
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "SERPIUM_SFP_RUNTIME_SIGNATURE_PREFLIGHT_PASS" -ForegroundColor Green
Write-Host "No driver was started. Use -Smoke for start/ABI/stop, or -Start to keep it running." -ForegroundColor Cyan
