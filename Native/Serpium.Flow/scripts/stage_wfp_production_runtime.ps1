#requires -version 5.1
[CmdletBinding()]
param(
    [string]$Root = "D:\Program\Serpium\SerpiumVPN",
    [ValidateSet("Debug","Release")]
    [string]$Configuration = "Release",
    [string]$ProductionSignedRoot = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "wfp_driver_owner_common.ps1")

if ([string]::IsNullOrWhiteSpace($ProductionSignedRoot)) {
    $ProductionSignedRoot = Join-Path $Root "Native\Serpium.Flow\production\x64\current"
}

if (-not (Test-Path -LiteralPath $ProductionSignedRoot -PathType Container)) {
    throw "Imported Microsoft-signed WFP package not found: $ProductionSignedRoot"
}

$receiptPath = Join-Path $ProductionSignedRoot "WFP_SIGNING_RECEIPT.json"
if (-not (Test-Path -LiteralPath $receiptPath -PathType Leaf)) {
    throw "WFP signing receipt missing: $receiptPath"
}

$receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
if ([int]$receipt.schema -ne 1 -or
    [string]$receipt.state -ne "MICROSOFT_SIGNED_IMPORTED" -or
    [string]$receipt.protocolAbi -ne "0x00040000" -or
    [string]$receipt.platform -ne "x64") {
    throw "Imported WFP signing receipt is invalid."
}

$localPackage = Join-Path $Root ("Native\Serpium.Flow\artifacts\x64\" + $Configuration + "\package")
$runtimeParent = Join-Path $Root "bin_files\wfp"
$runtimeRoot = Join-Path $runtimeParent "x64"
$stage = Join-Path $runtimeParent (".prod-stage-" + [Guid]::NewGuid().ToString("N"))
$previous = Join-Path $runtimeParent (".prod-previous-" + [Guid]::NewGuid().ToString("N"))

$localInf = Join-Path $localPackage "Serpium.Flow.Driver.inf"
if (-not (Test-Path -LiteralPath $localInf -PathType Leaf)) {
    throw "Current local WFP build package is missing INF: $localInf"
}

$localInfHash = (
    Get-FileHash -LiteralPath $localInf -Algorithm SHA256
).Hash.ToLowerInvariant()

if ($localInfHash -ne ([string]$receipt.submittedInfSha256).ToLowerInvariant()) {
    throw (
        "Current WFP INF no longer matches the package that was submitted to Partner Center. " +
        "Prepare and submit a new driver signing package for this source revision."
    )
}

[void](Assert-SerpiumWfpMicrosoftDriverTripletTrust -PackageRoot $ProductionSignedRoot)

New-Item -ItemType Directory -Path $stage -Force | Out-Null

foreach ($name in @(
    "Serpium.Flow.Service.exe",
    "BUILD_MANIFEST.json"
)) {
    $source = Join-Path $localPackage $name
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "Current WFP local package missing: $name"
    }
    Copy-Item -LiteralPath $source -Destination (Join-Path $stage $name) -Force
}

foreach ($name in @(
    "Serpium.Flow.Driver.sys",
    "Serpium.Flow.Driver.inf",
    "serpium.flow.driver.cat"
)) {
    Copy-Item -LiteralPath (Join-Path $ProductionSignedRoot $name) -Destination (Join-Path $stage $name) -Force
}

Copy-Item -LiteralPath $receiptPath -Destination (Join-Path $stage "WFP_SIGNING_RECEIPT.json") -Force

$projectVersion = "unknown"
$projectFile = Join-Path $Root "SerpiumVPN.csproj"
if (Test-Path -LiteralPath $projectFile -PathType Leaf) {
    [xml]$projectXml = Get-Content -LiteralPath $projectFile -Raw
    $versionNode = @($projectXml.Project.PropertyGroup.Version | Where-Object { $_ } | Select-Object -First 1)
    if ($versionNode.Count -gt 0) {
        $projectVersion = [string]$versionNode[0]
    }
}

$manifestFiles = @(
    "Serpium.Flow.Service.exe",
    "Serpium.Flow.Driver.sys",
    "Serpium.Flow.Driver.inf",
    "serpium.flow.driver.cat",
    "BUILD_MANIFEST.json"
)

$files = foreach ($name in $manifestFiles) {
    $path = Join-Path $stage $name
    [ordered]@{
        name = $name
        sha256 = (
            Get-FileHash -LiteralPath $path -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        size = (Get-Item -LiteralPath $path).Length
    }
}

$runtimeManifest = [ordered]@{
    schema = 1
    owner = "SerpiumVPN"
    component = "Serpium.Flow"
    productVersion = $projectVersion
    protocolAbi = "0x00040000"
    platform = "x64"
    generatedAtUtc = [DateTime]::UtcNow.ToString("o")
    installState = "PACKAGED_NOT_INSTALLED"
    driverTrust = "PRODUCTION_VERIFIED"
    signingReceiptSha256 = (
        Get-FileHash -LiteralPath (Join-Path $stage "WFP_SIGNING_RECEIPT.json") -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    files = @($files)
}

$runtimeManifest |
    ConvertTo-Json -Depth 6 |
    Set-Content -LiteralPath (Join-Path $stage "WFP_RUNTIME_MANIFEST.json") -Encoding utf8

[void](Assert-SerpiumWfpProductionTrust -PackageRoot $stage)

if (Test-Path -LiteralPath $runtimeRoot -PathType Container) {
    Move-Item -LiteralPath $runtimeRoot -Destination $previous
}

try {
    Move-Item -LiteralPath $stage -Destination $runtimeRoot
}
catch {
    if ((Test-Path -LiteralPath $previous -PathType Container) -and
        -not (Test-Path -LiteralPath $runtimeRoot)) {
        Move-Item -LiteralPath $previous -Destination $runtimeRoot
    }
    throw
}

Remove-Item -LiteralPath $previous -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Production-signed WFP runtime staged." -ForegroundColor Green
Write-Host ("Runtime: " + $runtimeRoot) -ForegroundColor Cyan
Write-Host "SERPIUM_WFP_PRODUCTION_RUNTIME_STAGE_PASS" -ForegroundColor Green
