#requires -version 5.1
[CmdletBinding()]
param(
    [string]$Root = "D:\Program\Serpium\SerpiumVPN",
    [string]$VisualStudioRoot = "D:\Program\Visual Studio\18",
    [ValidateSet("Debug","Release")]
    [string]$Configuration = "Release",
    [string]$SubmissionCertificateThumbprint = "",
    [string]$TimestampUrl = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

. (Join-Path $PSScriptRoot "wfp_driver_owner_common.ps1")

$stamp = Get-Date -Format "MMdd_HHmm"
$outputRoot = Join-Path $Root "publish\wfp-signing"
$submissionRoot = Join-Path $outputRoot ("submission_" + $stamp)
$driverFolderName = "SerpiumWFP"
$driverFolder = Join-Path $submissionRoot $driverFolderName
$diskFolder = Join-Path $submissionRoot "Disk1"
$receiptPath = Join-Path $submissionRoot "WFP_SUBMISSION.json"
$ddfPath = Join-Path $submissionRoot "SerpiumWFP.ddf"
$cabName = "WFP_Submit_$stamp.cab"
$cabPath = Join-Path $diskFolder $cabName

$nativeBuild = Join-Path $Root "Native\Serpium.Flow\scripts\build_wfp1.ps1"
$packageRoot = Join-Path $Root ("Native\Serpium.Flow\artifacts\x64\" + $Configuration + "\package")
$driverPdb = Join-Path $Root ("Native\Serpium.Flow\artifacts\x64\" + $Configuration + "\driver\Serpium.Flow.Driver.pdb")

if (-not (Test-Path -LiteralPath $nativeBuild -PathType Leaf)) {
    throw "WFP native build script not found: $nativeBuild"
}

& $nativeBuild -VisualStudioRoot $VisualStudioRoot -Configuration $Configuration
if ($LASTEXITCODE -ne 0) {
    throw "Native WFP build failed: $LASTEXITCODE"
}

$required = @(
    "Serpium.Flow.Driver.sys",
    "Serpium.Flow.Driver.inf",
    "serpium.flow.driver.cat"
)

foreach ($name in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $packageRoot $name) -PathType Leaf)) {
        throw "WFP submission package missing: $name"
    }
}

if (-not (Test-Path -LiteralPath $driverPdb -PathType Leaf)) {
    throw "WFP driver PDB missing: $driverPdb"
}

if (Test-Path -LiteralPath $submissionRoot) {
    Remove-Item -LiteralPath $submissionRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $driverFolder -Force | Out-Null
New-Item -ItemType Directory -Path $diskFolder -Force | Out-Null

foreach ($name in $required) {
    Copy-Item -LiteralPath (Join-Path $packageRoot $name) -Destination (Join-Path $driverFolder $name) -Force
}
Copy-Item -LiteralPath $driverPdb -Destination (Join-Path $driverFolder "Serpium.Flow.Driver.pdb") -Force

$files = @(
    "Serpium.Flow.Driver.inf",
    "Serpium.Flow.Driver.sys",
    "Serpium.Flow.Driver.pdb",
    "serpium.flow.driver.cat"
)

$ddf = @(
    "; Serpium WFP Partner Center submission",
    ".OPTION EXPLICIT",
    ".Set CabinetFileCountThreshold=0",
    ".Set FolderFileCountThreshold=0",
    ".Set FolderSizeThreshold=0",
    ".Set MaxCabinetSize=0",
    ".Set MaxDiskFileCount=0",
    ".Set MaxDiskSize=0",
    ".Set CompressionType=MSZIP",
    ".Set Cabinet=on",
    ".Set Compress=on",
    ".Set CabinetNameTemplate=$cabName",
    ".Set DiskDirectoryTemplate=$diskFolder",
    ".Set DestinationDir=$driverFolderName"
)

foreach ($name in $files) {
    $ddf += '"' + (Join-Path $driverFolder $name) + '"'
}

$ddf | Set-Content -LiteralPath $ddfPath -Encoding ascii

$makeCab = Join-Path $env:SystemRoot "System32\makecab.exe"
if (-not (Test-Path -LiteralPath $makeCab -PathType Leaf)) {
    throw "makecab.exe not found: $makeCab"
}

& $makeCab /F $ddfPath
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $cabPath -PathType Leaf)) {
    throw "MakeCab failed or CAB was not created."
}

$cabSigningState = "UNSIGNED_READY"
$cabSignerThumbprint = ""

if (-not [string]::IsNullOrWhiteSpace($SubmissionCertificateThumbprint)) {
    if ([string]::IsNullOrWhiteSpace($TimestampUrl)) {
        throw (
            "TimestampUrl is required when signing the Partner Center CAB. " +
            "Use the timestamp service recommended by your certificate provider."
        )
    }

    $signTool = Get-SerpiumWfpSignTool
    $thumbprint = $SubmissionCertificateThumbprint.Replace(" ","").ToUpperInvariant()

    & $signTool sign `
        /sha1 $thumbprint `
        /fd SHA256 `
        /tr $TimestampUrl `
        /td SHA256 `
        /v `
        $cabPath

    if ($LASTEXITCODE -ne 0) {
        throw "CAB signing failed: $LASTEXITCODE"
    }

    & $signTool verify /v /pa $cabPath
    if ($LASTEXITCODE -ne 0) {
        throw "Signed CAB verification failed: $LASTEXITCODE"
    }

    $cabSigningState = "SIGNED_FOR_SUBMISSION"
    $cabSignerThumbprint = $thumbprint
}

$hashes = [ordered]@{}
foreach ($name in $files) {
    $path = Join-Path $driverFolder $name
    $hashes[$name] = (
        Get-FileHash -LiteralPath $path -Algorithm SHA256
    ).Hash.ToLowerInvariant()
}

$receipt = [ordered]@{
    schema = 1
    product = "SerpiumVPN"
    component = "Serpium.Flow.Driver"
    protocolAbi = "0x00040000"
    platform = "x64"
    driverFolder = $driverFolderName
    createdAtUtc = [DateTime]::UtcNow.ToString("o")
    cabName = $cabName
    cabSha256 = (
        Get-FileHash -LiteralPath $cabPath -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    cabSigningState = $cabSigningState
    cabSignerThumbprint = $cabSignerThumbprint
    files = $hashes
    nextAction = if ($cabSigningState -eq "SIGNED_FOR_SUBMISSION") {
        "SUBMIT_TO_WINDOWS_HARDWARE_PARTNER_CENTER"
    } else {
        "SIGN_CAB_WITH_PARTNER_CENTER_REGISTERED_CERTIFICATE"
    }
}

$receipt |
    ConvertTo-Json -Depth 6 |
    Set-Content -LiteralPath $receiptPath -Encoding utf8

Write-Host ""
Write-Host "WFP Partner Center submission prepared." -ForegroundColor Green
Write-Host ("CAB: " + $cabPath) -ForegroundColor Cyan
Write-Host ("Receipt: " + $receiptPath) -ForegroundColor Cyan
Write-Host ("State: " + $cabSigningState) -ForegroundColor Cyan
Write-Host "SERPIUM_WFP_SIGNING_SUBMISSION_PREPARE_PASS" -ForegroundColor Green
