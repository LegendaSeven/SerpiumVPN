#requires -version 5.1
[CmdletBinding()]
param(
    [string]$Root = "D:\Program\Serpium\SerpiumVPN",
    [Parameter(Mandatory = $true)]
    [string]$SignedPackageRoot,
    [Parameter(Mandatory = $true)]
    [string]$SubmissionReceipt
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "wfp_driver_owner_common.ps1")

if (-not (Test-Path -LiteralPath $SignedPackageRoot -PathType Container)) {
    throw "Extracted Partner Center package directory not found: $SignedPackageRoot"
}
if (-not (Test-Path -LiteralPath $SubmissionReceipt -PathType Leaf)) {
    throw "WFP submission receipt not found: $SubmissionReceipt"
}

$submission = Get-Content -LiteralPath $SubmissionReceipt -Raw | ConvertFrom-Json
if ([int]$submission.schema -ne 1 -or
    [string]$submission.product -ne "SerpiumVPN" -or
    [string]$submission.component -ne "Serpium.Flow.Driver" -or
    [string]$submission.protocolAbi -ne "0x00040000" -or
    [string]$submission.platform -ne "x64") {
    throw "Submission receipt does not describe the Serpium WFP x64 ABI 0x00040000 package."
}

function Find-OneFile {
    param(
        [Parameter(Mandatory = $true)][string]$RootPath,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $matches = @(
        Get-ChildItem -LiteralPath $RootPath -File -Recurse |
            Where-Object { $_.Name -ieq $Name }
    )

    if ($matches.Count -ne 1) {
        throw "Expected exactly one $Name in Partner Center return; found $($matches.Count)."
    }

    return $matches[0].FullName
}

$returnInf = Find-OneFile -RootPath $SignedPackageRoot -Name "Serpium.Flow.Driver.inf"
$returnSys = Find-OneFile -RootPath $SignedPackageRoot -Name "Serpium.Flow.Driver.sys"
$returnCat = Find-OneFile -RootPath $SignedPackageRoot -Name "serpium.flow.driver.cat"

$submissionInfHash = [string]$submission.files.'Serpium.Flow.Driver.inf'
if ([string]::IsNullOrWhiteSpace($submissionInfHash)) {
    throw "Submission receipt does not contain the INF hash."
}

$returnInfHash = (
    Get-FileHash -LiteralPath $returnInf -Algorithm SHA256
).Hash.ToLowerInvariant()

if ($returnInfHash -ne $submissionInfHash.ToLowerInvariant()) {
    throw (
        "Partner Center return INF does not match the submitted Serpium package. " +
        "Refusing to import this signing response."
    )
}

$temp = Join-Path $env:TEMP ("SerpiumWfpSignedImport_" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $temp -Force | Out-Null

try {
    Copy-Item -LiteralPath $returnInf -Destination (Join-Path $temp "Serpium.Flow.Driver.inf") -Force
    Copy-Item -LiteralPath $returnSys -Destination (Join-Path $temp "Serpium.Flow.Driver.sys") -Force
    Copy-Item -LiteralPath $returnCat -Destination (Join-Path $temp "serpium.flow.driver.cat") -Force

    $trust = Assert-SerpiumWfpMicrosoftDriverTripletTrust -PackageRoot $temp

    $productionParent = Join-Path $Root "Native\Serpium.Flow\production\x64"
    $productionRoot = Join-Path $productionParent "current"
    $stage = Join-Path $productionParent (".stage-" + [Guid]::NewGuid().ToString("N"))
    $previous = Join-Path $productionParent (".previous-" + [Guid]::NewGuid().ToString("N"))

    New-Item -ItemType Directory -Path $stage -Force | Out-Null

    foreach ($name in @(
        "Serpium.Flow.Driver.inf",
        "Serpium.Flow.Driver.sys",
        "serpium.flow.driver.cat"
    )) {
        Copy-Item -LiteralPath (Join-Path $temp $name) -Destination (Join-Path $stage $name) -Force
    }

    $signedFiles = [ordered]@{}
    foreach ($name in @(
        "Serpium.Flow.Driver.inf",
        "Serpium.Flow.Driver.sys",
        "serpium.flow.driver.cat"
    )) {
        $signedFiles[$name] = (
            Get-FileHash -LiteralPath (Join-Path $stage $name) -Algorithm SHA256
        ).Hash.ToLowerInvariant()
    }

    $receipt = [ordered]@{
        schema = 1
        product = "SerpiumVPN"
        component = "Serpium.Flow.Driver"
        protocolAbi = "0x00040000"
        platform = "x64"
        state = "MICROSOFT_SIGNED_IMPORTED"
        importedAtUtc = [DateTime]::UtcNow.ToString("o")
        submissionReceiptSha256 = (
            Get-FileHash -LiteralPath $SubmissionReceipt -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        submittedInfSha256 = $submissionInfHash.ToLowerInvariant()
        signerSubject = [string]$trust.SignerSubject
        signerIssuer = [string]$trust.SignerIssuer
        signerThumbprint = [string]$trust.Thumbprint
        files = $signedFiles
    }

    $receipt |
        ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath (Join-Path $stage "WFP_SIGNING_RECEIPT.json") -Encoding utf8

    New-Item -ItemType Directory -Path $productionParent -Force | Out-Null

    if (Test-Path -LiteralPath $productionRoot -PathType Container) {
        Move-Item -LiteralPath $productionRoot -Destination $previous
    }

    try {
        Move-Item -LiteralPath $stage -Destination $productionRoot
    }
    catch {
        if ((Test-Path -LiteralPath $previous -PathType Container) -and
            -not (Test-Path -LiteralPath $productionRoot)) {
            Move-Item -LiteralPath $previous -Destination $productionRoot
        }
        throw
    }

    Remove-Item -LiteralPath $previous -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host "Microsoft-signed WFP package imported." -ForegroundColor Green
    Write-Host ("Production root: " + $productionRoot) -ForegroundColor Cyan
    Write-Host ("Signer: " + [string]$trust.SignerSubject) -ForegroundColor Cyan
    Write-Host "SERPIUM_WFP_SIGNED_RETURN_IMPORT_PASS" -ForegroundColor Green
}
finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
