#requires -version 5.1
[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "wfp11_common.ps1")

Assert-Wfp11Administrator

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$stage = Join-Path $env:TEMP ("Serpium_WFP11_Prepare_" + $stamp)
New-Item -ItemType Directory -Path $stage -Force | Out-Null

$signedDirectory = Get-Wfp11SignedPackageDirectory -Configuration $Configuration
$statePath = Get-Wfp11StatePath
$certificate = $null
$failure = $null
$resultLines = New-Object 'System.Collections.Generic.List[string]'

function Assert-Wfp11TestSigner {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedThumbprint
    )

    $signature = Get-AuthenticodeSignature -FilePath $Path

    if ([string]$signature.Status -ne "Valid") {
        throw "Authenticode verification failed for $Path`: $($signature.StatusMessage)"
    }

    if ($null -eq $signature.SignerCertificate) {
        throw "Authenticode verification did not return a signer certificate for $Path."
    }

    $actualThumbprint = $signature.SignerCertificate.Thumbprint.Replace(" ", "").ToUpperInvariant()

    if ($actualThumbprint -ine $ExpectedThumbprint) {
        throw "Unexpected Authenticode signer for $Path (actual: $actualThumbprint)."
    }
}

try {
    $secureBoot = Get-Wfp11SecureBootState

    if ($secureBoot.State -ne "Disabled") {
        throw "Secure Boot must be confirmed Disabled before creating the WFP-1.1 test environment (actual: $($secureBoot.State))."
    }

    Assert-Wfp11ServicesAbsent

    if (Test-Path -LiteralPath $statePath) {
        throw "A previous WFP-1.1 state file exists. Run cleanup first: $statePath"
    }

    if (Test-Path -LiteralPath $signedDirectory) {
        throw "A previous signed staging directory exists. Run cleanup first: $signedDirectory"
    }

    $packageResult = Test-Wfp11UnsignedPackage -Configuration $Configuration
    $manifest = $packageResult.Manifest
    $sdkVersion = [string]$manifest.sdkWdkVersion
    $signTool = Find-Wfp11SdkTool -Name "signtool.exe" -PreferredVersion $sdkVersion
    $inf2Cat = Find-Wfp11SdkTool -Name "Inf2Cat.exe" -PreferredVersion $sdkVersion

    $static = Get-Wfp11StaticMarkerSummary

    if ($static.MatchCount -ne 0) {
        throw "WFP registration API markers were found. WFP-1.1 only accepts the no-filter scaffold."
    }

    $wfp = Get-Wfp11WfpNameSummary

    if (-not $wfp.Available -or $wfp.MatchCount -ne 0) {
        throw "Serpium WFP runtime state is not clean."
    }

    New-Item -ItemType Directory -Path $signedDirectory -Force | Out-Null

    foreach ($name in @(
        "Serpium.Flow.Driver.sys",
        "Serpium.Flow.Driver.inf",
        "Serpium.Flow.Service.exe",
        "BUILD_MANIFEST.json"
    )) {
        Copy-Item -LiteralPath (Join-Path $packageResult.PackageDirectory $name) -Destination (Join-Path $signedDirectory $name) -Force
    }

    $runId = [guid]::NewGuid().ToString("N")
    $subject = $script:Wfp11CertificatePrefix + " " + $runId.Substring(0, 12)
    $certificate = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $subject `
        -FriendlyName "Serpium Flow WFP-1.1 ephemeral test certificate" `
        -CertStoreLocation "Cert:\LocalMachine\My" `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -KeyExportPolicy NonExportable `
        -NotAfter (Get-Date).AddMonths(3)

    if ($null -eq $certificate -or -not $certificate.HasPrivateKey) {
        throw "The WFP-1.1 test certificate was not created with a private key."
    }

    $certificatePath = Join-Path $signedDirectory "Serpium.Flow.WFP11.Test.cer"
    Export-Certificate -Cert $certificate -FilePath $certificatePath -Force | Out-Null
    Import-Certificate -FilePath $certificatePath -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
    Import-Certificate -FilePath $certificatePath -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null

    $thumbprint = $certificate.Thumbprint.Replace(" ", "").ToUpperInvariant()
    $driverPath = Join-Path $signedDirectory "Serpium.Flow.Driver.sys"
    $servicePath = Join-Path $signedDirectory "Serpium.Flow.Service.exe"
    $infPath = Join-Path $signedDirectory "Serpium.Flow.Driver.inf"
    $catalogPath = Join-Path $signedDirectory "Serpium.Flow.Driver.cat"

    Invoke-Wfp11Native -FilePath $signTool -Arguments @(
        "sign", "/v", "/fd", "SHA256", "/ph", "/s", "My", "/sm", "/sha1", $thumbprint, $driverPath
    ) -LogPath (Join-Path $stage "01-sign-driver.log") | Out-Null

    Invoke-Wfp11Native -FilePath $signTool -Arguments @(
        "sign", "/v", "/fd", "SHA256", "/s", "My", "/sm", "/sha1", $thumbprint, $servicePath
    ) -LogPath (Join-Path $stage "02-sign-service.log") | Out-Null

    Remove-Item -LiteralPath $catalogPath -Force -ErrorAction SilentlyContinue

    Invoke-Wfp11Native -FilePath $inf2Cat -Arguments @(
        ("/driver:" + $signedDirectory), "/os:10_X64", "/verbose"
    ) -LogPath (Join-Path $stage "03-inf2cat.log") | Out-Null

    if (-not (Test-Path -LiteralPath $catalogPath -PathType Leaf)) {
        throw "Inf2Cat did not create Serpium.Flow.Driver.cat in the signed staging directory."
    }

    Invoke-Wfp11Native -FilePath $signTool -Arguments @(
        "sign", "/v", "/fd", "SHA256", "/s", "My", "/sm", "/sha1", $thumbprint, $catalogPath
    ) -LogPath (Join-Path $stage "04-sign-catalog.log") | Out-Null

    Invoke-Wfp11Native -FilePath $signTool -Arguments @(
        "verify", "/pa", "/ph", "/v", $driverPath
    ) -LogPath (Join-Path $stage "05-verify-driver.log") | Out-Null

    Invoke-Wfp11Native -FilePath $signTool -Arguments @(
        "verify", "/pa", "/v", $catalogPath
    ) -LogPath (Join-Path $stage "06-verify-catalog.log") | Out-Null

    Invoke-Wfp11Native -FilePath $signTool -Arguments @(
        "verify", "/pa", "/v", $servicePath
    ) -LogPath (Join-Path $stage "07-verify-service.log") | Out-Null

    Assert-Wfp11TestSigner -Path $driverPath -ExpectedThumbprint $thumbprint
    Assert-Wfp11TestSigner -Path $servicePath -ExpectedThumbprint $thumbprint

    Invoke-Wfp11Native -FilePath $signTool -Arguments @(
        "verify", "/pa", "/v", "/c", $catalogPath, $infPath
    ) -LogPath (Join-Path $stage "08-verify-inf-membership.log") | Out-Null

    Invoke-Wfp11Native -FilePath $signTool -Arguments @(
        "verify", "/pa", "/v", "/c", $catalogPath, $driverPath
    ) -LogPath (Join-Path $stage "09-verify-driver-membership.log") | Out-Null

    $signedManifest = [ordered]@{
        schema = 1
        stage = "WFP-1.1 test signing"
        createdUtc = (Get-Date).ToUniversalTime().ToString("o")
        runId = $runId
        configuration = $Configuration
        wfpEnabled = $false
        certificate = [ordered]@{
            subject = $certificate.Subject
            thumbprint = $thumbprint
            notAfterUtc = $certificate.NotAfter.ToUniversalTime().ToString("o")
            privateKeyExportable = $false
        }
        package = [ordered]@{
            driverSha256 = (Get-FileHash -LiteralPath $driverPath -Algorithm SHA256).Hash.ToLowerInvariant()
            catalogSha256 = (Get-FileHash -LiteralPath $catalogPath -Algorithm SHA256).Hash.ToLowerInvariant()
            infSha256 = (Get-FileHash -LiteralPath $infPath -Algorithm SHA256).Hash.ToLowerInvariant()
            serviceSha256 = (Get-FileHash -LiteralPath $servicePath -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        sourceBuildManifestSha256 = (Get-FileHash -LiteralPath (Join-Path $signedDirectory "BUILD_MANIFEST.json") -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    $signedManifestPath = Join-Path $signedDirectory "WFP11_SIGNING_MANIFEST.json"
    Write-Wfp11JsonFile -Path $signedManifestPath -Value $signedManifest -Depth 8

    $bcd = Get-Wfp11BcdTestSigningState
    $state = [ordered]@{
        schema = 1
        runId = $runId
        configuration = $Configuration
        createdUtc = (Get-Date).ToUniversalTime().ToString("o")
        stage = "Prepared"
        signedPackageDirectory = $signedDirectory
        certificateSubject = $certificate.Subject
        certificateThumbprint = $thumbprint
        certificateCreatedByScript = $true
        bcdQueryWasAvailable = [bool]$bcd.Available
        bcdTestSigningWasEnabled = [bool]$bcd.Enabled
        bcdChangedByScript = $false
        installRunId = $null
    }
    Save-Wfp11State -State $state

    $resultLines.Add("State: PASS")
    $resultLines.Add("Stage: WFP-1.1 prepare signed package")
    $resultLines.Add("RunId: " + $runId)
    $resultLines.Add("SignedPackage: " + $signedDirectory)
    $resultLines.Add("CertificateSubject: " + $certificate.Subject)
    $resultLines.Add("CertificateThumbprint: " + $thumbprint)
    $resultLines.Add("CertificatePrivateKeyExportable: False")
    $resultLines.Add("VerificationPolicy: Authenticode test-signing policy (/pa)")
    $resultLines.Add("SignerThumbprintMatched: True")
    $resultLines.Add("KernelReleasePolicyVerification: NotApplicableForLocalTestCertificate")
    $resultLines.Add("SecureBoot: " + $secureBoot.State)
    $resultLines.Add("MemoryIntegrity: " + (Get-Wfp11MemoryIntegrityState))
    $resultLines.Add("WfpEnabled: False")
    $resultLines.Add("WfpRuntimeMatches: " + $wfp.MatchCount)
    $resultLines.Add("BcdChanged: False")
    $resultLines.Add("DriverOrServiceInstalled: False")
    Copy-Item -LiteralPath $signedManifestPath -Destination (Join-Path $stage "WFP11_SIGNING_MANIFEST.json") -Force
}
catch {
    $failure = $_.Exception.Message
    $resultLines.Add("State: FAIL")
    $resultLines.Add("Stage: WFP-1.1 prepare signed package")
    $resultLines.Add("Error: " + $failure)

    if ($null -ne $certificate) {
        try {
            Remove-Wfp11CertificateByThumbprint -Thumbprint $certificate.Thumbprint
            $resultLines.Add("CertificateRollback: PASS")
        }
        catch {
            $resultLines.Add("CertificateRollback: FAIL - " + $_.Exception.Message)
        }
    }

    Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $signedDirectory -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Wfp11Utf8File -Path (Join-Path $stage "PREPARE_RESULT.txt") -Lines ($resultLines.ToArray())
$archive = New-Wfp11ResultArchive -Prefix "Serpium_WFP11_Prepare_Result" -StageDirectory $stage

Write-Host ""

if ($null -eq $failure) {
    Write-Host "SERPIUM_WFP11_PREPARE_PASS" -ForegroundColor Green
    Write-Host ("Signed package: " + $signedDirectory) -ForegroundColor Cyan
    Write-Host ("Result archive: " + $archive) -ForegroundColor Cyan
    exit 0
}

Write-Host "SERPIUM_WFP11_PREPARE_FAIL" -ForegroundColor Red
Write-Host $failure -ForegroundColor Red
Write-Host ("Result archive: " + $archive) -ForegroundColor Yellow
exit 1
