#requires -version 5.1
[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "wfp2_common.ps1")

Assert-Wfp2Administrator

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$stage = Join-Path $env:TEMP ("Serpium_WFP2_Prepare_" + $stamp)
New-Item -ItemType Directory -Path $stage -Force | Out-Null

$signedDirectory = Get-Wfp2SignedPackageDirectory -Configuration $Configuration
$statePath = Get-Wfp2StatePath
$certificate = $null
$failure = $null
$resultLines = New-Object 'System.Collections.Generic.List[string]'

try {
    $secureBoot = Get-Wfp2SecureBootState

    if ($secureBoot.State -ne "Disabled") {
        throw "Secure Boot must be confirmed Disabled before creating the WFP-2 test environment (actual: $($secureBoot.State))."
    }

    $codeIntegrity = Get-Wfp2CodeIntegrityState

    if (-not $codeIntegrity.Available) {
        throw "Runtime Code Integrity state is unavailable."
    }

    if ($codeIntegrity.TestSigningRuntime) {
        throw "Windows Test Signing is unexpectedly active before WFP-2 preparation."
    }

    $bcd = Get-Wfp2BcdTestSigningState

    if (-not $bcd.Available) {
        throw "BCD state could not be read safely."
    }

    if ($bcd.Enabled) {
        throw "BCD TESTSIGNING is unexpectedly configured before WFP-2 preparation."
    }

    Assert-Wfp2ServicesAbsent

    if (Test-Path -LiteralPath (Get-Wfp2InstallRoot)) {
        throw "The isolated WFP-2 install root already exists."
    }

    if (Test-Path -LiteralPath (Get-Wfp2ServiceLogPath)) {
        throw "A pre-existing Serpium Flow service.log would be modified by the runtime test."
    }

    if (Test-Path -LiteralPath $statePath) {
        throw "A previous WFP-2 state file exists. Run cleanup first: $statePath"
    }

    if (Test-Path -LiteralPath $signedDirectory) {
        throw "A previous WFP-2 signed staging directory exists. Run cleanup first: $signedDirectory"
    }

    if ((Get-Wfp2CertificateCount -Prefix $script:Wfp2CertificatePrefix) -ne 0) {
        throw "A previous WFP-2 private test certificate exists."
    }

    if ((Get-Wfp2CertificateCount -Prefix $script:Wfp11CertificatePrefix) -ne 0) {
        throw "A previous WFP-1.1 private test certificate exists."
    }

    $wfp = Get-Wfp2WfpNameSummary

    if (-not $wfp.Available -or $wfp.MatchCount -ne 0) {
        throw "Serpium WFP runtime state is not clean."
    }

    $bfe = Get-Service -Name "BFE" -ErrorAction SilentlyContinue

    if ($null -eq $bfe -or [string]$bfe.Status -ne "Running") {
        throw "Base Filtering Engine must be running before WFP-2 preparation."
    }

    $packageResult = Test-Wfp2UnsignedPackage -Configuration $Configuration
    $manifest = $packageResult.Manifest
    $sdkVersion = [string]$manifest.sdkWdkVersion
    $signTool = Find-Wfp2SdkTool -Name "signtool.exe" -PreferredVersion $sdkVersion
    $inf2Cat = Find-Wfp2SdkTool -Name "Inf2Cat.exe" -PreferredVersion $sdkVersion

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
    $subject = $script:Wfp2CertificatePrefix + " " + $runId.Substring(0, 12)
    $certificate = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $subject `
        -FriendlyName "Serpium Flow WFP-2 ephemeral observe-only test certificate" `
        -CertStoreLocation "Cert:\LocalMachine\My" `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -KeyExportPolicy NonExportable `
        -NotAfter (Get-Date).AddMonths(3)

    if ($null -eq $certificate -or -not $certificate.HasPrivateKey) {
        throw "The WFP-2 test certificate was not created with a private key."
    }

    $certificatePath = Join-Path $signedDirectory "Serpium.Flow.WFP2.Test.cer"
    Export-Certificate -Cert $certificate -FilePath $certificatePath -Force | Out-Null
    Import-Certificate -FilePath $certificatePath -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
    Import-Certificate -FilePath $certificatePath -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null

    $thumbprint = $certificate.Thumbprint.Replace(" ", "").ToUpperInvariant()
    $driverPath = Join-Path $signedDirectory "Serpium.Flow.Driver.sys"
    $servicePath = Join-Path $signedDirectory "Serpium.Flow.Service.exe"
    $infPath = Join-Path $signedDirectory "Serpium.Flow.Driver.inf"
    $catalogPath = Join-Path $signedDirectory "Serpium.Flow.Driver.cat"

    Invoke-Wfp2Native -FilePath $signTool -Arguments @(
        "sign", "/v", "/fd", "SHA256", "/ph", "/s", "My", "/sm", "/sha1", $thumbprint, $driverPath
    ) -LogPath (Join-Path $stage "01-sign-driver.log") | Out-Null

    Invoke-Wfp2Native -FilePath $signTool -Arguments @(
        "sign", "/v", "/fd", "SHA256", "/s", "My", "/sm", "/sha1", $thumbprint, $servicePath
    ) -LogPath (Join-Path $stage "02-sign-service.log") | Out-Null

    Remove-Item -LiteralPath $catalogPath -Force -ErrorAction SilentlyContinue

    Invoke-Wfp2Native -FilePath $inf2Cat -Arguments @(
        ("/driver:" + $signedDirectory), "/os:10_X64", "/verbose"
    ) -LogPath (Join-Path $stage "03-inf2cat.log") | Out-Null

    if (-not (Test-Path -LiteralPath $catalogPath -PathType Leaf)) {
        throw "Inf2Cat did not create Serpium.Flow.Driver.cat in the signed staging directory."
    }

    Invoke-Wfp2Native -FilePath $signTool -Arguments @(
        "sign", "/v", "/fd", "SHA256", "/s", "My", "/sm", "/sha1", $thumbprint, $catalogPath
    ) -LogPath (Join-Path $stage "04-sign-catalog.log") | Out-Null

    Invoke-Wfp2Native -FilePath $signTool -Arguments @(
        "verify", "/pa", "/ph", "/v", $driverPath
    ) -LogPath (Join-Path $stage "05-verify-driver.log") | Out-Null

    Invoke-Wfp2Native -FilePath $signTool -Arguments @(
        "verify", "/pa", "/v", $catalogPath
    ) -LogPath (Join-Path $stage "06-verify-catalog.log") | Out-Null

    Invoke-Wfp2Native -FilePath $signTool -Arguments @(
        "verify", "/pa", "/v", $servicePath
    ) -LogPath (Join-Path $stage "07-verify-service.log") | Out-Null

    Assert-Wfp2TestSigner -Path $driverPath -ExpectedThumbprint $thumbprint
    Assert-Wfp2TestSigner -Path $servicePath -ExpectedThumbprint $thumbprint

    Invoke-Wfp2Native -FilePath $signTool -Arguments @(
        "verify", "/pa", "/v", "/c", $catalogPath, $infPath
    ) -LogPath (Join-Path $stage "08-verify-inf-membership.log") | Out-Null

    Invoke-Wfp2Native -FilePath $signTool -Arguments @(
        "verify", "/pa", "/v", "/c", $catalogPath, $driverPath
    ) -LogPath (Join-Path $stage "09-verify-driver-membership.log") | Out-Null

    $signedManifest = [ordered]@{
        schema = 2
        stage = "WFP-2 observe-only test signing"
        createdUtc = (Get-Date).ToUniversalTime().ToString("o")
        runId = $runId
        configuration = $Configuration
        wfpEnabled = $true
        wfpMode = "observe-only"
        wfpLayers = @("ALE_AUTH_CONNECT_V4", "ALE_AUTH_CONNECT_V6")
        filterAction = "FWP_ACTION_CALLOUT_INSPECTION"
        classifyAction = "FWP_ACTION_CONTINUE"
        trafficModification = $false
        blockingEnabled = $false
        redirectEnabled = $false
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

    $signedManifestPath = Join-Path $signedDirectory "WFP2_SIGNING_MANIFEST.json"
    Write-Wfp2JsonFile -Path $signedManifestPath -Value $signedManifest -Depth 8

    $state = [ordered]@{
        schema = 2
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
        programDataFlowExistedBefore = $null
        programDataSerpiumExistedBefore = $null
    }
    Save-Wfp2State -State $state

    $resultLines.Add("State: PASS")
    $resultLines.Add("Stage: WFP-2 prepare signed observe-only package")
    $resultLines.Add("RunId: " + $runId)
    $resultLines.Add("SignedPackage: " + $signedDirectory)
    $resultLines.Add("CertificateSubject: " + $certificate.Subject)
    $resultLines.Add("CertificateThumbprint: " + $thumbprint)
    $resultLines.Add("CertificatePrivateKeyExportable: False")
    $resultLines.Add("VerificationPolicy: Authenticode test-signing policy (/pa)")
    $resultLines.Add("SignerThumbprintMatched: True")
    $resultLines.Add("SecureBoot: " + $secureBoot.State)
    $resultLines.Add("MemoryIntegrity: " + (Get-Wfp2MemoryIntegrityState))
    $resultLines.Add("WfpEnabled: True")
    $resultLines.Add("WfpMode: observe-only")
    $resultLines.Add("FilterAction: FWP_ACTION_CALLOUT_INSPECTION")
    $resultLines.Add("ClassifyAction: FWP_ACTION_CONTINUE")
    $resultLines.Add("TrafficModification: False")
    $resultLines.Add("BlockingEnabled: False")
    $resultLines.Add("RedirectEnabled: False")
    $resultLines.Add("WfpRuntimeMatches: " + $wfp.MatchCount)
    $resultLines.Add("BcdChanged: False")
    $resultLines.Add("DriverOrServiceInstalled: False")
    $resultLines.Add("NetworkConfigurationChanges: none")
    Copy-Item -LiteralPath $signedManifestPath -Destination (Join-Path $stage "WFP2_SIGNING_MANIFEST.json") -Force
}
catch {
    $failure = $_.Exception.Message
    $resultLines.Add("State: FAIL")
    $resultLines.Add("Stage: WFP-2 prepare signed observe-only package")
    $resultLines.Add("Error: " + $failure)

    if ($null -ne $certificate) {
        try {
            Remove-Wfp2CertificateByThumbprint -Thumbprint $certificate.Thumbprint
            $resultLines.Add("CertificateRollback: PASS")
        }
        catch {
            $resultLines.Add("CertificateRollback: FAIL - " + $_.Exception.Message)
        }
    }

    Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $signedDirectory -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Wfp2Utf8File -Path (Join-Path $stage "PREPARE_RESULT.txt") -Lines ($resultLines.ToArray())
$archive = New-Wfp2ResultArchive -Prefix "Serpium_WFP2_Prepare_Result" -StageDirectory $stage

Write-Host ""

if ($null -eq $failure) {
    Write-Host "SERPIUM_WFP2_PREPARE_PASS" -ForegroundColor Green
    Write-Host ("Signed package: " + $signedDirectory) -ForegroundColor Cyan
    Write-Host ("Result archive: " + $archive) -ForegroundColor Cyan
    exit 0
}

Write-Host "SERPIUM_WFP2_PREPARE_FAIL" -ForegroundColor Red
Write-Host $failure -ForegroundColor Red
Write-Host ("Result archive: " + $archive) -ForegroundColor Yellow
exit 1
