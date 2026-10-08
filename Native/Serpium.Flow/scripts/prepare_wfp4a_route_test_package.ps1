#requires -version 5.1
[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "wfp4a_common.ps1")

Assert-Wfp4aAdministrator

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$stage = Join-Path $env:TEMP ("Serpium_WFP4A_Prepare_" + $stamp)
New-Item -ItemType Directory -Path $stage -Force | Out-Null

$signedDirectory = Get-Wfp4aSignedPackageDirectory -Configuration $Configuration
$statePath = Get-Wfp4aStatePath
$certificate = $null
$signedDirectoryCreatedByThisRun = $false
$stateWriteAttemptedByThisRun = $false
$failure = $null
$resultLines = New-Object 'System.Collections.Generic.List[string]'

try {
    $secureBoot = Get-Wfp4aSecureBootState

    if ($secureBoot.State -ne "Disabled") {
        throw "Secure Boot must be confirmed Disabled before creating the WFP-4A test environment (actual: $($secureBoot.State))."
    }

    $codeIntegrity = Get-Wfp4aCodeIntegrityState

    if (-not $codeIntegrity.Available) {
        throw "Runtime Code Integrity state is unavailable."
    }

    if ($codeIntegrity.TestSigningRuntime) {
        throw "Windows Test Signing is active. Reboot once after the verified WFP-3 cleanup before WFP-4A preparation."
    }

    $bcd = Get-Wfp4aBcdTestSigningState

    if (-not $bcd.Available) {
        throw "BCD state could not be read safely."
    }

    if ($bcd.Enabled) {
        throw "BCD TESTSIGNING is unexpectedly configured before WFP-4A preparation."
    }

    Assert-Wfp4aServicesAbsent

    if (Test-Path -LiteralPath (Get-Wfp4aInstallRoot)) {
        throw "The isolated WFP-4A install root already exists."
    }

    if (Test-Path -LiteralPath (Get-Wfp4aServiceLogPath)) {
        throw "A pre-existing Serpium Flow service.log would be modified by the runtime test."
    }

    if (Test-Path -LiteralPath $statePath) {
        throw "A previous WFP-4A state file exists. Run cleanup first: $statePath"
    }

    if (Test-Path -LiteralPath $signedDirectory) {
        throw "A previous WFP-4A signed staging directory exists. Run cleanup first: $signedDirectory"
    }

    if ((Get-Wfp4aCertificateCount -Prefix $script:Wfp4aCertificatePrefix) -ne 0) {
        throw "A previous WFP-4A test certificate remains in a machine store."
    }

    $oldWfp3State = Join-Path (Get-Wfp4aFlowRoot) "artifacts\wfp3\state.json"
    $oldWfp3Signed = Join-Path (Get-Wfp4aFlowRoot) ("artifacts\x64\" + $Configuration + "\wfp3-signed-package")

    if (Test-Path -LiteralPath $oldWfp3State) {
        throw "WFP-3 state remains present; its cleanup is not complete."
    }

    if (Test-Path -LiteralPath $oldWfp3Signed) {
        throw "WFP-3 signed staging remains present; its cleanup is not complete."
    }

    if ((Get-Wfp4aCertificateCount -Prefix $script:Wfp3CertificatePrefix) -ne 0) {
        throw "A previous WFP-3 test certificate remains in a machine store."
    }

    $oldWfp2State = Join-Path (Get-Wfp4aFlowRoot) "artifacts\wfp2\state.json"
    $oldWfp2Signed = Join-Path (Get-Wfp4aFlowRoot) ("artifacts\x64\" + $Configuration + "\wfp2-signed-package")

    if (Test-Path -LiteralPath $oldWfp2State) {
        throw "WFP-2 state remains present; its cleanup is not complete."
    }

    if (Test-Path -LiteralPath $oldWfp2Signed) {
        throw "WFP-2 signed staging remains present; its cleanup is not complete."
    }

    if ((Get-Wfp4aCertificateCount -Prefix $script:Wfp2CertificatePrefix) -ne 0) {
        throw "A previous WFP-2 test certificate remains in a machine store."
    }

    $oldWfp11State = Join-Path (Get-Wfp4aFlowRoot) "artifacts\wfp11\state.json"
    $oldWfp11Signed = Join-Path (Get-Wfp4aFlowRoot) ("artifacts\x64\" + $Configuration + "\wfp11-signed-package")

    if (Test-Path -LiteralPath $oldWfp11State) {
        throw "WFP-1.1 state remains present; its cleanup is not complete."
    }

    if (Test-Path -LiteralPath $oldWfp11Signed) {
        throw "WFP-1.1 signed staging remains present; its cleanup is not complete."
    }

    if ((Get-Wfp4aCertificateCount -Prefix $script:Wfp11CertificatePrefix) -ne 0) {
        throw "A previous WFP-1.1 test certificate remains in a machine store."
    }

    $wfp = Get-Wfp4aWfpNameSummary

    if (-not $wfp.Available -or $wfp.MatchCount -ne 0) {
        throw "Serpium WFP runtime state is not clean."
    }

    $bfe = Get-Service -Name "BFE" -ErrorAction SilentlyContinue

    if ($null -eq $bfe -or [string]$bfe.Status -ne "Running") {
        throw "Base Filtering Engine must be running before WFP-4A preparation."
    }

    $packageResult = Test-Wfp4aUnsignedPackage -Configuration $Configuration
    $manifest = $packageResult.Manifest
    $sdkVersion = [string]$manifest.sdkWdkVersion
    $signTool = Find-Wfp4aSdkTool -Name "signtool.exe" -PreferredVersion $sdkVersion
    $inf2Cat = Find-Wfp4aSdkTool -Name "Inf2Cat.exe" -PreferredVersion $sdkVersion

    New-Item -ItemType Directory -Path $signedDirectory -ErrorAction Stop | Out-Null
    $signedDirectoryCreatedByThisRun = $true

    foreach ($name in @(
        "Serpium.Flow.Driver.sys",
        "Serpium.Flow.Driver.inf",
        "Serpium.Flow.Service.exe",
        "BUILD_MANIFEST.json"
    )) {
        Copy-Item -LiteralPath (Join-Path $packageResult.PackageDirectory $name) -Destination (Join-Path $signedDirectory $name) -Force
    }

    $runId = [guid]::NewGuid().ToString("N")
    $subject = $script:Wfp4aCertificatePrefix + " " + $runId.Substring(0, 12)
    $certificate = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $subject `
        -FriendlyName "Serpium Flow WFP-4A ephemeral guarded-route test certificate" `
        -CertStoreLocation "Cert:\LocalMachine\My" `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -KeyExportPolicy NonExportable `
        -NotAfter (Get-Date).AddMonths(3)

    if ($null -eq $certificate -or -not $certificate.HasPrivateKey) {
        throw "The WFP-4A test certificate was not created with a private key."
    }

    $certificatePath = Join-Path $signedDirectory "Serpium.Flow.WFP4A.Test.cer"
    Export-Certificate -Cert $certificate -FilePath $certificatePath -Force | Out-Null
    Import-Certificate -FilePath $certificatePath -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
    Import-Certificate -FilePath $certificatePath -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null

    $thumbprint = $certificate.Thumbprint.Replace(" ", "").ToUpperInvariant()
    $driverPath = Join-Path $signedDirectory "Serpium.Flow.Driver.sys"
    $servicePath = Join-Path $signedDirectory "Serpium.Flow.Service.exe"
    $infPath = Join-Path $signedDirectory "Serpium.Flow.Driver.inf"
    $catalogPath = Join-Path $signedDirectory "Serpium.Flow.Driver.cat"

    Invoke-Wfp4aNative -FilePath $signTool -Arguments @(
        "sign", "/v", "/fd", "SHA256", "/ph", "/s", "My", "/sm", "/sha1", $thumbprint, $driverPath
    ) -LogPath (Join-Path $stage "01-sign-driver.log") | Out-Null

    Invoke-Wfp4aNative -FilePath $signTool -Arguments @(
        "sign", "/v", "/fd", "SHA256", "/s", "My", "/sm", "/sha1", $thumbprint, $servicePath
    ) -LogPath (Join-Path $stage "02-sign-service.log") | Out-Null

    Remove-Item -LiteralPath $catalogPath -Force -ErrorAction SilentlyContinue

    Invoke-Wfp4aNative -FilePath $inf2Cat -Arguments @(
        ("/driver:" + $signedDirectory), "/os:10_X64", "/verbose"
    ) -LogPath (Join-Path $stage "03-inf2cat.log") | Out-Null

    if (-not (Test-Path -LiteralPath $catalogPath -PathType Leaf)) {
        throw "Inf2Cat did not create Serpium.Flow.Driver.cat in the signed staging directory."
    }

    Invoke-Wfp4aNative -FilePath $signTool -Arguments @(
        "sign", "/v", "/fd", "SHA256", "/s", "My", "/sm", "/sha1", $thumbprint, $catalogPath
    ) -LogPath (Join-Path $stage "04-sign-catalog.log") | Out-Null

    Invoke-Wfp4aNative -FilePath $signTool -Arguments @(
        "verify", "/pa", "/ph", "/v", $driverPath
    ) -LogPath (Join-Path $stage "05-verify-driver.log") | Out-Null

    Invoke-Wfp4aNative -FilePath $signTool -Arguments @(
        "verify", "/pa", "/v", $catalogPath
    ) -LogPath (Join-Path $stage "06-verify-catalog.log") | Out-Null

    Invoke-Wfp4aNative -FilePath $signTool -Arguments @(
        "verify", "/pa", "/v", $servicePath
    ) -LogPath (Join-Path $stage "07-verify-service.log") | Out-Null

    Assert-Wfp4aTestSigner -Path $driverPath -ExpectedThumbprint $thumbprint
    Assert-Wfp4aTestSigner -Path $servicePath -ExpectedThumbprint $thumbprint

    Invoke-Wfp4aNative -FilePath $signTool -Arguments @(
        "verify", "/pa", "/v", "/c", $catalogPath, $infPath
    ) -LogPath (Join-Path $stage "08-verify-inf-membership.log") | Out-Null

    Invoke-Wfp4aNative -FilePath $signTool -Arguments @(
        "verify", "/pa", "/v", "/c", $catalogPath, $driverPath
    ) -LogPath (Join-Path $stage "09-verify-driver-membership.log") | Out-Null

    # The user-mode service is Authenticode-verified above. It is not referenced
    # by the driver INF, so it is intentionally not a member of the driver catalog.

    $signedManifest = [ordered]@{
        schema = 4
        stage = "WFP-4A guarded TCP route test signing"
        createdUtc = (Get-Date).ToUniversalTime().ToString("o")
        runId = $runId
        configuration = $Configuration
        wfpEnabled = $true
        wfpMode = "guarded-tcp-route-enforcement"
        protocolVersion = "0x00040000"
        wfpLayers = @("ALE_AUTH_CONNECT_V4", "ALE_AUTH_CONNECT_V6", "ALE_CONNECT_REDIRECT_V4", "ALE_CONNECT_REDIRECT_V6")
        filterActions = @("FWP_ACTION_CALLOUT_INSPECTION", "FWP_ACTION_CALLOUT_TERMINATING")
        classifyActions = @("FWP_ACTION_CONTINUE", "FWP_ACTION_PERMIT")
        trafficModification = $true
        blockingEnabled = $false
        redirectEnabled = $true
        injectionEnabled = $false
        routeEnforcementEnabled = $true
        routeEnforcementDefaultArmed = $false
        routeLeaseMilliseconds = 5000
        routeLeaseFailOpen = $true
        tcpOnly = $true
        udpQuicIncluded = $false
        killSwitchIncluded = $false
        localBridge = "transparent-to-local-socks5-no-auth"
        policyTransportEnabled = $true
        policyCommands = @("ADD_RULE", "REMOVE_RULE", "CLEAR_RULES", "ENUM_RULES", "ENUM_FLOWS")
        applicationRuleCapacity = 128
        observedFlowCapacity = 256
        existingFlowMutation = $false
        uiIntegrationIncluded = $false
        activeRelayManagerIntegrationIncluded = $false
        runtimeTestNetworkScope = "local-machine-only"
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

    $signedManifestPath = Join-Path $signedDirectory "WFP4A_SIGNING_MANIFEST.json"
    Write-Wfp4aJsonFile -Path $signedManifestPath -Value $signedManifest -Depth 8

    $state = [ordered]@{
        schema = 4
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
    $stateWriteAttemptedByThisRun = $true
    Save-Wfp4aState -State $state

    $resultLines.Add("State: PASS")
    $resultLines.Add("Stage: WFP-4A prepare signed guarded TCP route package")
    $resultLines.Add("RunId: " + $runId)
    $resultLines.Add("SignedPackage: " + $signedDirectory)
    $resultLines.Add("CertificateSubject: " + $certificate.Subject)
    $resultLines.Add("CertificateThumbprint: " + $thumbprint)
    $resultLines.Add("CertificatePrivateKeyExportable: False")
    $resultLines.Add("VerificationPolicy: Authenticode test-signing policy (/pa)")
    $resultLines.Add("SignerThumbprintMatched: True")
    $resultLines.Add("SecureBoot: " + $secureBoot.State)
    $resultLines.Add("MemoryIntegrity: " + (Get-Wfp4aMemoryIntegrityState))
    $resultLines.Add("WfpEnabled: True")
    $resultLines.Add("WfpMode: guarded-tcp-route-enforcement")
    $resultLines.Add("ProtocolVersion: 0x00040000")
    $resultLines.Add("PolicyTransportEnabled: True")
    $resultLines.Add("PolicyCommands: ADD_RULE,REMOVE_RULE,CLEAR_RULES,ENUM_RULES,ENUM_FLOWS")
    $resultLines.Add("ApplicationRuleCapacity: 128")
    $resultLines.Add("ObservedFlowCapacity: 256")
    $resultLines.Add("FilterActions: FWP_ACTION_CALLOUT_INSPECTION,FWP_ACTION_CALLOUT_TERMINATING")
    $resultLines.Add("ClassifyActions: FWP_ACTION_CONTINUE,FWP_ACTION_PERMIT")
    $resultLines.Add("TrafficModification: True")
    $resultLines.Add("BlockingEnabled: False")
    $resultLines.Add("RedirectEnabled: True")
    $resultLines.Add("InjectionEnabled: False")
    $resultLines.Add("RouteEnforcementEnabled: True")
    $resultLines.Add("RouteEnforcementDefaultArmed: False")
    $resultLines.Add("RouteLeaseMilliseconds: 5000")
    $resultLines.Add("RouteLeaseFailOpen: True")
    $resultLines.Add("TcpOnly: True")
    $resultLines.Add("UdpQuicIncluded: False")
    $resultLines.Add("KillSwitchIncluded: False")
    $resultLines.Add("RuntimeTestNetworkScope: local-machine-only")
    $resultLines.Add("ExistingFlowMutation: False")
    $resultLines.Add("WfpRuntimeMatches: " + $wfp.MatchCount)
    $resultLines.Add("BcdChanged: False")
    $resultLines.Add("DriverOrServiceInstalled: False")
    $resultLines.Add("NetworkConfigurationChanges: none")
    Copy-Item -LiteralPath $signedManifestPath -Destination (Join-Path $stage "WFP4A_SIGNING_MANIFEST.json") -Force
}
catch {
    $failure = $_.Exception.Message
    $resultLines.Add("State: FAIL")
    $resultLines.Add("Stage: WFP-4A prepare signed guarded TCP route package")
    $resultLines.Add("Error: " + $failure)

    if ($null -ne $certificate) {
        try {
            Remove-Wfp4aCertificateByThumbprint -Thumbprint $certificate.Thumbprint
            $resultLines.Add("CertificateRollback: PASS")
        }
        catch {
            $resultLines.Add("CertificateRollback: FAIL - " + $_.Exception.Message)
        }
    }

    if ($stateWriteAttemptedByThisRun) {
        Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue
    }

    if ($signedDirectoryCreatedByThisRun) {
        Remove-Item -LiteralPath $signedDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Wfp4aUtf8File -Path (Join-Path $stage "PREPARE_RESULT.txt") -Lines ($resultLines.ToArray())
$archive = New-Wfp4aResultArchive -Prefix "Serpium_WFP4A_RoutePrepare_Result" -StageDirectory $stage

Write-Host ""

if ($null -eq $failure) {
    Write-Host "SERPIUM_WFP4A_ROUTE_PREPARE_PASS" -ForegroundColor Green
    Write-Host ("Signed package: " + $signedDirectory) -ForegroundColor Cyan
    Write-Host ("Result archive: " + $archive) -ForegroundColor Cyan
    exit 0
}

Write-Host "SERPIUM_WFP4A_ROUTE_PREPARE_FAIL" -ForegroundColor Red
Write-Host $failure -ForegroundColor Red
Write-Host ("Result archive: " + $archive) -ForegroundColor Yellow
exit 1
