#requires -version 5.1
[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [Parameter(Mandatory = $true)]
    [ValidateSet("RUN")]
    [string]$ConfirmLifecycle
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "wfp11_common.ps1")

Assert-Wfp11Administrator

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$stage = Join-Path $env:TEMP ("Serpium_WFP11_Lifecycle_" + $stamp)
New-Item -ItemType Directory -Path $stage -Force | Out-Null

$report = New-Object 'System.Collections.Generic.List[string]'
$failure = $null
$driverCreated = $false
$userServiceCreated = $false
$runId = [guid]::NewGuid().ToString("N")
$installRoot = Join-Path $env:ProgramFiles "Serpium\Flow\WFP11"
$driverTarget = Join-Path $installRoot "Driver\Serpium.Flow.Driver.sys"
$serviceTarget = Join-Path $installRoot "Service\Serpium.Flow.Service.exe"
$ownershipMarker = Join-Path $installRoot "WFP11_INSTALL_STATE.json"
$serviceLog = Join-Path $env:ProgramData "Serpium\Flow\service.log"
$state = $null

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

function Remove-OwnedInstallRoot {
    param([string]$ExpectedRunId)

    if (-not (Test-Path -LiteralPath $installRoot -PathType Container)) {
        return
    }

    if (-not (Test-Path -LiteralPath $ownershipMarker -PathType Leaf)) {
        throw "Install root exists without the WFP-1.1 ownership marker: $installRoot"
    }

    $marker = Get-Content -LiteralPath $ownershipMarker -Raw | ConvertFrom-Json

    if ([string]$marker.runId -ne $ExpectedRunId) {
        throw "Install ownership marker does not match this lifecycle run."
    }

    Remove-Item -LiteralPath $installRoot -Recurse -Force -ErrorAction Stop
}

function Test-ServicePathOwned {
    param(
        [AllowNull()]
        [object]$Record,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedPath
    )

    if ($null -eq $Record) {
        return $false
    }

    $actual = [string]$Record.PathName
    return $actual.IndexOf($ExpectedPath, [StringComparison]::OrdinalIgnoreCase) -ge 0
}

function Invoke-LifecycleRollback {
    $rollbackLines = New-Object 'System.Collections.Generic.List[string]'

    try {
        $userRecord = Get-Wfp11UserService

        if ($null -ne $userRecord) {
            if (-not (Test-ServicePathOwned -Record $userRecord -ExpectedPath $serviceTarget)) {
                throw "Refusing to remove SerpiumFlowService because its binary path is not owned by this run."
            }

            if (Test-Path -LiteralPath $serviceTarget -PathType Leaf) {
                Invoke-Wfp11Native -FilePath $serviceTarget -Arguments @("stop") -LogPath (Join-Path $stage "rollback-user-stop.log") -AllowFailure | Out-Null
                Invoke-Wfp11Native -FilePath $serviceTarget -Arguments @("uninstall") -LogPath (Join-Path $stage "rollback-user-delete.log") -AllowFailure | Out-Null
            }
            else {
                $sc = Join-Path $env:SystemRoot "System32\sc.exe"
                Invoke-Wfp11Native -FilePath $sc -Arguments @("stop", $script:Wfp11UserServiceName) -LogPath (Join-Path $stage "rollback-user-stop.log") -AllowFailure | Out-Null
                Invoke-Wfp11Native -FilePath $sc -Arguments @("delete", $script:Wfp11UserServiceName) -LogPath (Join-Path $stage "rollback-user-delete.log") -AllowFailure | Out-Null
            }

            Wait-Wfp11ServiceState -Kind User -State Absent -TimeoutSeconds 20
        }

        $rollbackLines.Add("UserServiceRollback: PASS")
    }
    catch {
        $rollbackLines.Add("UserServiceRollback: FAIL - " + $_.Exception.Message)
    }

    try {
        $driverRecord = Get-Wfp11DriverService

        if ($null -ne $driverRecord) {
            if (-not (Test-ServicePathOwned -Record $driverRecord -ExpectedPath $driverTarget)) {
                throw "Refusing to remove SerpiumFlow because its binary path is not owned by this run."
            }

            $sc = Join-Path $env:SystemRoot "System32\sc.exe"
            Invoke-Wfp11Native -FilePath $sc -Arguments @("stop", $script:Wfp11DriverServiceName) -LogPath (Join-Path $stage "rollback-driver-stop.log") -AllowFailure | Out-Null
            Invoke-Wfp11Native -FilePath $sc -Arguments @("delete", $script:Wfp11DriverServiceName) -LogPath (Join-Path $stage "rollback-driver-delete.log") -AllowFailure | Out-Null
            Wait-Wfp11ServiceState -Kind Driver -State Absent -TimeoutSeconds 20
        }

        $rollbackLines.Add("DriverServiceRollback: PASS")
    }
    catch {
        $rollbackLines.Add("DriverServiceRollback: FAIL - " + $_.Exception.Message)
    }

    try {
        Remove-OwnedInstallRoot -ExpectedRunId $runId
        $rollbackLines.Add("InstallFilesRollback: PASS")
    }
    catch {
        $rollbackLines.Add("InstallFilesRollback: FAIL - " + $_.Exception.Message)
    }

    try {
        if (Test-Path -LiteralPath $serviceLog) {
            Remove-Item -LiteralPath $serviceLog -Force -ErrorAction Stop
        }

        if (Test-Path -LiteralPath $serviceLog) {
            throw "Service log still exists after rollback."
        }

        $rollbackLines.Add("ServiceLogRollback: PASS")
    }
    catch {
        $rollbackLines.Add("ServiceLogRollback: FAIL - " + $_.Exception.Message)
    }

    return $rollbackLines.ToArray()
}

try {
    $state = Get-Wfp11State

    if ($null -eq $state) {
        throw "WFP-1.1 state is missing. Run prepare_wfp11_test_package.ps1 first."
    }

    if ([string]$state.configuration -ne $Configuration) {
        throw "WFP-1.1 state configuration does not match $Configuration."
    }

    $secureBoot = Get-Wfp11SecureBootState

    if ($secureBoot.State -ne "Disabled") {
        throw "Secure Boot must be Disabled for this test (actual: $($secureBoot.State))."
    }

    $codeIntegrity = Get-Wfp11CodeIntegrityState

    if (-not $codeIntegrity.Available -or -not $codeIntegrity.TestSigningRuntime) {
        throw "Windows Test Signing is not active in the current boot. Run enable_wfp11_testsigning.ps1 and reboot first."
    }

    Assert-Wfp11ServicesAbsent

    if (Test-Path -LiteralPath $installRoot) {
        throw "The isolated WFP-1.1 install root already exists: $installRoot"
    }

    if (Test-Path -LiteralPath $serviceLog) {
        throw "A pre-existing service log would be modified by the lifecycle test: $serviceLog"
    }

    $signedDirectory = [string]$state.signedPackageDirectory
    $signedManifestPath = Join-Path $signedDirectory "WFP11_SIGNING_MANIFEST.json"

    if (-not (Test-Path -LiteralPath $signedManifestPath -PathType Leaf)) {
        throw "Signed package manifest is missing: $signedManifestPath"
    }

    $signedManifest = Get-Content -LiteralPath $signedManifestPath -Raw | ConvertFrom-Json

    if ([bool]$signedManifest.wfpEnabled) {
        throw "Signed package reports wfpEnabled=true. WFP-1.1 must not register filters."
    }

    $driverSource = Join-Path $signedDirectory "Serpium.Flow.Driver.sys"
    $serviceSource = Join-Path $signedDirectory "Serpium.Flow.Service.exe"
    $catalogSource = Join-Path $signedDirectory "Serpium.Flow.Driver.cat"
    $infSource = Join-Path $signedDirectory "Serpium.Flow.Driver.inf"
    $certificateSource = Join-Path $signedDirectory "Serpium.Flow.WFP11.Test.cer"

    $hashChecks = @(
        [pscustomobject]@{ Path = $driverSource; Expected = [string]$signedManifest.package.driverSha256 },
        [pscustomobject]@{ Path = $serviceSource; Expected = [string]$signedManifest.package.serviceSha256 },
        [pscustomobject]@{ Path = $catalogSource; Expected = [string]$signedManifest.package.catalogSha256 },
        [pscustomobject]@{ Path = $infSource; Expected = [string]$signedManifest.package.infSha256 }
    )

    foreach ($check in $hashChecks) {
        if (-not (Test-Path -LiteralPath $check.Path -PathType Leaf)) {
            throw "Signed package file is missing: $($check.Path)"
        }

        $actual = (Get-FileHash -LiteralPath $check.Path -Algorithm SHA256).Hash

        if ($actual -ine $check.Expected) {
            throw "Signed package hash mismatch: $($check.Path)"
        }
    }

    $certificateThumbprint = [string]$state.certificateThumbprint

    if ([string]$signedManifest.certificate.thumbprint -ine $certificateThumbprint) {
        throw "Signed manifest certificate thumbprint does not match WFP-1.1 state."
    }

    foreach ($store in @("My", "Root", "TrustedPublisher")) {
        if (-not (Test-Path -LiteralPath ("Cert:\LocalMachine\$store\" + $certificateThumbprint))) {
            throw "WFP-1.1 certificate is missing from LocalMachine\$store."
        }
    }

    $buildManifest = Get-Content -LiteralPath (Join-Path $signedDirectory "BUILD_MANIFEST.json") -Raw | ConvertFrom-Json
    $signTool = Find-Wfp11SdkTool -Name "signtool.exe" -PreferredVersion ([string]$buildManifest.sdkWdkVersion)

    Invoke-Wfp11Native -FilePath $signTool -Arguments @("verify", "/pa", "/ph", "/v", $driverSource) -LogPath (Join-Path $stage "01-verify-driver.log") | Out-Null
    Invoke-Wfp11Native -FilePath $signTool -Arguments @("verify", "/pa", "/v", $catalogSource) -LogPath (Join-Path $stage "02-verify-catalog.log") | Out-Null
    Invoke-Wfp11Native -FilePath $signTool -Arguments @("verify", "/pa", "/v", $serviceSource) -LogPath (Join-Path $stage "03-verify-service.log") | Out-Null
    Invoke-Wfp11Native -FilePath $signTool -Arguments @("verify", "/pa", "/v", "/c", $catalogSource, $driverSource) -LogPath (Join-Path $stage "04-verify-catalog-membership.log") | Out-Null

    Assert-Wfp11TestSigner -Path $driverSource -ExpectedThumbprint $certificateThumbprint
    Assert-Wfp11TestSigner -Path $serviceSource -ExpectedThumbprint $certificateThumbprint

    $static = Get-Wfp11StaticMarkerSummary

    if ($static.MatchCount -ne 0) {
        throw "WFP registration API markers were found in the source tree."
    }

    $wfpBefore = Get-Wfp11WfpNameSummary

    if (-not $wfpBefore.Available -or $wfpBefore.MatchCount -ne 0) {
        throw "WFP state is not clean before lifecycle installation."
    }

    New-Item -ItemType Directory -Path (Split-Path -Parent $driverTarget) -Force | Out-Null
    New-Item -ItemType Directory -Path (Split-Path -Parent $serviceTarget) -Force | Out-Null
    Write-Wfp11JsonFile -Path $ownershipMarker -Value ([ordered]@{
        schema = 1
        runId = $runId
        createdUtc = (Get-Date).ToUniversalTime().ToString("o")
        stage = "Copying"
    }) -Depth 5
    Copy-Item -LiteralPath $driverSource -Destination $driverTarget -Force
    Copy-Item -LiteralPath $serviceSource -Destination $serviceTarget -Force
    Copy-Item -LiteralPath $catalogSource -Destination (Join-Path $installRoot "Driver\Serpium.Flow.Driver.cat") -Force
    Copy-Item -LiteralPath $infSource -Destination (Join-Path $installRoot "Driver\Serpium.Flow.Driver.inf") -Force
    Copy-Item -LiteralPath $certificateSource -Destination (Join-Path $installRoot "Driver\Serpium.Flow.WFP11.Test.cer") -Force

    Write-Wfp11JsonFile -Path $ownershipMarker -Value ([ordered]@{
        schema = 1
        runId = $runId
        createdUtc = (Get-Date).ToUniversalTime().ToString("o")
        stage = "InstalledFiles"
        driverSha256 = (Get-FileHash -LiteralPath $driverTarget -Algorithm SHA256).Hash.ToLowerInvariant()
        serviceSha256 = (Get-FileHash -LiteralPath $serviceTarget -Algorithm SHA256).Hash.ToLowerInvariant()
    }) -Depth 5

    $state.installRunId = $runId
    $state.stage = "LifecycleRunning"
    Save-Wfp11State -State $state

    $sc = Join-Path $env:SystemRoot "System32\sc.exe"
    Invoke-Wfp11Native -FilePath $sc -Arguments @(
        "create", $script:Wfp11DriverServiceName,
        "type=", "kernel",
        "start=", "demand",
        "error=", "normal",
        "binPath=", $driverTarget,
        "DisplayName=", "Serpium Flow Driver"
    ) -LogPath (Join-Path $stage "05-driver-create.log") | Out-Null
    $driverCreated = $true

    $driverRecord = Get-Wfp11DriverService

    if (-not (Test-ServicePathOwned -Record $driverRecord -ExpectedPath $driverTarget)) {
        throw "Created driver service path does not match the isolated install path."
    }

    Invoke-Wfp11Native -FilePath $sc -Arguments @("start", $script:Wfp11DriverServiceName) -LogPath (Join-Path $stage "06-driver-start.log") | Out-Null
    Wait-Wfp11ServiceState -Kind Driver -State Running -TimeoutSeconds 20

    Invoke-Wfp11Native -FilePath $serviceTarget -Arguments @("install") -LogPath (Join-Path $stage "07-user-service-install.log") | Out-Null
    $userServiceCreated = $true

    $userRecord = Get-Wfp11UserService

    if (-not (Test-ServicePathOwned -Record $userRecord -ExpectedPath $serviceTarget)) {
        throw "Created user service path does not match the isolated install path."
    }

    Invoke-Wfp11Native -FilePath $serviceTarget -Arguments @("start") -LogPath (Join-Path $stage "08-user-service-start.log") | Out-Null
    Wait-Wfp11ServiceState -Kind User -State Running -TimeoutSeconds 20

    $statusResult = Invoke-Wfp11Native -FilePath $serviceTarget -Arguments @("status") -LogPath (Join-Path $stage "09-driver-status.log")

    if (($statusResult.Output -join "`n") -notmatch 'SERPIUM_WFP1_DRIVER_READY') {
        throw "Driver status did not return SERPIUM_WFP1_DRIVER_READY."
    }

    if (($statusResult.Output -join "`n") -notmatch '(?im)^Flags:\s+0x00000007\s*$') {
        throw "Driver status flags do not prove DRIVER_READY + CONTROL_DEVICE + WFP_DISABLED."
    }

    $pingResult = Invoke-Wfp11Native -FilePath $serviceTarget -Arguments @("ping") -LogPath (Join-Path $stage "10-driver-ping.log")

    if (($pingResult.Output -join "`n") -notmatch 'SERPIUM_WFP1_PING_PASS') {
        throw "Driver ping did not return SERPIUM_WFP1_PING_PASS."
    }

    Start-Sleep -Seconds 4
    Wait-Wfp11ServiceState -Kind User -State Running -TimeoutSeconds 5
    Wait-Wfp11ServiceState -Kind Driver -State Running -TimeoutSeconds 5

    $wfpDuring = Get-Wfp11WfpNameSummary

    if (-not $wfpDuring.Available -or $wfpDuring.MatchCount -ne 0) {
        throw "Serpium-named WFP objects appeared during the WFP-1.1 lifecycle test."
    }

    Invoke-Wfp11Native -FilePath $serviceTarget -Arguments @("stop") -LogPath (Join-Path $stage "11-user-service-stop.log") | Out-Null
    Wait-Wfp11ServiceState -Kind User -State Stopped -TimeoutSeconds 20
    Invoke-Wfp11Native -FilePath $serviceTarget -Arguments @("uninstall") -LogPath (Join-Path $stage "12-user-service-delete.log") | Out-Null
    Wait-Wfp11ServiceState -Kind User -State Absent -TimeoutSeconds 20
    $userServiceCreated = $false

    Invoke-Wfp11Native -FilePath $sc -Arguments @("stop", $script:Wfp11DriverServiceName) -LogPath (Join-Path $stage "13-driver-stop.log") | Out-Null
    Wait-Wfp11ServiceState -Kind Driver -State Stopped -TimeoutSeconds 20
    Invoke-Wfp11Native -FilePath $sc -Arguments @("delete", $script:Wfp11DriverServiceName) -LogPath (Join-Path $stage "14-driver-delete.log") | Out-Null
    Wait-Wfp11ServiceState -Kind Driver -State Absent -TimeoutSeconds 20
    $driverCreated = $false

    Remove-OwnedInstallRoot -ExpectedRunId $runId
    Remove-Item -LiteralPath $serviceLog -Force -ErrorAction SilentlyContinue

    if (Test-Path -LiteralPath $serviceLog) {
        throw "WFP-1.1 service log remained after lifecycle cleanup."
    }

    $wfpAfter = Get-Wfp11WfpNameSummary

    if (-not $wfpAfter.Available -or $wfpAfter.MatchCount -ne 0) {
        throw "WFP state is not clean after lifecycle removal."
    }

    Assert-Wfp11ServicesAbsent

    $state.installRunId = $null
    $state.stage = "LifecyclePassed"
    Save-Wfp11State -State $state

    $report.Add("State: PASS")
    $report.Add("Stage: WFP-1.1 safe lifecycle")
    $report.Add("RunId: " + $runId)
    $report.Add("SecureBoot: " + [string]$secureBoot.State)
    $report.Add("MemoryIntegrity: " + (Get-Wfp11MemoryIntegrityState))
    $report.Add("CodeIntegrityOptions: " + ("0x{0:X8}" -f [uint32]$codeIntegrity.Options))
    $report.Add("TestSigningRuntime: True")
    $report.Add("VerificationPolicy: Authenticode test-signing policy (/pa)")
    $report.Add("SignerThumbprintMatched: True")
    $report.Add("DriverStatus: PASS")
    $report.Add("DriverPing: PASS")
    $report.Add("ExpectedStatusFlags: 0x00000007")
    $report.Add("WfpEnabled: False")
    $report.Add("SerpiumWfpMatchesBefore: " + $wfpBefore.MatchCount)
    $report.Add("SerpiumWfpMatchesDuring: " + $wfpDuring.MatchCount)
    $report.Add("SerpiumWfpMatchesAfter: " + $wfpAfter.MatchCount)
    $report.Add("DriverServiceAfter: Absent")
    $report.Add("UserServiceAfter: Absent")
    $report.Add("InstallFilesAfter: Absent")
    $report.Add("ServiceLogAfter: Absent")
    $report.Add("CertificateAfter: Present (remove with cleanup_wfp11.ps1)")
    $report.Add("BcdAfter: Preserved (restore with cleanup_wfp11.ps1)")
}
catch {
    $failure = $_.Exception.Message
    $report.Add("State: FAIL")
    $report.Add("Stage: WFP-1.1 safe lifecycle")
    $report.Add("RunId: " + $runId)
    $report.Add("Error: " + $failure)

    try {
        $eventFilter = @{
            LogName = "Microsoft-Windows-CodeIntegrity/Operational"
            StartTime = (Get-Date).AddMinutes(-30)
        }
        $allEvents = @(Get-WinEvent -FilterHashtable $eventFilter -ErrorAction SilentlyContinue)
        $events = @($allEvents | Select-Object -First 30)

        if ($events.Count -gt 0) {
            $eventLines = @($events | ForEach-Object {
                ([string]$_.TimeCreated + " | " + [string]$_.Id + " | " + [string]$_.LevelDisplayName + " | " + ([string]$_.Message).Replace("`r", " ").Replace("`n", " "))
            })
            Write-Wfp11Utf8File -Path (Join-Path $stage "CODE_INTEGRITY_EVENTS.txt") -Lines $eventLines
        }
    }
    catch {
    }
}
finally {
    $rollbackSucceeded = $true

    if ($driverCreated -or $userServiceCreated -or (Test-Path -LiteralPath $installRoot)) {
        $rollback = Invoke-LifecycleRollback
        foreach ($line in $rollback) {
            $report.Add([string]$line)

            if ([string]$line -match ': FAIL') {
                $rollbackSucceeded = $false
            }
        }
    }

    if ($null -ne $failure -and $null -ne $state) {
        try {
            Remove-Wfp11CertificateByThumbprint -Thumbprint ([string]$state.certificateThumbprint)
            $report.Add("CertificateFailureRollback: PASS")
        }
        catch {
            $rollbackSucceeded = $false
            $report.Add("CertificateFailureRollback: FAIL - " + $_.Exception.Message)
        }

        if ([bool]$state.bcdChangedByScript) {
            try {
                $bcdedit = Join-Path $env:SystemRoot "System32\bcdedit.exe"
                Invoke-Wfp11Native -FilePath $bcdedit -Arguments @("-set", "TESTSIGNING", "OFF") -LogPath (Join-Path $stage "failure-bcd-rollback.log") | Out-Null
                $report.Add("BcdFailureRollback: PASS_REBOOT_REQUIRED")
            }
            catch {
                $rollbackSucceeded = $false
                $report.Add("BcdFailureRollback: FAIL - " + $_.Exception.Message)
            }
        }

        if ($rollbackSucceeded) {
            Remove-Item -LiteralPath ([string]$state.signedPackageDirectory) -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath (Get-Wfp11StatePath) -Force -ErrorAction SilentlyContinue
            $report.Add("FailureStateCleanup: PASS")
        }
        else {
            $report.Add("FailureStateCleanup: PRESERVED_FOR_RECOVERY")
        }
    }
}

Write-Wfp11Utf8File -Path (Join-Path $stage "LIFECYCLE_RESULT.txt") -Lines ($report.ToArray())
$archive = New-Wfp11ResultArchive -Prefix "Serpium_WFP11_Lifecycle_Result" -StageDirectory $stage

Write-Host ""

if ($null -eq $failure) {
    Write-Host "SERPIUM_WFP11_LIFECYCLE_PASS" -ForegroundColor Green
    Write-Host ("Result archive: " + $archive) -ForegroundColor Cyan
    exit 0
}

Write-Host "SERPIUM_WFP11_LIFECYCLE_FAIL" -ForegroundColor Red
Write-Host $failure -ForegroundColor Red
Write-Host ("Result archive: " + $archive) -ForegroundColor Yellow
exit 1
