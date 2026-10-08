#requires -version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("ENABLE")]
    [string]$ConfirmEnable
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "wfp4a_common.ps1")

Assert-Wfp4aAdministrator

$state = Get-Wfp4aState

if ($null -eq $state) {
    throw "WFP-4A state is missing. Run prepare_wfp4a_route_test_package.ps1 first."
}

$stateIdentity = Assert-Wfp4aStateIdentity -State $state

$stateStage = [string]$state.stage

if ([int]$state.schema -ne 4 -or $stateStage -notin @("Prepared", "TestSigningConfigured")) {
    throw "WFP-4A state is not at an allowed test-signing stage."
}

$signedManifest = Join-Path $stateIdentity.SignedPackageDirectory "WFP4A_SIGNING_MANIFEST.json"

if (-not (Test-Path -LiteralPath $signedManifest -PathType Leaf)) {
    throw "The WFP-4A signed package manifest is missing: $signedManifest"
}

$manifest = Get-Content -LiteralPath $signedManifest -Raw | ConvertFrom-Json

if (
    [int]$manifest.schema -ne 4 -or
    -not [bool]$manifest.wfpEnabled -or
    [string]$manifest.wfpMode -ne "guarded-tcp-route-enforcement" -or
    [string]$manifest.protocolVersion -ne "0x00040000" -or
    -not [bool]$manifest.policyTransportEnabled -or
    (@($manifest.filterActions | ForEach-Object { [string]$_ }) -notcontains "FWP_ACTION_CALLOUT_INSPECTION") -or
    (@($manifest.filterActions | ForEach-Object { [string]$_ }) -notcontains "FWP_ACTION_CALLOUT_TERMINATING") -or
    (@($manifest.classifyActions | ForEach-Object { [string]$_ }) -notcontains "FWP_ACTION_CONTINUE") -or
    (@($manifest.classifyActions | ForEach-Object { [string]$_ }) -notcontains "FWP_ACTION_PERMIT") -or
    -not [bool]$manifest.trafficModification -or
    [bool]$manifest.blockingEnabled -or
    -not [bool]$manifest.redirectEnabled -or
    [bool]$manifest.injectionEnabled -or
    -not [bool]$manifest.routeEnforcementEnabled -or
    [bool]$manifest.routeEnforcementDefaultArmed -or
    [int]$manifest.routeLeaseMilliseconds -ne 5000 -or
    -not [bool]$manifest.routeLeaseFailOpen -or
    -not [bool]$manifest.tcpOnly -or
    [bool]$manifest.udpQuicIncluded -or
    [bool]$manifest.killSwitchIncluded -or
    [string]$manifest.runtimeTestNetworkScope -ne "local-machine-only" -or
    [bool]$manifest.existingFlowMutation
) {
    throw "The signed package manifest violates the guarded fail-open WFP-4A route contract."
}

[string[]]$policyCommands = @($manifest.policyCommands | ForEach-Object { [string]$_ })

if (
    $policyCommands.Count -ne 5 -or
    $policyCommands -notcontains "ADD_RULE" -or
    $policyCommands -notcontains "REMOVE_RULE" -or
    $policyCommands -notcontains "CLEAR_RULES" -or
    $policyCommands -notcontains "ENUM_RULES" -or
    $policyCommands -notcontains "ENUM_FLOWS" -or
    [int]$manifest.applicationRuleCapacity -ne 128 -or
    [int]$manifest.observedFlowCapacity -ne 256
) {
    throw "The signed package manifest does not contain the exact bounded WFP-4A policy contract."
}

if (
    [string]$manifest.runId -ne [string]$state.runId -or
    [string]$manifest.certificate.thumbprint -ine [string]$state.certificateThumbprint
) {
    throw "The signed package manifest does not match the guarded WFP-4A state."
}

$packageResult = Test-Wfp4aUnsignedPackage -Configuration ([string]$state.configuration)
$currentBuildManifest = Join-Path $packageResult.PackageDirectory "BUILD_MANIFEST.json"

if ((Get-FileHash -LiteralPath $currentBuildManifest -Algorithm SHA256).Hash -ine [string]$manifest.sourceBuildManifestSha256) {
    throw "The verified unsigned WFP-4A build package changed after preparation."
}

foreach ($store in @("My", "Root", "TrustedPublisher")) {
    $certificatePath = "Cert:\LocalMachine\$store\$($state.certificateThumbprint)"

    if (-not (Test-Path -LiteralPath $certificatePath)) {
        throw "The WFP-4A test certificate is missing from LocalMachine\$store."
    }
}

Assert-Wfp4aServicesAbsent

$wfp = Get-Wfp4aWfpNameSummary

if (-not $wfp.Available -or $wfp.MatchCount -ne 0) {
    throw "Serpium WFP runtime state is not clean."
}

$secureBoot = Get-Wfp4aSecureBootState

if ($secureBoot.State -ne "Disabled") {
    throw "Secure Boot must be Disabled. This script does not change firmware settings (actual: $($secureBoot.State))."
}

$codeIntegrity = Get-Wfp4aCodeIntegrityState
$bcdBefore = Get-Wfp4aBcdTestSigningState

if (-not $codeIntegrity.Available) {
    throw "Runtime Code Integrity state is unavailable."
}

if (-not $bcdBefore.Available) {
    throw "BCD state could not be read safely. No BCD change was made."
}

if ($stateStage -eq "Prepared") {
    if ([bool]$state.bcdChangedByScript) {
        throw "Prepared WFP-4A state unexpectedly claims BCD ownership."
    }

    if ($bcdBefore.Enabled -or $codeIntegrity.TestSigningRuntime) {
        throw "TESTSIGNING changed outside the guarded WFP-4A transition."
    }
}
else {
    if (-not [bool]$state.bcdChangedByScript) {
        throw "Configured WFP-4A state does not prove guarded BCD ownership."
    }

    if (-not $bcdBefore.Enabled) {
        throw "Configured WFP-4A state requires BCD TESTSIGNING to remain enabled."
    }
}

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$stage = Join-Path $env:TEMP ("Serpium_WFP4A_EnableTestSigning_" + $stamp)
New-Item -ItemType Directory -Path $stage -Force | Out-Null
$report = New-Object 'System.Collections.Generic.List[string]'
$changedNow = $false
$failure = $null

try {
    if ($codeIntegrity.TestSigningRuntime) {
        $state.stage = "TestSigningActive"
        Save-Wfp4aState -State $state
        $report.Add("State: PASS")
        $report.Add("TestSigningRuntime: True")
        $report.Add("BcdChangedNow: False")
        $report.Add("RebootRequired: False")
    }
    else {
        if (-not $bcdBefore.Enabled) {
            $bcdedit = Join-Path $env:SystemRoot "System32\bcdedit.exe"
            Invoke-Wfp4aNative -FilePath $bcdedit -Arguments @("-set", "TESTSIGNING", "ON") -LogPath (Join-Path $stage "bcdedit-enable.log") | Out-Null
            $changedNow = $true
            $state.bcdChangedByScript = $true
        }

        $state.stage = "TestSigningConfigured"
        Save-Wfp4aState -State $state
        $report.Add("State: PASS_REBOOT_REQUIRED")
        $report.Add("TestSigningRuntime: False")
        $report.Add("BcdWasConfigured: " + [string]$bcdBefore.Enabled)
        $report.Add("BcdChangedNow: " + [string]$changedNow)
        $report.Add("RebootRequired: True")
    }

    $report.Add("SecureBoot: " + [string]$secureBoot.State)
    $report.Add("MemoryIntegrity: " + (Get-Wfp4aMemoryIntegrityState))
    $report.Add("WfpMode: guarded-tcp-route-enforcement")
    $report.Add("PolicyTransportEnabled: True")
    $report.Add("RouteEnforcementEnabled: True")
    $report.Add("RouteEnforcementDefaultArmed: False")
    $report.Add("RouteLeaseMilliseconds: 5000")
    $report.Add("RouteLeaseFailOpen: True")
    $report.Add("RuntimeTestNetworkScope: local-machine-only")
    $report.Add("DriverOrServiceInstalled: False")
    $report.Add("NetworkConfigurationChanges: none")
}
catch {
    $failure = $_.Exception.Message
    $report.Add("State: FAIL")
    $report.Add("Error: " + $failure)

    if ($changedNow) {
        try {
            $bcdedit = Join-Path $env:SystemRoot "System32\bcdedit.exe"
            Invoke-Wfp4aNative -FilePath $bcdedit -Arguments @("-set", "TESTSIGNING", "OFF") -LogPath (Join-Path $stage "bcdedit-rollback.log") | Out-Null
            $state.bcdChangedByScript = $false
            $state.stage = "Prepared"
            Save-Wfp4aState -State $state
            $report.Add("BcdRollback: PASS_REBOOT_REQUIRED")
        }
        catch {
            $report.Add("BcdRollback: FAIL - " + $_.Exception.Message)
        }
    }
}

Write-Wfp4aUtf8File -Path (Join-Path $stage "ENABLE_TESTSIGNING_RESULT.txt") -Lines ($report.ToArray())
$archive = New-Wfp4aResultArchive -Prefix "Serpium_WFP4A_RouteEnableTestSigning_Result" -StageDirectory $stage

Write-Host ""

if ($null -ne $failure) {
    Write-Host "SERPIUM_WFP4A_ROUTE_ENABLE_TESTSIGNING_FAIL" -ForegroundColor Red
    Write-Host $failure -ForegroundColor Red
    Write-Host ("Result archive: " + $archive) -ForegroundColor Yellow
    exit 1
}

if ($codeIntegrity.TestSigningRuntime) {
    Write-Host "SERPIUM_WFP4A_ROUTE_TESTSIGNING_ALREADY_ACTIVE" -ForegroundColor Green
}
else {
    Write-Host "SERPIUM_WFP4A_ROUTE_TESTSIGNING_CONFIGURED_REBOOT_REQUIRED" -ForegroundColor Green
}

Write-Host ("Result archive: " + $archive) -ForegroundColor Cyan
exit 0
