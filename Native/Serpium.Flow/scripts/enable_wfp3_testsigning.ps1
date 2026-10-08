#requires -version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("ENABLE")]
    [string]$ConfirmEnable
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "wfp3_common.ps1")

Assert-Wfp3Administrator

$state = Get-Wfp3State

if ($null -eq $state) {
    throw "WFP-3 state is missing. Run prepare_wfp3_policy_test_package.ps1 first."
}

$stateIdentity = Assert-Wfp3StateIdentity -State $state

if ([int]$state.schema -ne 3 -or [string]$state.stage -ne "Prepared") {
    throw "WFP-3 state is not at the Prepared stage."
}

$signedManifest = Join-Path $stateIdentity.SignedPackageDirectory "WFP3_SIGNING_MANIFEST.json"

if (-not (Test-Path -LiteralPath $signedManifest -PathType Leaf)) {
    throw "The WFP-3 signed package manifest is missing: $signedManifest"
}

$manifest = Get-Content -LiteralPath $signedManifest -Raw | ConvertFrom-Json

if (
    [int]$manifest.schema -ne 3 -or
    -not [bool]$manifest.wfpEnabled -or
    [string]$manifest.wfpMode -ne "observe-only-policy-transport" -or
    [string]$manifest.protocolVersion -ne "0x00030000" -or
    -not [bool]$manifest.policyTransportEnabled -or
    [string]$manifest.filterAction -ne "FWP_ACTION_CALLOUT_INSPECTION" -or
    [string]$manifest.classifyAction -ne "FWP_ACTION_CONTINUE" -or
    [bool]$manifest.trafficModification -or
    [bool]$manifest.blockingEnabled -or
    [bool]$manifest.redirectEnabled -or
    [bool]$manifest.injectionEnabled -or
    [bool]$manifest.routeEnforcementEnabled -or
    [bool]$manifest.existingFlowMutation
) {
    throw "The signed package manifest violates the WFP-3 fail-open policy-transport contract."
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
    throw "The signed package manifest does not contain the exact bounded WFP-3 policy contract."
}

if (
    [string]$manifest.runId -ne [string]$state.runId -or
    [string]$manifest.certificate.thumbprint -ine [string]$state.certificateThumbprint
) {
    throw "The signed package manifest does not match the guarded WFP-3 state."
}

$packageResult = Test-Wfp3UnsignedPackage -Configuration ([string]$state.configuration)
$currentBuildManifest = Join-Path $packageResult.PackageDirectory "BUILD_MANIFEST.json"

if ((Get-FileHash -LiteralPath $currentBuildManifest -Algorithm SHA256).Hash -ine [string]$manifest.sourceBuildManifestSha256) {
    throw "The verified unsigned WFP-3 build package changed after preparation."
}

foreach ($store in @("My", "Root", "TrustedPublisher")) {
    $certificatePath = "Cert:\LocalMachine\$store\$($state.certificateThumbprint)"

    if (-not (Test-Path -LiteralPath $certificatePath)) {
        throw "The WFP-3 test certificate is missing from LocalMachine\$store."
    }
}

Assert-Wfp3ServicesAbsent

$wfp = Get-Wfp3WfpNameSummary

if (-not $wfp.Available -or $wfp.MatchCount -ne 0) {
    throw "Serpium WFP runtime state is not clean."
}

$secureBoot = Get-Wfp3SecureBootState

if ($secureBoot.State -ne "Disabled") {
    throw "Secure Boot must be Disabled. This script does not change firmware settings (actual: $($secureBoot.State))."
}

$codeIntegrity = Get-Wfp3CodeIntegrityState
$bcdBefore = Get-Wfp3BcdTestSigningState

if (-not $codeIntegrity.Available) {
    throw "Runtime Code Integrity state is unavailable."
}

if (-not $bcdBefore.Available) {
    throw "BCD state could not be read safely. No BCD change was made."
}

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$stage = Join-Path $env:TEMP ("Serpium_WFP3_EnableTestSigning_" + $stamp)
New-Item -ItemType Directory -Path $stage -Force | Out-Null
$report = New-Object 'System.Collections.Generic.List[string]'
$changedNow = $false
$failure = $null

try {
    if ($codeIntegrity.TestSigningRuntime) {
        $state.stage = "TestSigningActive"
        Save-Wfp3State -State $state
        $report.Add("State: PASS")
        $report.Add("TestSigningRuntime: True")
        $report.Add("BcdChangedNow: False")
        $report.Add("RebootRequired: False")
    }
    else {
        if (-not $bcdBefore.Enabled) {
            $bcdedit = Join-Path $env:SystemRoot "System32\bcdedit.exe"
            Invoke-Wfp3Native -FilePath $bcdedit -Arguments @("-set", "TESTSIGNING", "ON") -LogPath (Join-Path $stage "bcdedit-enable.log") | Out-Null
            $changedNow = $true
            $state.bcdChangedByScript = $true
        }

        $state.stage = "TestSigningConfigured"
        Save-Wfp3State -State $state
        $report.Add("State: PASS_REBOOT_REQUIRED")
        $report.Add("TestSigningRuntime: False")
        $report.Add("BcdWasConfigured: " + [string]$bcdBefore.Enabled)
        $report.Add("BcdChangedNow: " + [string]$changedNow)
        $report.Add("RebootRequired: True")
    }

    $report.Add("SecureBoot: " + [string]$secureBoot.State)
    $report.Add("MemoryIntegrity: " + (Get-Wfp3MemoryIntegrityState))
    $report.Add("WfpMode: observe-only-policy-transport")
    $report.Add("PolicyTransportEnabled: True")
    $report.Add("RouteEnforcementEnabled: False")
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
            Invoke-Wfp3Native -FilePath $bcdedit -Arguments @("-set", "TESTSIGNING", "OFF") -LogPath (Join-Path $stage "bcdedit-rollback.log") | Out-Null
            $state.bcdChangedByScript = $false
            $state.stage = "Prepared"
            Save-Wfp3State -State $state
            $report.Add("BcdRollback: PASS_REBOOT_REQUIRED")
        }
        catch {
            $report.Add("BcdRollback: FAIL - " + $_.Exception.Message)
        }
    }
}

Write-Wfp3Utf8File -Path (Join-Path $stage "ENABLE_TESTSIGNING_RESULT.txt") -Lines ($report.ToArray())
$archive = New-Wfp3ResultArchive -Prefix "Serpium_WFP3_PolicyEnableTestSigning_Result" -StageDirectory $stage

Write-Host ""

if ($null -ne $failure) {
    Write-Host "SERPIUM_WFP3_POLICY_ENABLE_TESTSIGNING_FAIL" -ForegroundColor Red
    Write-Host $failure -ForegroundColor Red
    Write-Host ("Result archive: " + $archive) -ForegroundColor Yellow
    exit 1
}

if ($codeIntegrity.TestSigningRuntime) {
    Write-Host "SERPIUM_WFP3_POLICY_TESTSIGNING_ALREADY_ACTIVE" -ForegroundColor Green
}
else {
    Write-Host "SERPIUM_WFP3_POLICY_TESTSIGNING_CONFIGURED_REBOOT_REQUIRED" -ForegroundColor Green
}

Write-Host ("Result archive: " + $archive) -ForegroundColor Cyan
exit 0
