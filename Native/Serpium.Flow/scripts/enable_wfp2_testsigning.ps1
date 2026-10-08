#requires -version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("ENABLE")]
    [string]$ConfirmEnable
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "wfp2_common.ps1")

Assert-Wfp2Administrator

$state = Get-Wfp2State

if ($null -eq $state) {
    throw "WFP-2 state is missing. Run prepare_wfp2_test_package.ps1 first."
}

$stateIdentity = Assert-Wfp2StateIdentity -State $state

if ([int]$state.schema -ne 2 -or [string]$state.stage -ne "Prepared") {
    throw "WFP-2 state is not at the Prepared stage."
}

$signedManifest = Join-Path $stateIdentity.SignedPackageDirectory "WFP2_SIGNING_MANIFEST.json"

if (-not (Test-Path -LiteralPath $signedManifest -PathType Leaf)) {
    throw "The WFP-2 signed package manifest is missing: $signedManifest"
}

$manifest = Get-Content -LiteralPath $signedManifest -Raw | ConvertFrom-Json

if (
    [int]$manifest.schema -ne 2 -or
    -not [bool]$manifest.wfpEnabled -or
    [string]$manifest.wfpMode -ne "observe-only" -or
    [string]$manifest.filterAction -ne "FWP_ACTION_CALLOUT_INSPECTION" -or
    [string]$manifest.classifyAction -ne "FWP_ACTION_CONTINUE" -or
    [bool]$manifest.trafficModification -or
    [bool]$manifest.blockingEnabled -or
    [bool]$manifest.redirectEnabled
) {
    throw "The signed package manifest violates the WFP-2 observe-only contract."
}

if (
    [string]$manifest.runId -ne [string]$state.runId -or
    [string]$manifest.certificate.thumbprint -ine [string]$state.certificateThumbprint
) {
    throw "The signed package manifest does not match the guarded WFP-2 state."
}

foreach ($store in @("My", "Root", "TrustedPublisher")) {
    $certificatePath = "Cert:\LocalMachine\$store\$($state.certificateThumbprint)"

    if (-not (Test-Path -LiteralPath $certificatePath)) {
        throw "The WFP-2 test certificate is missing from LocalMachine\$store."
    }
}

Assert-Wfp2ServicesAbsent

$wfp = Get-Wfp2WfpNameSummary

if (-not $wfp.Available -or $wfp.MatchCount -ne 0) {
    throw "Serpium WFP runtime state is not clean."
}

$secureBoot = Get-Wfp2SecureBootState

if ($secureBoot.State -ne "Disabled") {
    throw "Secure Boot must be Disabled. This script does not change firmware settings (actual: $($secureBoot.State))."
}

$codeIntegrity = Get-Wfp2CodeIntegrityState
$bcdBefore = Get-Wfp2BcdTestSigningState

if (-not $codeIntegrity.Available) {
    throw "Runtime Code Integrity state is unavailable."
}

if (-not $bcdBefore.Available) {
    throw "BCD state could not be read safely. No BCD change was made."
}

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$stage = Join-Path $env:TEMP ("Serpium_WFP2_EnableTestSigning_" + $stamp)
New-Item -ItemType Directory -Path $stage -Force | Out-Null
$report = New-Object 'System.Collections.Generic.List[string]'
$changedNow = $false
$failure = $null

try {
    if ($codeIntegrity.TestSigningRuntime) {
        $state.stage = "TestSigningActive"
        Save-Wfp2State -State $state
        $report.Add("State: PASS")
        $report.Add("TestSigningRuntime: True")
        $report.Add("BcdChangedNow: False")
        $report.Add("RebootRequired: False")
    }
    else {
        if (-not $bcdBefore.Enabled) {
            $bcdedit = Join-Path $env:SystemRoot "System32\bcdedit.exe"
            Invoke-Wfp2Native -FilePath $bcdedit -Arguments @("-set", "TESTSIGNING", "ON") -LogPath (Join-Path $stage "bcdedit-enable.log") | Out-Null
            $changedNow = $true
            $state.bcdChangedByScript = $true
        }

        $state.stage = "TestSigningConfigured"
        Save-Wfp2State -State $state
        $report.Add("State: PASS_REBOOT_REQUIRED")
        $report.Add("TestSigningRuntime: False")
        $report.Add("BcdWasConfigured: " + [string]$bcdBefore.Enabled)
        $report.Add("BcdChangedNow: " + [string]$changedNow)
        $report.Add("RebootRequired: True")
    }

    $report.Add("SecureBoot: " + [string]$secureBoot.State)
    $report.Add("MemoryIntegrity: " + (Get-Wfp2MemoryIntegrityState))
    $report.Add("WfpMode: observe-only")
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
            Invoke-Wfp2Native -FilePath $bcdedit -Arguments @("-set", "TESTSIGNING", "OFF") -LogPath (Join-Path $stage "bcdedit-rollback.log") | Out-Null
            $state.bcdChangedByScript = $false
            $state.stage = "Prepared"
            Save-Wfp2State -State $state
            $report.Add("BcdRollback: PASS_REBOOT_REQUIRED")
        }
        catch {
            $report.Add("BcdRollback: FAIL - " + $_.Exception.Message)
        }
    }
}

Write-Wfp2Utf8File -Path (Join-Path $stage "ENABLE_TESTSIGNING_RESULT.txt") -Lines ($report.ToArray())
$archive = New-Wfp2ResultArchive -Prefix "Serpium_WFP2_EnableTestSigning_Result" -StageDirectory $stage

Write-Host ""

if ($null -ne $failure) {
    Write-Host "SERPIUM_WFP2_ENABLE_TESTSIGNING_FAIL" -ForegroundColor Red
    Write-Host $failure -ForegroundColor Red
    Write-Host ("Result archive: " + $archive) -ForegroundColor Yellow
    exit 1
}

if ($codeIntegrity.TestSigningRuntime) {
    Write-Host "SERPIUM_WFP2_TESTSIGNING_ALREADY_ACTIVE" -ForegroundColor Green
}
else {
    Write-Host "SERPIUM_WFP2_TESTSIGNING_CONFIGURED_REBOOT_REQUIRED" -ForegroundColor Green
}

Write-Host ("Result archive: " + $archive) -ForegroundColor Cyan
exit 0
