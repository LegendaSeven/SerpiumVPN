#requires -version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("ENABLE")]
    [string]$ConfirmEnable
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "wfp11_common.ps1")

Assert-Wfp11Administrator

$state = Get-Wfp11State

if ($null -eq $state) {
    throw "WFP-1.1 state is missing. Run prepare_wfp11_test_package.ps1 first."
}

$signedManifest = Join-Path ([string]$state.signedPackageDirectory) "WFP11_SIGNING_MANIFEST.json"

if (-not (Test-Path -LiteralPath $signedManifest -PathType Leaf)) {
    throw "The signed package manifest is missing: $signedManifest"
}

foreach ($store in @("My", "Root", "TrustedPublisher")) {
    $certificatePath = "Cert:\LocalMachine\$store\$($state.certificateThumbprint)"

    if (-not (Test-Path -LiteralPath $certificatePath)) {
        throw "The WFP-1.1 test certificate is missing from LocalMachine\$store."
    }
}

$secureBoot = Get-Wfp11SecureBootState

if ($secureBoot.State -ne "Disabled") {
    throw "Secure Boot must be Disabled. This script does not change firmware settings (actual: $($secureBoot.State))."
}

$codeIntegrity = Get-Wfp11CodeIntegrityState
$bcdBefore = Get-Wfp11BcdTestSigningState

if (-not $codeIntegrity.Available) {
    throw "Runtime Code Integrity state is unavailable."
}

if (-not $bcdBefore.Available) {
    throw "BCD state could not be read safely. No BCD change was made."
}

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$stage = Join-Path $env:TEMP ("Serpium_WFP11_EnableTestSigning_" + $stamp)
New-Item -ItemType Directory -Path $stage -Force | Out-Null
$report = New-Object 'System.Collections.Generic.List[string]'
$changedNow = $false
$failure = $null

try {
    if ($codeIntegrity.TestSigningRuntime) {
        $state.stage = "TestSigningActive"
        Save-Wfp11State -State $state
        $report.Add("State: PASS")
        $report.Add("TestSigningRuntime: True")
        $report.Add("BcdChangedNow: False")
        $report.Add("RebootRequired: False")
    }
    else {
        if (-not $bcdBefore.Enabled) {
            $bcdedit = Join-Path $env:SystemRoot "System32\bcdedit.exe"
            Invoke-Wfp11Native -FilePath $bcdedit -Arguments @("-set", "TESTSIGNING", "ON") -LogPath (Join-Path $stage "bcdedit-enable.log") | Out-Null
            $changedNow = $true
            $state.bcdChangedByScript = $true
        }

        $state.stage = "TestSigningConfigured"
        Save-Wfp11State -State $state
        $report.Add("State: PASS_REBOOT_REQUIRED")
        $report.Add("TestSigningRuntime: False")
        $report.Add("BcdWasConfigured: " + [string]$bcdBefore.Enabled)
        $report.Add("BcdChangedNow: " + [string]$changedNow)
        $report.Add("RebootRequired: True")
    }

    $report.Add("SecureBoot: " + [string]$secureBoot.State)
    $report.Add("MemoryIntegrity: " + (Get-Wfp11MemoryIntegrityState))
    $report.Add("DriverOrServiceInstalled: False")
    $report.Add("NetworkChanges: none")
}
catch {
    $failure = $_.Exception.Message
    $report.Add("State: FAIL")
    $report.Add("Error: " + $failure)

    if ($changedNow) {
        try {
            $bcdedit = Join-Path $env:SystemRoot "System32\bcdedit.exe"
            Invoke-Wfp11Native -FilePath $bcdedit -Arguments @("-set", "TESTSIGNING", "OFF") -LogPath (Join-Path $stage "bcdedit-rollback.log") | Out-Null
            $state.bcdChangedByScript = $false
            $state.stage = "Prepared"
            Save-Wfp11State -State $state
            $report.Add("BcdRollback: PASS_REBOOT_REQUIRED")
        }
        catch {
            $report.Add("BcdRollback: FAIL - " + $_.Exception.Message)
        }
    }
}

Write-Wfp11Utf8File -Path (Join-Path $stage "ENABLE_TESTSIGNING_RESULT.txt") -Lines ($report.ToArray())
$archive = New-Wfp11ResultArchive -Prefix "Serpium_WFP11_EnableTestSigning_Result" -StageDirectory $stage

Write-Host ""

if ($null -ne $failure) {
    Write-Host "SERPIUM_WFP11_ENABLE_TESTSIGNING_FAIL" -ForegroundColor Red
    Write-Host $failure -ForegroundColor Red
    Write-Host ("Result archive: " + $archive) -ForegroundColor Yellow
    exit 1
}

if ($codeIntegrity.TestSigningRuntime) {
    Write-Host "SERPIUM_WFP11_TESTSIGNING_ALREADY_ACTIVE" -ForegroundColor Green
}
else {
    Write-Host "SERPIUM_WFP11_TESTSIGNING_CONFIGURED_REBOOT_REQUIRED" -ForegroundColor Green
}

Write-Host ("Result archive: " + $archive) -ForegroundColor Cyan
exit 0
