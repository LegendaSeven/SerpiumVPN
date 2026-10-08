#requires -version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("CLEANUP")]
    [string]$ConfirmCleanup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "wfp11_common.ps1")

Assert-Wfp11Administrator

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$stage = Join-Path $env:TEMP ("Serpium_WFP11_Cleanup_" + $stamp)
New-Item -ItemType Directory -Path $stage -Force | Out-Null
$report = New-Object 'System.Collections.Generic.List[string]'
$failure = $null
$rebootRequired = $false

try {
    $state = Get-Wfp11State

    if ($null -eq $state) {
        Assert-Wfp11ServicesAbsent
        $wfp = Get-Wfp11WfpNameSummary

        if (-not $wfp.Available -or $wfp.MatchCount -ne 0) {
            throw "No WFP-1.1 state file exists, but WFP state is not clean."
        }

        $report.Add("State: PASS")
        $report.Add("Detail: No WFP-1.1 state exists and both services are absent.")
        $report.Add("RebootRequired: False")
    }
    else {
        $installRoot = Join-Path $env:ProgramFiles "Serpium\Flow\WFP11"
        $driverTarget = Join-Path $installRoot "Driver\Serpium.Flow.Driver.sys"
        $serviceTarget = Join-Path $installRoot "Service\Serpium.Flow.Service.exe"
        $ownershipMarker = Join-Path $installRoot "WFP11_INSTALL_STATE.json"

        $userRecord = Get-Wfp11UserService

        if ($null -ne $userRecord) {
            if ([string]$userRecord.PathName -notlike ("*" + $serviceTarget + "*")) {
                throw "Refusing to remove SerpiumFlowService because its path is not owned by WFP-1.1."
            }

            if (Test-Path -LiteralPath $serviceTarget -PathType Leaf) {
                Invoke-Wfp11Native -FilePath $serviceTarget -Arguments @("stop") -LogPath (Join-Path $stage "user-stop.log") -AllowFailure | Out-Null
                Invoke-Wfp11Native -FilePath $serviceTarget -Arguments @("uninstall") -LogPath (Join-Path $stage "user-delete.log") | Out-Null
            }
            else {
                throw "Owned user service exists but its executable is missing. Manual inspection is required."
            }

            Wait-Wfp11ServiceState -Kind User -State Absent -TimeoutSeconds 20
        }

        $driverRecord = Get-Wfp11DriverService

        if ($null -ne $driverRecord) {
            if ([string]$driverRecord.PathName -notlike ("*" + $driverTarget + "*")) {
                throw "Refusing to remove SerpiumFlow because its path is not owned by WFP-1.1."
            }

            $sc = Join-Path $env:SystemRoot "System32\sc.exe"
            Invoke-Wfp11Native -FilePath $sc -Arguments @("stop", $script:Wfp11DriverServiceName) -LogPath (Join-Path $stage "driver-stop.log") -AllowFailure | Out-Null
            Invoke-Wfp11Native -FilePath $sc -Arguments @("delete", $script:Wfp11DriverServiceName) -LogPath (Join-Path $stage "driver-delete.log") | Out-Null
            Wait-Wfp11ServiceState -Kind Driver -State Absent -TimeoutSeconds 20
        }

        if (Test-Path -LiteralPath $installRoot -PathType Container) {
            if (-not (Test-Path -LiteralPath $ownershipMarker -PathType Leaf)) {
                throw "Refusing to remove install files without the WFP-1.1 ownership marker."
            }

            $marker = Get-Content -LiteralPath $ownershipMarker -Raw | ConvertFrom-Json

            if (-not [string]::IsNullOrWhiteSpace([string]$state.installRunId) -and [string]$marker.runId -ne [string]$state.installRunId) {
                throw "Install ownership marker does not match WFP-1.1 state."
            }

            Remove-Item -LiteralPath $installRoot -Recurse -Force -ErrorAction Stop
        }

        Remove-Wfp11CertificateByThumbprint -Thumbprint ([string]$state.certificateThumbprint)

        if (Test-Path -LiteralPath ([string]$state.signedPackageDirectory)) {
            Remove-Item -LiteralPath ([string]$state.signedPackageDirectory) -Recurse -Force -ErrorAction Stop
        }

        if ([bool]$state.bcdChangedByScript) {
            $bcdedit = Join-Path $env:SystemRoot "System32\bcdedit.exe"
            Invoke-Wfp11Native -FilePath $bcdedit -Arguments @("-set", "TESTSIGNING", "OFF") -LogPath (Join-Path $stage "bcdedit-disable.log") | Out-Null
            $rebootRequired = $true
        }

        Remove-Item -LiteralPath (Get-Wfp11StatePath) -Force -ErrorAction Stop
        Assert-Wfp11ServicesAbsent

        $wfp = Get-Wfp11WfpNameSummary

        if (-not $wfp.Available -or $wfp.MatchCount -ne 0) {
            throw "WFP state is not clean after WFP-1.1 cleanup."
        }

        $report.Add("State: PASS")
        $report.Add("DriverService: Absent")
        $report.Add("UserService: Absent")
        $report.Add("InstallFiles: Absent")
        $report.Add("TestCertificate: Removed")
        $report.Add("SerpiumWfpMatches: " + $wfp.MatchCount)
        $report.Add("TestSigningRestored: " + [string]([bool]$state.bcdChangedByScript))
        $report.Add("RebootRequired: " + [string]$rebootRequired)
    }
}
catch {
    $failure = $_.Exception.Message
    $report.Add("State: FAIL")
    $report.Add("Error: " + $failure)
    $report.Add("Safety: state file was preserved when possible; no unowned service or directory was removed.")
}

Write-Wfp11Utf8File -Path (Join-Path $stage "CLEANUP_RESULT.txt") -Lines ($report.ToArray())
$archive = New-Wfp11ResultArchive -Prefix "Serpium_WFP11_Cleanup_Result" -StageDirectory $stage

Write-Host ""

if ($null -ne $failure) {
    Write-Host "SERPIUM_WFP11_CLEANUP_FAIL" -ForegroundColor Red
    Write-Host $failure -ForegroundColor Red
    Write-Host ("Result archive: " + $archive) -ForegroundColor Yellow
    exit 1
}

if ($rebootRequired) {
    Write-Host "SERPIUM_WFP11_CLEANUP_PASS_REBOOT_REQUIRED" -ForegroundColor Green
}
else {
    Write-Host "SERPIUM_WFP11_CLEANUP_PASS" -ForegroundColor Green
}

Write-Host ("Result archive: " + $archive) -ForegroundColor Cyan
exit 0
