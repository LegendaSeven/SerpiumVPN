#requires -version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("CLEANUP")]
    [string]$ConfirmCleanup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "wfp4a_common.ps1")

Assert-Wfp4aAdministrator

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$stage = Join-Path $env:TEMP ("Serpium_WFP4A_Cleanup_" + $stamp)
New-Item -ItemType Directory -Path $stage -Force | Out-Null
$report = New-Object 'System.Collections.Generic.List[string]'
$failure = $null
$rebootRequired = $false

try {
    $state = Get-Wfp4aState

    if ($null -eq $state) {
        Assert-Wfp4aServicesAbsent

        if (Test-Path -LiteralPath (Get-Wfp4aInstallRoot)) {
            throw "No WFP-4A state exists, but the isolated install root remains."
        }

        if (Test-Path -LiteralPath (Get-Wfp4aServiceLogPath)) {
            throw "No WFP-4A state exists, but service.log remains."
        }

        if ((Get-Wfp4aCertificateCount -Prefix $script:Wfp4aCertificatePrefix) -ne 0) {
            throw "No WFP-4A state exists, but a matching test certificate remains in a machine store."
        }

        $wfp = Get-Wfp4aWfpNameSummary

        if (-not $wfp.Available -or $wfp.MatchCount -ne 0) {
            throw "No WFP-4A state exists, but WFP state is not clean."
        }

        $report.Add("State: PASS")
        $report.Add("Detail: No WFP-4A state exists and runtime artifacts are absent.")
        $report.Add("SerpiumWfpMatches: " + $wfp.MatchCount)
        $report.Add("RebootRequired: False")
    }
    else {
        $stateIdentity = Assert-Wfp4aStateIdentity -State $state

        $installRoot = Get-Wfp4aInstallRoot
        $driverTarget = Join-Path $installRoot "Driver\Serpium.Flow.Driver.sys"
        $serviceTarget = Join-Path $installRoot "Service\Serpium.Flow.Service.exe"
        $ownershipMarker = Join-Path $installRoot "WFP4A_INSTALL_STATE.json"

        $driverBeforeDisarm = Get-Wfp4aDriverService

        if (
            $null -ne $driverBeforeDisarm -and
            [string]$driverBeforeDisarm.State -eq "Running" -and
            (Test-Path -LiteralPath $serviceTarget -PathType Leaf)
        ) {
            $disarm = Invoke-Wfp4aNative -FilePath $serviceTarget -Arguments @("disarm-route") -LogPath (Join-Path $stage "route-disarm.log") -AllowFailure

            if (
                $disarm.ExitCode -ne 0 -or
                ($disarm.Output -join "`n") -notmatch '(?m)^SERPIUM_WFP4A_ROUTE_DISARMED\s*$'
            ) {
                throw "Owned WFP-4A driver is running but guarded route disarm failed."
            }
        }

        $userRecord = Get-Wfp4aUserService

        if ($null -ne $userRecord) {
            if ([string]$userRecord.PathName -notlike ("*" + $serviceTarget + "*")) {
                throw "Refusing to remove SerpiumFlowService because its path is not owned by WFP-4A."
            }

            if (Test-Path -LiteralPath $serviceTarget -PathType Leaf) {
                Invoke-Wfp4aNative -FilePath $serviceTarget -Arguments @("stop") -LogPath (Join-Path $stage "user-stop.log") -AllowFailure | Out-Null
                Invoke-Wfp4aNative -FilePath $serviceTarget -Arguments @("uninstall") -LogPath (Join-Path $stage "user-delete.log") | Out-Null
            }
            else {
                throw "Owned user service exists but its executable is missing. Manual inspection is required."
            }

            Wait-Wfp4aServiceState -Kind User -State Absent -TimeoutSeconds 20
        }

        $driverRecord = Get-Wfp4aDriverService

        if ($null -ne $driverRecord) {
            if ([string]$driverRecord.PathName -notlike ("*" + $driverTarget + "*")) {
                throw "Refusing to remove SerpiumFlow because its path is not owned by WFP-4A."
            }

            $sc = Join-Path $env:SystemRoot "System32\sc.exe"
            Invoke-Wfp4aNative -FilePath $sc -Arguments @("stop", $script:Wfp4aDriverServiceName) -LogPath (Join-Path $stage "driver-stop.log") -AllowFailure | Out-Null
            Invoke-Wfp4aNative -FilePath $sc -Arguments @("delete", $script:Wfp4aDriverServiceName) -LogPath (Join-Path $stage "driver-delete.log") | Out-Null
            Wait-Wfp4aServiceState -Kind Driver -State Absent -TimeoutSeconds 20
        }

        if (Test-Path -LiteralPath $installRoot -PathType Container) {
            if (-not (Test-Path -LiteralPath $ownershipMarker -PathType Leaf)) {
                throw "Refusing to remove install files without the WFP-4A ownership marker."
            }

            $marker = Get-Content -LiteralPath $ownershipMarker -Raw | ConvertFrom-Json

            if (-not [string]::IsNullOrWhiteSpace([string]$state.installRunId) -and [string]$marker.runId -ne [string]$state.installRunId) {
                throw "Install ownership marker does not match WFP-4A state."
            }

            Remove-Item -LiteralPath $installRoot -Recurse -Force -ErrorAction Stop
        }

        $serviceLog = Get-Wfp4aServiceLogPath

        if (Test-Path -LiteralPath $serviceLog) {
            Remove-Item -LiteralPath $serviceLog -Force -ErrorAction Stop
        }

        $programDataFlowRoot = Split-Path -Parent $serviceLog
        $programDataSerpiumRoot = Split-Path -Parent $programDataFlowRoot

        if (
            $null -ne $state.programDataFlowExistedBefore -and
            -not [bool]$state.programDataFlowExistedBefore -and
            (Test-Path -LiteralPath $programDataFlowRoot -PathType Container)
        ) {
            $flowChildren = @(Get-ChildItem -LiteralPath $programDataFlowRoot -Force -ErrorAction Stop)

            if ($flowChildren.Count -eq 0) {
                Remove-Item -LiteralPath $programDataFlowRoot -Force -ErrorAction Stop
            }
        }

        if (
            $null -ne $state.programDataSerpiumExistedBefore -and
            -not [bool]$state.programDataSerpiumExistedBefore -and
            (Test-Path -LiteralPath $programDataSerpiumRoot -PathType Container)
        ) {
            $serpiumChildren = @(Get-ChildItem -LiteralPath $programDataSerpiumRoot -Force -ErrorAction Stop)

            if ($serpiumChildren.Count -eq 0) {
                Remove-Item -LiteralPath $programDataSerpiumRoot -Force -ErrorAction Stop
            }
        }

        Remove-Wfp4aCertificateByThumbprint -Thumbprint ([string]$stateIdentity.CertificateThumbprint)

        if (Test-Path -LiteralPath ([string]$stateIdentity.SignedPackageDirectory)) {
            Remove-Item -LiteralPath ([string]$stateIdentity.SignedPackageDirectory) -Recurse -Force -ErrorAction Stop
        }

        if ([bool]$state.bcdChangedByScript) {
            $bcdedit = Join-Path $env:SystemRoot "System32\bcdedit.exe"
            Invoke-Wfp4aNative -FilePath $bcdedit -Arguments @("-set", "TESTSIGNING", "OFF") -LogPath (Join-Path $stage "bcdedit-disable.log") | Out-Null
            $rebootRequired = $true
        }

        Assert-Wfp4aServicesAbsent

        if (Test-Path -LiteralPath $installRoot) {
            throw "WFP-4A install files remain after cleanup."
        }

        if (Test-Path -LiteralPath $serviceLog) {
            throw "WFP-4A service.log remains after cleanup."
        }

        if ((Get-Wfp4aCertificateCount -Prefix $script:Wfp4aCertificatePrefix) -ne 0) {
            throw "A WFP-4A test certificate remains in a machine store after cleanup."
        }

        $wfp = Get-Wfp4aWfpNameSummary

        if (-not $wfp.Available -or $wfp.MatchCount -ne 0) {
            throw "WFP state is not clean after WFP-4A cleanup."
        }

        Remove-Item -LiteralPath (Get-Wfp4aStatePath) -Force -ErrorAction Stop

        $report.Add("State: PASS")
        $report.Add("DriverService: Absent")
        $report.Add("UserService: Absent")
        $report.Add("InstallFiles: Absent")
        $report.Add("ServiceLog: Absent")
        $report.Add("TestCertificate: Removed")
        $report.Add("SerpiumWfpMatches: " + $wfp.MatchCount)
        $report.Add("TestSigningRestored: " + [string]([bool]$state.bcdChangedByScript))
        $report.Add("NetworkConfigurationChanges: none")
        $report.Add("RebootRequired: " + [string]$rebootRequired)
    }
}
catch {
    $failure = $_.Exception.Message
    $report.Add("State: FAIL")
    $report.Add("Error: " + $failure)
    $report.Add("Safety: state file was preserved when possible; no unowned service or directory was removed.")
}

Write-Wfp4aUtf8File -Path (Join-Path $stage "CLEANUP_RESULT.txt") -Lines ($report.ToArray())
$archive = New-Wfp4aResultArchive -Prefix "Serpium_WFP4A_RouteCleanup_Result" -StageDirectory $stage

Write-Host ""

if ($null -ne $failure) {
    Write-Host "SERPIUM_WFP4A_ROUTE_CLEANUP_FAIL" -ForegroundColor Red
    Write-Host $failure -ForegroundColor Red
    Write-Host ("Result archive: " + $archive) -ForegroundColor Yellow
    exit 1
}

if ($rebootRequired) {
    Write-Host "SERPIUM_WFP4A_ROUTE_CLEANUP_PASS_REBOOT_REQUIRED" -ForegroundColor Green
}
else {
    Write-Host "SERPIUM_WFP4A_ROUTE_CLEANUP_PASS" -ForegroundColor Green
}

Write-Host ("Result archive: " + $archive) -ForegroundColor Cyan
exit 0
