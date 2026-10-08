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
$stage = Join-Path $env:TEMP ("Serpium_WFP11_Preflight_" + $stamp)
New-Item -ItemType Directory -Path $stage -Force | Out-Null

$lines = New-Object 'System.Collections.Generic.List[string]'
$failures = New-Object 'System.Collections.Generic.List[string]'
$blockers = New-Object 'System.Collections.Generic.List[string]'

function Add-PreflightLine {
    param([string]$Name, [string]$Value)
    $lines.Add($Name + ": " + $Value)
}

try {
    Add-PreflightLine "CollectedAt" (Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz")
    Add-PreflightLine "ComputerName" $env:COMPUTERNAME
    Add-PreflightLine "OSVersion" ([Environment]::OSVersion.VersionString)
    Add-PreflightLine "PowerShell" $PSVersionTable.PSVersion.ToString()
    Add-PreflightLine "Elevated" "True"
    Add-PreflightLine "Configuration" $Configuration
    $lines.Add("")

    try {
        $packageResult = Test-Wfp11UnsignedPackage -Configuration $Configuration
        $manifest = $packageResult.Manifest
        Add-PreflightLine "BuildPackage" "PASS"
        Add-PreflightLine "BuildMode" ([string]$manifest.buildMode)
        Add-PreflightLine "SdkWdkVersion" ([string]$manifest.sdkWdkVersion)
        Add-PreflightLine "KmdfVersion" ([string]$manifest.kmdfVersion)
        Add-PreflightLine "WfpEnabled" ([string]$manifest.wfpEnabled)

        $signTool = Find-Wfp11SdkTool -Name "signtool.exe" -PreferredVersion ([string]$manifest.sdkWdkVersion)
        $inf2Cat = Find-Wfp11SdkTool -Name "Inf2Cat.exe" -PreferredVersion ([string]$manifest.sdkWdkVersion)
        Add-PreflightLine "SignTool" $signTool
        Add-PreflightLine "Inf2Cat" $inf2Cat

        foreach ($name in @(
            "Serpium.Flow.Driver.sys",
            "Serpium.Flow.Driver.cat",
            "Serpium.Flow.Service.exe"
        )) {
            $path = Join-Path $packageResult.PackageDirectory $name
            $signature = Get-AuthenticodeSignature -LiteralPath $path
            Add-PreflightLine ("UnsignedPackageSignature_" + $name) ([string]$signature.Status)
        }
    }
    catch {
        $failures.Add("Build/tool check: " + $_.Exception.Message)
        Add-PreflightLine "BuildPackage" "FAIL"
    }

    $lines.Add("")
    $secureBoot = Get-Wfp11SecureBootState
    Add-PreflightLine "SecureBoot" ([string]$secureBoot.State)
    Add-PreflightLine "SecureBootDetail" ([string]$secureBoot.Detail)

    if ($secureBoot.State -eq "Enabled") {
        $blockers.Add("Secure Boot is enabled. WFP-1.1 does not change firmware settings.")
    }
    elseif ($secureBoot.State -eq "Unknown") {
        $blockers.Add("Secure Boot state is unknown.")
    }

    Add-PreflightLine "MemoryIntegrity" (Get-Wfp11MemoryIntegrityState)

    $wdfRuntimePath = Join-Path $env:SystemRoot "System32\drivers\Wdf01000.sys"

    if (Test-Path -LiteralPath $wdfRuntimePath -PathType Leaf) {
        $wdfRuntime = Get-Item -LiteralPath $wdfRuntimePath
        Add-PreflightLine "WdfRuntimePath" $wdfRuntime.FullName
        Add-PreflightLine "WdfRuntimeFileVersion" ([string]$wdfRuntime.VersionInfo.FileVersion)
        Add-PreflightLine "WdfRuntimeSha256" (Get-FileHash -LiteralPath $wdfRuntimePath -Algorithm SHA256).Hash
    }
    else {
        $failures.Add("Wdf01000.sys is missing from System32\\drivers.")
    }

    $codeIntegrity = Get-Wfp11CodeIntegrityState
    Add-PreflightLine "CodeIntegrityQueryAvailable" ([string]$codeIntegrity.Available)
    Add-PreflightLine "CodeIntegrityOptions" ("0x{0:X8}" -f [uint32]$codeIntegrity.Options)
    Add-PreflightLine "TestSigningRuntime" ([string]$codeIntegrity.TestSigningRuntime)

    if (-not $codeIntegrity.Available) {
        $failures.Add("Runtime Code Integrity state is unavailable: " + [string]$codeIntegrity.NtStatus)
    }

    $bcd = Get-Wfp11BcdTestSigningState
    Add-PreflightLine "BcdQueryAvailable" ([string]$bcd.Available)
    Add-PreflightLine "BcdTestSigningConfigured" ([string]$bcd.Enabled)
    Add-PreflightLine "BcdDetail" ([string]$bcd.Detail)

    if (-not $bcd.Available) {
        $failures.Add("BCD test-signing state is unavailable.")
    }

    $lines.Add("")
    $driverService = Get-Wfp11DriverService
    $userService = Get-Wfp11UserService
    Add-PreflightLine "SerpiumFlowDriverService" $(if ($null -eq $driverService) { "Absent" } else { [string]$driverService.State })
    Add-PreflightLine "SerpiumFlowUserService" $(if ($null -eq $userService) { "Absent" } else { [string]$userService.State })

    if ($null -ne $driverService) {
        $failures.Add("SerpiumFlow already exists. It will not be overwritten.")
    }

    if ($null -ne $userService) {
        $failures.Add("SerpiumFlowService already exists. It will not be overwritten.")
    }

    $serviceLog = Join-Path $env:ProgramData "Serpium\Flow\service.log"
    Add-PreflightLine "ExistingWfp11ServiceLog" $(if (Test-Path -LiteralPath $serviceLog) { "Present" } else { "Absent" })

    if (Test-Path -LiteralPath $serviceLog) {
        $failures.Add("A pre-existing Serpium Flow service.log would be modified by the lifecycle test.")
    }

    $statePath = Get-Wfp11StatePath
    Add-PreflightLine "Wfp11StateFile" $(if (Test-Path -LiteralPath $statePath) { "Present" } else { "Absent" })

    if (Test-Path -LiteralPath $statePath) {
        $failures.Add("A previous WFP-1.1 state file exists. Run cleanup before preparing a new package.")
    }

    $signedDirectory = Get-Wfp11SignedPackageDirectory -Configuration $Configuration
    Add-PreflightLine "SignedStagingDirectory" $(if (Test-Path -LiteralPath $signedDirectory) { "Present" } else { "Absent" })

    if (Test-Path -LiteralPath $signedDirectory) {
        $failures.Add("A previous signed staging directory exists. Run cleanup before preparing a new package.")
    }

    $certificateCount = @(
        Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
            Where-Object { $_.Subject -like ($script:Wfp11CertificatePrefix + "*") }
    ).Count
    Add-PreflightLine "MatchingPrivateCertificates" ([string]$certificateCount)

    if ($certificateCount -gt 0) {
        $failures.Add("A previous Serpium WFP-1.1 private certificate exists.")
    }

    $static = Get-Wfp11StaticMarkerSummary
    Add-PreflightLine "StaticWfpRegistrationMarkers" ([string]$static.MatchCount)
    Add-PreflightLine "StaticWfpDetail" ([string]$static.Detail)

    if ($static.MatchCount -ne 0) {
        $failures.Add("WFP registration API markers were found in WFP-1.1 sources.")
    }

    $wfp = Get-Wfp11WfpNameSummary
    Add-PreflightLine "WfpStateAvailable" ([string]$wfp.Available)
    Add-PreflightLine "SerpiumWfpNameMatches" ([string]$wfp.MatchCount)
    Add-PreflightLine "WfpStateSha256" ([string]$wfp.StateSha256)
    Add-PreflightLine "WfpStateDetail" ([string]$wfp.Detail)

    if (-not $wfp.Available) {
        $failures.Add("WFP state could not be inspected.")
    }
    elseif ($wfp.MatchCount -ne 0) {
        $failures.Add("Serpium-named WFP objects already exist.")
    }
}
catch {
    $failures.Add("Unhandled preflight error: " + $_.Exception.Message)
}

$state = "PASS"
$exitCode = 0

if ($failures.Count -gt 0) {
    $state = "FAIL"
    $exitCode = 1
}
elseif ($blockers.Count -gt 0) {
    $state = "BLOCKED"
    $exitCode = 2
}

$report = @(
    ("State: " + $state),
    "Stage: WFP-1.1 preflight (read only)",
    "NetworkChanges: none",
    "ServiceChanges: none",
    "CertificateChanges: none",
    "BcdChanges: none",
    ""
) + $lines.ToArray() + @(
    "",
    "BLOCKERS:"
) + $(if ($blockers.Count -eq 0) { @("<none>") } else { $blockers.ToArray() }) + @(
    "",
    "FAILURES:"
) + $(if ($failures.Count -eq 0) { @("<none>") } else { $failures.ToArray() })

Write-Wfp11Utf8File -Path (Join-Path $stage "PREFLIGHT.txt") -Lines $report

$archive = New-Wfp11ResultArchive -Prefix "Serpium_WFP11_Preflight_Result" -StageDirectory $stage

Write-Host ""
Write-Host ("SERPIUM_WFP11_PREFLIGHT_" + $state) -ForegroundColor $(if ($state -eq "PASS") { "Green" } elseif ($state -eq "BLOCKED") { "Yellow" } else { "Red" })
Write-Host ("Archive: " + $archive) -ForegroundColor Cyan

exit $exitCode
