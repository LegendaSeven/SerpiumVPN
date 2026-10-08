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
$stage = Join-Path $env:TEMP ("Serpium_WFP2_Preflight_" + $stamp)
New-Item -ItemType Directory -Path $stage -Force | Out-Null

$lines = New-Object 'System.Collections.Generic.List[string]'
$failures = New-Object 'System.Collections.Generic.List[string]'
$blockers = New-Object 'System.Collections.Generic.List[string]'

function Add-Wfp2PreflightLine {
    param([string]$Name, [string]$Value)
    $lines.Add($Name + ": " + $Value)
}

try {
    Add-Wfp2PreflightLine "CollectedAt" (Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz")
    Add-Wfp2PreflightLine "ComputerName" $env:COMPUTERNAME
    Add-Wfp2PreflightLine "OSVersion" ([Environment]::OSVersion.VersionString)
    Add-Wfp2PreflightLine "PowerShell" $PSVersionTable.PSVersion.ToString()
    Add-Wfp2PreflightLine "Elevated" "True"
    Add-Wfp2PreflightLine "Configuration" $Configuration
    $lines.Add("")

    try {
        $packageResult = Test-Wfp2UnsignedPackage -Configuration $Configuration
        $manifest = $packageResult.Manifest
        Add-Wfp2PreflightLine "BuildPackage" "PASS"
        Add-Wfp2PreflightLine "BuildMode" ([string]$manifest.buildMode)
        Add-Wfp2PreflightLine "SdkWdkVersion" ([string]$manifest.sdkWdkVersion)
        Add-Wfp2PreflightLine "KmdfVersion" ([string]$manifest.kmdfVersion)
        Add-Wfp2PreflightLine "WfpEnabled" ([string]$manifest.wfpEnabled)
        Add-Wfp2PreflightLine "WfpMode" ([string]$manifest.wfpMode)
        Add-Wfp2PreflightLine "FilterAction" ([string]$manifest.filterAction)
        Add-Wfp2PreflightLine "ClassifyAction" ([string]$manifest.classifyAction)
        Add-Wfp2PreflightLine "TrafficModification" ([string]$manifest.trafficModification)
        Add-Wfp2PreflightLine "BlockingEnabled" ([string]$manifest.blockingEnabled)
        Add-Wfp2PreflightLine "RedirectEnabled" ([string]$manifest.redirectEnabled)

        $signTool = Find-Wfp2SdkTool -Name "signtool.exe" -PreferredVersion ([string]$manifest.sdkWdkVersion)
        $inf2Cat = Find-Wfp2SdkTool -Name "Inf2Cat.exe" -PreferredVersion ([string]$manifest.sdkWdkVersion)
        Add-Wfp2PreflightLine "SignTool" $signTool
        Add-Wfp2PreflightLine "Inf2Cat" $inf2Cat

        foreach ($name in @(
            "Serpium.Flow.Driver.sys",
            "Serpium.Flow.Driver.cat",
            "Serpium.Flow.Service.exe"
        )) {
            $path = Join-Path $packageResult.PackageDirectory $name
            $signature = Get-AuthenticodeSignature -LiteralPath $path
            Add-Wfp2PreflightLine ("UnsignedPackageSignature_" + $name) ([string]$signature.Status)
        }
    }
    catch {
        $failures.Add("Build/tool check: " + $_.Exception.Message)
        Add-Wfp2PreflightLine "BuildPackage" "FAIL"
    }

    $lines.Add("")
    $secureBoot = Get-Wfp2SecureBootState
    Add-Wfp2PreflightLine "SecureBoot" ([string]$secureBoot.State)
    Add-Wfp2PreflightLine "SecureBootDetail" ([string]$secureBoot.Detail)

    if ($secureBoot.State -eq "Enabled") {
        $blockers.Add("Secure Boot is enabled. WFP-2 does not change firmware settings.")
    }
    elseif ($secureBoot.State -eq "Unknown") {
        $blockers.Add("Secure Boot state is unknown.")
    }

    Add-Wfp2PreflightLine "MemoryIntegrity" (Get-Wfp2MemoryIntegrityState)

    $wdfRuntimePath = Join-Path $env:SystemRoot "System32\drivers\Wdf01000.sys"

    if (Test-Path -LiteralPath $wdfRuntimePath -PathType Leaf) {
        $wdfRuntime = Get-Item -LiteralPath $wdfRuntimePath
        Add-Wfp2PreflightLine "WdfRuntimePath" $wdfRuntime.FullName
        Add-Wfp2PreflightLine "WdfRuntimeFileVersion" ([string]$wdfRuntime.VersionInfo.FileVersion)
        Add-Wfp2PreflightLine "WdfRuntimeSha256" (Get-FileHash -LiteralPath $wdfRuntimePath -Algorithm SHA256).Hash
    }
    else {
        $failures.Add("Wdf01000.sys is missing from System32\drivers.")
    }

    $codeIntegrity = Get-Wfp2CodeIntegrityState
    Add-Wfp2PreflightLine "CodeIntegrityQueryAvailable" ([string]$codeIntegrity.Available)
    Add-Wfp2PreflightLine "CodeIntegrityOptions" ("0x{0:X8}" -f [uint32]$codeIntegrity.Options)
    Add-Wfp2PreflightLine "TestSigningRuntime" ([string]$codeIntegrity.TestSigningRuntime)

    if (-not $codeIntegrity.Available) {
        $failures.Add("Runtime Code Integrity state is unavailable: " + [string]$codeIntegrity.NtStatus)
    }
    elseif ($codeIntegrity.TestSigningRuntime) {
        $failures.Add("Windows Test Signing is unexpectedly active before WFP-2 preparation.")
    }

    $bcd = Get-Wfp2BcdTestSigningState
    Add-Wfp2PreflightLine "BcdQueryAvailable" ([string]$bcd.Available)
    Add-Wfp2PreflightLine "BcdTestSigningConfigured" ([string]$bcd.Enabled)
    Add-Wfp2PreflightLine "BcdDetail" ([string]$bcd.Detail)

    if (-not $bcd.Available) {
        $failures.Add("BCD test-signing state is unavailable.")
    }
    elseif ($bcd.Enabled) {
        $failures.Add("BCD TESTSIGNING is unexpectedly configured before WFP-2 preparation.")
    }

    $bfe = Get-Service -Name "BFE" -ErrorAction SilentlyContinue
    Add-Wfp2PreflightLine "BaseFilteringEngine" $(if ($null -eq $bfe) { "Unavailable" } else { [string]$bfe.Status })

    if ($null -eq $bfe -or [string]$bfe.Status -ne "Running") {
        $blockers.Add("Base Filtering Engine must be running for the guarded WFP-2 runtime test.")
    }

    $lines.Add("")
    $driverService = Get-Wfp2DriverService
    $userService = Get-Wfp2UserService
    Add-Wfp2PreflightLine "SerpiumFlowDriverService" $(if ($null -eq $driverService) { "Absent" } else { [string]$driverService.State })
    Add-Wfp2PreflightLine "SerpiumFlowUserService" $(if ($null -eq $userService) { "Absent" } else { [string]$userService.State })

    if ($null -ne $driverService) {
        $failures.Add("SerpiumFlow already exists. It will not be overwritten.")
    }

    if ($null -ne $userService) {
        $failures.Add("SerpiumFlowService already exists. It will not be overwritten.")
    }

    $installRoot = Get-Wfp2InstallRoot
    Add-Wfp2PreflightLine "Wfp2InstallRoot" $(if (Test-Path -LiteralPath $installRoot) { "Present" } else { "Absent" })

    if (Test-Path -LiteralPath $installRoot) {
        $failures.Add("The isolated WFP-2 install root already exists.")
    }

    $serviceLog = Get-Wfp2ServiceLogPath
    Add-Wfp2PreflightLine "ExistingServiceLog" $(if (Test-Path -LiteralPath $serviceLog) { "Present" } else { "Absent" })

    if (Test-Path -LiteralPath $serviceLog) {
        $failures.Add("A pre-existing Serpium Flow service.log would be modified by the runtime test.")
    }

    $statePath = Get-Wfp2StatePath
    Add-Wfp2PreflightLine "Wfp2StateFile" $(if (Test-Path -LiteralPath $statePath) { "Present" } else { "Absent" })

    if (Test-Path -LiteralPath $statePath) {
        $failures.Add("A previous WFP-2 state file exists. Run cleanup before preparing a package.")
    }

    $signedDirectory = Get-Wfp2SignedPackageDirectory -Configuration $Configuration
    Add-Wfp2PreflightLine "Wfp2SignedStaging" $(if (Test-Path -LiteralPath $signedDirectory) { "Present" } else { "Absent" })

    if (Test-Path -LiteralPath $signedDirectory) {
        $failures.Add("A previous WFP-2 signed staging directory exists.")
    }

    $oldWfp11State = Join-Path (Get-Wfp2FlowRoot) "artifacts\wfp11\state.json"
    $oldWfp11Signed = Join-Path (Get-Wfp2FlowRoot) ("artifacts\x64\" + $Configuration + "\wfp11-signed-package")
    Add-Wfp2PreflightLine "Wfp11StateFile" $(if (Test-Path -LiteralPath $oldWfp11State) { "Present" } else { "Absent" })
    Add-Wfp2PreflightLine "Wfp11SignedStaging" $(if (Test-Path -LiteralPath $oldWfp11Signed) { "Present" } else { "Absent" })

    if (Test-Path -LiteralPath $oldWfp11State) {
        $failures.Add("WFP-1.1 state remains present; its cleanup is not complete.")
    }

    if (Test-Path -LiteralPath $oldWfp11Signed) {
        $failures.Add("WFP-1.1 signed staging remains present; its cleanup is not complete.")
    }

    $wfp2Certificates = Get-Wfp2CertificateCount -Prefix $script:Wfp2CertificatePrefix
    $wfp11Certificates = Get-Wfp2CertificateCount -Prefix $script:Wfp11CertificatePrefix
    Add-Wfp2PreflightLine "Wfp2PrivateCertificates" ([string]$wfp2Certificates)
    Add-Wfp2PreflightLine "Wfp11PrivateCertificates" ([string]$wfp11Certificates)

    if ($wfp2Certificates -gt 0) {
        $failures.Add("A previous Serpium WFP-2 private test certificate exists.")
    }

    if ($wfp11Certificates -gt 0) {
        $failures.Add("A previous Serpium WFP-1.1 private test certificate exists.")
    }

    $wfp = Get-Wfp2WfpNameSummary
    Add-Wfp2PreflightLine "WfpStateAvailable" ([string]$wfp.Available)
    Add-Wfp2PreflightLine "SerpiumWfpNameMatches" ([string]$wfp.MatchCount)
    Add-Wfp2PreflightLine "WfpStateSha256" ([string]$wfp.StateSha256)
    Add-Wfp2PreflightLine "WfpStateDetail" ([string]$wfp.Detail)

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
    "Stage: WFP-2 runtime preflight (read only)",
    "NetworkConfigurationChanges: none",
    "ExternalConnections: none",
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

Write-Wfp2Utf8File -Path (Join-Path $stage "PREFLIGHT.txt") -Lines $report
$archive = New-Wfp2ResultArchive -Prefix "Serpium_WFP2_Preflight_Result" -StageDirectory $stage

Write-Host ""
Write-Host ("SERPIUM_WFP2_PREFLIGHT_" + $state) -ForegroundColor $(if ($state -eq "PASS") { "Green" } elseif ($state -eq "BLOCKED") { "Yellow" } else { "Red" })
Write-Host ("Archive: " + $archive) -ForegroundColor Cyan

exit $exitCode
