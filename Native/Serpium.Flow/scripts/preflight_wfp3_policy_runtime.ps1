#requires -version 5.1
[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "wfp3_common.ps1")

Assert-Wfp3Administrator

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$stage = Join-Path $env:TEMP ("Serpium_WFP3_Preflight_" + $stamp)
New-Item -ItemType Directory -Path $stage -Force | Out-Null

$lines = New-Object 'System.Collections.Generic.List[string]'
$failures = New-Object 'System.Collections.Generic.List[string]'
$blockers = New-Object 'System.Collections.Generic.List[string]'

function Add-Wfp3PreflightLine {
    param([string]$Name, [string]$Value)
    $lines.Add($Name + ": " + $Value)
}

try {
    Add-Wfp3PreflightLine "CollectedAt" (Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz")
    Add-Wfp3PreflightLine "ComputerName" $env:COMPUTERNAME
    Add-Wfp3PreflightLine "OSVersion" ([Environment]::OSVersion.VersionString)
    Add-Wfp3PreflightLine "PowerShell" $PSVersionTable.PSVersion.ToString()
    Add-Wfp3PreflightLine "Elevated" "True"
    Add-Wfp3PreflightLine "Configuration" $Configuration
    $lines.Add("")

    try {
        $packageResult = Test-Wfp3UnsignedPackage -Configuration $Configuration
        $manifest = $packageResult.Manifest
        Add-Wfp3PreflightLine "BuildPackage" "PASS"
        Add-Wfp3PreflightLine "BuildMode" ([string]$manifest.buildMode)
        Add-Wfp3PreflightLine "SdkWdkVersion" ([string]$manifest.sdkWdkVersion)
        Add-Wfp3PreflightLine "KmdfVersion" ([string]$manifest.kmdfVersion)
        Add-Wfp3PreflightLine "WfpEnabled" ([string]$manifest.wfpEnabled)
        Add-Wfp3PreflightLine "WfpMode" ([string]$manifest.wfpMode)
        Add-Wfp3PreflightLine "ProtocolVersion" ([string]$manifest.protocolVersion)
        Add-Wfp3PreflightLine "PolicyTransportEnabled" ([string]$manifest.policyTransportEnabled)
        Add-Wfp3PreflightLine "PolicyCommands" ((@($manifest.policyCommands) | ForEach-Object { [string]$_ }) -join ",")
        Add-Wfp3PreflightLine "ApplicationRuleCapacity" ([string]$manifest.applicationRuleCapacity)
        Add-Wfp3PreflightLine "ObservedFlowCapacity" ([string]$manifest.observedFlowCapacity)
        Add-Wfp3PreflightLine "FilterAction" ([string]$manifest.filterAction)
        Add-Wfp3PreflightLine "ClassifyAction" ([string]$manifest.classifyAction)
        Add-Wfp3PreflightLine "TrafficModification" ([string]$manifest.trafficModification)
        Add-Wfp3PreflightLine "BlockingEnabled" ([string]$manifest.blockingEnabled)
        Add-Wfp3PreflightLine "RedirectEnabled" ([string]$manifest.redirectEnabled)
        Add-Wfp3PreflightLine "InjectionEnabled" ([string]$manifest.injectionEnabled)
        Add-Wfp3PreflightLine "RouteEnforcementEnabled" ([string]$manifest.routeEnforcementEnabled)
        Add-Wfp3PreflightLine "ExistingFlowMutation" ([string]$manifest.existingFlowMutation)

        $signTool = Find-Wfp3SdkTool -Name "signtool.exe" -PreferredVersion ([string]$manifest.sdkWdkVersion)
        $inf2Cat = Find-Wfp3SdkTool -Name "Inf2Cat.exe" -PreferredVersion ([string]$manifest.sdkWdkVersion)
        Add-Wfp3PreflightLine "SignTool" $signTool
        Add-Wfp3PreflightLine "Inf2Cat" $inf2Cat

        foreach ($name in @(
            "Serpium.Flow.Driver.sys",
            "Serpium.Flow.Driver.cat",
            "Serpium.Flow.Service.exe"
        )) {
            $path = Join-Path $packageResult.PackageDirectory $name
            $signature = Get-AuthenticodeSignature -LiteralPath $path
            Add-Wfp3PreflightLine ("UnsignedPackageSignature_" + $name) ([string]$signature.Status)
        }
    }
    catch {
        $failures.Add("Build/tool check: " + $_.Exception.Message)
        Add-Wfp3PreflightLine "BuildPackage" "FAIL"
    }

    $lines.Add("")
    $secureBoot = Get-Wfp3SecureBootState
    Add-Wfp3PreflightLine "SecureBoot" ([string]$secureBoot.State)
    Add-Wfp3PreflightLine "SecureBootDetail" ([string]$secureBoot.Detail)

    if ($secureBoot.State -eq "Enabled") {
        $blockers.Add("Secure Boot is enabled. WFP-3 does not change firmware settings.")
    }
    elseif ($secureBoot.State -eq "Unknown") {
        $blockers.Add("Secure Boot state is unknown.")
    }

    Add-Wfp3PreflightLine "MemoryIntegrity" (Get-Wfp3MemoryIntegrityState)

    $wdfRuntimePath = Join-Path $env:SystemRoot "System32\drivers\Wdf01000.sys"

    if (Test-Path -LiteralPath $wdfRuntimePath -PathType Leaf) {
        $wdfRuntime = Get-Item -LiteralPath $wdfRuntimePath
        Add-Wfp3PreflightLine "WdfRuntimePath" $wdfRuntime.FullName
        Add-Wfp3PreflightLine "WdfRuntimeFileVersion" ([string]$wdfRuntime.VersionInfo.FileVersion)
        Add-Wfp3PreflightLine "WdfRuntimeSha256" (Get-FileHash -LiteralPath $wdfRuntimePath -Algorithm SHA256).Hash
    }
    else {
        $failures.Add("Wdf01000.sys is missing from System32\drivers.")
    }

    $codeIntegrity = Get-Wfp3CodeIntegrityState
    Add-Wfp3PreflightLine "CodeIntegrityQueryAvailable" ([string]$codeIntegrity.Available)
    Add-Wfp3PreflightLine "CodeIntegrityOptions" ("0x{0:X8}" -f [uint32]$codeIntegrity.Options)
    Add-Wfp3PreflightLine "TestSigningRuntime" ([string]$codeIntegrity.TestSigningRuntime)

    if (-not $codeIntegrity.Available) {
        $failures.Add("Runtime Code Integrity state is unavailable: " + [string]$codeIntegrity.NtStatus)
    }
    elseif ($codeIntegrity.TestSigningRuntime) {
        $failures.Add("Windows Test Signing is active. Reboot once after the verified WFP-2 cleanup before WFP-3 preparation.")
    }

    $bcd = Get-Wfp3BcdTestSigningState
    Add-Wfp3PreflightLine "BcdQueryAvailable" ([string]$bcd.Available)
    Add-Wfp3PreflightLine "BcdTestSigningConfigured" ([string]$bcd.Enabled)
    Add-Wfp3PreflightLine "BcdDetail" ([string]$bcd.Detail)

    if (-not $bcd.Available) {
        $failures.Add("BCD test-signing state is unavailable.")
    }
    elseif ($bcd.Enabled) {
        $failures.Add("BCD TESTSIGNING is unexpectedly configured before WFP-3 preparation.")
    }

    $bfe = Get-Service -Name "BFE" -ErrorAction SilentlyContinue
    Add-Wfp3PreflightLine "BaseFilteringEngine" $(if ($null -eq $bfe) { "Unavailable" } else { [string]$bfe.Status })

    if ($null -eq $bfe -or [string]$bfe.Status -ne "Running") {
        $blockers.Add("Base Filtering Engine must be running for the guarded WFP-3 policy runtime test.")
    }

    $lines.Add("")
    $driverService = Get-Wfp3DriverService
    $userService = Get-Wfp3UserService
    Add-Wfp3PreflightLine "SerpiumFlowDriverService" $(if ($null -eq $driverService) { "Absent" } else { [string]$driverService.State })
    Add-Wfp3PreflightLine "SerpiumFlowUserService" $(if ($null -eq $userService) { "Absent" } else { [string]$userService.State })

    if ($null -ne $driverService) {
        $failures.Add("SerpiumFlow already exists. It will not be overwritten.")
    }

    if ($null -ne $userService) {
        $failures.Add("SerpiumFlowService already exists. It will not be overwritten.")
    }

    $installRoot = Get-Wfp3InstallRoot
    Add-Wfp3PreflightLine "Wfp3InstallRoot" $(if (Test-Path -LiteralPath $installRoot) { "Present" } else { "Absent" })

    if (Test-Path -LiteralPath $installRoot) {
        $failures.Add("The isolated WFP-3 install root already exists.")
    }

    $serviceLog = Get-Wfp3ServiceLogPath
    Add-Wfp3PreflightLine "ExistingServiceLog" $(if (Test-Path -LiteralPath $serviceLog) { "Present" } else { "Absent" })

    if (Test-Path -LiteralPath $serviceLog) {
        $failures.Add("A pre-existing Serpium Flow service.log would be modified by the runtime test.")
    }

    $statePath = Get-Wfp3StatePath
    Add-Wfp3PreflightLine "Wfp3StateFile" $(if (Test-Path -LiteralPath $statePath) { "Present" } else { "Absent" })

    if (Test-Path -LiteralPath $statePath) {
        $failures.Add("A previous WFP-3 state file exists. Run cleanup before preparing a package.")
    }

    $signedDirectory = Get-Wfp3SignedPackageDirectory -Configuration $Configuration
    Add-Wfp3PreflightLine "Wfp3SignedStaging" $(if (Test-Path -LiteralPath $signedDirectory) { "Present" } else { "Absent" })

    if (Test-Path -LiteralPath $signedDirectory) {
        $failures.Add("A previous WFP-3 signed staging directory exists.")
    }

    $oldWfp2State = Join-Path (Get-Wfp3FlowRoot) "artifacts\wfp2\state.json"
    $oldWfp2Signed = Join-Path (Get-Wfp3FlowRoot) ("artifacts\x64\" + $Configuration + "\wfp2-signed-package")
    Add-Wfp3PreflightLine "Wfp2StateFile" $(if (Test-Path -LiteralPath $oldWfp2State) { "Present" } else { "Absent" })
    Add-Wfp3PreflightLine "Wfp2SignedStaging" $(if (Test-Path -LiteralPath $oldWfp2Signed) { "Present" } else { "Absent" })

    if (Test-Path -LiteralPath $oldWfp2State) {
        $failures.Add("WFP-2 state remains present; its cleanup is not complete.")
    }

    if (Test-Path -LiteralPath $oldWfp2Signed) {
        $failures.Add("WFP-2 signed staging remains present; its cleanup is not complete.")
    }

    $oldWfp11State = Join-Path (Get-Wfp3FlowRoot) "artifacts\wfp11\state.json"
    $oldWfp11Signed = Join-Path (Get-Wfp3FlowRoot) ("artifacts\x64\" + $Configuration + "\wfp11-signed-package")
    Add-Wfp3PreflightLine "Wfp11StateFile" $(if (Test-Path -LiteralPath $oldWfp11State) { "Present" } else { "Absent" })
    Add-Wfp3PreflightLine "Wfp11SignedStaging" $(if (Test-Path -LiteralPath $oldWfp11Signed) { "Present" } else { "Absent" })

    if (Test-Path -LiteralPath $oldWfp11State) {
        $failures.Add("WFP-1.1 state remains present; its cleanup is not complete.")
    }

    if (Test-Path -LiteralPath $oldWfp11Signed) {
        $failures.Add("WFP-1.1 signed staging remains present; its cleanup is not complete.")
    }

    $wfp3Certificates = Get-Wfp3CertificateCount -Prefix $script:Wfp3CertificatePrefix
    $wfp2Certificates = Get-Wfp3CertificateCount -Prefix $script:Wfp2CertificatePrefix
    $wfp11Certificates = Get-Wfp3CertificateCount -Prefix $script:Wfp11CertificatePrefix
    Add-Wfp3PreflightLine "Wfp3PrivateCertificates" ([string]$wfp3Certificates)
    Add-Wfp3PreflightLine "Wfp2PrivateCertificates" ([string]$wfp2Certificates)
    Add-Wfp3PreflightLine "Wfp11PrivateCertificates" ([string]$wfp11Certificates)

    if ($wfp3Certificates -gt 0) {
        $failures.Add("A previous Serpium WFP-3 private test certificate exists.")
    }

    if ($wfp2Certificates -gt 0) {
        $failures.Add("A previous Serpium WFP-2 private test certificate exists.")
    }

    if ($wfp11Certificates -gt 0) {
        $failures.Add("A previous Serpium WFP-1.1 private test certificate exists.")
    }

    $wfp = Get-Wfp3WfpNameSummary
    Add-Wfp3PreflightLine "WfpStateAvailable" ([string]$wfp.Available)
    Add-Wfp3PreflightLine "SerpiumWfpNameMatches" ([string]$wfp.MatchCount)
    Add-Wfp3PreflightLine "WfpStateSha256" ([string]$wfp.StateSha256)
    Add-Wfp3PreflightLine "WfpStateDetail" ([string]$wfp.Detail)

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
    "Stage: WFP-3 policy runtime preflight (read only)",
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

Write-Wfp3Utf8File -Path (Join-Path $stage "PREFLIGHT.txt") -Lines $report
$archive = New-Wfp3ResultArchive -Prefix "Serpium_WFP3_PolicyPreflight_Result" -StageDirectory $stage

Write-Host ""
Write-Host ("SERPIUM_WFP3_POLICY_PREFLIGHT_" + $state) -ForegroundColor $(if ($state -eq "PASS") { "Green" } elseif ($state -eq "BLOCKED") { "Yellow" } else { "Red" })
Write-Host ("Archive: " + $archive) -ForegroundColor Cyan

exit $exitCode
