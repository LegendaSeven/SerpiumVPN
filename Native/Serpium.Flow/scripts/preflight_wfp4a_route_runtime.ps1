#requires -version 5.1
[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "wfp4a_common.ps1")

Assert-Wfp4aAdministrator

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$stage = Join-Path $env:TEMP ("Serpium_WFP4A_Preflight_" + $stamp)
New-Item -ItemType Directory -Path $stage -Force | Out-Null

$lines = New-Object 'System.Collections.Generic.List[string]'
$failures = New-Object 'System.Collections.Generic.List[string]'
$blockers = New-Object 'System.Collections.Generic.List[string]'

function Add-Wfp4aPreflightLine {
    param([string]$Name, [string]$Value)
    $lines.Add($Name + ": " + $Value)
}

try {
    Add-Wfp4aPreflightLine "CollectedAt" (Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz")
    Add-Wfp4aPreflightLine "ComputerName" $env:COMPUTERNAME
    Add-Wfp4aPreflightLine "OSVersion" ([Environment]::OSVersion.VersionString)
    Add-Wfp4aPreflightLine "PowerShell" $PSVersionTable.PSVersion.ToString()
    Add-Wfp4aPreflightLine "Elevated" "True"
    Add-Wfp4aPreflightLine "Configuration" $Configuration
    $lines.Add("")

    try {
        $packageResult = Test-Wfp4aUnsignedPackage -Configuration $Configuration
        $manifest = $packageResult.Manifest
        Add-Wfp4aPreflightLine "BuildPackage" "PASS"
        Add-Wfp4aPreflightLine "BuildMode" ([string]$manifest.buildMode)
        Add-Wfp4aPreflightLine "SdkWdkVersion" ([string]$manifest.sdkWdkVersion)
        Add-Wfp4aPreflightLine "KmdfVersion" ([string]$manifest.kmdfVersion)
        Add-Wfp4aPreflightLine "WfpEnabled" ([string]$manifest.wfpEnabled)
        Add-Wfp4aPreflightLine "WfpMode" ([string]$manifest.wfpMode)
        Add-Wfp4aPreflightLine "ProtocolVersion" ([string]$manifest.protocolVersion)
        Add-Wfp4aPreflightLine "PolicyTransportEnabled" ([string]$manifest.policyTransportEnabled)
        Add-Wfp4aPreflightLine "PolicyCommands" ((@($manifest.policyCommands) | ForEach-Object { [string]$_ }) -join ",")
        Add-Wfp4aPreflightLine "ApplicationRuleCapacity" ([string]$manifest.applicationRuleCapacity)
        Add-Wfp4aPreflightLine "ObservedFlowCapacity" ([string]$manifest.observedFlowCapacity)
        Add-Wfp4aPreflightLine "FilterActions" ((@($manifest.filterActions) | ForEach-Object { [string]$_ }) -join ",")
        Add-Wfp4aPreflightLine "ClassifyActions" ((@($manifest.classifyActions) | ForEach-Object { [string]$_ }) -join ",")
        Add-Wfp4aPreflightLine "TrafficModification" ([string]$manifest.trafficModification)
        Add-Wfp4aPreflightLine "BlockingEnabled" ([string]$manifest.blockingEnabled)
        Add-Wfp4aPreflightLine "RedirectEnabled" ([string]$manifest.redirectEnabled)
        Add-Wfp4aPreflightLine "InjectionEnabled" ([string]$manifest.injectionEnabled)
        Add-Wfp4aPreflightLine "RouteEnforcementEnabled" ([string]$manifest.routeEnforcementEnabled)
        Add-Wfp4aPreflightLine "RouteEnforcementDefaultArmed" ([string]$manifest.routeEnforcementDefaultArmed)
        Add-Wfp4aPreflightLine "RouteLeaseMilliseconds" ([string]$manifest.routeLeaseMilliseconds)
        Add-Wfp4aPreflightLine "RouteLeaseFailOpen" ([string]$manifest.routeLeaseFailOpen)
        Add-Wfp4aPreflightLine "TcpOnly" ([string]$manifest.tcpOnly)
        Add-Wfp4aPreflightLine "UdpQuicIncluded" ([string]$manifest.udpQuicIncluded)
        Add-Wfp4aPreflightLine "KillSwitchIncluded" ([string]$manifest.killSwitchIncluded)
        Add-Wfp4aPreflightLine "LocalBridge" ([string]$manifest.localBridge)
        Add-Wfp4aPreflightLine "ExistingFlowMutation" ([string]$manifest.existingFlowMutation)

        $signTool = Find-Wfp4aSdkTool -Name "signtool.exe" -PreferredVersion ([string]$manifest.sdkWdkVersion)
        $inf2Cat = Find-Wfp4aSdkTool -Name "Inf2Cat.exe" -PreferredVersion ([string]$manifest.sdkWdkVersion)
        Add-Wfp4aPreflightLine "SignTool" $signTool
        Add-Wfp4aPreflightLine "Inf2Cat" $inf2Cat

        foreach ($name in @(
            "Serpium.Flow.Driver.sys",
            "Serpium.Flow.Driver.cat",
            "Serpium.Flow.Service.exe"
        )) {
            $path = Join-Path $packageResult.PackageDirectory $name
            $signature = Get-AuthenticodeSignature -LiteralPath $path
            Add-Wfp4aPreflightLine ("UnsignedPackageSignature_" + $name) ([string]$signature.Status)
        }
    }
    catch {
        $failures.Add("Build/tool check: " + $_.Exception.Message)
        Add-Wfp4aPreflightLine "BuildPackage" "FAIL"
    }

    $lines.Add("")
    $secureBoot = Get-Wfp4aSecureBootState
    Add-Wfp4aPreflightLine "SecureBoot" ([string]$secureBoot.State)
    Add-Wfp4aPreflightLine "SecureBootDetail" ([string]$secureBoot.Detail)

    if ($secureBoot.State -eq "Enabled") {
        $blockers.Add("Secure Boot is enabled. WFP-4A does not change firmware settings.")
    }
    elseif ($secureBoot.State -eq "Unknown") {
        $blockers.Add("Secure Boot state is unknown.")
    }

    Add-Wfp4aPreflightLine "MemoryIntegrity" (Get-Wfp4aMemoryIntegrityState)

    $wdfRuntimePath = Join-Path $env:SystemRoot "System32\drivers\Wdf01000.sys"

    if (Test-Path -LiteralPath $wdfRuntimePath -PathType Leaf) {
        $wdfRuntime = Get-Item -LiteralPath $wdfRuntimePath
        Add-Wfp4aPreflightLine "WdfRuntimePath" $wdfRuntime.FullName
        Add-Wfp4aPreflightLine "WdfRuntimeFileVersion" ([string]$wdfRuntime.VersionInfo.FileVersion)
        Add-Wfp4aPreflightLine "WdfRuntimeSha256" (Get-FileHash -LiteralPath $wdfRuntimePath -Algorithm SHA256).Hash
    }
    else {
        $failures.Add("Wdf01000.sys is missing from System32\drivers.")
    }

    $codeIntegrity = Get-Wfp4aCodeIntegrityState
    Add-Wfp4aPreflightLine "CodeIntegrityQueryAvailable" ([string]$codeIntegrity.Available)
    Add-Wfp4aPreflightLine "CodeIntegrityOptions" ("0x{0:X8}" -f [uint32]$codeIntegrity.Options)
    Add-Wfp4aPreflightLine "TestSigningRuntime" ([string]$codeIntegrity.TestSigningRuntime)

    if (-not $codeIntegrity.Available) {
        $failures.Add("Runtime Code Integrity state is unavailable: " + [string]$codeIntegrity.NtStatus)
    }
    elseif ($codeIntegrity.TestSigningRuntime) {
        $failures.Add("Windows Test Signing is active. Reboot once after the verified WFP-3 cleanup before WFP-4A preparation.")
    }

    $bcd = Get-Wfp4aBcdTestSigningState
    Add-Wfp4aPreflightLine "BcdQueryAvailable" ([string]$bcd.Available)
    Add-Wfp4aPreflightLine "BcdTestSigningConfigured" ([string]$bcd.Enabled)
    Add-Wfp4aPreflightLine "BcdDetail" ([string]$bcd.Detail)

    if (-not $bcd.Available) {
        $failures.Add("BCD test-signing state is unavailable.")
    }
    elseif ($bcd.Enabled) {
        $failures.Add("BCD TESTSIGNING is unexpectedly configured before WFP-4A preparation.")
    }

    $bfe = Get-Service -Name "BFE" -ErrorAction SilentlyContinue
    Add-Wfp4aPreflightLine "BaseFilteringEngine" $(if ($null -eq $bfe) { "Unavailable" } else { [string]$bfe.Status })

    if ($null -eq $bfe -or [string]$bfe.Status -ne "Running") {
        $blockers.Add("Base Filtering Engine must be running for the guarded WFP-4A route runtime test.")
    }

    $routeV4 = New-Object 'System.Collections.Generic.List[string]'
    $routeV6 = New-Object 'System.Collections.Generic.List[string]'

    foreach ($adapter in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if (
            $adapter.OperationalStatus -ne [Net.NetworkInformation.OperationalStatus]::Up -or
            $adapter.NetworkInterfaceType -eq [Net.NetworkInformation.NetworkInterfaceType]::Loopback -or
            $adapter.NetworkInterfaceType -eq [Net.NetworkInformation.NetworkInterfaceType]::Tunnel
        ) {
            continue
        }

        foreach ($unicast in $adapter.GetIPProperties().UnicastAddresses) {
            $address = $unicast.Address

            if ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
                if (-not $address.Equals([Net.IPAddress]::Any) -and -not $address.Equals([Net.IPAddress]::Loopback)) {
                    $routeV4.Add($address.ToString())
                }
            }
            elseif ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
                if (-not $address.Equals([Net.IPAddress]::IPv6Any) -and -not $address.Equals([Net.IPAddress]::IPv6Loopback) -and -not $address.IsIPv6Multicast) {
                    $routeV6.Add($address.ToString())
                }
            }
        }
    }

    Add-Wfp4aPreflightLine "LocalNonLoopbackIPv4Count" ([string]$routeV4.Count)
    Add-Wfp4aPreflightLine "LocalNonLoopbackIPv6Count" ([string]$routeV6.Count)
    Add-Wfp4aPreflightLine "IPv6DataPathPolicy" $(if ($routeV6.Count -gt 0) { "Required" } else { "SkipWithReason" })

    if ($routeV4.Count -eq 0) {
        $blockers.Add("A local non-loopback IPv4 address is required for the isolated redirect and fail-open data-path test.")
    }

    $lines.Add("")
    $driverService = Get-Wfp4aDriverService
    $userService = Get-Wfp4aUserService
    Add-Wfp4aPreflightLine "SerpiumFlowDriverService" $(if ($null -eq $driverService) { "Absent" } else { [string]$driverService.State })
    Add-Wfp4aPreflightLine "SerpiumFlowUserService" $(if ($null -eq $userService) { "Absent" } else { [string]$userService.State })

    if ($null -ne $driverService) {
        $failures.Add("SerpiumFlow already exists. It will not be overwritten.")
    }

    if ($null -ne $userService) {
        $failures.Add("SerpiumFlowService already exists. It will not be overwritten.")
    }

    $installRoot = Get-Wfp4aInstallRoot
    Add-Wfp4aPreflightLine "Wfp4aInstallRoot" $(if (Test-Path -LiteralPath $installRoot) { "Present" } else { "Absent" })

    if (Test-Path -LiteralPath $installRoot) {
        $failures.Add("The isolated WFP-4A install root already exists.")
    }

    $serviceLog = Get-Wfp4aServiceLogPath
    Add-Wfp4aPreflightLine "ExistingServiceLog" $(if (Test-Path -LiteralPath $serviceLog) { "Present" } else { "Absent" })

    if (Test-Path -LiteralPath $serviceLog) {
        $failures.Add("A pre-existing Serpium Flow service.log would be modified by the runtime test.")
    }

    $statePath = Get-Wfp4aStatePath
    Add-Wfp4aPreflightLine "Wfp4aStateFile" $(if (Test-Path -LiteralPath $statePath) { "Present" } else { "Absent" })

    if (Test-Path -LiteralPath $statePath) {
        $failures.Add("A previous WFP-4A state file exists. Run cleanup before preparing a package.")
    }

    $signedDirectory = Get-Wfp4aSignedPackageDirectory -Configuration $Configuration
    Add-Wfp4aPreflightLine "Wfp4aSignedStaging" $(if (Test-Path -LiteralPath $signedDirectory) { "Present" } else { "Absent" })

    if (Test-Path -LiteralPath $signedDirectory) {
        $failures.Add("A previous WFP-4A signed staging directory exists.")
    }

    $oldWfp3State = Join-Path (Get-Wfp4aFlowRoot) "artifacts\wfp3\state.json"
    $oldWfp3Signed = Join-Path (Get-Wfp4aFlowRoot) ("artifacts\x64\" + $Configuration + "\wfp3-signed-package")
    Add-Wfp4aPreflightLine "Wfp3StateFile" $(if (Test-Path -LiteralPath $oldWfp3State) { "Present" } else { "Absent" })
    Add-Wfp4aPreflightLine "Wfp3SignedStaging" $(if (Test-Path -LiteralPath $oldWfp3Signed) { "Present" } else { "Absent" })

    if (Test-Path -LiteralPath $oldWfp3State) {
        $failures.Add("WFP-3 state remains present; its cleanup is not complete.")
    }

    if (Test-Path -LiteralPath $oldWfp3Signed) {
        $failures.Add("WFP-3 signed staging remains present; its cleanup is not complete.")
    }

    $oldWfp2State = Join-Path (Get-Wfp4aFlowRoot) "artifacts\wfp2\state.json"
    $oldWfp2Signed = Join-Path (Get-Wfp4aFlowRoot) ("artifacts\x64\" + $Configuration + "\wfp2-signed-package")
    Add-Wfp4aPreflightLine "Wfp2StateFile" $(if (Test-Path -LiteralPath $oldWfp2State) { "Present" } else { "Absent" })
    Add-Wfp4aPreflightLine "Wfp2SignedStaging" $(if (Test-Path -LiteralPath $oldWfp2Signed) { "Present" } else { "Absent" })

    if (Test-Path -LiteralPath $oldWfp2State) {
        $failures.Add("WFP-2 state remains present; its cleanup is not complete.")
    }

    if (Test-Path -LiteralPath $oldWfp2Signed) {
        $failures.Add("WFP-2 signed staging remains present; its cleanup is not complete.")
    }

    $oldWfp11State = Join-Path (Get-Wfp4aFlowRoot) "artifacts\wfp11\state.json"
    $oldWfp11Signed = Join-Path (Get-Wfp4aFlowRoot) ("artifacts\x64\" + $Configuration + "\wfp11-signed-package")
    Add-Wfp4aPreflightLine "Wfp11StateFile" $(if (Test-Path -LiteralPath $oldWfp11State) { "Present" } else { "Absent" })
    Add-Wfp4aPreflightLine "Wfp11SignedStaging" $(if (Test-Path -LiteralPath $oldWfp11Signed) { "Present" } else { "Absent" })

    if (Test-Path -LiteralPath $oldWfp11State) {
        $failures.Add("WFP-1.1 state remains present; its cleanup is not complete.")
    }

    if (Test-Path -LiteralPath $oldWfp11Signed) {
        $failures.Add("WFP-1.1 signed staging remains present; its cleanup is not complete.")
    }

    $wfp4aCertificates = Get-Wfp4aCertificateCount -Prefix $script:Wfp4aCertificatePrefix
    $wfp3Certificates = Get-Wfp4aCertificateCount -Prefix $script:Wfp3CertificatePrefix
    $wfp2Certificates = Get-Wfp4aCertificateCount -Prefix $script:Wfp2CertificatePrefix
    $wfp11Certificates = Get-Wfp4aCertificateCount -Prefix $script:Wfp11CertificatePrefix
    Add-Wfp4aPreflightLine "Wfp4aCertificateStoreMatches" ([string]$wfp4aCertificates)
    Add-Wfp4aPreflightLine "Wfp3CertificateStoreMatches" ([string]$wfp3Certificates)
    Add-Wfp4aPreflightLine "Wfp2CertificateStoreMatches" ([string]$wfp2Certificates)
    Add-Wfp4aPreflightLine "Wfp11CertificateStoreMatches" ([string]$wfp11Certificates)

    if ($wfp4aCertificates -gt 0) {
        $failures.Add("A previous Serpium WFP-4A test certificate remains in a machine store.")
    }

    if ($wfp3Certificates -gt 0) {
        $failures.Add("A previous Serpium WFP-3 test certificate remains in a machine store.")
    }

    if ($wfp2Certificates -gt 0) {
        $failures.Add("A previous Serpium WFP-2 test certificate remains in a machine store.")
    }

    if ($wfp11Certificates -gt 0) {
        $failures.Add("A previous Serpium WFP-1.1 test certificate remains in a machine store.")
    }

    $wfp = Get-Wfp4aWfpNameSummary
    Add-Wfp4aPreflightLine "WfpStateAvailable" ([string]$wfp.Available)
    Add-Wfp4aPreflightLine "SerpiumWfpNameMatches" ([string]$wfp.MatchCount)
    Add-Wfp4aPreflightLine "WfpStateSha256" ([string]$wfp.StateSha256)
    Add-Wfp4aPreflightLine "WfpStateDetail" ([string]$wfp.Detail)

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
    "Stage: WFP-4A guarded route runtime preflight (read only)",
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

Write-Wfp4aUtf8File -Path (Join-Path $stage "PREFLIGHT.txt") -Lines $report
$archive = New-Wfp4aResultArchive -Prefix "Serpium_WFP4A_RoutePreflight_Result" -StageDirectory $stage

Write-Host ""
Write-Host ("SERPIUM_WFP4A_ROUTE_PREFLIGHT_" + $state) -ForegroundColor $(if ($state -eq "PASS") { "Green" } elseif ($state -eq "BLOCKED") { "Yellow" } else { "Red" })
Write-Host ("Archive: " + $archive) -ForegroundColor Cyan

exit $exitCode
