#requires -version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:Wfp3DriverServiceName = "SerpiumFlow"
$script:Wfp3UserServiceName = "SerpiumFlowService"
$script:Wfp3CertificatePrefix = "CN=Serpium Flow WFP3 Policy Test Signing"
$script:Wfp2CertificatePrefix = "CN=Serpium Flow WFP2 Observe Test Signing"
$script:Wfp11CertificatePrefix = "CN=Serpium Flow WFP11 Test Signing"

function Write-Wfp3Utf8File {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Lines = @()
    )

    $parent = Split-Path -Parent $Path

    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    [string[]]$safeLines = @("<empty>")

    if ($null -ne $Lines -and @($Lines).Count -gt 0) {
        $safeLines = [string[]]$Lines
    }

    [IO.File]::WriteAllLines(
        $Path,
        $safeLines,
        (New-Object System.Text.UTF8Encoding($false))
    )
}

function Write-Wfp3JsonFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [object]$Value,

        [int]$Depth = 8
    )

    $parent = Split-Path -Parent $Path

    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    [IO.File]::WriteAllText(
        $Path,
        ($Value | ConvertTo-Json -Depth $Depth),
        (New-Object System.Text.UTF8Encoding($false))
    )
}

function Get-Wfp3CanonicalSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $text = [IO.File]::ReadAllText($Path)
    $canonical = $text.Replace("`r`n", "`n").Replace("`r", "`n")
    [byte[]]$bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($canonical)
    $algorithm = [Security.Cryptography.SHA256]::Create()

    try {
        [byte[]]$hash = $algorithm.ComputeHash($bytes)
        return ([BitConverter]::ToString($hash).Replace("-", "")).ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
    }
}

function Invoke-Wfp3Native {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Arguments,

        [AllowNull()]
        [string]$LogPath,

        [switch]$AllowFailure
    )

    $oldPreference = $ErrorActionPreference

    try {
        $ErrorActionPreference = "Continue"
        [string[]]$output = @(& $FilePath @Arguments 2>&1 | ForEach-Object { [string]$_ })
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $oldPreference
    }

    if (-not [string]::IsNullOrWhiteSpace($LogPath)) {
        $command = $FilePath + " " + ($Arguments -join " ")
        $logLines = @(
            "COMMAND:",
            $command,
            "",
            "OUTPUT:"
        ) + @($output) + @(
            "",
            ("EXIT CODE: " + $exitCode)
        )
        Write-Wfp3Utf8File -Path $LogPath -Lines $logLines
    }

    $result = [pscustomobject]@{
        FilePath = $FilePath
        Arguments = @($Arguments)
        ExitCode = $exitCode
        Output = @($output)
    }

    if (-not $AllowFailure -and $exitCode -ne 0) {
        $message = "Native command failed with exit code $exitCode`: $FilePath"

        if (-not [string]::IsNullOrWhiteSpace($LogPath)) {
            $message += " (log: $LogPath)"
        }

        throw $message
    }

    return $result
}

function Assert-Wfp3Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $administrator = [Security.Principal.WindowsBuiltInRole]::Administrator

    if (-not $principal.IsInRole($administrator)) {
        throw "This WFP-3 policy runtime stage must run from PowerShell started as Administrator."
    }
}

function Get-Wfp3FlowRoot {
    return (Split-Path -Parent $PSScriptRoot)
}

function Get-Wfp3UnsignedPackageDirectory {
    param(
        [ValidateSet("Debug", "Release")]
        [string]$Configuration = "Release"
    )

    return (Join-Path (Get-Wfp3FlowRoot) ("artifacts\x64\" + $Configuration + "\package"))
}

function Get-Wfp3SignedPackageDirectory {
    param(
        [ValidateSet("Debug", "Release")]
        [string]$Configuration = "Release"
    )

    return (Join-Path (Get-Wfp3FlowRoot) ("artifacts\x64\" + $Configuration + "\wfp3-signed-package"))
}

function Get-Wfp3StatePath {
    return (Join-Path (Get-Wfp3FlowRoot) "artifacts\wfp3\state.json")
}

function Get-Wfp3State {
    $path = Get-Wfp3StatePath

    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return $null
    }

    return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json)
}

function Save-Wfp3State {
    param(
        [Parameter(Mandatory = $true)]
        [object]$State
    )

    Write-Wfp3JsonFile -Path (Get-Wfp3StatePath) -Value $State -Depth 8
}

function Assert-Wfp3StateIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [object]$State
    )

    foreach ($property in @(
        "schema", "runId", "configuration", "stage", "signedPackageDirectory",
        "certificateSubject", "certificateThumbprint", "certificateCreatedByScript",
        "bcdTestSigningWasEnabled", "bcdChangedByScript", "installRunId",
        "programDataFlowExistedBefore", "programDataSerpiumExistedBefore"
    )) {
        if ($State.PSObject.Properties.Name -notcontains $property) {
            throw "WFP-3 state is missing required property: $property"
        }
    }

    if ([int]$State.schema -ne 3) {
        throw "WFP-3 state schema is not 3."
    }

    if ([string]$State.runId -notmatch '^[0-9a-fA-F]{32}$') {
        throw "WFP-3 state run ID is invalid."
    }

    if ([string]$State.stage -notin @(
        "Prepared", "TestSigningConfigured", "TestSigningActive",
        "LifecycleRunning", "LifecyclePassed"
    )) {
        throw "WFP-3 state stage is invalid."
    }

    if ($State.certificateCreatedByScript -isnot [bool] -or -not [bool]$State.certificateCreatedByScript) {
        throw "WFP-3 state does not prove harness ownership of the test certificate."
    }

    if ($State.bcdTestSigningWasEnabled -isnot [bool] -or [bool]$State.bcdTestSigningWasEnabled) {
        throw "WFP-3 state does not originate from the required clean BCD baseline."
    }

    if ($State.bcdChangedByScript -isnot [bool]) {
        throw "WFP-3 state BCD ownership flag is invalid."
    }

    if (
        $null -ne $State.installRunId -and
        -not [string]::IsNullOrWhiteSpace([string]$State.installRunId) -and
        [string]$State.installRunId -notmatch '^[0-9a-fA-F]{32}$'
    ) {
        throw "WFP-3 state install run ID is invalid."
    }

    foreach ($property in @("programDataFlowExistedBefore", "programDataSerpiumExistedBefore")) {
        if ($null -ne $State.$property -and $State.$property -isnot [bool]) {
            throw "WFP-3 state telemetry-directory ownership flag is invalid: $property"
        }
    }

    $configuration = [string]$State.configuration

    if ($configuration -notin @("Debug", "Release")) {
        throw "WFP-3 state configuration is invalid."
    }

    $expectedSignedDirectory = [IO.Path]::GetFullPath(
        (Get-Wfp3SignedPackageDirectory -Configuration $configuration)
    ).TrimEnd("\")
    $actualSignedDirectory = [IO.Path]::GetFullPath(
        [string]$State.signedPackageDirectory
    ).TrimEnd("\")

    if (-not $actualSignedDirectory.Equals($expectedSignedDirectory, [StringComparison]::OrdinalIgnoreCase)) {
        throw "WFP-3 state signed-package path is outside the guarded staging directory."
    }

    $thumbprint = ([string]$State.certificateThumbprint).Replace(" ", "").ToUpperInvariant()

    if ($thumbprint -notmatch '^[0-9A-F]{40}$') {
        throw "WFP-3 state certificate thumbprint is invalid."
    }

    if ([string]$State.certificateSubject -notlike ($script:Wfp3CertificatePrefix + "*")) {
        throw "WFP-3 state certificate subject is not owned by this harness."
    }

    return [pscustomobject]@{
        Configuration = $configuration
        SignedPackageDirectory = $actualSignedDirectory
        CertificateThumbprint = $thumbprint
    }
}

function Get-Wfp3InstallRoot {
    return (Join-Path $env:ProgramFiles "Serpium\Flow\WFP3")
}

function Get-Wfp3ServiceLogPath {
    return (Join-Path $env:ProgramData "Serpium\Flow\service.log")
}

function Get-Wfp3KitsRoot {
    $path = "HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots"
    $root = (Get-ItemProperty -LiteralPath $path -ErrorAction Stop).KitsRoot10

    if ([string]::IsNullOrWhiteSpace([string]$root)) {
        throw "KitsRoot10 is missing from the Windows Kits registry entry."
    }

    return ([IO.Path]::GetFullPath([string]$root).TrimEnd("\"))
}

function Find-Wfp3SdkTool {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [AllowNull()]
        [string]$PreferredVersion
    )

    $kitsRoot = Get-Wfp3KitsRoot
    $binRoot = Join-Path $kitsRoot "bin"
    $candidates = New-Object 'System.Collections.Generic.List[string]'

    if (-not [string]::IsNullOrWhiteSpace($PreferredVersion)) {
        $candidates.Add((Join-Path $binRoot ("$PreferredVersion\x64\" + $Name)))
        $candidates.Add((Join-Path $binRoot ("$PreferredVersion\x86\" + $Name)))
    }

    foreach ($candidate in @(
        Get-ChildItem -LiteralPath $binRoot -Recurse -File -Filter $Name -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\' } |
            Sort-Object LastWriteTimeUtc -Descending |
            Select-Object -ExpandProperty FullName
    )) {
        $candidates.Add([string]$candidate)
    }

    foreach ($candidate in @(
        Get-ChildItem -LiteralPath $binRoot -Recurse -File -Filter $Name -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x86\\' } |
            Sort-Object LastWriteTimeUtc -Descending |
            Select-Object -ExpandProperty FullName
    )) {
        $candidates.Add([string]$candidate)
    }

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }

    throw "$Name was not found under $binRoot."
}

function Get-Wfp3BuildManifest {
    param(
        [ValidateSet("Debug", "Release")]
        [string]$Configuration = "Release"
    )

    $path = Join-Path (Get-Wfp3UnsignedPackageDirectory -Configuration $Configuration) "BUILD_MANIFEST.json"

    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "WFP-3 build manifest is missing: $path"
    }

    return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json)
}

function Assert-Wfp3ManifestProperty {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($Object.PSObject.Properties.Name -notcontains $Name) {
        throw "BUILD_MANIFEST.json is missing required property: $Name"
    }
}

function Assert-Wfp3PolicyTransportSource {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DriverSource
    )

    if (-not (Test-Path -LiteralPath $DriverSource -PathType Leaf)) {
        throw "WFP-3 driver source is missing: $DriverSource"
    }

    $text = [IO.File]::ReadAllText($DriverSource)

    foreach ($required in @(
        "FWP_ACTION_CALLOUT_INSPECTION",
        "FWP_ACTION_CONTINUE",
        "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
        "FWPM_LAYER_ALE_AUTH_CONNECT_V6",
        "FwpsCalloutRegister0",
        "FWPM_SESSION_FLAG_DYNAMIC",
        "IOCTL_SERPIUM_FLOW_ADD_RULE",
        "IOCTL_SERPIUM_FLOW_REMOVE_RULE",
        "IOCTL_SERPIUM_FLOW_CLEAR_RULES",
        "IOCTL_SERPIUM_FLOW_ENUM_RULES",
        "IOCTL_SERPIUM_FLOW_ENUM_FLOWS"
    )) {
        if ($text.IndexOf($required, [StringComparison]::Ordinal) -lt 0) {
            throw "Required WFP-3 policy-transport marker is missing: $required"
        }
    }

    foreach ($forbidden in @(
        '\bFWP_ACTION_BLOCK\b',
        '\bFWP_ACTION_PERMIT\b',
        '\bFwps[A-Za-z0-9_]*Inject[A-Za-z0-9_]*\s*\(',
        '\bFwpsPend[A-Za-z0-9_]*\s*\(',
        '\bFWPS_CLASSIFY_OUT_FLAG_ABSORB\b',
        '\bFWPM_LAYER_ALE_(BIND|CONNECT)_REDIRECT_[Vv][46]\b'
    )) {
        if ([regex]::IsMatch($text, $forbidden)) {
            throw "Forbidden traffic-modification marker found in driver.c: $forbidden"
        }
    }

    $continueAssignments = [regex]::Matches(
        $text,
        'ClassifyOut->actionType\s*=\s*FWP_ACTION_CONTINUE\s*;'
    )
    $allActionAssignments = [regex]::Matches(
        $text,
        'ClassifyOut->actionType\s*='
    )

    if ($continueAssignments.Count -ne 2 -or $allActionAssignments.Count -ne 2) {
        throw "Both WFP-3 V4/V6 classify callbacks must contain exactly one FWP_ACTION_CONTINUE assignment."
    }
}

function Test-Wfp3UnsignedPackage {
    param(
        [ValidateSet("Debug", "Release")]
        [string]$Configuration = "Release"
    )

    $package = Get-Wfp3UnsignedPackageDirectory -Configuration $Configuration
    $manifest = Get-Wfp3BuildManifest -Configuration $Configuration

    foreach ($name in @(
        "Serpium.Flow.Driver.sys",
        "Serpium.Flow.Driver.inf",
        "Serpium.Flow.Driver.cat",
        "Serpium.Flow.Service.exe",
        "BUILD_MANIFEST.json"
    )) {
        $path = Join-Path $package $name

        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Required WFP-3 package file is missing: $path"
        }
    }

    foreach ($property in @(
        "schema", "buildMode", "configuration", "sdkWdkVersion", "kmdfVersion", "platform",
        "msbuildKernelToolsetUsed", "wfpEnabled", "wfpMode", "wfpLayers",
        "filterAction", "classifyAction", "trafficModification",
        "blockingEnabled", "redirectEnabled", "injectionEnabled",
        "routeEnforcementEnabled", "policyTransportEnabled",
        "protocolVersion", "policyCommands", "applicationRuleCapacity",
        "observedFlowCapacity", "existingFlowMutation", "package", "sources"
    )) {
        Assert-Wfp3ManifestProperty -Object $manifest -Name $property
    }

    if ([int]$manifest.schema -ne 3) {
        throw "WFP-3 requires BUILD_MANIFEST schema 3."
    }

    if ([string]$manifest.buildMode -ne "direct-cl-link" -or [string]$manifest.platform -ne "x64") {
        throw "WFP-3 requires the verified direct-cl-link x64 package."
    }

    if ([string]$manifest.configuration -ne $Configuration) {
        throw "WFP-3 build manifest configuration does not match $Configuration."
    }

    if ([version]([string]$manifest.kmdfVersion) -ne [version]"1.33") {
        throw "WFP-3 runtime testing is pinned to KMDF 1.33."
    }

    if ([bool]$manifest.msbuildKernelToolsetUsed) {
        throw "WFP-3 runtime testing only accepts the verified direct build."
    }

    if (
        -not [bool]$manifest.wfpEnabled -or
        [string]$manifest.wfpMode -ne "observe-only-policy-transport" -or
        [string]$manifest.protocolVersion -ne "0x00030000" -or
        -not [bool]$manifest.policyTransportEnabled
    ) {
        throw "Build manifest does not identify the WFP-3 policy-transport package."
    }

    if (
        [string]$manifest.filterAction -ne "FWP_ACTION_CALLOUT_INSPECTION" -or
        [string]$manifest.classifyAction -ne "FWP_ACTION_CONTINUE" -or
        [bool]$manifest.trafficModification -or
        [bool]$manifest.blockingEnabled -or
        [bool]$manifest.redirectEnabled -or
        [bool]$manifest.injectionEnabled -or
        [bool]$manifest.routeEnforcementEnabled -or
        [bool]$manifest.existingFlowMutation
    ) {
        throw "Build manifest violates the WFP-3 fail-open policy-transport contract."
    }

    [string[]]$commands = @($manifest.policyCommands | ForEach-Object { [string]$_ })

    if (
        $commands.Count -ne 5 -or
        $commands -notcontains "ADD_RULE" -or
        $commands -notcontains "REMOVE_RULE" -or
        $commands -notcontains "CLEAR_RULES" -or
        $commands -notcontains "ENUM_RULES" -or
        $commands -notcontains "ENUM_FLOWS" -or
        [int]$manifest.applicationRuleCapacity -ne 128 -or
        [int]$manifest.observedFlowCapacity -ne 256
    ) {
        throw "Build manifest does not contain the exact bounded WFP-3 policy contract."
    }

    [string[]]$layers = @($manifest.wfpLayers | ForEach-Object { [string]$_ })

    if (
        $layers.Count -ne 2 -or
        $layers -notcontains "ALE_AUTH_CONNECT_V4" -or
        $layers -notcontains "ALE_AUTH_CONNECT_V6"
    ) {
        throw "Build manifest does not contain exactly the WFP-3 V4/V6 ALE connect layers."
    }

    $sourceExpectations = [ordered]@{
        driver = "56f42a5d08492b9a895f48222cf1323df7b73b863fbc5dd4564eab84c6a4ea1b"
        service = "0c65e56cd66784b7f2832acd86579ebcabf8863611330b197520d3a3d54b5f22"
        protocol = "00b3d302ad446d95e7e64f13951e2c330c45117aac31cb6004ad43db268fcf23"
        inf = "c4c158d7c894cb2ed5e4be19cda716b71b0b03fcc34bfe880debaeb6ae1dd3c7"
    }

    foreach ($name in $sourceExpectations.Keys) {
        Assert-Wfp3ManifestProperty -Object $manifest.sources -Name $name

        if ([string]$manifest.sources.$name -ine [string]$sourceExpectations[$name]) {
            throw "Build manifest source hash is not the verified WFP-3A Policy Core v1 version: $name"
        }
    }

    $flowRoot = Get-Wfp3FlowRoot
    $sourcePaths = [ordered]@{
        driver = Join-Path $flowRoot "Serpium.Flow.Driver\driver.c"
        service = Join-Path $flowRoot "Serpium.Flow.Service\service.cpp"
        protocol = Join-Path $flowRoot "Serpium.Flow.Protocol\serpium_flow_protocol.h"
        inf = Join-Path $flowRoot "Serpium.Flow.Driver\Serpium.Flow.Driver.inf"
    }

    foreach ($name in $sourcePaths.Keys) {
        $path = [string]$sourcePaths[$name]

        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Verified WFP-3 source file is missing: $path"
        }

        if ((Get-Wfp3CanonicalSha256 -Path $path) -ine [string]$sourceExpectations[$name]) {
            throw "Current source tree no longer matches the verified WFP-3 build: $path"
        }
    }

    Assert-Wfp3PolicyTransportSource -DriverSource ([string]$sourcePaths.driver)

    foreach ($name in @("driverSha256", "catalogSha256", "serviceSha256")) {
        Assert-Wfp3ManifestProperty -Object $manifest.package -Name $name
    }

    $checks = @(
        [pscustomobject]@{ Name = "Serpium.Flow.Driver.sys"; Expected = [string]$manifest.package.driverSha256 },
        [pscustomobject]@{ Name = "Serpium.Flow.Driver.cat"; Expected = [string]$manifest.package.catalogSha256 },
        [pscustomobject]@{ Name = "Serpium.Flow.Service.exe"; Expected = [string]$manifest.package.serviceSha256 }
    )

    foreach ($check in $checks) {
        $path = Join-Path $package $check.Name
        $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash

        if ($actual -ine $check.Expected) {
            throw "Build manifest hash mismatch for $($check.Name)."
        }
    }

    $packageInf = Join-Path $package "Serpium.Flow.Driver.inf"

    if ((Get-Wfp3CanonicalSha256 -Path $packageInf) -ine [string]$sourceExpectations.inf) {
        throw "Packaged INF does not match the verified WFP-3 source."
    }

    return [pscustomobject]@{
        PackageDirectory = $package
        Manifest = $manifest
    }
}

function Get-Wfp3SecureBootState {
    try {
        $enabled = Confirm-SecureBootUEFI -ErrorAction Stop

        return [pscustomobject]@{
            State = $(if ($enabled) { "Enabled" } else { "Disabled" })
            Detail = "Confirm-SecureBootUEFI"
        }
    }
    catch {
        try {
            $value = (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -ErrorAction Stop).UEFISecureBootEnabled

            if ($value -eq 1) {
                return [pscustomobject]@{ State = "Enabled"; Detail = "Registry fallback" }
            }

            if ($value -eq 0) {
                return [pscustomobject]@{ State = "Disabled"; Detail = "Registry fallback" }
            }
        }
        catch {
        }

        return [pscustomobject]@{
            State = "Unknown"
            Detail = $_.Exception.Message
        }
    }
}

function Get-Wfp3MemoryIntegrityState {
    try {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
        $value = (Get-ItemProperty -LiteralPath $path -ErrorAction Stop).Enabled
        return $(if ($value -eq 1) { "Enabled" } else { "Disabled" })
    }
    catch {
        return "Unknown"
    }
}

function Get-Wfp3CodeIntegrityState {
    if ($null -eq ("Serpium.Wfp3.NativeMethods" -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace Serpium.Wfp3
{
    [StructLayout(LayoutKind.Sequential)]
    public struct SystemCodeIntegrityInformation
    {
        public UInt32 Length;
        public UInt32 CodeIntegrityOptions;
    }

    public static class NativeMethods
    {
        [DllImport("ntdll.dll")]
        public static extern Int32 NtQuerySystemInformation(
            Int32 informationClass,
            ref SystemCodeIntegrityInformation information,
            Int32 informationLength,
            IntPtr returnLength);
    }
}
'@
    }

    $information = New-Object Serpium.Wfp3.SystemCodeIntegrityInformation
    $length = [Runtime.InteropServices.Marshal]::SizeOf($information)
    $information.Length = [uint32]$length
    $status = [Serpium.Wfp3.NativeMethods]::NtQuerySystemInformation(
        103,
        [ref]$information,
        $length,
        [IntPtr]::Zero
    )

    if ($status -ne 0) {
        return [pscustomobject]@{
            Available = $false
            Options = 0
            TestSigningRuntime = $false
            NtStatus = ("0x{0:X8}" -f ([uint32]$status))
        }
    }

    return [pscustomobject]@{
        Available = $true
        Options = [uint32]$information.CodeIntegrityOptions
        TestSigningRuntime = (($information.CodeIntegrityOptions -band 0x2) -ne 0)
        NtStatus = "0x00000000"
    }
}

function Get-Wfp3BcdTestSigningState {
    $bcdedit = Join-Path $env:SystemRoot "System32\bcdedit.exe"
    $result = Invoke-Wfp3Native -FilePath $bcdedit -Arguments @("/enum") -LogPath $null -AllowFailure

    if ($result.ExitCode -ne 0) {
        return [pscustomobject]@{
            Available = $false
            Enabled = $false
            Detail = ($result.Output -join " | ")
        }
    }

    $line = @($result.Output | Where-Object { $_ -match '(?i)^\s*testsigning\s+' } | Select-Object -First 1)

    if ($line.Count -eq 0) {
        return [pscustomobject]@{ Available = $true; Enabled = $false; Detail = "Entry absent" }
    }

    $disabled = ([string]$line[0]) -match '(?i)\b(no|off|false|0)\b'

    return [pscustomobject]@{
        Available = $true
        Enabled = (-not $disabled)
        Detail = [string]$line[0]
    }
}

function Get-Wfp3DriverService {
    return @(
        Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name='SerpiumFlow'" -ErrorAction SilentlyContinue
    ) | Select-Object -First 1
}

function Get-Wfp3UserService {
    return @(
        Get-CimInstance -ClassName Win32_Service -Filter "Name='SerpiumFlowService'" -ErrorAction SilentlyContinue
    ) | Select-Object -First 1
}

function Assert-Wfp3ServicesAbsent {
    if ($null -ne (Get-Wfp3DriverService)) {
        throw "Service SerpiumFlow already exists. Run the WFP-3 cleanup stage or inspect it manually."
    }

    if ($null -ne (Get-Wfp3UserService)) {
        throw "Service SerpiumFlowService already exists. Run the WFP-3 cleanup stage or inspect it manually."
    }
}

function Wait-Wfp3ServiceState {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Driver", "User")]
        [string]$Kind,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Running", "Stopped", "Absent")]
        [string]$State,

        [int]$TimeoutSeconds = 20
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $record = $null

    do {
        $record = if ($Kind -eq "Driver") { Get-Wfp3DriverService } else { Get-Wfp3UserService }

        if ($State -eq "Absent" -and $null -eq $record) {
            return
        }

        if ($null -ne $record -and [string]$record.State -eq $State) {
            return
        }

        Start-Sleep -Milliseconds 250
    }
    while ((Get-Date) -lt $deadline)

    $actual = if ($null -eq $record) { "Absent" } else { [string]$record.State }
    throw "$Kind service did not reach $State within $TimeoutSeconds seconds (actual: $actual)."
}

function Get-Wfp3WfpNameSummary {
    $temp = Join-Path $env:TEMP ("Serpium_WFP3_WfpState_" + [guid]::NewGuid().ToString("N") + ".xml")
    $netsh = Join-Path $env:SystemRoot "System32\netsh.exe"

    try {
        $result = Invoke-Wfp3Native -FilePath $netsh -Arguments @("wfp", "show", "state", ("file=" + $temp)) -LogPath $null -AllowFailure

        if ($result.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $temp -PathType Leaf)) {
            return [pscustomobject]@{
                Available = $false
                MatchCount = -1
                StateSha256 = "<unavailable>"
                Detail = ($result.Output -join " | ")
            }
        }

        $matches = @(
            Select-String -LiteralPath $temp -Pattern 'SerpiumFlow|Serpium[ .]Flow' -ErrorAction SilentlyContinue
        )

        return [pscustomobject]@{
            Available = $true
            MatchCount = $matches.Count
            StateSha256 = (Get-FileHash -LiteralPath $temp -Algorithm SHA256).Hash
            Detail = $(if ($matches.Count -eq 0) { "No Serpium Flow WFP objects" } else { "Serpium Flow text found in WFP state" })
        }
    }
    finally {
        Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
    }
}

function Get-Wfp3CertificateCount {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prefix
    )

    return @(
        Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
            Where-Object { $_.Subject -like ($Prefix + "*") }
    ).Count
}

function Remove-Wfp3CertificateByThumbprint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Thumbprint
    )

    $normalized = $Thumbprint.Replace(" ", "").ToUpperInvariant()

    foreach ($store in @("My", "Root", "TrustedPublisher")) {
        $path = "Cert:\LocalMachine\$store\$normalized"

        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
        }
    }
}

function Assert-Wfp3TestSigner {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedThumbprint
    )

    $signature = Get-AuthenticodeSignature -FilePath $Path

    if ([string]$signature.Status -ne "Valid") {
        throw "Authenticode verification failed for $Path`: $($signature.StatusMessage)"
    }

    if ($null -eq $signature.SignerCertificate) {
        throw "Authenticode verification did not return a signer certificate for $Path."
    }

    $actualThumbprint = $signature.SignerCertificate.Thumbprint.Replace(" ", "").ToUpperInvariant()

    if ($actualThumbprint -ine $ExpectedThumbprint) {
        throw "Unexpected Authenticode signer for $Path (actual: $actualThumbprint)."
    }
}

function New-Wfp3ResultArchive {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prefix,

        [Parameter(Mandatory = $true)]
        [string]$StageDirectory
    )

    $downloads = Join-Path $env:USERPROFILE "Downloads"
    New-Item -ItemType Directory -Path $downloads -Force | Out-Null
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $zip = Join-Path $downloads ($Prefix + "_" + $stamp + ".zip")
    Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
    Compress-Archive -Path (Join-Path $StageDirectory "*") -DestinationPath $zip -CompressionLevel Optimal -Force
    return $zip
}
