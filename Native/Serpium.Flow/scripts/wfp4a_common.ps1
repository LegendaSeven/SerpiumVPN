#requires -version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:Wfp4aDriverServiceName = "SerpiumFlow"
$script:Wfp4aUserServiceName = "SerpiumFlowService"
$script:Wfp4aCertificatePrefix = "CN=Serpium Flow WFP4A Route Test Signing"
$script:Wfp3CertificatePrefix = "CN=Serpium Flow WFP3 Policy Test Signing"
$script:Wfp2CertificatePrefix = "CN=Serpium Flow WFP2 Observe Test Signing"
$script:Wfp11CertificatePrefix = "CN=Serpium Flow WFP11 Test Signing"

function Write-Wfp4aUtf8File {
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

function Write-Wfp4aJsonFile {
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

function Get-Wfp4aCanonicalSha256 {
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

function Invoke-Wfp4aNative {
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
        Write-Wfp4aUtf8File -Path $LogPath -Lines $logLines
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

function Assert-Wfp4aAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $administrator = [Security.Principal.WindowsBuiltInRole]::Administrator

    if (-not $principal.IsInRole($administrator)) {
        throw "This WFP-4A policy runtime stage must run from PowerShell started as Administrator."
    }
}

function Get-Wfp4aFlowRoot {
    return (Split-Path -Parent $PSScriptRoot)
}

function Get-Wfp4aUnsignedPackageDirectory {
    param(
        [ValidateSet("Debug", "Release")]
        [string]$Configuration = "Release"
    )

    return (Join-Path (Get-Wfp4aFlowRoot) ("artifacts\x64\" + $Configuration + "\package"))
}

function Get-Wfp4aSignedPackageDirectory {
    param(
        [ValidateSet("Debug", "Release")]
        [string]$Configuration = "Release"
    )

    return (Join-Path (Get-Wfp4aFlowRoot) ("artifacts\x64\" + $Configuration + "\wfp4a-signed-package"))
}

function Get-Wfp4aStatePath {
    return (Join-Path (Get-Wfp4aFlowRoot) "artifacts\wfp4a\state.json")
}

function Get-Wfp4aState {
    $path = Get-Wfp4aStatePath

    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return $null
    }

    return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json)
}

function Save-Wfp4aState {
    param(
        [Parameter(Mandatory = $true)]
        [object]$State
    )

    Write-Wfp4aJsonFile -Path (Get-Wfp4aStatePath) -Value $State -Depth 8
}

function Assert-Wfp4aStateIdentity {
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
            throw "WFP-4A state is missing required property: $property"
        }
    }

    if ([int]$State.schema -ne 4) {
        throw "WFP-4A state schema is not 4."
    }

    if ([string]$State.runId -notmatch '^[0-9a-fA-F]{32}$') {
        throw "WFP-4A state run ID is invalid."
    }

    if ([string]$State.stage -notin @(
        "Prepared", "TestSigningConfigured", "TestSigningActive",
        "LifecycleRunning", "LifecyclePassed"
    )) {
        throw "WFP-4A state stage is invalid."
    }

    if ($State.certificateCreatedByScript -isnot [bool] -or -not [bool]$State.certificateCreatedByScript) {
        throw "WFP-4A state does not prove harness ownership of the test certificate."
    }

    if ($State.bcdTestSigningWasEnabled -isnot [bool] -or [bool]$State.bcdTestSigningWasEnabled) {
        throw "WFP-4A state does not originate from the required clean BCD baseline."
    }

    if ($State.bcdChangedByScript -isnot [bool]) {
        throw "WFP-4A state BCD ownership flag is invalid."
    }

    if (
        $null -ne $State.installRunId -and
        -not [string]::IsNullOrWhiteSpace([string]$State.installRunId) -and
        [string]$State.installRunId -notmatch '^[0-9a-fA-F]{32}$'
    ) {
        throw "WFP-4A state install run ID is invalid."
    }

    foreach ($property in @("programDataFlowExistedBefore", "programDataSerpiumExistedBefore")) {
        if ($null -ne $State.$property -and $State.$property -isnot [bool]) {
            throw "WFP-4A state telemetry-directory ownership flag is invalid: $property"
        }
    }

    $configuration = [string]$State.configuration

    if ($configuration -notin @("Debug", "Release")) {
        throw "WFP-4A state configuration is invalid."
    }

    $expectedSignedDirectory = [IO.Path]::GetFullPath(
        (Get-Wfp4aSignedPackageDirectory -Configuration $configuration)
    ).TrimEnd("\")
    $actualSignedDirectory = [IO.Path]::GetFullPath(
        [string]$State.signedPackageDirectory
    ).TrimEnd("\")

    if (-not $actualSignedDirectory.Equals($expectedSignedDirectory, [StringComparison]::OrdinalIgnoreCase)) {
        throw "WFP-4A state signed-package path is outside the guarded staging directory."
    }

    $thumbprint = ([string]$State.certificateThumbprint).Replace(" ", "").ToUpperInvariant()

    if ($thumbprint -notmatch '^[0-9A-F]{40}$') {
        throw "WFP-4A state certificate thumbprint is invalid."
    }

    if ([string]$State.certificateSubject -notlike ($script:Wfp4aCertificatePrefix + "*")) {
        throw "WFP-4A state certificate subject is not owned by this harness."
    }

    return [pscustomobject]@{
        Configuration = $configuration
        SignedPackageDirectory = $actualSignedDirectory
        CertificateThumbprint = $thumbprint
    }
}

function Get-Wfp4aInstallRoot {
    return (Join-Path $env:ProgramFiles "Serpium\Flow\WFP4A")
}

function Get-Wfp4aServiceLogPath {
    return (Join-Path $env:ProgramData "Serpium\Flow\service.log")
}

function Get-Wfp4aKitsRoot {
    $path = "HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots"
    $root = (Get-ItemProperty -LiteralPath $path -ErrorAction Stop).KitsRoot10

    if ([string]::IsNullOrWhiteSpace([string]$root)) {
        throw "KitsRoot10 is missing from the Windows Kits registry entry."
    }

    return ([IO.Path]::GetFullPath([string]$root).TrimEnd("\"))
}

function Find-Wfp4aSdkTool {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [AllowNull()]
        [string]$PreferredVersion
    )

    $kitsRoot = Get-Wfp4aKitsRoot
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

function Get-Wfp4aBuildManifest {
    param(
        [ValidateSet("Debug", "Release")]
        [string]$Configuration = "Release"
    )

    $path = Join-Path (Get-Wfp4aUnsignedPackageDirectory -Configuration $Configuration) "BUILD_MANIFEST.json"

    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "WFP-4A build manifest is missing: $path"
    }

    return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json)
}

function Assert-Wfp4aManifestProperty {
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

function Assert-Wfp4aRouteCoreSource {
    param(
        [Parameter(Mandatory = $true)][string]$DriverSource,
        [Parameter(Mandatory = $true)][string]$ServiceSource,
        [Parameter(Mandatory = $true)][string]$BridgeSource
    )

    foreach ($path in @($DriverSource, $ServiceSource, $BridgeSource)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Required WFP-4A source is missing: $path"
        }
    }

    $driverText = [IO.File]::ReadAllText($DriverSource)

    foreach ($required in @(
        "FWP_ACTION_CALLOUT_INSPECTION",
        "FWP_ACTION_CALLOUT_TERMINATING",
        "FWP_ACTION_CONTINUE",
        "FWP_ACTION_PERMIT",
        "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
        "FWPM_LAYER_ALE_AUTH_CONNECT_V6",
        "FWPM_LAYER_ALE_CONNECT_REDIRECT_V4",
        "FWPM_LAYER_ALE_CONNECT_REDIRECT_V6",
        "FwpsAcquireWritableLayerDataPointer0",
        "FwpsApplyModifiedLayerData0",
        "FwpsQueryConnectionRedirectState0",
        "localRedirectTargetPID",
        "localRedirectContext",
        "IOCTL_SERPIUM_FLOW_CONFIGURE_ROUTE",
        "IOCTL_SERPIUM_FLOW_DISARM_ROUTE",
        "SERPIUM_FLOW_ROUTE_LEASE_MIN_MILLISECONDS",
        "FWPM_SESSION_FLAG_DYNAMIC",
        "FWPS_CONNECT_REQUEST0*"
    )) {
        if ($driverText.IndexOf($required, [StringComparison]::Ordinal) -lt 0) {
            throw "Required WFP-4A guarded-route marker is missing: $required"
        }
    }

    foreach ($forbidden in @(
        '\bFWP_ACTION_BLOCK\b',
        '\bFwps[A-Za-z0-9_]*Inject[A-Za-z0-9_]*\s*\(',
        '\bFwpsPend[A-Za-z0-9_]*\s*\(',
        '\bFWPS_CLASSIFY_OUT_FLAG_ABSORB\b',
        '\bPFWPS_CONNECT_REQUEST0\b'
    )) {
        if ([regex]::IsMatch($driverText, $forbidden)) {
            throw "Forbidden WFP-4A marker found in driver.c: $forbidden"
        }
    }

    $continueAssignments = [regex]::Matches(
        $driverText,
        'ClassifyOut->actionType\s*=\s*FWP_ACTION_CONTINUE\s*;'
    )
    $permitAssignments = [regex]::Matches(
        $driverText,
        'ClassifyOut->actionType\s*=\s*FWP_ACTION_PERMIT\s*;'
    )
    $allActionAssignments = [regex]::Matches(
        $driverText,
        'ClassifyOut->actionType\s*='
    )

    if (
        $continueAssignments.Count -ne 2 -or
        $permitAssignments.Count -ne 4 -or
        $allActionAssignments.Count -ne 6
    ) {
        throw "WFP-4A requires exactly two CONTINUE and four PERMIT classify assignments."
    }

    $serviceText = [IO.File]::ReadAllText($ServiceSource)
    $bridgeText = [IO.File]::ReadAllText($BridgeSource)

    foreach ($required in @(
        "SERPIUM_WFP4A_ROUTE_CORE_READY",
        "SERPIUM_WFP4A_PING_PASS",
        "bridge <local-socks5-port> <backend-pid>",
        "disarm-route"
    )) {
        if ($serviceText.IndexOf($required, [StringComparison]::Ordinal) -lt 0) {
            throw "Required WFP-4A service marker is missing: $required"
        }
    }

    foreach ($required in @(
        "SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT",
        "SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS",
        "SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS",
        "SERPIUM_WFP4A_BRIDGE_READY",
        "SERPIUM_WFP4A_BRIDGE_DISARMED",
        "SOCKS5 backend: 127.0.0.1",
        "kLeaseMilliseconds = 5000"
    )) {
        if ($bridgeText.IndexOf($required, [StringComparison]::Ordinal) -lt 0) {
            throw "Required WFP-4A bridge marker is missing: $required"
        }
    }
}

function Test-Wfp4aUnsignedPackage {
    param(
        [ValidateSet("Debug", "Release")]
        [string]$Configuration = "Release"
    )

    $package = Get-Wfp4aUnsignedPackageDirectory -Configuration $Configuration
    $manifest = Get-Wfp4aBuildManifest -Configuration $Configuration

    foreach ($name in @(
        "Serpium.Flow.Driver.sys",
        "Serpium.Flow.Driver.inf",
        "Serpium.Flow.Driver.cat",
        "Serpium.Flow.Service.exe",
        "BUILD_MANIFEST.json"
    )) {
        $path = Join-Path $package $name

        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Required WFP-4A package file is missing: $path"
        }
    }

    foreach ($property in @(
        "schema", "buildMode", "configuration", "sdkWdkVersion", "kmdfVersion", "platform",
        "msbuildKernelToolsetUsed", "wfpEnabled", "wfpMode", "wfpLayers",
        "filterActions", "classifyActions", "trafficModification",
        "blockingEnabled", "redirectEnabled", "injectionEnabled",
        "routeEnforcementEnabled", "routeEnforcementDefaultArmed",
        "routeLeaseMilliseconds", "routeLeaseFailOpen", "tcpOnly",
        "udpQuicIncluded", "killSwitchIncluded", "localBridge",
        "policyTransportEnabled", "protocolVersion", "policyCommands",
        "applicationRuleCapacity", "observedFlowCapacity",
        "existingFlowMutation", "uiIntegrationIncluded",
        "activeRelayManagerIntegrationIncluded", "package", "sources"
    )) {
        Assert-Wfp4aManifestProperty -Object $manifest -Name $property
    }

    if ([int]$manifest.schema -ne 4) {
        throw "WFP-4A requires BUILD_MANIFEST schema 4."
    }

    if ([string]$manifest.buildMode -ne "direct-cl-link" -or [string]$manifest.platform -ne "x64") {
        throw "WFP-4A requires the verified direct-cl-link x64 package."
    }

    if ([string]$manifest.configuration -ne $Configuration) {
        throw "WFP-4A build manifest configuration does not match $Configuration."
    }

    if ([version]([string]$manifest.kmdfVersion) -ne [version]"1.33") {
        throw "WFP-4A runtime testing is pinned to KMDF 1.33."
    }

    if ([bool]$manifest.msbuildKernelToolsetUsed) {
        throw "WFP-4A runtime testing only accepts the verified direct build."
    }

    if (
        -not [bool]$manifest.wfpEnabled -or
        [string]$manifest.wfpMode -ne "guarded-tcp-route-enforcement" -or
        [string]$manifest.protocolVersion -ne "0x00040000" -or
        -not [bool]$manifest.policyTransportEnabled
    ) {
        throw "Build manifest does not identify the WFP-4A guarded TCP route package."
    }

    [string[]]$filterActions = @($manifest.filterActions | ForEach-Object { [string]$_ })
    [string[]]$classifyActions = @($manifest.classifyActions | ForEach-Object { [string]$_ })

    if (
        $filterActions.Count -ne 2 -or
        $filterActions -notcontains "FWP_ACTION_CALLOUT_INSPECTION" -or
        $filterActions -notcontains "FWP_ACTION_CALLOUT_TERMINATING" -or
        $classifyActions.Count -ne 2 -or
        $classifyActions -notcontains "FWP_ACTION_CONTINUE" -or
        $classifyActions -notcontains "FWP_ACTION_PERMIT" -or
        -not [bool]$manifest.trafficModification -or
        [bool]$manifest.blockingEnabled -or
        -not [bool]$manifest.redirectEnabled -or
        [bool]$manifest.injectionEnabled -or
        -not [bool]$manifest.routeEnforcementEnabled -or
        [bool]$manifest.routeEnforcementDefaultArmed -or
        [int]$manifest.routeLeaseMilliseconds -ne 5000 -or
        -not [bool]$manifest.routeLeaseFailOpen -or
        -not [bool]$manifest.tcpOnly -or
        [bool]$manifest.udpQuicIncluded -or
        [bool]$manifest.killSwitchIncluded -or
        [string]$manifest.localBridge -ne "transparent-to-local-socks5-no-auth" -or
        [bool]$manifest.existingFlowMutation -or
        [bool]$manifest.uiIntegrationIncluded -or
        [bool]$manifest.activeRelayManagerIntegrationIncluded
    ) {
        throw "Build manifest violates the guarded fail-open WFP-4A route contract."
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
        throw "Build manifest does not contain the exact bounded WFP-4A policy contract."
    }

    [string[]]$layers = @($manifest.wfpLayers | ForEach-Object { [string]$_ })

    if (
        $layers.Count -ne 4 -or
        $layers -notcontains "ALE_AUTH_CONNECT_V4" -or
        $layers -notcontains "ALE_AUTH_CONNECT_V6" -or
        $layers -notcontains "ALE_CONNECT_REDIRECT_V4" -or
        $layers -notcontains "ALE_CONNECT_REDIRECT_V6"
    ) {
        throw "Build manifest does not contain the exact WFP-4A observation and redirect layers."
    }

    $sourceExpectations = [ordered]@{
        driver = "2606e7b796fe84d814f7860cbc9116d862b6b89d65efff1b809b0314d22f4569"
        service = "911ee171c4d42bae98734cf00ad369c887e4d40abdacd5c61d33db2e374f873b"
        bridge = "707d6c9e41a14c2b4212df48c396320631818790badfbb95eaa380b8e21d7dee"
        bridgeHeader = "0c44ea77cf573ed5ec082a62db9f256d953bb103b5ac4b2cec18338ed2e1bb62"
        protocol = "7a1aaa66caf659429dfe6fa1cc60d651ac35b9a95faa5dcde5a3a0da6da45409"
        inf = "0f34373d0baa5fc5b836099d1de901dc0a92c6add31100c0d709e7cdb7113e30"
    }

    foreach ($name in $sourceExpectations.Keys) {
        Assert-Wfp4aManifestProperty -Object $manifest.sources -Name $name

        if ([string]$manifest.sources.$name -ine [string]$sourceExpectations[$name]) {
            throw "Build manifest source hash is not the verified WFP-4A Route Core plus ConnectRequest hotfix version: $name"
        }
    }

    $flowRoot = Get-Wfp4aFlowRoot
    $sourcePaths = [ordered]@{
        driver = Join-Path $flowRoot "Serpium.Flow.Driver\driver.c"
        service = Join-Path $flowRoot "Serpium.Flow.Service\service.cpp"
        bridge = Join-Path $flowRoot "Serpium.Flow.Service\bridge.cpp"
        bridgeHeader = Join-Path $flowRoot "Serpium.Flow.Service\bridge.h"
        protocol = Join-Path $flowRoot "Serpium.Flow.Protocol\serpium_flow_protocol.h"
        inf = Join-Path $flowRoot "Serpium.Flow.Driver\Serpium.Flow.Driver.inf"
    }

    foreach ($name in $sourcePaths.Keys) {
        $path = [string]$sourcePaths[$name]

        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Verified WFP-4A source file is missing: $path"
        }

        if ((Get-Wfp4aCanonicalSha256 -Path $path) -ine [string]$sourceExpectations[$name]) {
            throw "Current source tree no longer matches the verified WFP-4A build: $path"
        }
    }

    Assert-Wfp4aRouteCoreSource `
        -DriverSource ([string]$sourcePaths.driver) `
        -ServiceSource ([string]$sourcePaths.service) `
        -BridgeSource ([string]$sourcePaths.bridge)

    foreach ($name in @("driverSha256", "catalogSha256", "serviceSha256")) {
        Assert-Wfp4aManifestProperty -Object $manifest.package -Name $name
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

    if ((Get-Wfp4aCanonicalSha256 -Path $packageInf) -ine [string]$sourceExpectations.inf) {
        throw "Packaged INF does not match the verified WFP-4A source."
    }

    return [pscustomobject]@{
        PackageDirectory = $package
        Manifest = $manifest
    }
}

function Get-Wfp4aSecureBootState {
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

function Get-Wfp4aMemoryIntegrityState {
    try {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
        $value = (Get-ItemProperty -LiteralPath $path -ErrorAction Stop).Enabled
        return $(if ($value -eq 1) { "Enabled" } else { "Disabled" })
    }
    catch {
        return "Unknown"
    }
}

function Get-Wfp4aCodeIntegrityState {
    if ($null -eq ("Serpium.Wfp4a.NativeMethods" -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace Serpium.Wfp4a
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

    $information = New-Object Serpium.Wfp4a.SystemCodeIntegrityInformation
    $length = [Runtime.InteropServices.Marshal]::SizeOf($information)
    $information.Length = [uint32]$length
    $status = [Serpium.Wfp4a.NativeMethods]::NtQuerySystemInformation(
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

function Get-Wfp4aBcdTestSigningState {
    $bcdedit = Join-Path $env:SystemRoot "System32\bcdedit.exe"
    $result = Invoke-Wfp4aNative -FilePath $bcdedit -Arguments @("/enum") -LogPath $null -AllowFailure

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

function Get-Wfp4aDriverService {
    return @(
        Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name='SerpiumFlow'" -ErrorAction SilentlyContinue
    ) | Select-Object -First 1
}

function Get-Wfp4aUserService {
    return @(
        Get-CimInstance -ClassName Win32_Service -Filter "Name='SerpiumFlowService'" -ErrorAction SilentlyContinue
    ) | Select-Object -First 1
}

function Assert-Wfp4aServicesAbsent {
    if ($null -ne (Get-Wfp4aDriverService)) {
        throw "Service SerpiumFlow already exists. Run the WFP-4A cleanup stage or inspect it manually."
    }

    if ($null -ne (Get-Wfp4aUserService)) {
        throw "Service SerpiumFlowService already exists. Run the WFP-4A cleanup stage or inspect it manually."
    }
}

function Wait-Wfp4aServiceState {
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
        $record = if ($Kind -eq "Driver") { Get-Wfp4aDriverService } else { Get-Wfp4aUserService }

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

function Get-Wfp4aWfpNameSummary {
    $temp = Join-Path $env:TEMP ("Serpium_WFP4A_WfpState_" + [guid]::NewGuid().ToString("N") + ".xml")
    $netsh = Join-Path $env:SystemRoot "System32\netsh.exe"

    try {
        $result = Invoke-Wfp4aNative -FilePath $netsh -Arguments @("wfp", "show", "state", ("file=" + $temp)) -LogPath $null -AllowFailure

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

function Get-Wfp4aCertificateCount {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prefix
    )

    $count = 0

    foreach ($store in @("My", "Root", "TrustedPublisher")) {
        $count += @(
            Get-ChildItem ("Cert:\LocalMachine\" + $store) -ErrorAction SilentlyContinue |
                Where-Object { $_.Subject -like ($Prefix + "*") }
        ).Count
    }

    return $count
}

function Remove-Wfp4aCertificateByThumbprint {
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

function Assert-Wfp4aTestSigner {
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

function New-Wfp4aResultArchive {
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
