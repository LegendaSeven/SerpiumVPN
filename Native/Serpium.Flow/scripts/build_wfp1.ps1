#requires -version 5.1
[CmdletBinding()]
param(
    [string]$VisualStudioRoot = "D:\Program\Visual Studio\18",

    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

try {
    [Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
    $OutputEncoding = New-Object System.Text.UTF8Encoding($false)
}
catch {
}

$flowRoot = Split-Path -Parent $PSScriptRoot
$driverSource = Join-Path $flowRoot "Serpium.Flow.Driver\driver.c"
$driverHeader = Join-Path $flowRoot "Serpium.Flow.Driver\driver.h"
$driverInfSource = Join-Path $flowRoot "Serpium.Flow.Driver\Serpium.Flow.Driver.inf"
$serviceSource = Join-Path $flowRoot "Serpium.Flow.Service\service.cpp"
$bridgeSource = Join-Path $flowRoot "Serpium.Flow.Service\bridge.cpp"
$bridgeHeader = Join-Path $flowRoot "Serpium.Flow.Service\bridge.h"
$protocolDirectory = Join-Path $flowRoot "Serpium.Flow.Protocol"
$protocolHeader = Join-Path $protocolDirectory "serpium_flow_protocol.h"

$artifactRoot = Join-Path $flowRoot ("artifacts\x64\" + $Configuration)
$driverOutputDirectory = Join-Path $artifactRoot "driver"
$serviceOutputDirectory = Join-Path $artifactRoot "service"
$packageDirectory = Join-Path $artifactRoot "package"
$objectRoot = Join-Path $flowRoot ("obj\x64\" + $Configuration + "\direct")
$logRoot = Join-Path $flowRoot "logs"

$driverObject = Join-Path $objectRoot "Serpium.Flow.Driver.obj"
$serviceObject = Join-Path $objectRoot "Serpium.Flow.Service.obj"
$bridgeObject = Join-Path $objectRoot "Serpium.Flow.Bridge.obj"
$driverOutput = Join-Path $driverOutputDirectory "Serpium.Flow.Driver.sys"
$driverPdb = Join-Path $driverOutputDirectory "Serpium.Flow.Driver.pdb"
$serviceOutput = Join-Path $serviceOutputDirectory "Serpium.Flow.Service.exe"
$servicePdb = Join-Path $serviceOutputDirectory "Serpium.Flow.Service.pdb"

$stamp = Get-Date -Format "MMdd_HHmm"
$resultZip = Join-Path `
    $env:USERPROFILE `
    ("Downloads\WFP_Native_RESULT_" + $stamp + ".zip")

function Write-Utf8Lines {
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

function Get-CanonicalSha256 {
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

function Invoke-Logged {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )

    $commandLine = $FilePath + " " + ($Arguments -join " ")
    Write-Host ""
    Write-Host $commandLine -ForegroundColor DarkGray

    $oldPreference = $ErrorActionPreference

    try {
        $ErrorActionPreference = "Continue"
        $output = @(& $FilePath @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $oldPreference
    }

    $logLines = @(
        "COMMAND:",
        $commandLine,
        "",
        "OUTPUT:"
    ) + @($output) + @(
        "",
        ("EXIT CODE: " + $exitCode)
    )

    Write-Utf8Lines -Path $LogPath -Lines $logLines

    foreach ($line in $output) {
        Write-Host ([string]$line)
    }

    if ($exitCode -ne 0) {
        throw "Команда завершилась с кодом $exitCode. Лог: $LogPath"
    }
}

function Find-VisualStudioRoot {
    param(
        [AllowNull()]
        [string]$PreferredRoot
    )

    if (
        -not [string]::IsNullOrWhiteSpace($PreferredRoot) -and
        (Test-Path -LiteralPath $PreferredRoot -PathType Container)
    ) {
        return [IO.Path]::GetFullPath($PreferredRoot).TrimEnd("\")
    }

    $vswhereCandidates = @(
        (Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"),
        (Join-Path $env:ProgramFiles "Microsoft Visual Studio\Installer\vswhere.exe")
    )

    $vswhere = $vswhereCandidates |
        Where-Object {
            Test-Path -LiteralPath $_ -PathType Leaf
        } |
        Select-Object -First 1

    if ($null -eq $vswhere) {
        return $null
    }

    $detected = & $vswhere `
        -latest `
        -prerelease `
        -products "*" `
        -property installationPath 2>$null |
        Select-Object -First 1

    if (
        [string]::IsNullOrWhiteSpace([string]$detected) -or
        -not (Test-Path -LiteralPath ([string]$detected) -PathType Container)
    ) {
        return $null
    }

    return [IO.Path]::GetFullPath([string]$detected).TrimEnd("\")
}

function Get-KitsRoot {
    foreach ($registryPath in @(
        "HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots"
    )) {
        try {
            $item = Get-ItemProperty -LiteralPath $registryPath -ErrorAction Stop
            $candidate = [string]$item.KitsRoot10

            if (
                -not [string]::IsNullOrWhiteSpace($candidate) -and
                (Test-Path -LiteralPath $candidate -PathType Container)
            ) {
                return [IO.Path]::GetFullPath($candidate).TrimEnd("\")
            }
        }
        catch {
        }
    }

    $fallback = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10"

    if (Test-Path -LiteralPath $fallback -PathType Container) {
        return [IO.Path]::GetFullPath($fallback).TrimEnd("\")
    }

    return $null
}

function Get-LatestMsvcToolset {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VsRoot
    )

    $root = Join-Path $VsRoot "VC\Tools\MSVC"

    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        return $null
    }

    return Get-ChildItem `
        -LiteralPath $root `
        -Directory `
        -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -match '^\d+\.\d+\.\d+$'
        } |
        Sort-Object {
            try {
                [version]$_.Name
            }
            catch {
                [version]"0.0.0"
            }
        } -Descending |
        Where-Object {
            $clCandidate = Join-Path `
                $_.FullName `
                "bin\Hostx64\x64\cl.exe"

            $linkCandidate = Join-Path `
                $_.FullName `
                "bin\Hostx64\x64\link.exe"

            (Test-Path -LiteralPath $clCandidate -PathType Leaf) -and
            (Test-Path -LiteralPath $linkCandidate -PathType Leaf)
        } |
        Select-Object -First 1
}

function Get-LatestSdkVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$KitsRoot
    )

    $includeRoot = Join-Path $KitsRoot "Include"

    if (-not (Test-Path -LiteralPath $includeRoot -PathType Container)) {
        return $null
    }

    return Get-ChildItem `
        -LiteralPath $includeRoot `
        -Directory `
        -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -match '^\d+\.\d+\.\d+\.\d+$'
        } |
        Sort-Object {
            try {
                [version]$_.Name
            }
            catch {
                [version]"0.0.0.0"
            }
        } -Descending |
        Where-Object {
            $version = $_.Name

            $sharedHeader = Join-Path `
                $KitsRoot `
                "Include\$version\shared\ntdef.h"

            $kernelHeader = Join-Path `
                $KitsRoot `
                "Include\$version\km\ntddk.h"

            $kernelLibrary = Join-Path `
                $KitsRoot `
                "Lib\$version\km\x64\ntoskrnl.lib"

            $userLibrary = Join-Path `
                $KitsRoot `
                "Lib\$version\um\x64\kernel32.lib"

            $ucrtLibrary = Join-Path `
                $KitsRoot `
                "Lib\$version\ucrt\x64\libucrt.lib"

            $resourceCompiler = Join-Path `
                $KitsRoot `
                "bin\$version\x64\rc.exe"

            $manifestTool = Join-Path `
                $KitsRoot `
                "bin\$version\x64\mt.exe"

            (Test-Path -LiteralPath $sharedHeader -PathType Leaf) -and
            (Test-Path -LiteralPath $kernelHeader -PathType Leaf) -and
            (Test-Path -LiteralPath $kernelLibrary -PathType Leaf) -and
            (Test-Path -LiteralPath $userLibrary -PathType Leaf) -and
            (Test-Path -LiteralPath $ucrtLibrary -PathType Leaf) -and
            (Test-Path -LiteralPath $resourceCompiler -PathType Leaf) -and
            (Test-Path -LiteralPath $manifestTool -PathType Leaf)
        } |
        Select-Object -First 1
}

function Get-LatestKmdfVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$KitsRoot
    )

    $includeRoot = Join-Path $KitsRoot "Include\wdf\kmdf"

    if (-not (Test-Path -LiteralPath $includeRoot -PathType Container)) {
        return $null
    }

    return Get-ChildItem `
        -LiteralPath $includeRoot `
        -Directory `
        -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -match '^\d+\.\d+$'
        } |
        Sort-Object {
            try {
                [version]$_.Name
            }
            catch {
                [version]"0.0"
            }
        } -Descending |
        Where-Object {
            $version = $_.Name
            $libraryRoot = Join-Path `
                $KitsRoot `
                ("Lib\wdf\kmdf\x64\" + $version)

            $wdfHeader = Join-Path $_.FullName "wdf.h"
            $entryLibrary = Join-Path `
                $libraryRoot `
                "WdfDriverEntry.lib"
            $loaderLibrary = Join-Path `
                $libraryRoot `
                "WdfLdr.lib"

            (Test-Path -LiteralPath $wdfHeader -PathType Leaf) -and
            (Test-Path -LiteralPath $entryLibrary -PathType Leaf) -and
            (Test-Path -LiteralPath $loaderLibrary -PathType Leaf)
        } |
        Select-Object -First 1
}

function Find-Inf2Cat {
    param(
        [Parameter(Mandatory = $true)]
        [string]$KitsRoot
    )

    $binRoot = Join-Path $KitsRoot "bin"

    if (-not (Test-Path -LiteralPath $binRoot -PathType Container)) {
        return $null
    }

    $candidates = @(
        Get-ChildItem `
            -LiteralPath $binRoot `
            -Recurse `
            -File `
            -Filter "Inf2Cat.exe" `
            -ErrorAction SilentlyContinue
    )

    $preferred = $candidates |
        Where-Object {
            $_.FullName -match '\\x86\\Inf2Cat\.exe$'
        } |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1

    if ($null -ne $preferred) {
        return $preferred
    }

    return $candidates |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
}

function Export-DirectBuildResult {
    param(
        [Parameter(Mandatory = $true)]
        [string]$State,

        [AllowNull()]
        [string]$FailureMessage
    )

    $stage = Join-Path `
        $env:TEMP `
        ("WFP_Native_RESULT_" + $stamp)

    Remove-Item `
        -LiteralPath $stage `
        -Recurse `
        -Force `
        -ErrorAction SilentlyContinue

    New-Item -ItemType Directory -Path $stage -Force | Out-Null

    if (Test-Path -LiteralPath $logRoot -PathType Container) {
        Copy-Item `
            -LiteralPath $logRoot `
            -Destination (Join-Path $stage "logs") `
            -Recurse `
            -Force
    }

    if (Test-Path -LiteralPath $packageDirectory -PathType Container) {
        Copy-Item `
            -LiteralPath $packageDirectory `
            -Destination (Join-Path $stage "package") `
            -Recurse `
            -Force
    }

    Copy-Item `
        -LiteralPath $PSCommandPath `
        -Destination (Join-Path $stage "build_wfp1.ps1") `
        -Force

    $failureText = "<none>"

    if (-not [string]::IsNullOrWhiteSpace($FailureMessage)) {
        $failureText = $FailureMessage
    }

    $summary = @(
        ("State: " + $State),
        ("Created: " + (Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz")),
        ("Flow root: " + $flowRoot),
        ("Configuration: " + $Configuration),
        ("Failure: " + $failureText)
    )

    Write-Utf8Lines `
        -Path (Join-Path $stage "RESULT.txt") `
        -Lines $summary

    Remove-Item `
        -LiteralPath $resultZip `
        -Force `
        -ErrorAction SilentlyContinue

    Compress-Archive `
        -Path (Join-Path $stage "*") `
        -DestinationPath $resultZip `
        -CompressionLevel Optimal `
        -Force

    return $resultZip
}

Remove-Item -LiteralPath $logRoot -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
Remove-Item -LiteralPath $objectRoot -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $artifactRoot -Recurse -Force -ErrorAction SilentlyContinue

New-Item -ItemType Directory -Path $objectRoot -Force | Out-Null
New-Item -ItemType Directory -Path $driverOutputDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $serviceOutputDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $packageDirectory -Force | Out-Null

try {
    foreach ($requiredSource in @(
        $driverSource,
        $driverHeader,
        $driverInfSource,
        $serviceSource,
        $bridgeSource,
        $bridgeHeader,
        $protocolHeader
    )) {
        if (-not (Test-Path -LiteralPath $requiredSource -PathType Leaf)) {
            throw "Не найден обязательный исходник: $requiredSource"
        }
    }

    $driverSourceText = [IO.File]::ReadAllText($driverSource)

    foreach ($requiredMarker in @(
        "FWP_ACTION_CALLOUT_INSPECTION",
        "FWP_ACTION_CONTINUE",
        "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
        "FWPM_LAYER_ALE_AUTH_CONNECT_V6",
        "FWPM_LAYER_ALE_CONNECT_REDIRECT_V4",
        "FWPM_LAYER_ALE_CONNECT_REDIRECT_V6",
        "FwpsCalloutRegister0",
        "FwpsCalloutRegister1",
        "FwpsRedirectHandleCreate0",
        "FwpsQueryConnectionRedirectState0",
        "FwpsAcquireWritableLayerDataPointer0",
        "FwpsApplyModifiedLayerData0",
        "FWPM_SESSION_FLAG_DYNAMIC",
        "SerpiumFlowAddRule",
        "SerpiumFlowRemoveRule",
        "SerpiumFlowClearRules",
        "SerpiumFlowEnumerateRules",
        "SerpiumFlowEnumerateFlows"
    )) {
        if ($driverSourceText.IndexOf($requiredMarker, [StringComparison]::Ordinal) -lt 0) {
            throw "WFP-4A guarded route marker is missing from driver.c: $requiredMarker"
        }
    }

    # U2 intentionally contains exactly one FWP_ACTION_BLOCK: the lease-gated
    # QUIC UDP/443 -> TCP fallback classify path. Keep the old broad guard for
    # destructive packet operations, but allow injection handle/query helpers.
    $blockMatches = [regex]::Matches($driverSourceText, '\bFWP_ACTION_BLOCK\b')
    if ($blockMatches.Count -ne 1) {
        throw "WFP U2 safety check expected exactly one FWP_ACTION_BLOCK in driver.c; found $($blockMatches.Count)."
    }

    foreach ($requiredU2Marker in @(
        "SerpiumFlowShouldBlockQuic",
        "SERPIUM_FLOW_ROUTE_CONFIG_FLAG_QUIC_TCP_FALLBACK",
        "SERPIUM_FLOW_ROUTE_CONFIG_FLAG_DOMAIN_QUIC_FALLBACK",
        "FWPM_LAYER_DATAGRAM_DATA_V4",
        "FWPM_LAYER_DATAGRAM_DATA_V6",
        "FWPM_CONDITION_IP_REMOTE_PORT",
        "FwpsInjectionHandleCreate0",
        "FwpsQueryPacketInjectionState0",
        "FWP_ACTION_BLOCK"
    )) {
        if ($driverSourceText.IndexOf($requiredU2Marker, [StringComparison]::Ordinal) -lt 0) {
            throw "WFP U2 safety marker is missing from driver.c: $requiredU2Marker"
        }
    }

    foreach ($forbiddenPattern in @(
        '\bFwpsInject(?!ionHandle(?:Create|Destroy))[A-Za-z0-9_]*\s*\(',
        '\bFwpsPend[A-Za-z0-9_]*\s*\(',
        '\bFWPS_CLASSIFY_OUT_FLAG_ABSORB\b'
    )) {
        if ([regex]::IsMatch($driverSourceText, $forbiddenPattern)) {
            throw "Forbidden WFP U2 packet action found in driver.c: $forbiddenPattern"
        }
    }

    foreach ($allowedInjectionHelper in @(
        "FwpsInjectionHandleCreate0",
        "FwpsInjectionHandleDestroy0",
        "FwpsQueryPacketInjectionState0"
    )) {
        if ($driverSourceText.IndexOf($allowedInjectionHelper, [StringComparison]::Ordinal) -lt 0) {
            throw "Required safe WFP U2 injection helper is missing from driver.c: $allowedInjectionHelper"
        }
    }

    $protocolSourceText = [IO.File]::ReadAllText($protocolHeader)

    foreach ($requiredProtocolMarker in @(
        "SERPIUM_FLOW_PROTOCOL_VERSION       0x00040000u",
        "IOCTL_SERPIUM_FLOW_ADD_RULE",
        "IOCTL_SERPIUM_FLOW_REMOVE_RULE",
        "IOCTL_SERPIUM_FLOW_CLEAR_RULES",
        "IOCTL_SERPIUM_FLOW_ENUM_RULES",
        "IOCTL_SERPIUM_FLOW_ENUM_FLOWS",
        "IOCTL_SERPIUM_FLOW_CONFIGURE_ROUTE",
        "IOCTL_SERPIUM_FLOW_DISARM_ROUTE",
        "IOCTL_SERPIUM_FLOW_REPLACE_RULES",
        "SERPIUM_FLOW_ROUTE_LEASE_MAX_MILLISECONDS",
        "SERPIUM_FLOW_REDIRECT_CONTEXT_MAGIC",
        "SERPIUM_FLOW_ROUTE_CONFIG_FLAG_INSPECT_ALL_TCP"
    )) {
        if ($protocolSourceText.IndexOf($requiredProtocolMarker, [StringComparison]::Ordinal) -lt 0) {
            throw "WFP-4A protocol marker is missing: $requiredProtocolMarker"
        }
    }

    $serviceSourceText = [IO.File]::ReadAllText($serviceSource)

    foreach ($requiredServiceMarker in @(
        "FwpmGetAppIdFromFileName0",
        "SERPIUM_WFP4A_ADD_RULE_PASS",
        "SERPIUM_WFP4A_REMOVE_RULE_PASS",
        "SERPIUM_WFP4A_CLEAR_RULES_PASS",
        "SERPIUM_WFP4A_SYNC_RULES_PASS",
        "SERPIUM_WFP4A_LIST_RULES_PASS",
        "SERPIUM_WFP4A_LIST_FLOWS_PASS",
        "RunTcpRouteBridgeCommand",
        "RunTcpDomainRouteBridgeCommand",
        "DisarmTcpRouteCommand"
    )) {
        if ($serviceSourceText.IndexOf($requiredServiceMarker, [StringComparison]::Ordinal) -lt 0) {
            throw "WFP-4A service marker is missing: $requiredServiceMarker"
        }
    }

    $bridgeSourceText = [IO.File]::ReadAllText($bridgeSource)

    foreach ($requiredBridgeMarker in @(
        "SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS",
        "SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT",
        "SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS",
        "SERPIUM_WFP4A_BRIDGE_READY",
        "SERPIUM_WFP4A_BRIDGE_DISARMED",
        "ProbeLocalSocks",
        "AreBackendProcessesAlive",
        "SERPIUM_WFP4A_DOMAIN_POLICY_APPLIED",
        "TryExtractTlsSni",
        "TryExtractHttpHost",
        "ConnectToOriginalDestination"
    )) {
        if ($bridgeSourceText.IndexOf($requiredBridgeMarker, [StringComparison]::Ordinal) -lt 0) {
            throw "WFP-4A bridge marker is missing: $requiredBridgeMarker"
        }
    }

    $resolvedVsRoot = Find-VisualStudioRoot -PreferredRoot $VisualStudioRoot

    if ($null -eq $resolvedVsRoot) {
        throw "Visual Studio не найдена. Передайте корректный -VisualStudioRoot."
    }

    $msvcToolset = Get-LatestMsvcToolset -VsRoot $resolvedVsRoot

    if ($null -eq $msvcToolset) {
        throw "MSVC x64 toolset с cl.exe/link.exe не найден: $resolvedVsRoot"
    }

    $kitsRoot = Get-KitsRoot

    if ($null -eq $kitsRoot) {
        throw "Windows Kits root не найден."
    }

    $sdkVersionDirectory = Get-LatestSdkVersion -KitsRoot $kitsRoot

    if ($null -eq $sdkVersionDirectory) {
        throw "Полная версия Windows SDK/WDK x64 не найдена."
    }

    $kmdfVersionDirectory = Get-LatestKmdfVersion -KitsRoot $kitsRoot

    if ($null -eq $kmdfVersionDirectory) {
        throw "KMDF include/libs не найдены."
    }

    # The installed WDK can contain a framework version newer than the inbox
    # runtime on the target Windows build. WFP-4A only uses APIs available in
    # KMDF 1.33, which is also the version declared by the vcxproj.
    $compatibleKmdfVersion = "1.33"
    $compatibleKmdfInclude = Join-Path $kitsRoot ("Include\wdf\kmdf\" + $compatibleKmdfVersion)
    $compatibleKmdfLibrary = Join-Path $kitsRoot ("Lib\wdf\kmdf\x64\" + $compatibleKmdfVersion)

    foreach ($requiredKmdfFile in @(
        (Join-Path $compatibleKmdfInclude "wdf.h"),
        (Join-Path $compatibleKmdfLibrary "WdfDriverEntry.lib"),
        (Join-Path $compatibleKmdfLibrary "WdfLdr.lib")
    )) {
        if (-not (Test-Path -LiteralPath $requiredKmdfFile -PathType Leaf)) {
            throw "KMDF 1.33 compatibility file not found: $requiredKmdfFile"
        }
    }

    $kmdfVersionDirectory = Get-Item -LiteralPath $compatibleKmdfInclude

    $sdkVersion = $sdkVersionDirectory.Name
    $kmdfVersion = $kmdfVersionDirectory.Name
    $kmdfParts = $kmdfVersion.Split(".")

    if ($kmdfParts.Count -ne 2) {
        throw "Неожиданный номер KMDF: $kmdfVersion"
    }

    $kmdfMajor = $kmdfParts[0]
    $kmdfMinor = $kmdfParts[1]

    $toolBin = Join-Path $msvcToolset.FullName "bin\Hostx64\x64"
    $cl = Join-Path $toolBin "cl.exe"
    $link = Join-Path $toolBin "link.exe"
    $dumpbin = Join-Path $toolBin "dumpbin.exe"
    $sdkBinX64 = Join-Path $kitsRoot "bin\$sdkVersion\x64"
    $rc = Join-Path $sdkBinX64 "rc.exe"
    $mt = Join-Path $sdkBinX64 "mt.exe"

    $msvcInclude = Join-Path $msvcToolset.FullName "include"
    $msvcLib = Join-Path $msvcToolset.FullName "lib\x64"

    $sharedInclude = Join-Path $kitsRoot "Include\$sdkVersion\shared"
    $kmInclude = Join-Path $kitsRoot "Include\$sdkVersion\km"
    $kmCrtInclude = Join-Path $kitsRoot "Include\$sdkVersion\km\crt"
    $umInclude = Join-Path $kitsRoot "Include\$sdkVersion\um"
    $ucrtInclude = Join-Path $kitsRoot "Include\$sdkVersion\ucrt"
    $wdfInclude = $kmdfVersionDirectory.FullName

    $kmLib = Join-Path $kitsRoot "Lib\$sdkVersion\km\x64"
    $umLib = Join-Path $kitsRoot "Lib\$sdkVersion\um\x64"
    $ucrtLib = Join-Path $kitsRoot "Lib\$sdkVersion\ucrt\x64"
    $wdfLib = Join-Path $kitsRoot ("Lib\wdf\kmdf\x64\" + $kmdfVersion)

    $bufferOverflowLibrary = Join-Path $kmLib "BufferOverflowFastFailK.lib"

    if (-not (Test-Path -LiteralPath $bufferOverflowLibrary -PathType Leaf)) {
        $bufferOverflowLibrary = Join-Path $kmLib "BufferOverflowK.lib"
    }

    $requiredToolsAndLibraries = @(
        $cl,
        $link,
        $rc,
        $mt,
        $msvcInclude,
        $msvcLib,
        $sharedInclude,
        $kmInclude,
        $umInclude,
        $ucrtInclude,
        $wdfInclude,
        $kmLib,
        $umLib,
        $ucrtLib,
        $wdfLib,
        $bufferOverflowLibrary,
        (Join-Path $kmLib "ntoskrnl.lib"),
        (Join-Path $kmLib "hal.lib"),
        (Join-Path $kmLib "wmilib.lib"),
        (Join-Path $kmLib "fwpkclnt.lib"),
        (Join-Path $kmLib "ntstrsafe.lib"),
        (Join-Path $umLib "Fwpuclnt.lib"),
        (Join-Path $umLib "Ws2_32.lib"),
        (Join-Path $wdfLib "WdfDriverEntry.lib"),
        (Join-Path $wdfLib "WdfLdr.lib")
    )

    foreach ($required in $requiredToolsAndLibraries) {
        if (-not (Test-Path -LiteralPath $required)) {
            throw "Не найден обязательный tool/include/lib: $required"
        }
    }

    $env:PATH = (
        $toolBin + ";" +
        $sdkBinX64 + ";" +
        (Join-Path $resolvedVsRoot "Common7\IDE") + ";" +
        $env:PATH
    )

    Write-Host ""
    Write-Host "=== SERPIUM WFP-4A GUARDED TCP ROUTE DIRECT TOOLCHAIN ===" -ForegroundColor Cyan
    Write-Host ("Visual Studio: " + $resolvedVsRoot) -ForegroundColor DarkCyan
    Write-Host ("MSVC: " + $msvcToolset.Name) -ForegroundColor DarkCyan
    Write-Host ("Windows SDK/WDK: " + $sdkVersion) -ForegroundColor DarkCyan
    Write-Host ("KMDF: " + $kmdfVersion) -ForegroundColor DarkCyan
    Write-Host "MSBuild driver toolset: not used" -ForegroundColor Green
    Write-Host ""

    $driverCompileArguments = @(
        "/nologo",
        "/c",
        "/TC",
        "/W4",
        "/WX-",
        "/kernel",
        "/GS",
        "/Zl",
        "/Oi",
        "/Gy",
        "/Gw",
        "/Zp8",
        "/FC",
        "/D_AMD64_",
        "/DAMD64",
        "/D_WIN64",
        "/DWIN64",
        "/D_KERNEL_MODE",
        "/DUNICODE",
        "/D_UNICODE",
        "/DWINVER=0x0A00",
        "/D_WIN32_WINNT=0x0A00",
        "/DNTDDI_VERSION=0x0A000000",
        "/DNDIS630=1",
        ("/DKMDF_VERSION_MAJOR=" + $kmdfMajor),
        ("/DKMDF_VERSION_MINOR=" + $kmdfMinor),
        ("/I" + $protocolDirectory),
        ("/I" + $wdfInclude),
        ("/I" + $sharedInclude),
        ("/I" + $kmInclude),
        ("/I" + $kmCrtInclude),
        ("/Fo" + $driverObject)
    )

    if ($Configuration -eq "Release") {
        $driverCompileArguments += @(
            "/O2",
            "/Ob2",
            "/DNDEBUG"
        )
    }
    else {
        $driverCompileArguments += @(
            "/Od",
            "/Zi",
            "/DDBG=1"
        )
    }

    $driverCompileArguments += $driverSource

    Invoke-Logged `
        -FilePath $cl `
        -Arguments $driverCompileArguments `
        -LogPath (Join-Path $logRoot "driver-direct-compile.log")

    $driverLinkArguments = @(
        "/NOLOGO",
        ("/OUT:" + $driverOutput),
        ("/PDB:" + $driverPdb),
        "/DRIVER",
        "/SUBSYSTEM:NATIVE,10.00",
        "/ENTRY:FxDriverEntry",
        "/MACHINE:X64",
        "/INCREMENTAL:NO",
        "/MANIFEST:NO",
        "/NODEFAULTLIB",
        "/NXCOMPAT",
        "/DYNAMICBASE",
        "/OPT:REF",
        "/OPT:ICF",
        "/DEBUG:FULL",
        $driverObject,
        (Join-Path $wdfLib "WdfDriverEntry.lib"),
        (Join-Path $wdfLib "WdfLdr.lib"),
        $bufferOverflowLibrary,
        (Join-Path $kmLib "ntoskrnl.lib"),
        (Join-Path $kmLib "hal.lib"),
        (Join-Path $kmLib "wmilib.lib"),
        (Join-Path $kmLib "fwpkclnt.lib"),
        (Join-Path $kmLib "ntstrsafe.lib")
    )

    Invoke-Logged `
        -FilePath $link `
        -Arguments $driverLinkArguments `
        -LogPath (Join-Path $logRoot "driver-direct-link.log")

    $serviceCompileArguments = @(
        "/nologo",
        "/c",
        "/TP",
        "/std:c++20",
        "/EHsc",
        "/W4",
        "/WX-",
        "/GS",
        "/Gy",
        "/Gw",
        "/FC",
        "/MT",
        "/DUNICODE",
        "/D_UNICODE",
        "/DWIN32_LEAN_AND_MEAN",
        "/DWINVER=0x0A00",
        "/D_WIN32_WINNT=0x0A00",
        "/DNTDDI_VERSION=0x0A000000",
        ("/I" + $protocolDirectory),
        ("/I" + $msvcInclude),
        ("/I" + $sharedInclude),
        ("/I" + $umInclude),
        ("/I" + $ucrtInclude)
    )

    if ($Configuration -eq "Release") {
        $serviceCompileArguments += @(
            "/O2",
            "/Ob2",
            "/DNDEBUG"
        )
    }
    else {
        $serviceCompileArguments += @(
            "/Od",
            "/Zi",
            "/D_DEBUG"
        )
    }

    $serviceCompileBaseArguments = @($serviceCompileArguments)
    $serviceCompileArguments += @(
        ("/Fo" + $serviceObject),
        $serviceSource
    )

    Invoke-Logged `
        -FilePath $cl `
        -Arguments $serviceCompileArguments `
        -LogPath (Join-Path $logRoot "service-direct-compile.log")

    $bridgeCompileArguments = @($serviceCompileBaseArguments) + @(
        ("/Fo" + $bridgeObject),
        $bridgeSource
    )

    Invoke-Logged `
        -FilePath $cl `
        -Arguments $bridgeCompileArguments `
        -LogPath (Join-Path $logRoot "bridge-direct-compile.log")

    $serviceLinkArguments = @(
        "/NOLOGO",
        ("/OUT:" + $serviceOutput),
        ("/PDB:" + $servicePdb),
        "/SUBSYSTEM:CONSOLE,10.00",
        "/MACHINE:X64",
        "/INCREMENTAL:NO",
        "/MANIFEST:EMBED",
        "/NXCOMPAT",
        "/DYNAMICBASE",
        "/OPT:REF",
        "/OPT:ICF",
        "/DEBUG:FULL",
        ("/LIBPATH:" + $msvcLib),
        ("/LIBPATH:" + $umLib),
        ("/LIBPATH:" + $ucrtLib),
        $serviceObject,
        $bridgeObject,
        "Advapi32.lib",
        "Kernel32.lib",
        "Fwpuclnt.lib",
        "Ws2_32.lib"
    )

    Invoke-Logged `
        -FilePath $link `
        -Arguments $serviceLinkArguments `
        -LogPath (Join-Path $logRoot "service-direct-link.log")

    foreach ($requiredArtifact in @(
        $driverOutput,
        $serviceOutput
    )) {
        if (-not (Test-Path -LiteralPath $requiredArtifact -PathType Leaf)) {
            throw "Ожидаемый артефакт не найден: $requiredArtifact"
        }
    }

    Copy-Item `
        -LiteralPath $driverOutput `
        -Destination (Join-Path $packageDirectory "Serpium.Flow.Driver.sys") `
        -Force

    Copy-Item `
        -LiteralPath $serviceOutput `
        -Destination (Join-Path $packageDirectory "Serpium.Flow.Service.exe") `
        -Force

    Copy-Item `
        -LiteralPath $driverInfSource `
        -Destination (Join-Path $packageDirectory "Serpium.Flow.Driver.inf") `
        -Force

    $inf2cat = Find-Inf2Cat -KitsRoot $kitsRoot

    if ($null -eq $inf2cat) {
        throw "Inf2Cat.exe не найден."
    }

    Invoke-Logged `
        -FilePath $inf2cat.FullName `
        -Arguments @(
            ("/driver:" + $packageDirectory),
            "/os:10_X64",
            "/verbose"
        ) `
        -LogPath (Join-Path $logRoot "inf2cat-direct.log")

    $catalogPath = Join-Path $packageDirectory "Serpium.Flow.Driver.cat"

    if (-not (Test-Path -LiteralPath $catalogPath -PathType Leaf)) {
        throw "Inf2Cat не создал Serpium.Flow.Driver.cat"
    }

    if (Test-Path -LiteralPath $dumpbin -PathType Leaf) {
        Invoke-Logged `
            -FilePath $dumpbin `
            -Arguments @("/headers", $driverOutput) `
            -LogPath (Join-Path $logRoot "driver-headers.log")

        Invoke-Logged `
            -FilePath $dumpbin `
            -Arguments @("/headers", $serviceOutput) `
            -LogPath (Join-Path $logRoot "service-headers.log")
    }

    $manifest = [ordered]@{
        schema = 4
        buildMode = "direct-cl-link"
        configuration = $Configuration
        visualStudioRoot = $resolvedVsRoot
        msvcVersion = $msvcToolset.Name
        kitsRoot = $kitsRoot
        sdkWdkVersion = $sdkVersion
        kmdfVersion = $kmdfVersion
        platform = "x64"
        driverToolset = "cl.exe + link.exe"
        msbuildKernelToolsetUsed = $false
        wfpEnabled = $true
        wfpMode = "guarded-tcp-udp-route-enforcement-domain-bridge-quic-fallback-datagram-core"
        protocolVersion = "0x00040000"
        wfpLayers = @(
            "ALE_AUTH_CONNECT_V4",
            "ALE_AUTH_CONNECT_V6",
            "ALE_CONNECT_REDIRECT_V4",
            "ALE_CONNECT_REDIRECT_V6",
            "DATAGRAM_DATA_V4",
            "DATAGRAM_DATA_V6"
        )
        filterActions = @(
            "FWP_ACTION_CALLOUT_INSPECTION",
            "FWP_ACTION_CALLOUT_TERMINATING"
        )
        classifyActions = @(
            "FWP_ACTION_CONTINUE",
            "FWP_ACTION_PERMIT",
            "FWP_ACTION_BLOCK"
        )
        trafficModification = $true
        blockingEnabled = $true
        blockingScope = "lease-gated UDP/443 QUIC fallback only"
        redirectEnabled = $true
        injectionEnabled = $false
        datagramDataCoreEnabled = $true
        datagramInjectionHandleCreated = $true
        datagramSelfInjectionGuard = "FwpsQueryPacketInjectionState0"
        routeEnforcementEnabled = $true
        routeEnforcementDefaultArmed = $false
        routeLeaseMilliseconds = 5000
        routeLeaseFailOpen = $true
        tcpOnly = $false
        domainRoutingEnabled = $true
        domainRoutingMatch = "HTTP Host + TLS ClientHello SNI"
        domainRoutingInspectAllTcp = $true
        domainRoutingUnknownHostFailOpen = "DIRECT"
        udpQuicIncluded = $true
        udpApplicationRoutingIncluded = $true
        quicTcpFallbackIncluded = $true
        quicTcpFallbackMode = "selected/full-tunnel UDP443 blocked while healthy route lease forces TCP"
        domainQuicFallbackIncluded = $true
        domainQuicFallbackMode = "when domain bridge active UDP443 blocked for non-bypass apps to force HTTP2/TLS SNI path"
        udpProxyTransport = "SOCKS5 UDP ASSOCIATE"
        udpConnectedSocketCompatibility = "SOURCE_IMPLEMENTED_RUNTIME_NOT_PROVEN"
        udpRedirectRecordsTransport = "WSARecvMsg + WSASendMsg"
        quicRuntimeValidationRequired = $true
        quicApplicationRoutingIncluded = $true
        quicApplicationRoutingStrategy = "TCP fallback for UDP443; U1 SOCKS5 UDP remains for non-QUIC UDP"
        quicApplicationRoutingSourceCandidate = $false
        quicDomainRoutingIncluded = $true
        quicDomainRoutingStrategy = "force TCP when domain policy active; hostname remains HTTP Host/TLS SNI"
        nativeUdpDatagramProxyIncluded = $false
        nativeUdpDatagramProxyDeferred = "separate transparent UDP transport if non-QUIC connected UDP requires it"
        killSwitchIncluded = $false
        localBridge = "transparent-tcp-plus-udp-associate-to-local-socks5-no-auth"
        policyTransportEnabled = $true
        policyCommands = @(
            "ADD_RULE",
            "REMOVE_RULE",
            "CLEAR_RULES",
            "REPLACE_RULES",
            "ENUM_RULES",
            "ENUM_FLOWS"
        )
        applicationRuleCapacity = 128
        observedFlowCapacity = 256
        existingFlowMutation = $false
        uiIntegrationIncluded = $false
        activeRelayManagerIntegrationIncluded = $false
        package = [ordered]@{
            driverSha256 = (
                Get-FileHash `
                    -LiteralPath (Join-Path $packageDirectory "Serpium.Flow.Driver.sys") `
                    -Algorithm SHA256
            ).Hash.ToLowerInvariant()
            catalogSha256 = (
                Get-FileHash `
                    -LiteralPath $catalogPath `
                    -Algorithm SHA256
            ).Hash.ToLowerInvariant()
            serviceSha256 = (
                Get-FileHash `
                    -LiteralPath (Join-Path $packageDirectory "Serpium.Flow.Service.exe") `
                    -Algorithm SHA256
            ).Hash.ToLowerInvariant()
        }
        sources = [ordered]@{
            driver = Get-CanonicalSha256 -Path $driverSource
            service = Get-CanonicalSha256 -Path $serviceSource
            bridge = Get-CanonicalSha256 -Path $bridgeSource
            bridgeHeader = Get-CanonicalSha256 -Path $bridgeHeader
            protocol = Get-CanonicalSha256 -Path $protocolHeader
            inf = Get-CanonicalSha256 -Path $driverInfSource
        }
    }

    [IO.File]::WriteAllText(
        (Join-Path $packageDirectory "BUILD_MANIFEST.json"),
        ($manifest | ConvertTo-Json -Depth 6),
        (New-Object System.Text.UTF8Encoding($false))
    )

    $archive = Export-DirectBuildResult `
        -State "PASS" `
        -FailureMessage $null

    Write-Host ""
    Write-Host "SERPIUM_WFP4A_ROUTE_CORE_BUILD_PASS" -ForegroundColor Green
    Write-Host ("Package: " + $packageDirectory) -ForegroundColor Cyan
    Write-Host ("Result archive: " + $archive) -ForegroundColor Cyan
}
catch {
    $message = $_.Exception.Message

    Write-Utf8Lines `
        -Path (Join-Path $logRoot "direct-build-failure.txt") `
        -Lines @(
            ("Error: " + $message),
            ("Line: " + $_.InvocationInfo.ScriptLineNumber),
            "",
            "Position:",
            $_.InvocationInfo.PositionMessage,
            "",
            "Stack:",
            $_.ScriptStackTrace
        )

    $archive = $null

    try {
        $archive = Export-DirectBuildResult `
            -State "FAIL" `
            -FailureMessage $message
    }
    catch {
    }

    Write-Host ""
    Write-Host "SERPIUM_WFP4A_ROUTE_CORE_BUILD_FAILED" -ForegroundColor Red
    Write-Host $message -ForegroundColor Red

    if (-not [string]::IsNullOrWhiteSpace([string]$archive)) {
        Write-Host ("Result archive: " + $archive) -ForegroundColor Yellow
    }

    exit 1
}
