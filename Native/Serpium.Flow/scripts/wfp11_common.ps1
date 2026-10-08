#requires -version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:Wfp11DriverServiceName = "SerpiumFlow"
$script:Wfp11UserServiceName = "SerpiumFlowService"
$script:Wfp11CertificatePrefix = "CN=Serpium Flow WFP11 Test Signing"

function Write-Wfp11Utf8File {
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

function Write-Wfp11JsonFile {
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

function Invoke-Wfp11Native {
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
        Write-Wfp11Utf8File -Path $LogPath -Lines $logLines
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

function Assert-Wfp11Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $administrator = [Security.Principal.WindowsBuiltInRole]::Administrator

    if (-not $principal.IsInRole($administrator)) {
        throw "This WFP-1.1 stage must run from PowerShell started as Administrator."
    }
}

function Get-Wfp11FlowRoot {
    return (Split-Path -Parent $PSScriptRoot)
}

function Get-Wfp11UnsignedPackageDirectory {
    param(
        [ValidateSet("Debug", "Release")]
        [string]$Configuration = "Release"
    )

    return (Join-Path (Get-Wfp11FlowRoot) ("artifacts\x64\" + $Configuration + "\package"))
}

function Get-Wfp11SignedPackageDirectory {
    param(
        [ValidateSet("Debug", "Release")]
        [string]$Configuration = "Release"
    )

    return (Join-Path (Get-Wfp11FlowRoot) ("artifacts\x64\" + $Configuration + "\wfp11-signed-package"))
}

function Get-Wfp11StatePath {
    return (Join-Path (Get-Wfp11FlowRoot) "artifacts\wfp11\state.json")
}

function Get-Wfp11State {
    $path = Get-Wfp11StatePath

    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return $null
    }

    return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json)
}

function Save-Wfp11State {
    param(
        [Parameter(Mandatory = $true)]
        [object]$State
    )

    Write-Wfp11JsonFile -Path (Get-Wfp11StatePath) -Value $State -Depth 8
}

function Get-Wfp11KitsRoot {
    $path = "HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots"
    $root = (Get-ItemProperty -LiteralPath $path -ErrorAction Stop).KitsRoot10

    if ([string]::IsNullOrWhiteSpace([string]$root)) {
        throw "KitsRoot10 is missing from the Windows Kits registry entry."
    }

    return ([IO.Path]::GetFullPath([string]$root).TrimEnd("\"))
}

function Find-Wfp11SdkTool {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [AllowNull()]
        [string]$PreferredVersion
    )

    $kitsRoot = Get-Wfp11KitsRoot
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

function Get-Wfp11BuildManifest {
    param(
        [ValidateSet("Debug", "Release")]
        [string]$Configuration = "Release"
    )

    $path = Join-Path (Get-Wfp11UnsignedPackageDirectory -Configuration $Configuration) "BUILD_MANIFEST.json"

    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "WFP-1 build manifest is missing: $path"
    }

    return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json)
}

function Test-Wfp11UnsignedPackage {
    param(
        [ValidateSet("Debug", "Release")]
        [string]$Configuration = "Release"
    )

    $package = Get-Wfp11UnsignedPackageDirectory -Configuration $Configuration
    $manifest = Get-Wfp11BuildManifest -Configuration $Configuration

    foreach ($name in @(
        "Serpium.Flow.Driver.sys",
        "Serpium.Flow.Driver.inf",
        "Serpium.Flow.Driver.cat",
        "Serpium.Flow.Service.exe",
        "BUILD_MANIFEST.json"
    )) {
        $path = Join-Path $package $name

        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Required WFP-1 package file is missing: $path"
        }
    }

    if ([bool]$manifest.wfpEnabled) {
        throw "BUILD_MANIFEST.json reports wfpEnabled=true. WFP-1.1 must not load a filtering driver."
    }

    if ([version]([string]$manifest.kmdfVersion) -gt [version]"1.33") {
        throw "WFP-1.1 package is bound to KMDF $($manifest.kmdfVersion). Rebuild with the patched KMDF 1.33 compatibility target."
    }

    $checks = @(
        [pscustomobject]@{
            Name = "Serpium.Flow.Driver.sys"
            Expected = [string]$manifest.package.driverSha256
        },
        [pscustomobject]@{
            Name = "Serpium.Flow.Driver.cat"
            Expected = [string]$manifest.package.catalogSha256
        },
        [pscustomobject]@{
            Name = "Serpium.Flow.Service.exe"
            Expected = [string]$manifest.package.serviceSha256
        }
    )

    foreach ($check in $checks) {
        $path = Join-Path $package $check.Name
        $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash

        if ($actual -ine $check.Expected) {
            throw "Build manifest hash mismatch for $($check.Name)."
        }
    }

    return [pscustomobject]@{
        PackageDirectory = $package
        Manifest = $manifest
    }
}

function Get-Wfp11SecureBootState {
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

function Get-Wfp11MemoryIntegrityState {
    try {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
        $value = (Get-ItemProperty -LiteralPath $path -ErrorAction Stop).Enabled
        return $(if ($value -eq 1) { "Enabled" } else { "Disabled" })
    }
    catch {
        return "Unknown"
    }
}

function Get-Wfp11CodeIntegrityState {
    if ($null -eq ("Serpium.Wfp11.NativeMethods" -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace Serpium.Wfp11
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

    $information = New-Object Serpium.Wfp11.SystemCodeIntegrityInformation
    $length = [Runtime.InteropServices.Marshal]::SizeOf($information)
    $information.Length = [uint32]$length
    $status = [Serpium.Wfp11.NativeMethods]::NtQuerySystemInformation(
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

function Get-Wfp11BcdTestSigningState {
    $bcdedit = Join-Path $env:SystemRoot "System32\bcdedit.exe"
    $result = Invoke-Wfp11Native -FilePath $bcdedit -Arguments @("/enum") -LogPath $null -AllowFailure

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

function Get-Wfp11DriverService {
    return @(
        Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name='SerpiumFlow'" -ErrorAction SilentlyContinue
    ) | Select-Object -First 1
}

function Get-Wfp11UserService {
    return @(
        Get-CimInstance -ClassName Win32_Service -Filter "Name='SerpiumFlowService'" -ErrorAction SilentlyContinue
    ) | Select-Object -First 1
}

function Assert-Wfp11ServicesAbsent {
    if ($null -ne (Get-Wfp11DriverService)) {
        throw "Service SerpiumFlow already exists. Run the WFP-1.1 cleanup stage or inspect it manually."
    }

    if ($null -ne (Get-Wfp11UserService)) {
        throw "Service SerpiumFlowService already exists. Run the WFP-1.1 cleanup stage or inspect it manually."
    }
}

function Wait-Wfp11ServiceState {
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

    do {
        $record = if ($Kind -eq "Driver") { Get-Wfp11DriverService } else { Get-Wfp11UserService }

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

function Get-Wfp11WfpNameSummary {
    $temp = Join-Path $env:TEMP ("Serpium_WFP11_WfpState_" + [guid]::NewGuid().ToString("N") + ".xml")
    $netsh = Join-Path $env:SystemRoot "System32\netsh.exe"

    try {
        $result = Invoke-Wfp11Native -FilePath $netsh -Arguments @("wfp", "show", "state", ("file=" + $temp)) -LogPath $null -AllowFailure

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

function Get-Wfp11StaticMarkerSummary {
    $flowRoot = Get-Wfp11FlowRoot
    $paths = @(
        (Join-Path $flowRoot "Serpium.Flow.Driver\driver.c"),
        (Join-Path $flowRoot "Serpium.Flow.Driver\driver.h"),
        (Join-Path $flowRoot "Serpium.Flow.Service\service.cpp"),
        (Join-Path $flowRoot "Serpium.Flow.Protocol\serpium_flow_protocol.h")
    )
    $pattern = '\b(Fwps|Fwpm)[A-Za-z0-9_]*\s*\('
    $matches = @()

    foreach ($path in $paths) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $matches += @(Select-String -LiteralPath $path -Pattern $pattern -AllMatches)
        }
    }

    return [pscustomobject]@{
        MatchCount = $matches.Count
        Detail = $(if ($matches.Count -eq 0) { "No WFP registration API calls in collected sources" } else { "WFP registration API markers found" })
    }
}

function Remove-Wfp11CertificateByThumbprint {
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

function New-Wfp11ResultArchive {
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
