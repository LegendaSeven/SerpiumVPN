#requires -version 5.1
[CmdletBinding()]
param(
    [string]$VisualStudioRoot = "D:\Program\Visual Studio\18",

    [ValidateSet("Debug","Release")]
    [string]$Configuration = "Release"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

try {
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
    $OutputEncoding = New-Object System.Text.UTF8Encoding($false)
} catch {}

$root = Split-Path -Parent $PSScriptRoot
$protocol = Join-Path $root "Serpium.SFP.Protocol"
$kernelDir = Join-Path $root "Serpium.SFP.Kernel"
$serviceDir = Join-Path $root "Serpium.SFP.Service"
$bridgeDir = Join-Path $root "Serpium.SFP.Bridge"
$runtimeDir = Join-Path $root "Serpium.SFP.Runtime"
$apiDir = Join-Path $root "Serpium.SFP.Api"
$cliDir = Join-Path $root "Serpium.SFP.Cli"

$artifactRoot = Join-Path $root ("artifacts\x64\" + $Configuration)
$kernelOutDir = Join-Path $artifactRoot "driver"
$serviceOutDir = Join-Path $artifactRoot "monitor"
$bridgeOutDir = Join-Path $artifactRoot "bridge"
$runtimeOutDir = Join-Path $artifactRoot "runtime"
$apiOutDir = Join-Path $artifactRoot "api"
$cliOutDir = Join-Path $artifactRoot "cli"
$packageDir = Join-Path $artifactRoot "package"
$objDir = Join-Path $root ("obj\x64\" + $Configuration)

Remove-Item -LiteralPath $artifactRoot -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $objDir -Recurse -Force -ErrorAction SilentlyContinue

New-Item -ItemType Directory -Path $kernelOutDir,$serviceOutDir,$bridgeOutDir,$runtimeOutDir,$apiOutDir,$cliOutDir,$packageDir,$objDir -Force | Out-Null

$msvcRoot = Join-Path $VisualStudioRoot "VC\Tools\MSVC"
if (-not (Test-Path -LiteralPath $msvcRoot -PathType Container)) {
    throw "MSVC root not found: $msvcRoot"
}

$msvc = Get-ChildItem -LiteralPath $msvcRoot -Directory |
    Sort-Object { [version]$_.Name } -Descending |
    Select-Object -First 1

if ($null -eq $msvc) {
    throw "MSVC toolset not found."
}

$toolBin = Join-Path $msvc.FullName "bin\Hostx64\x64"
$cl = Join-Path $toolBin "cl.exe"
$link = Join-Path $toolBin "link.exe"
$msvcInclude = Join-Path $msvc.FullName "include"

$kitsRoot = $null
foreach ($key in @(
    "HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots"
)) {
    try {
        $candidate = [string](Get-ItemProperty -LiteralPath $key -ErrorAction Stop).KitsRoot10
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and
            (Test-Path -LiteralPath $candidate -PathType Container)) {
            $kitsRoot = [IO.Path]::GetFullPath($candidate).TrimEnd("\")
            break
        }
    } catch {}
}

if ([string]::IsNullOrWhiteSpace($kitsRoot)) {
    $fallback = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10"
    if (Test-Path -LiteralPath $fallback -PathType Container) {
        $kitsRoot = $fallback
    }
}

if ([string]::IsNullOrWhiteSpace($kitsRoot)) {
    throw "Windows Kits root not found."
}

$sdkVersion = Get-ChildItem -LiteralPath (Join-Path $kitsRoot "Include") -Directory |
    Where-Object {
        Test-Path -LiteralPath (Join-Path $_.FullName "km\fwpsk.h") -PathType Leaf
    } |
    Sort-Object { [version]$_.Name } -Descending |
    Select-Object -ExpandProperty Name -First 1

if ([string]::IsNullOrWhiteSpace($sdkVersion)) {
    throw "WDK headers with fwpsk.h not found."
}

$kmdfBase = Join-Path $kitsRoot "Include\wdf\kmdf"
$kmdf = Get-ChildItem -LiteralPath $kmdfBase -Directory |
    Where-Object {
        Test-Path -LiteralPath (Join-Path $_.FullName "wdf.h") -PathType Leaf
    } |
    Sort-Object { [version]$_.Name } -Descending |
    Select-Object -First 1

if ($null -eq $kmdf) {
    throw "KMDF include not found."
}

$kmdfVersion = $kmdf.Name
$parts = $kmdfVersion.Split(".")
$kmdfMajor = [int]$parts[0]
$kmdfMinor = if ($parts.Count -gt 1) { [int]$parts[1] } else { 0 }

$shared = Join-Path $kitsRoot "Include\$sdkVersion\shared"
$km = Join-Path $kitsRoot "Include\$sdkVersion\km"
$kmCrt = Join-Path $kitsRoot "Include\$sdkVersion\km\crt"
$um = Join-Path $kitsRoot "Include\$sdkVersion\um"
$ucrt = Join-Path $kitsRoot "Include\$sdkVersion\ucrt"
$wdfInclude = $kmdf.FullName

$kmLib = Join-Path $kitsRoot "Lib\$sdkVersion\km\x64"
$umLib = Join-Path $kitsRoot "Lib\$sdkVersion\um\x64"
$ucrtLib = Join-Path $kitsRoot "Lib\$sdkVersion\ucrt\x64"
$wdfLib = Join-Path $kitsRoot "Lib\wdf\kmdf\x64\$kmdfVersion"
$msvcLib = Join-Path $msvc.FullName "lib\x64"

$bufferOverflow = Join-Path $kmLib "BufferOverflowFastFailK.lib"
if (-not (Test-Path -LiteralPath $bufferOverflow -PathType Leaf)) {
    $bufferOverflow = Join-Path $kmLib "BufferOverflowK.lib"
}

$required = @(
    $cl,$link,$shared,$km,$kmCrt,$um,$ucrt,$wdfInclude,
    $kmLib,$umLib,$ucrtLib,$wdfLib,$msvcInclude,$msvcLib,
    (Join-Path $kmLib "ntoskrnl.lib"),
    (Join-Path $kmLib "hal.lib"),
    (Join-Path $kmLib "wmilib.lib"),
    (Join-Path $kmLib "fwpkclnt.lib"),
    (Join-Path $kmLib "ntstrsafe.lib"),
    (Join-Path $wdfLib "WdfDriverEntry.lib"),
    (Join-Path $wdfLib "WdfLdr.lib"),
    (Join-Path $umLib "uuid.lib"),
    (Join-Path $umLib "fwpuclnt.lib"),
    (Join-Path $umLib "wintrust.lib"),
    (Join-Path $umLib "crypt32.lib"),
    $bufferOverflow
)

foreach ($path in $required) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required tool/include/lib missing: $path"
    }
}

Write-Host "=== Serpium SFP API v1 ===" -ForegroundColor Cyan
Write-Host "VS: $VisualStudioRoot"
Write-Host "MSVC: $($msvc.Name)"
Write-Host "WDK: $sdkVersion"
Write-Host "KMDF: $kmdfVersion"
Write-Host ""

function Invoke-Native {
    param(
        [string]$File,
        [string[]]$Arguments
    )

    Write-Host ($File + " " + ($Arguments -join " ")) -ForegroundColor DarkGray
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Native command failed with exit code $LASTEXITCODE"
    }
}

$kernelObj = Join-Path $objDir "Serpium.SFP.Kernel.obj"
$kernelSys = Join-Path $kernelOutDir "Serpium.SFP.Kernel.sys"
$kernelPdb = Join-Path $kernelOutDir "Serpium.SFP.Kernel.pdb"

$kernelArgs = @(
    "/nologo","/c","/TC","/W4","/WX-","/kernel","/GS","/Zl",
    "/Oi","/Gy","/Gw","/Zp8","/FC",
    "/D_AMD64_","/DAMD64","/D_WIN64","/DWIN64",
    "/DUNICODE","/D_UNICODE",
    "/DWINVER=0x0A00","/D_WIN32_WINNT=0x0A00",
    "/DNTDDI_VERSION=NTDDI_WIN10_VB","/DNDIS630=1",
    ("/DKMDF_VERSION_MAJOR=" + $kmdfMajor),
    ("/DKMDF_VERSION_MINOR=" + $kmdfMinor),
    ("/I" + $protocol),
    ("/I" + $wdfInclude),
    ("/I" + $shared),
    ("/I" + $km),
    ("/I" + $kmCrt),
    ("/Fo" + $kernelObj)
)

if ($Configuration -eq "Release") {
    $kernelArgs += @("/O2","/Ob2","/DNDEBUG")
} else {
    $kernelArgs += @("/Od","/Zi","/DDBG=1")
}

$kernelArgs += (Join-Path $kernelDir "driver.c")
Invoke-Native $cl $kernelArgs

$kernelLink = @(
    "/NOLOGO",
    ("/OUT:" + $kernelSys),
    ("/PDB:" + $kernelPdb),
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
    $kernelObj,
    (Join-Path $wdfLib "WdfDriverEntry.lib"),
    (Join-Path $wdfLib "WdfLdr.lib"),
    $bufferOverflow,
    (Join-Path $kmLib "ntoskrnl.lib"),
    (Join-Path $kmLib "hal.lib"),
    (Join-Path $kmLib "wmilib.lib"),
    (Join-Path $kmLib "fwpkclnt.lib"),
    (Join-Path $kmLib "ntstrsafe.lib")
)

Invoke-Native $link $kernelLink

$serviceObj = Join-Path $objDir "Serpium.SFP.Service.obj"
$serviceExe = Join-Path $serviceOutDir "Serpium.SFP.Service.exe"
$servicePdb = Join-Path $serviceOutDir "Serpium.SFP.Service.pdb"

$serviceCompile = @(
    "/nologo","/c","/TP","/std:c++20","/EHsc","/W4","/WX-","/GS",
    "/Gy","/Gw","/FC","/MT","/DUNICODE","/D_UNICODE",
    ("/I" + $protocol),
    ("/I" + $msvcInclude),
    ("/I" + $shared),
    ("/I" + $um),
    ("/I" + $ucrt),
    ("/Fo" + $serviceObj)
)

if ($Configuration -eq "Release") {
    $serviceCompile += @("/O2","/Ob2","/DNDEBUG")
} else {
    $serviceCompile += @("/Od","/Zi","/D_DEBUG")
}

$serviceCompile += (Join-Path $serviceDir "sfpctl.cpp")
Invoke-Native $cl $serviceCompile

$serviceLink = @(
    "/NOLOGO",
    ("/OUT:" + $serviceExe),
    ("/PDB:" + $servicePdb),
    ("/LIBPATH:" + $msvcLib),
    ("/LIBPATH:" + $ucrtLib),
    ("/LIBPATH:" + $umLib),
    "/MACHINE:X64",
    "/SUBSYSTEM:CONSOLE",
    "/INCREMENTAL:NO",
    "/DYNAMICBASE",
    "/NXCOMPAT",
    "/OPT:REF",
    "/OPT:ICF",
    $serviceObj,
    (Join-Path $msvcLib "libcmt.lib"),
    (Join-Path $msvcLib "libcpmt.lib"),
    (Join-Path $msvcLib "libvcruntime.lib"),
    (Join-Path $msvcLib "oldnames.lib"),
    (Join-Path $ucrtLib "libucrt.lib"),
    (Join-Path $umLib "kernel32.lib"),
    (Join-Path $umLib "user32.lib"),
    (Join-Path $umLib "advapi32.lib"),
    (Join-Path $umLib "ws2_32.lib"),
    (Join-Path $umLib "uuid.lib"),
    (Join-Path $umLib "fwpuclnt.lib")
)

Invoke-Native $link $serviceLink


$bridgeObj = Join-Path $objDir "Serpium.SFP.Bridge.obj"
$bridgeExe = Join-Path $bridgeOutDir "Serpium.SFP.Bridge.exe"
$bridgePdb = Join-Path $bridgeOutDir "Serpium.SFP.Bridge.pdb"

$bridgeCompile = @(
    "/nologo","/c","/TP","/std:c++20","/EHsc","/W4","/WX-","/GS",
    "/Gy","/Gw","/FC","/MT","/DUNICODE","/D_UNICODE",
    ("/I" + $protocol),
    ("/I" + $msvcInclude),
    ("/I" + $shared),
    ("/I" + $um),
    ("/I" + $ucrt),
    ("/Fo" + $bridgeObj)
)

if ($Configuration -eq "Release") {
    $bridgeCompile += @("/O2","/Ob2","/DNDEBUG")
} else {
    $bridgeCompile += @("/Od","/Zi","/D_DEBUG")
}

$bridgeCompile += (Join-Path $bridgeDir "bridge.cpp")
Invoke-Native $cl $bridgeCompile

$bridgeLink = @(
    "/NOLOGO",
    ("/OUT:" + $bridgeExe),
    ("/PDB:" + $bridgePdb),
    ("/LIBPATH:" + $msvcLib),
    ("/LIBPATH:" + $ucrtLib),
    ("/LIBPATH:" + $umLib),
    "/MACHINE:X64",
    "/SUBSYSTEM:CONSOLE",
    "/INCREMENTAL:NO",
    "/DYNAMICBASE",
    "/NXCOMPAT",
    "/OPT:REF",
    "/OPT:ICF",
    $bridgeObj,
    (Join-Path $msvcLib "libcmt.lib"),
    (Join-Path $msvcLib "libcpmt.lib"),
    (Join-Path $msvcLib "libvcruntime.lib"),
    (Join-Path $msvcLib "oldnames.lib"),
    (Join-Path $ucrtLib "libucrt.lib"),
    (Join-Path $umLib "kernel32.lib"),
    (Join-Path $umLib "advapi32.lib"),
    (Join-Path $umLib "ws2_32.lib")
)

Invoke-Native $link $bridgeLink


$runtimeObj = Join-Path $objDir "Serpium.SFP.Runtime.obj"
$runtimeExe = Join-Path $runtimeOutDir "Serpium.SFP.Runtime.exe"
$runtimePdb = Join-Path $runtimeOutDir "Serpium.SFP.Runtime.pdb"

$runtimeCompile = @(
    "/nologo","/c","/TP","/std:c++20","/EHsc","/W4","/WX-","/GS",
    "/Gy","/Gw","/FC","/MT","/DUNICODE","/D_UNICODE",
    ("/I" + $protocol),
    ("/I" + $msvcInclude),
    ("/I" + $shared),
    ("/I" + $um),
    ("/I" + $ucrt),
    ("/Fo" + $runtimeObj)
)

if ($Configuration -eq "Release") {
    $runtimeCompile += @("/O2","/Ob2","/DNDEBUG")
} else {
    $runtimeCompile += @("/Od","/Zi","/D_DEBUG")
}

$runtimeCompile += (Join-Path $runtimeDir "runtime.cpp")
Invoke-Native $cl $runtimeCompile

$runtimeLink = @(
    "/NOLOGO",
    ("/OUT:" + $runtimeExe),
    ("/PDB:" + $runtimePdb),
    ("/LIBPATH:" + $msvcLib),
    ("/LIBPATH:" + $ucrtLib),
    ("/LIBPATH:" + $umLib),
    "/MACHINE:X64",
    "/SUBSYSTEM:CONSOLE",
    "/INCREMENTAL:NO",
    "/DYNAMICBASE",
    "/NXCOMPAT",
    "/OPT:REF",
    "/OPT:ICF",
    $runtimeObj,
    (Join-Path $msvcLib "libcmt.lib"),
    (Join-Path $msvcLib "libcpmt.lib"),
    (Join-Path $msvcLib "libvcruntime.lib"),
    (Join-Path $msvcLib "oldnames.lib"),
    (Join-Path $ucrtLib "libucrt.lib"),
    (Join-Path $umLib "kernel32.lib"),
    (Join-Path $umLib "advapi32.lib"),
    (Join-Path $umLib "wintrust.lib"),
    (Join-Path $umLib "crypt32.lib")
)

Invoke-Native $link $runtimeLink


$apiObj = Join-Path $objDir "Serpium.SFP.Api.obj"
$apiExe = Join-Path $apiOutDir "Serpium.SFP.ApiHost.exe"
$apiPdb = Join-Path $apiOutDir "Serpium.SFP.ApiHost.pdb"

$apiCompile = @(
    "/nologo","/c","/TP","/std:c++20","/EHsc","/W4","/WX-","/GS",
    "/Gy","/Gw","/FC","/MT","/DUNICODE","/D_UNICODE",
    ("/I" + $protocol),
    ("/I" + $apiDir),
    ("/I" + $msvcInclude),
    ("/I" + $shared),
    ("/I" + $um),
    ("/I" + $ucrt),
    ("/Fo" + $apiObj)
)

if ($Configuration -eq "Release") {
    $apiCompile += @("/O2","/Ob2","/DNDEBUG")
} else {
    $apiCompile += @("/Od","/Zi","/D_DEBUG")
}

$apiCompile += (Join-Path $apiDir "api_host.cpp")
Invoke-Native $cl $apiCompile

$apiLink = @(
    "/NOLOGO",
    ("/OUT:" + $apiExe),
    ("/PDB:" + $apiPdb),
    ("/LIBPATH:" + $msvcLib),
    ("/LIBPATH:" + $ucrtLib),
    ("/LIBPATH:" + $umLib),
    "/MACHINE:X64",
    "/SUBSYSTEM:CONSOLE",
    "/INCREMENTAL:NO",
    "/DYNAMICBASE",
    "/NXCOMPAT",
    "/OPT:REF",
    "/OPT:ICF",
    $apiObj,
    (Join-Path $msvcLib "libcmt.lib"),
    (Join-Path $msvcLib "libcpmt.lib"),
    (Join-Path $msvcLib "libvcruntime.lib"),
    (Join-Path $msvcLib "oldnames.lib"),
    (Join-Path $ucrtLib "libucrt.lib"),
    (Join-Path $umLib "kernel32.lib"),
    (Join-Path $umLib "advapi32.lib"),
    (Join-Path $umLib "fwpuclnt.lib")
)

Invoke-Native $link $apiLink

$cliObj = Join-Path $objDir "Serpium.SFP.Cli.obj"
$cliExe = Join-Path $cliOutDir "Serpium.SFP.Cli.exe"
$cliPdb = Join-Path $cliOutDir "Serpium.SFP.Cli.pdb"

$cliCompile = @(
    "/nologo","/c","/TP","/std:c++20","/EHsc","/W4","/WX-","/GS",
    "/Gy","/Gw","/FC","/MT","/DUNICODE","/D_UNICODE",
    ("/I" + $protocol),
    ("/I" + $apiDir),
    ("/I" + $msvcInclude),
    ("/I" + $shared),
    ("/I" + $um),
    ("/I" + $ucrt),
    ("/Fo" + $cliObj)
)

if ($Configuration -eq "Release") {
    $cliCompile += @("/O2","/Ob2","/DNDEBUG")
} else {
    $cliCompile += @("/Od","/Zi","/D_DEBUG")
}

$cliCompile += (Join-Path $cliDir "cli.cpp")
Invoke-Native $cl $cliCompile

$cliLink = @(
    "/NOLOGO",
    ("/OUT:" + $cliExe),
    ("/PDB:" + $cliPdb),
    ("/LIBPATH:" + $msvcLib),
    ("/LIBPATH:" + $ucrtLib),
    ("/LIBPATH:" + $umLib),
    "/MACHINE:X64",
    "/SUBSYSTEM:CONSOLE",
    "/INCREMENTAL:NO",
    "/DYNAMICBASE",
    "/NXCOMPAT",
    "/OPT:REF",
    "/OPT:ICF",
    $cliObj,
    (Join-Path $msvcLib "libcmt.lib"),
    (Join-Path $msvcLib "libcpmt.lib"),
    (Join-Path $msvcLib "libvcruntime.lib"),
    (Join-Path $msvcLib "oldnames.lib"),
    (Join-Path $ucrtLib "libucrt.lib"),
    (Join-Path $umLib "kernel32.lib")
)

Invoke-Native $link $cliLink

Copy-Item -LiteralPath $kernelSys -Destination $packageDir -Force
Copy-Item -LiteralPath (Join-Path $kernelDir "Serpium.SFP.Kernel.inf") -Destination $packageDir -Force
Copy-Item -LiteralPath $serviceExe -Destination $packageDir -Force
Copy-Item -LiteralPath $bridgeExe -Destination $packageDir -Force
Copy-Item -LiteralPath $runtimeExe -Destination $packageDir -Force
Copy-Item -LiteralPath $apiExe -Destination $packageDir -Force
Copy-Item -LiteralPath $cliExe -Destination $packageDir -Force
Copy-Item -LiteralPath (Join-Path $root "Serpium.SFP.Client\SfpClient.cs") -Destination $packageDir -Force

$manifest = [ordered]@{
    schema = 1
    component = "Serpium.SFP"
    phase = "ApiV1"
    mode = "stable-user-mode-routing-api"
    protocol = "0x00010001"
    platform = "x64"
    configuration = $Configuration
    msvc = $msvc.Name
    wdk = $sdkVersion
    kmdf = $kmdfVersion
    minimumWindows = "Windows 10 version 2004 (NTDDI_WIN10_VB)"
    layers = @(
        "ALE_AUTH_CONNECT_V4",
        "ALE_AUTH_CONNECT_V6",
        "ALE_FLOW_ESTABLISHED_V4",
        "ALE_FLOW_ESTABLISHED_V6",
        "ALE_CONNECT_REDIRECT_V4",
        "ALE_CONNECT_REDIRECT_V6"
    )
    transport = "blocking ReadFile; no polling"
    routeDecision = $true
    routeRedirect = $true
    redirectTransport = "TCP -> local SFP Bridge -> SOCKS5 Relay"
    udpRedirect = $false
    kernelAbiFrozen = "0x00010001"
    runtimeLoadMode = "demand-start SCM; explicit user command only"
    signatureGate = "WinVerifyTrust + Windows kernel loader authority"
    bootConfigurationChanges = $false
    sfpApiVersion = "0x00010000"
    sfpApiPipe = "\\.\pipe\Serpium.SFP.v1"
    kernelSourceChanged = $false
    hardCutoverApi = $true
    policyPersistence = '%ProgramData%\Serpium\SFP\policy.state'
    staleFlowAbort = $true
    files = @{}
}

foreach ($file in Get-ChildItem -LiteralPath $packageDir -File) {
    $manifest.files[$file.Name] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
}

$manifest |
    ConvertTo-Json -Depth 6 |
    Set-Content -LiteralPath (Join-Path $packageDir "BUILD_MANIFEST.json") -Encoding utf8

Write-Host ""
Write-Host "SERPIUM_SFP_API_V1_BUILD_PASS" -ForegroundColor Green
Write-Host "Package: $packageDir" -ForegroundColor Cyan
