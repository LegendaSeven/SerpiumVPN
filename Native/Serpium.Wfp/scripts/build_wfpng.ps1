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
$protocol = Join-Path $root "Serpium.Wfp.Protocol"
$driverDir = Join-Path $root "Serpium.Wfp.Driver"
$monitorDir = Join-Path $root "Serpium.Wfp.Monitor"

$artifactRoot = Join-Path $root ("artifacts\x64\" + $Configuration)
$driverOutDir = Join-Path $artifactRoot "driver"
$monitorOutDir = Join-Path $artifactRoot "monitor"
$packageDir = Join-Path $artifactRoot "package"
$objDir = Join-Path $root ("obj\x64\" + $Configuration)

Remove-Item -LiteralPath $artifactRoot -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $objDir -Recurse -Force -ErrorAction SilentlyContinue

New-Item -ItemType Directory -Path $driverOutDir,$monitorOutDir,$packageDir,$objDir -Force | Out-Null

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
    $bufferOverflow
)

foreach ($path in $required) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required tool/include/lib missing: $path"
    }
}

Write-Host "=== Serpium WFP CleanRoom P1 ===" -ForegroundColor Cyan
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

$driverObj = Join-Path $objDir "Serpium.Wfp.Driver.obj"
$driverSys = Join-Path $driverOutDir "Serpium.Wfp.Driver.sys"
$driverPdb = Join-Path $driverOutDir "Serpium.Wfp.Driver.pdb"

$driverArgs = @(
    "/nologo","/c","/TC","/W4","/WX-","/kernel","/GS","/Zl",
    "/Oi","/Gy","/Gw","/Zp8","/FC",
    "/D_AMD64_","/DAMD64","/D_WIN64","/DWIN64","/D_KERNEL_MODE",
    "/DUNICODE","/D_UNICODE",
    "/DWINVER=0x0A00","/D_WIN32_WINNT=0x0A00",
    "/DNTDDI_VERSION=0x0A000000","/DNDIS630=1",
    ("/DKMDF_VERSION_MAJOR=" + $kmdfMajor),
    ("/DKMDF_VERSION_MINOR=" + $kmdfMinor),
    ("/I" + $protocol),
    ("/I" + $wdfInclude),
    ("/I" + $shared),
    ("/I" + $km),
    ("/I" + $kmCrt),
    ("/Fo" + $driverObj)
)

if ($Configuration -eq "Release") {
    $driverArgs += @("/O2","/Ob2","/DNDEBUG")
} else {
    $driverArgs += @("/Od","/Zi","/DDBG=1")
}

$driverArgs += (Join-Path $driverDir "driver.c")
Invoke-Native $cl $driverArgs

$driverLink = @(
    "/NOLOGO",
    ("/OUT:" + $driverSys),
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
    $driverObj,
    (Join-Path $wdfLib "WdfDriverEntry.lib"),
    (Join-Path $wdfLib "WdfLdr.lib"),
    $bufferOverflow,
    (Join-Path $kmLib "ntoskrnl.lib"),
    (Join-Path $kmLib "hal.lib"),
    (Join-Path $kmLib "wmilib.lib"),
    (Join-Path $kmLib "fwpkclnt.lib"),
    (Join-Path $kmLib "ntstrsafe.lib")
)

Invoke-Native $link $driverLink

$monitorObj = Join-Path $objDir "Serpium.Wfp.Monitor.obj"
$monitorExe = Join-Path $monitorOutDir "Serpium.Wfp.Monitor.exe"
$monitorPdb = Join-Path $monitorOutDir "Serpium.Wfp.Monitor.pdb"

$monitorCompile = @(
    "/nologo","/c","/TP","/std:c++20","/EHsc","/W4","/WX-","/GS",
    "/Gy","/Gw","/FC","/MT","/DUNICODE","/D_UNICODE",
    ("/I" + $protocol),
    ("/I" + $msvcInclude),
    ("/I" + $shared),
    ("/I" + $um),
    ("/I" + $ucrt),
    ("/Fo" + $monitorObj)
)

if ($Configuration -eq "Release") {
    $monitorCompile += @("/O2","/Ob2","/DNDEBUG")
} else {
    $monitorCompile += @("/Od","/Zi","/D_DEBUG")
}

$monitorCompile += (Join-Path $monitorDir "monitor.cpp")
Invoke-Native $cl $monitorCompile

$monitorLink = @(
    "/NOLOGO",
    ("/OUT:" + $monitorExe),
    ("/PDB:" + $monitorPdb),
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
    $monitorObj,
    (Join-Path $msvcLib "libcmt.lib"),
    (Join-Path $msvcLib "libcpmt.lib"),
    (Join-Path $msvcLib "libvcruntime.lib"),
    (Join-Path $msvcLib "oldnames.lib"),
    (Join-Path $ucrtLib "libucrt.lib"),
    (Join-Path $umLib "kernel32.lib"),
    (Join-Path $umLib "user32.lib"),
    (Join-Path $umLib "advapi32.lib"),
    (Join-Path $umLib "ws2_32.lib"),
    (Join-Path $umLib "uuid.lib")
)

Invoke-Native $link $monitorLink

Copy-Item -LiteralPath $driverSys -Destination $packageDir -Force
Copy-Item -LiteralPath (Join-Path $driverDir "Serpium.Wfp.Driver.inf") -Destination $packageDir -Force
Copy-Item -LiteralPath $monitorExe -Destination $packageDir -Force

$manifest = [ordered]@{
    schema = 1
    component = "Serpium.Wfp"
    phase = "P1"
    mode = "event-driven-observe-only"
    protocol = "0x00010000"
    platform = "x64"
    configuration = $Configuration
    msvc = $msvc.Name
    wdk = $sdkVersion
    kmdf = $kmdfVersion
    layers = @(
        "ALE_AUTH_CONNECT_V4",
        "ALE_AUTH_CONNECT_V6",
        "ALE_FLOW_ESTABLISHED_V4",
        "ALE_FLOW_ESTABLISHED_V6"
    )
    transport = "blocking ReadFile; no polling"
    enforcement = $false
    files = @{}
}

foreach ($file in Get-ChildItem -LiteralPath $packageDir -File) {
    $manifest.files[$file.Name] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
}

$manifest |
    ConvertTo-Json -Depth 6 |
    Set-Content -LiteralPath (Join-Path $packageDir "BUILD_MANIFEST.json") -Encoding utf8

Write-Host ""
Write-Host "SERPIUM_WFP_CLEANROOM_P1_BUILD_PASS" -ForegroundColor Green
Write-Host "Package: $packageDir" -ForegroundColor Cyan
