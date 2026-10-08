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

$flowRoot = Split-Path -Parent $PSScriptRoot
$driverProject = Join-Path $flowRoot "Serpium.Flow.Driver\Serpium.Flow.Driver.vcxproj"
$serviceProject = Join-Path $flowRoot "Serpium.Flow.Service\Serpium.Flow.Service.vcxproj"
$artifactRoot = Join-Path $flowRoot ("artifacts\x64\" + $Configuration)
$logRoot = Join-Path $flowRoot "logs"

New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
Remove-Item -LiteralPath $artifactRoot -Recurse -Force -ErrorAction SilentlyContinue

function Invoke-Logged {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )

    $oldPreference = $ErrorActionPreference

    try {
        $ErrorActionPreference = "Continue"
        $output = @(& $FilePath @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $oldPreference
    }

    [IO.File]::WriteAllLines(
        $LogPath,
        [string[]]$output,
        (New-Object Text.UTF8Encoding($false))
    )

    $output | ForEach-Object { Write-Host ([string]$_) }

    if ($exitCode -ne 0) {
        throw "Команда завершилась с кодом $exitCode. Лог: $LogPath"
    }
}

$msbuildCandidates = @(
    (Join-Path $VisualStudioRoot "MSBuild\Current\Bin\MSBuild.exe"),
    (Join-Path $VisualStudioRoot "MSBuild\17.0\Bin\MSBuild.exe")
)

$msbuild = $msbuildCandidates |
    Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
    Select-Object -First 1

if ($null -eq $msbuild) {
    throw "MSBuild.exe не найден в $VisualStudioRoot"
}

$kitsRoot = (Get-ItemProperty `
    "HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots" `
    -ErrorAction Stop).KitsRoot10

$latestSdk = Get-ChildItem `
    (Join-Path $kitsRoot "Include") `
    -Directory `
    -ErrorAction Stop |
    Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
    Sort-Object { [version]$_.Name } -Descending |
    Select-Object -First 1

if ($null -eq $latestSdk) {
    throw "Windows SDK/WDK version не найдена."
}

$targetVersion = $latestSdk.Name

Write-Host ""
Write-Host "=== WFP-1 BUILD ===" -ForegroundColor Cyan
Write-Host "MSBuild: $msbuild" -ForegroundColor DarkCyan
Write-Host "WindowsTargetPlatformVersion: $targetVersion" -ForegroundColor DarkCyan
Write-Host ""

Invoke-Logged `
    -FilePath $msbuild `
    -Arguments @(
        $driverProject,
        "/m",
        "/t:Rebuild",
        "/p:Configuration=$Configuration",
        "/p:Platform=x64",
        "/p:WindowsTargetPlatformVersion=$targetVersion",
        "/nologo"
    ) `
    -LogPath (Join-Path $logRoot "driver-build.log")

Invoke-Logged `
    -FilePath $msbuild `
    -Arguments @(
        $serviceProject,
        "/m",
        "/t:Rebuild",
        "/p:Configuration=$Configuration",
        "/p:Platform=x64",
        "/p:WindowsTargetPlatformVersion=$targetVersion",
        "/nologo"
    ) `
    -LogPath (Join-Path $logRoot "service-build.log")

$driverOutput = Join-Path $artifactRoot "driver\Serpium.Flow.Driver.sys"
$serviceOutput = Join-Path $artifactRoot "service\Serpium.Flow.Service.exe"

foreach ($required in @($driverOutput, $serviceOutput)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Ожидаемый артефакт не найден: $required"
    }
}

$packageDir = Join-Path $artifactRoot "package"
Remove-Item -LiteralPath $packageDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $packageDir -Force | Out-Null

Copy-Item $driverOutput (Join-Path $packageDir "Serpium.Flow.Driver.sys") -Force
Copy-Item $serviceOutput (Join-Path $packageDir "Serpium.Flow.Service.exe") -Force
Copy-Item `
    (Join-Path $flowRoot "Serpium.Flow.Driver\Serpium.Flow.Driver.inf") `
    (Join-Path $packageDir "Serpium.Flow.Driver.inf") `
    -Force

$inf2cat = Get-ChildItem `
    (Join-Path $kitsRoot "bin") `
    -Recurse `
    -File `
    -Filter "Inf2Cat.exe" `
    -ErrorAction Stop |
    Where-Object { $_.FullName -match '\\x86\\Inf2Cat\.exe$' } |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1

if ($null -eq $inf2cat) {
    throw "Inf2Cat.exe x86 не найден."
}

Invoke-Logged `
    -FilePath $inf2cat.FullName `
    -Arguments @(
        "/driver:$packageDir",
        "/os:10_X64",
        "/verbose"
    ) `
    -LogPath (Join-Path $logRoot "inf2cat.log")

$catPath = Join-Path $packageDir "Serpium.Flow.Driver.cat"

if (-not (Test-Path -LiteralPath $catPath -PathType Leaf)) {
    throw "Inf2Cat не создал Serpium.Flow.Driver.cat"
}

Write-Host ""
Write-Host "SERPIUM_WFP1_BUILD_PASS" -ForegroundColor Green
Write-Host "Package: $packageDir" -ForegroundColor Cyan
