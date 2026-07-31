[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ProjectPath,

    [string]$ManifestPath,

    [string]$SerpiumRoot,

    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [bool]$CreateZip = $true,

    [switch]$IncludeSymbols
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

function Resolve-ExistingPath
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    if (-not (Test-Path -LiteralPath $Path))
    {
        throw "$Description was not found: $Path"
    }

    return (Resolve-Path -LiteralPath $Path).Path
}

function Find-SerpiumRoot
{
    param([Parameter(Mandatory = $true)][string]$StartDirectory)

    $cursor = Get-Item -LiteralPath $StartDirectory

    while ($null -ne $cursor)
    {
        if (Test-Path -LiteralPath (Join-Path $cursor.FullName "SerpiumVPN.csproj"))
        {
            return $cursor.FullName
        }

        $cursor = $cursor.Parent
    }

    throw "SerpiumVPN repository root was not found above '$StartDirectory'."
}

function Get-RequiredManifestProperty
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Manifest,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $property = $Manifest.PSObject.Properties[$Name]

    if ($null -eq $property -or $null -eq $property.Value)
    {
        throw "manifest.json property '$Name' is required."
    }

    return $property.Value
}

function Read-ContractInteger
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$ContractSource,

        [Parameter(Mandatory = $true)]
        [string]$ConstantName
    )

    $pattern = "public\s+const\s+int\s+" + [regex]::Escape($ConstantName) + "\s*=\s*(\d+)\s*;"
    $match = [regex]::Match($ContractSource, $pattern)

    if (-not $match.Success)
    {
        throw "Could not read EngineContract.$ConstantName from the SDK source."
    }

    return [int]$match.Groups[1].Value
}

function Invoke-DotNet
{
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    & dotnet @Arguments

    if ($LASTEXITCODE -ne 0)
    {
        throw "dotnet $($Arguments -join ' ') failed with exit code $LASTEXITCODE."
    }
}

$projectFullPath = Resolve-ExistingPath -Path $ProjectPath -Description "Engine project"
$projectDirectory = Split-Path -Parent $projectFullPath

if ([string]::IsNullOrWhiteSpace($ManifestPath))
{
    $ManifestPath = Join-Path $projectDirectory "manifest.json"
}

$manifestFullPath = Resolve-ExistingPath -Path $ManifestPath -Description "Engine manifest"

if ([string]::IsNullOrWhiteSpace($SerpiumRoot))
{
    $SerpiumRoot = Find-SerpiumRoot -StartDirectory $projectDirectory
}
else
{
    $SerpiumRoot = Resolve-ExistingPath -Path $SerpiumRoot -Description "SerpiumVPN repository root"
}

$hostProject = Join-Path $SerpiumRoot "SerpiumVPN.csproj"

if (-not (Test-Path -LiteralPath $hostProject))
{
    throw "The selected Serpium root does not contain SerpiumVPN.csproj: $SerpiumRoot"
}

$contractPath = Join-Path $SerpiumRoot "SDK\Serpium.Engine.Abstractions\EngineContract.cs"
$contractSource = Get-Content -LiteralPath (Resolve-ExistingPath -Path $contractPath -Description "Engine contract") -Raw
$requiredSchemaVersion = Read-ContractInteger -ContractSource $contractSource -ConstantName "ManifestSchemaVersion"
$requiredApiVersion = Read-ContractInteger -ContractSource $contractSource -ConstantName "ApiVersion"

$manifestJson = Get-Content -LiteralPath $manifestFullPath -Raw
$manifest = $manifestJson | ConvertFrom-Json

$schemaVersion = [int](Get-RequiredManifestProperty -Manifest $manifest -Name "schemaVersion")
$engineId = [string](Get-RequiredManifestProperty -Manifest $manifest -Name "id")
$apiVersion = [int](Get-RequiredManifestProperty -Manifest $manifest -Name "apiVersion")
$assembly = [string](Get-RequiredManifestProperty -Manifest $manifest -Name "assembly")
$entryType = [string](Get-RequiredManifestProperty -Manifest $manifest -Name "entryType")

if ($schemaVersion -ne $requiredSchemaVersion)
{
    throw "Unsupported manifest schemaVersion '$schemaVersion'. Required: $requiredSchemaVersion."
}

if ($apiVersion -ne $requiredApiVersion)
{
    throw "Incompatible manifest apiVersion '$apiVersion'. Required: $requiredApiVersion."
}

if ($engineId -notmatch '^[A-Za-z0-9._-]{1,100}$')
{
    throw "manifest.json id may contain only letters, digits, '.', '-' and '_' and must be 1-100 characters long."
}

if ([string]::IsNullOrWhiteSpace($entryType))
{
    throw "manifest.json entryType cannot be empty."
}

if ([System.IO.Path]::IsPathRooted($assembly) -or $assembly -match '(^|[\\/])\.\.([\\/]|$)')
{
    throw "manifest.json assembly must be a safe path inside the engine package."
}

if (-not $assembly.EndsWith(".dll", [System.StringComparison]::OrdinalIgnoreCase))
{
    throw "manifest.json assembly must point to a DLL file."
}

Write-Host "Building engine '$engineId'..." -ForegroundColor Cyan

Invoke-DotNet -Arguments @(
    "build",
    $projectFullPath,
    "-c", $Configuration,
    "-p:SerpiumRoot=$SerpiumRoot"
)

$targetPathOutput = & dotnet msbuild $projectFullPath `
    "-getProperty:TargetPath" `
    "-p:Configuration=$Configuration" `
    "-p:SerpiumRoot=$SerpiumRoot" `
    "-nologo"

if ($LASTEXITCODE -ne 0)
{
    throw "Could not resolve the engine TargetPath. Exit code: $LASTEXITCODE"
}

$targetPath = $targetPathOutput |
    Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
    Select-Object -Last 1

$targetPath = ([string]$targetPath).Trim()

if (-not [System.IO.Path]::IsPathRooted($targetPath))
{
    $targetPath = Join-Path $projectDirectory $targetPath
}

$targetPath = Resolve-ExistingPath -Path $targetPath -Description "Built engine assembly"
$targetDirectory = Split-Path -Parent $targetPath
$targetFileName = Split-Path -Leaf $targetPath
$manifestAssemblyName = Split-Path -Leaf $assembly

if (-not [string]::Equals($targetFileName, $manifestAssemblyName, [System.StringComparison]::OrdinalIgnoreCase))
{
    throw "The built assembly '$targetFileName' does not match manifest.json assembly '$manifestAssemblyName'."
}

$packageDirectory = Join-Path (Join-Path $SerpiumRoot "Engines") $engineId
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("SerpiumEnginePackage_" + [Guid]::NewGuid().ToString("N"))
$stagingPackage = Join-Path $temporaryRoot $engineId
$stagingRuntime = Join-Path $stagingPackage "Runtime"

try
{
    New-Item -ItemType Directory -Path $stagingRuntime -Force | Out-Null

    $files = Get-ChildItem -LiteralPath $targetDirectory -Recurse -File

    foreach ($file in $files)
    {
        if (-not $IncludeSymbols -and $file.Extension -ieq ".pdb")
        {
            continue
        }

        if ($file.Name -like "Serpium.Engine.Abstractions.*")
        {
            continue
        }

        $relativePath = $file.FullName.Substring($targetDirectory.Length).TrimStart('\', '/')
        $destination = Join-Path $stagingRuntime $relativePath
        $destinationDirectory = Split-Path -Parent $destination

        New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $destination -Force
    }

    $stagedMainAssembly = Join-Path $stagingRuntime $targetFileName

    if (-not (Test-Path -LiteralPath $stagedMainAssembly))
    {
        throw "The main engine assembly was not copied into the package."
    }

    $manifest.assembly = ("Runtime/" + $targetFileName)
    $manifest | ConvertTo-Json -Depth 20 |
        Set-Content -LiteralPath (Join-Path $stagingPackage "manifest.json") -Encoding utf8

    if (Test-Path -LiteralPath $packageDirectory)
    {
        Remove-Item -LiteralPath $packageDirectory -Recurse -Force
    }

    New-Item -ItemType Directory -Path (Split-Path -Parent $packageDirectory) -Force | Out-Null
    Move-Item -LiteralPath $stagingPackage -Destination $packageDirectory

    $zipPath = $null

    if ($CreateZip)
    {
        $packagesDirectory = Join-Path $SerpiumRoot "SDK\Packages"
        New-Item -ItemType Directory -Path $packagesDirectory -Force | Out-Null

        $version = "1.0.0"
        $versionProperty = $manifest.PSObject.Properties["version"]

        if ($null -ne $versionProperty -and -not [string]::IsNullOrWhiteSpace([string]$versionProperty.Value))
        {
            $version = [string]$versionProperty.Value
        }

        $safeVersion = $version -replace '[^A-Za-z0-9._-]', '_'
        $zipPath = Join-Path $packagesDirectory ("$engineId-v$safeVersion.zip")

        Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue
        Compress-Archive -LiteralPath $packageDirectory -DestinationPath $zipPath -Force
    }

    Write-Host ""
    Write-Host "Engine package installed successfully." -ForegroundColor Green
    Write-Host "Package: $packageDirectory"

    if ($null -ne $zipPath)
    {
        Write-Host "Archive: $zipPath"
    }

    Write-Host "Restart SerpiumVPN to let DynamicEngineLoader discover '$engineId'."
}
finally
{
    if (Test-Path -LiteralPath $temporaryRoot)
    {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
