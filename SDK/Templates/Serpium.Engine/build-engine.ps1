[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [switch]$IncludeSymbols,

    [switch]$NoZip
)

$ErrorActionPreference = "Stop"

$project = Get-ChildItem -LiteralPath $PSScriptRoot -Filter *.csproj -File |
    Select-Object -First 1

if ($null -eq $project)
{
    throw "No engine .csproj was found in '$PSScriptRoot'."
}

$cursor = Get-Item -LiteralPath $PSScriptRoot
$serpiumRoot = $null

while ($null -ne $cursor)
{
    if (Test-Path -LiteralPath (Join-Path $cursor.FullName "SerpiumVPN.csproj"))
    {
        $serpiumRoot = $cursor.FullName
        break
    }

    $cursor = $cursor.Parent
}

if ([string]::IsNullOrWhiteSpace($serpiumRoot))
{
    throw "SerpiumVPN repository root was not found above '$PSScriptRoot'."
}

$packager = Join-Path $serpiumRoot "SDK\Tools\Build-SerpiumEngine.ps1"

if (-not (Test-Path -LiteralPath $packager))
{
    throw "Serpium engine packager was not found: $packager"
}

$arguments = @{
    ProjectPath = $project.FullName
    ManifestPath = (Join-Path $PSScriptRoot "manifest.json")
    SerpiumRoot = $serpiumRoot
    Configuration = $Configuration
    IncludeSymbols = $IncludeSymbols
    CreateZip = (-not $NoZip)
}

& $packager @arguments
