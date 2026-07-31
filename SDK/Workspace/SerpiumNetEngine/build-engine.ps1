[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [switch]$IncludeSymbols,

    [switch]$NoZip
)

$ErrorActionPreference = "Stop"

$project = Join-Path $PSScriptRoot "Serpium.SerpiumNet.Engine.csproj"
$manifest = Join-Path $PSScriptRoot "manifest.json"

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

& $packager `
    -ProjectPath $project `
    -ManifestPath $manifest `
    -SerpiumRoot $serpiumRoot `
    -Configuration $Configuration `
    -IncludeSymbols:$IncludeSymbols `
    -CreateZip:(-not $NoZip)
