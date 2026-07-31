[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$templatePath = Join-Path $root "SDK\Templates\Serpium.Engine"

if (-not (Test-Path -LiteralPath (Join-Path $templatePath ".template.config\template.json")))
{
    throw "Serpium engine template was not found: $templatePath"
}

& dotnet new install $templatePath --force

if ($LASTEXITCODE -ne 0)
{
    throw "dotnet new failed to install the Serpium engine template. Exit code: $LASTEXITCODE"
}

Write-Host ""
Write-Host "Serpium engine template installed." -ForegroundColor Green
Write-Host "Create an engine with:"
Write-Host "  dotnet new serpium-engine -n MyEngine"
