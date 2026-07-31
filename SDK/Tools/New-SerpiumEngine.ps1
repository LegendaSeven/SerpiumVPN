[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z_][A-Za-z0-9_.]*$')]
    [string]$Name,

    [ValidatePattern('^[A-Za-z0-9._-]{1,100}$')]
    [string]$Id,

    [switch]$Force
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$templatePath = Join-Path $root "SDK\Templates\Serpium.Engine"
$workspace = Join-Path $root "SDK\Workspace"
$target = Join-Path $workspace $Name

if ((Test-Path -LiteralPath $target) -and -not $Force)
{
    throw "Engine source directory already exists: $target. Use -Force to replace it."
}

New-Item -ItemType Directory -Path $workspace -Force | Out-Null

& dotnet new install $templatePath --force

if ($LASTEXITCODE -ne 0)
{
    throw "Could not install or update the serpium-engine template. Exit code: $LASTEXITCODE"
}

$newArguments = @("new", "serpium-engine", "-n", $Name, "-o", $target)

if ($Force)
{
    $newArguments += "--force"
}

& dotnet @newArguments

if ($LASTEXITCODE -ne 0)
{
    throw "Could not create engine '$Name'. Exit code: $LASTEXITCODE"
}

if (-not [string]::IsNullOrWhiteSpace($Id))
{
    $manifestPath = Join-Path $target "manifest.json"
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $manifest.id = $Id
    $manifest | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $manifestPath -Encoding utf8
}

Write-Host ""
Write-Host "Engine source created:" -ForegroundColor Green
Write-Host "  $target"
Write-Host ""
Write-Host "Build and install it with:"
Write-Host "  & '$target\build-engine.ps1'"
