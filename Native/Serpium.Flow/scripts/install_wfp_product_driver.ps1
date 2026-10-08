#requires -version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PackageRoot,
    [Parameter(Mandatory = $true)][ValidateSet("INSTALL")][string]$ConfirmInstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "wfp_driver_owner_common.ps1")

Assert-SerpiumWfpAdministrator
$trust = Assert-SerpiumWfpProductionTrust -PackageRoot $PackageRoot

$current = Get-SerpiumWfpDriverCim
if ($null -ne $current) {
    throw (
        "SerpiumFlow driver service already exists. " +
        "Use the controlled update/uninstall workflow instead of overwriting it."
    )
}

$inf = Join-Path $PackageRoot "Serpium.Flow.Driver.inf"
$arguments = @(
    "setupapi.dll,InstallHinfSection",
    "DefaultInstall",
    "132",
    $inf
)

$process = Start-Process `
    -FilePath (Join-Path $env:SystemRoot "System32\rundll32.exe") `
    -ArgumentList $arguments `
    -Wait `
    -PassThru `
    -WindowStyle Hidden

if ($process.ExitCode -ne 0) {
    throw "SetupAPI DefaultInstall failed with exit code $($process.ExitCode)."
}

Start-Sleep -Milliseconds 350
$installed = Get-SerpiumWfpDriverCim
if ($null -eq $installed) {
    throw "SetupAPI returned success but SerpiumFlow driver service was not created."
}

Write-SerpiumWfpDriverState `
    -State "INSTALLED_STOPPED" `
    -PackageRoot $PackageRoot `
    -SignerThumbprint $trust.Thumbprint `
    -Message "Production-trusted driver package installed. Demand-start driver was not started."

Write-Host "SERPIUM_WFP_PRODUCT_DRIVER_INSTALL_PASS" -ForegroundColor Green
