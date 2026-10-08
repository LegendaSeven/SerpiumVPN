#requires -version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PackageRoot,
    [Parameter(Mandatory = $true)][ValidateSet("UNINSTALL")][string]$ConfirmUninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "wfp_driver_owner_common.ps1")

Assert-SerpiumWfpAdministrator

$state = Read-SerpiumWfpDriverState
if ($null -eq $state) {
    throw (
        "Serpium WFP ownership state is absent. " +
        "Refusing to delete a driver service that cannot be proven to be product-owned."
    )
}
if ([string]$state.owner -ne "SerpiumVPN" -or
    [string]$state.serviceName -ne $script:SerpiumWfpServiceName -or
    [string]$state.protocolAbi -ne $script:SerpiumWfpProtocolAbi) {
    throw "WFP ownership state does not match this product/ABI."
}

$driver = Get-SerpiumWfpDriverCim
if ($null -eq $driver) {
    Write-SerpiumWfpDriverState `
        -State "NOT_INSTALLED" `
        -PackageRoot $PackageRoot `
        -Message "Driver service already absent during controlled uninstall."
    Write-Host "SERPIUM_WFP_PRODUCT_DRIVER_UNINSTALL_PASS" -ForegroundColor Green
    exit 0
}

$expectedSuffix = "\System32\drivers\Serpium.Flow.Driver.sys"
$pathName = ([string]$driver.PathName).Trim('"')
if ($pathName -notlike "*$expectedSuffix") {
    throw (
        "SerpiumFlow service exists but its binary path is unexpected. " +
        "Refusing product cleanup: $pathName"
    )
}

$inf = Join-Path $PackageRoot "Serpium.Flow.Driver.inf"
$arguments = @(
    "setupapi.dll,InstallHinfSection",
    "DefaultUninstall",
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
    throw "SetupAPI DefaultUninstall failed with exit code $($process.ExitCode)."
}

Start-Sleep -Milliseconds 350
if ($null -ne (Get-SerpiumWfpDriverCim)) {
    throw "SerpiumFlow driver service remains after controlled uninstall."
}

Write-SerpiumWfpDriverState `
    -State "NOT_INSTALLED" `
    -PackageRoot $PackageRoot `
    -Message "Controlled production driver uninstall completed."

Write-Host "SERPIUM_WFP_PRODUCT_DRIVER_UNINSTALL_PASS" -ForegroundColor Green
