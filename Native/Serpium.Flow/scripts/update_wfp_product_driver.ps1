#requires -version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CurrentPackageRoot,
    [Parameter(Mandatory = $true)][string]$NewPackageRoot,
    [Parameter(Mandatory = $true)][ValidateSet("UPDATE")][string]$ConfirmUpdate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "wfp_driver_owner_common.ps1")

Assert-SerpiumWfpAdministrator

# New package must be proven production-trusted before touching the installed one.
$newTrust = Assert-SerpiumWfpProductionTrust -PackageRoot $NewPackageRoot
$currentDriver = Get-SerpiumWfpDriverCim

if ($null -eq $currentDriver) {
    & (Join-Path $PSScriptRoot "install_wfp_product_driver.ps1") `
        -PackageRoot $NewPackageRoot `
        -ConfirmInstall INSTALL
    exit $LASTEXITCODE
}

# Rollback is only promised if the current package still passes the same
# production-trust boundary.
$currentTrust = Assert-SerpiumWfpProductionTrust -PackageRoot $CurrentPackageRoot

try {
    & (Join-Path $PSScriptRoot "uninstall_wfp_product_driver.ps1") `
        -PackageRoot $CurrentPackageRoot `
        -ConfirmUninstall UNINSTALL

    & (Join-Path $PSScriptRoot "install_wfp_product_driver.ps1") `
        -PackageRoot $NewPackageRoot `
        -ConfirmInstall INSTALL

    Write-Host "SERPIUM_WFP_PRODUCT_DRIVER_UPDATE_PASS" -ForegroundColor Green
}
catch {
    $original = $_.Exception.Message
    Write-Warning "New WFP driver update failed. Attempting product-owned rollback."

    try {
        if ($null -ne (Get-SerpiumWfpDriverCim)) {
            & (Join-Path $PSScriptRoot "uninstall_wfp_product_driver.ps1") `
                -PackageRoot $NewPackageRoot `
                -ConfirmUninstall UNINSTALL
        }

        & (Join-Path $PSScriptRoot "install_wfp_product_driver.ps1") `
            -PackageRoot $CurrentPackageRoot `
            -ConfirmInstall INSTALL

        throw (
            "WFP driver update failed and previous production package was restored. " +
            "Original error: $original"
        )
    }
    catch {
        Write-SerpiumWfpDriverState `
            -State "RECOVERY_REQUIRED" `
            -PackageRoot $CurrentPackageRoot `
            -SignerThumbprint $currentTrust.Thumbprint `
            -Message (
                "Automatic rollback failed after update error. " +
                "Manual product recovery is required; no broad service deletion was attempted."
            )
        throw
    }
}
