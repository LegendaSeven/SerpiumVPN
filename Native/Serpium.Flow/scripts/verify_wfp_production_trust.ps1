#requires -version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PackageRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "wfp_driver_owner_common.ps1")

$result = Assert-SerpiumWfpProductionTrust -PackageRoot $PackageRoot
$result | Format-List

Write-Host "SERPIUM_WFP_PRODUCTION_TRUST_PASS" -ForegroundColor Green
