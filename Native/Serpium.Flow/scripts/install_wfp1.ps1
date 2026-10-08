#requires -version 5.1
[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [Parameter(Mandatory = $true)]
    [ValidateSet("RUN")]
    [string]$ConfirmLifecycle
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Warning "Persistent WFP-1 installation is disabled. Running the isolated install/test/uninstall WFP-1.1 lifecycle."
& (Join-Path $PSScriptRoot "test_wfp11_lifecycle.ps1") -Configuration $Configuration -ConfirmLifecycle $ConfirmLifecycle

