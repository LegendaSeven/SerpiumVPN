#requires -version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("CLEANUP")]
    [string]$ConfirmCleanup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Warning "WFP-1 legacy uninstall entry point redirected to ownership-checked WFP-1.1 cleanup."
& (Join-Path $PSScriptRoot "cleanup_wfp11.ps1") -ConfirmCleanup $ConfirmCleanup

