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

Write-Warning "WFP-1 status-only test is superseded by the isolated WFP-1.1 lifecycle test."
& (Join-Path $PSScriptRoot "test_wfp11_lifecycle.ps1") -Configuration $Configuration -ConfirmLifecycle $ConfirmLifecycle

