#requires -version 5.1
[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Warning "WFP-1 legacy signing entry point redirected to the safe WFP-1.1 staging workflow."
& (Join-Path $PSScriptRoot "prepare_wfp11_test_package.ps1") -Configuration $Configuration

