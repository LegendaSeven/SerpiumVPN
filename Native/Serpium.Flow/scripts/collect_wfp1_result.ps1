#requires -version 5.1
[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Warning "WFP-1 legacy collector redirected to the read-only WFP-1.1 preflight collector."
& (Join-Path $PSScriptRoot "preflight_wfp11.ps1") -Configuration $Configuration

