#requires -version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("ENABLE")]
    [string]$ConfirmEnable
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Warning "WFP-1 legacy test-signing entry point redirected to the guarded WFP-1.1 workflow."
& (Join-Path $PSScriptRoot "enable_wfp11_testsigning.ps1") -ConfirmEnable $ConfirmEnable

