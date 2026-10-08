#requires -version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PackageRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "wfp_driver_owner_common.ps1")

$state = Read-SerpiumWfpDriverState
$driver = Get-SerpiumWfpDriverCim

if ($null -eq $state -and $null -eq $driver) {
    [pscustomobject]@{
        State = "NOT_INSTALLED"
        Owned = $true
        ServicePresent = $false
        Action = "NONE"
    } | Format-List
    exit 0
}

if ($null -eq $state -and $null -ne $driver) {
    [pscustomobject]@{
        State = "ORPHANED_NOT_TOUCHED"
        Owned = $false
        ServicePresent = $true
        Action = "REFUSE_AUTOMATIC_DELETE"
    } | Format-List
    exit 2
}

if ($null -ne $state -and $null -eq $driver) {
    Write-SerpiumWfpDriverState `
        -State "NOT_INSTALLED" `
        -PackageRoot $PackageRoot `
        -Message "Ownership state existed but driver service is absent."
    [pscustomobject]@{
        State = "NOT_INSTALLED"
        Owned = $true
        ServicePresent = $false
        Action = "STATE_REPAIRED"
    } | Format-List
    exit 0
}

[pscustomobject]@{
    State = [string]$state.state
    Owned = (
        [string]$state.owner -eq "SerpiumVPN" -and
        [string]$state.serviceName -eq $script:SerpiumWfpServiceName
    )
    ServicePresent = $true
    ServiceState = [string]$driver.State
    StartMode = [string]$driver.StartMode
    PathName = [string]$driver.PathName
    Action = "NONE"
} | Format-List
