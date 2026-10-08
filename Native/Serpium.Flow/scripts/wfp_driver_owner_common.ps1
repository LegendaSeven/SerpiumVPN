#requires -version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:SerpiumWfpServiceName = "SerpiumFlow"
$script:SerpiumWfpProtocolAbi = "0x00040000"
$script:SerpiumWfpStateRoot = Join-Path $env:ProgramData "SerpiumVPN\WFP"
$script:SerpiumWfpStatePath = Join-Path $script:SerpiumWfpStateRoot "driver-state.json"

function Get-SerpiumWfpSignTool {
    $roots = @(
        (Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"),
        (Join-Path $env:ProgramFiles "Windows Kits\10\bin")
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) }

    $candidates = foreach ($root in $roots) {
        Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending |
            ForEach-Object {
                Join-Path $_.FullName "x64\signtool.exe"
            }
    }

    $path = @($candidates | Where-Object {
        Test-Path -LiteralPath $_ -PathType Leaf
    } | Select-Object -First 1)

    if ($path.Count -ne 1) {
        throw "Windows SDK signtool.exe x64 not found."
    }

    return $path[0]
}

function Get-SerpiumWfpRuntimeManifest {
    param([Parameter(Mandatory = $true)][string]$PackageRoot)

    $manifestPath = Join-Path $PackageRoot "WFP_RUNTIME_MANIFEST.json"
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "WFP_RUNTIME_MANIFEST.json not found: $manifestPath"
    }

    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ([int]$manifest.schema -ne 1) {
        throw "Unsupported WFP runtime manifest schema: $($manifest.schema)"
    }
    if ([string]$manifest.protocolAbi -ne $script:SerpiumWfpProtocolAbi) {
        throw "Unsupported WFP ABI: $($manifest.protocolAbi)"
    }
    if ([string]$manifest.platform -ne "x64") {
        throw "Unsupported WFP platform: $($manifest.platform)"
    }

    return $manifest
}

function Assert-SerpiumWfpPackageHashes {
    param([Parameter(Mandatory = $true)][string]$PackageRoot)

    $manifest = Get-SerpiumWfpRuntimeManifest -PackageRoot $PackageRoot
    $required = @(
        "Serpium.Flow.Service.exe",
        "Serpium.Flow.Driver.sys",
        "Serpium.Flow.Driver.inf",
        "serpium.flow.driver.cat",
        "BUILD_MANIFEST.json"
    )

    foreach ($name in $required) {
        $entry = @($manifest.files | Where-Object {
            [string]$_.name -ieq $name
        } | Select-Object -First 1)

        if ($entry.Count -ne 1) {
            throw "WFP manifest missing $name"
        }

        $path = Join-Path $PackageRoot $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "WFP package missing $name"
        }

        $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        $expected = ([string]$entry[0].sha256).ToLowerInvariant()
        if ($actual -ne $expected) {
            throw "WFP package hash mismatch: $name"
        }
    }

    return $manifest
}

function Invoke-SerpiumSignToolVerify {
    param(
        [Parameter(Mandatory = $true)][string]$SignTool,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $output = & $SignTool @Arguments 2>&1
    $exit = $LASTEXITCODE

    if ($exit -ne 0) {
        $detail = ($output | Select-Object -Last 12) -join [Environment]::NewLine
        throw "$Label failed with exit code $exit.`n$detail"
    }

    return @($output)
}

function Assert-SerpiumWfpMicrosoftDriverTripletTrust {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$PackageRoot)

    $cat = Join-Path $PackageRoot "serpium.flow.driver.cat"
    $sys = Join-Path $PackageRoot "Serpium.Flow.Driver.sys"
    $inf = Join-Path $PackageRoot "Serpium.Flow.Driver.inf"

    foreach ($requiredPath in @($cat, $sys, $inf)) {
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
            throw "Microsoft-signed WFP driver triplet is incomplete: $requiredPath"
        }
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $cat
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate) {
        throw "WFP catalog does not have a valid trusted Authenticode signature."
    }

    $certificate = $signature.SignerCertificate
    $signerText = (
        [string]$certificate.Subject + " " +
        [string]$certificate.Issuer
    )

    if ($signerText -notmatch '(?i)\bMicrosoft\b') {
        throw (
            "WFP catalog is trusted locally but is not Microsoft production-signed. " +
            "Import the package returned by Windows Hardware Partner Center."
        )
    }

    if ([string]$certificate.Subject -eq [string]$certificate.Issuer) {
        throw "Self-signed WFP catalog certificates are not accepted for production."
    }

    $signTool = Get-SerpiumWfpSignTool

    [void](Invoke-SerpiumSignToolVerify `
        -SignTool $signTool `
        -Arguments @("verify","/v","/pa",$cat) `
        -Label "Catalog Authenticode verification")

    [void](Invoke-SerpiumSignToolVerify `
        -SignTool $signTool `
        -Arguments @("verify","/v","/kp","/c",$cat,$sys) `
        -Label "Kernel-policy SYS/catalog verification")

    [void](Invoke-SerpiumSignToolVerify `
        -SignTool $signTool `
        -Arguments @("verify","/v","/pa","/c",$cat,$inf) `
        -Label "INF/catalog verification")

    return [pscustomobject]@{
        State = "MICROSOFT_DRIVER_TRIPLET_VERIFIED"
        ProtocolAbi = $script:SerpiumWfpProtocolAbi
        SignerSubject = [string]$certificate.Subject
        SignerIssuer = [string]$certificate.Issuer
        Thumbprint = [string]$certificate.Thumbprint
        Catalog = $cat
        Sys = $sys
        Inf = $inf
    }
}

function Assert-SerpiumWfpProductionTrust {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$PackageRoot)

    [void](Assert-SerpiumWfpPackageHashes -PackageRoot $PackageRoot)
    $triplet = Assert-SerpiumWfpMicrosoftDriverTripletTrust -PackageRoot $PackageRoot

    return [pscustomobject]@{
        State = "PRODUCTION_VERIFIED"
        ProtocolAbi = $script:SerpiumWfpProtocolAbi
        SignerSubject = [string]$triplet.SignerSubject
        SignerIssuer = [string]$triplet.SignerIssuer
        Thumbprint = [string]$triplet.Thumbprint
        Catalog = [string]$triplet.Catalog
    }
}

function Assert-SerpiumWfpAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Administrator privileges are required for WFP driver ownership operations."
    }
}

function Get-SerpiumWfpDriverCim {
    return Get-CimInstance Win32_SystemDriver `
        -Filter "Name='$($script:SerpiumWfpServiceName)'" `
        -ErrorAction SilentlyContinue
}

function Write-SerpiumWfpDriverState {
    param(
        [Parameter(Mandatory = $true)][string]$State,
        [Parameter(Mandatory = $true)][string]$PackageRoot,
        [string]$SignerThumbprint = "",
        [string]$Message = ""
    )

    New-Item -ItemType Directory -Path $script:SerpiumWfpStateRoot -Force | Out-Null

    $manifestPath = Join-Path $PackageRoot "WFP_RUNTIME_MANIFEST.json"
    $manifestHash = if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
        (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    } else {
        ""
    }

    $record = [ordered]@{
        schema = 1
        owner = "SerpiumVPN"
        serviceName = $script:SerpiumWfpServiceName
        protocolAbi = $script:SerpiumWfpProtocolAbi
        state = $State
        packageRoot = [IO.Path]::GetFullPath($PackageRoot)
        runtimeManifestSha256 = $manifestHash
        signerThumbprint = $SignerThumbprint
        message = $Message
        updatedAtUtc = [DateTime]::UtcNow.ToString("o")
    }

    $record |
        ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath $script:SerpiumWfpStatePath -Encoding utf8
}

function Read-SerpiumWfpDriverState {
    if (-not (Test-Path -LiteralPath $script:SerpiumWfpStatePath -PathType Leaf)) {
        return $null
    }

    try {
        return Get-Content -LiteralPath $script:SerpiumWfpStatePath -Raw | ConvertFrom-Json
    } catch {
        return [pscustomobject]@{
            schema = 0
            owner = "UNKNOWN"
            state = "CORRUPT"
            message = $_.Exception.Message
        }
    }
}
