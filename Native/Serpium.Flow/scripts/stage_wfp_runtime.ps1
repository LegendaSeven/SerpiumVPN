#requires -version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Root,
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$package = Join-Path $Root ("Native\Serpium.Flow\artifacts\x64\" + $Configuration + "\package")
$destinationParent = Join-Path $Root "bin_files\wfp"
$destination = Join-Path $destinationParent "x64"
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$stage = Join-Path $destinationParent (".stage-" + $stamp)
$previous = Join-Path $destinationParent (".previous-" + $stamp)

$required = @(
    "Serpium.Flow.Service.exe",
    "Serpium.Flow.Driver.sys",
    "Serpium.Flow.Driver.inf",
    "serpium.flow.driver.cat",
    "BUILD_MANIFEST.json"
)

if (-not (Test-Path -LiteralPath $package -PathType Container)) {
    throw "Native WFP package not found: $package"
}

foreach ($name in $required) {
    $path = Join-Path $package $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Native WFP package is incomplete: $name"
    }
}

$nativeManifestPath = Join-Path $package "BUILD_MANIFEST.json"
$nativeManifest = Get-Content -LiteralPath $nativeManifestPath -Raw | ConvertFrom-Json
if (-not $nativeManifest.wfpEnabled) {
    throw "Native manifest says wfpEnabled=false."
}
if ([string]$nativeManifest.protocolVersion -ne "0x00040000") {
    throw "Unexpected WFP ABI: $($nativeManifest.protocolVersion)"
}
if ([string]$nativeManifest.platform -ne "x64") {
    throw "Unexpected WFP platform: $($nativeManifest.platform)"
}

New-Item -ItemType Directory -Path $destinationParent -Force | Out-Null
Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $previous -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $stage -Force | Out-Null

foreach ($name in $required) {
    Copy-Item -LiteralPath (Join-Path $package $name) -Destination (Join-Path $stage $name) -Force
}

$projectVersion = "unknown"
$projectFile = Join-Path $Root "SerpiumVPN.csproj"
if (Test-Path -LiteralPath $projectFile -PathType Leaf) {
    [xml]$projectXml = Get-Content -LiteralPath $projectFile -Raw
    $versionNode = @($projectXml.Project.PropertyGroup.Version | Where-Object { $_ } | Select-Object -First 1)
    if ($versionNode.Count -gt 0) {
        $projectVersion = [string]$versionNode[0]
    }
}

$files = foreach ($name in $required) {
    $filePath = Join-Path $stage $name
    [ordered]@{
        name = $name
        sha256 = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash.ToLowerInvariant()
        size = (Get-Item -LiteralPath $filePath).Length
    }
}

$runtimeManifest = [ordered]@{
    schema = 1
    owner = "SerpiumVPN"
    component = "Serpium.Flow"
    productVersion = $projectVersion
    protocolAbi = "0x00040000"
    platform = "x64"
    sourceBuildMode = [string]$nativeManifest.buildMode
    sourceWfpMode = [string]$nativeManifest.wfpMode
    generatedAtUtc = [DateTime]::UtcNow.ToString("o")
    installState = "PACKAGED_NOT_INSTALLED"
    signingState = "UNCHANGED"
    files = @($files)
}

$runtimeManifest |
    ConvertTo-Json -Depth 6 |
    Set-Content -LiteralPath (Join-Path $stage "WFP_RUNTIME_MANIFEST.json") -Encoding utf8

if (Test-Path -LiteralPath $destination -PathType Container) {
    Move-Item -LiteralPath $destination -Destination $previous
}

try {
    Move-Item -LiteralPath $stage -Destination $destination
}
catch {
    if ((Test-Path -LiteralPath $previous -PathType Container) -and
        -not (Test-Path -LiteralPath $destination)) {
        Move-Item -LiteralPath $previous -Destination $destination
    }
    throw
}

Remove-Item -LiteralPath $previous -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "WFP runtime packaged: $destination" -ForegroundColor Cyan
Write-Host "SERPIUM_WFP_RUNTIME_STAGE_PASS" -ForegroundColor Green
