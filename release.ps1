param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$')]
    [string]$Version,

    [string]$Runtime = "win-x64",

    [switch]$SelfContained,

    [switch]$PublishGitHub,

    [string]$GitHubRepo = "LegendaSeven/SerpiumVPN",

    [switch]$Draft
)

$ErrorActionPreference = "Stop"
if (Get-Variable PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectFile = Join-Path $ProjectRoot "SerpiumVPN.csproj"
$UpdaterProjectFile = Join-Path $ProjectRoot "SerpiumUpdater\SerpiumUpdater.csproj"
$PublishDir = Join-Path $ProjectRoot "publish\app"
$UpdaterPublishDir = Join-Path $ProjectRoot "publish\updater"
$ReleaseDir = Join-Path $ProjectRoot "publish\releases"
$InstallerDir = Join-Path $ProjectRoot "publish\installer"
$InstallerScript = Join-Path $ProjectRoot "installer\SerpiumVPN_Inno.iss"
if (-not (Test-Path $InstallerScript)) {
    $InstallerScript = Join-Path $ProjectRoot "SerpiumVPN_Inno.iss"
}
$ArchiveName = "SerpiumVPN-$Version.zip"
$ArchivePath = Join-Path $ReleaseDir $ArchiveName
$ManifestPath = Join-Path $ReleaseDir "update.json"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Assert-NativeSuccess {
    param([string]$CommandName)

    if ($LASTEXITCODE -ne 0) {
        throw "$CommandName failed with exit code $LASTEXITCODE."
    }
}

if (-not (Test-Path $ProjectFile)) {
    throw "Project file not found: $ProjectFile"
}

if (-not (Test-Path $UpdaterProjectFile)) {
    throw "Updater project file not found: $UpdaterProjectFile"
}

if ($PublishGitHub) {
    $ghCommand = Get-Command "gh" -ErrorAction SilentlyContinue
    if ($null -eq $ghCommand) {
        throw "GitHub CLI was not found. Install it from https://cli.github.com/ and run: gh auth login"
    }
}

Write-Step "Cleaning release folders"
foreach ($dir in @($PublishDir, $UpdaterPublishDir, $ReleaseDir, $InstallerDir)) {
    if (Test-Path $dir) {
        Remove-Item -LiteralPath $dir -Recurse -Force
    }

    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

$selfContainedValue = if ($SelfContained) { "true" } else { "false" }
$assemblyVersion = ($Version -split "-")[0]

Write-Step "Publishing SerpiumVPN $Version for $Runtime"
dotnet publish $ProjectFile `
    -c Release `
    -r $Runtime `
    --self-contained $selfContainedValue `
    -p:Version=$Version `
    -p:AssemblyVersion=$assemblyVersion `
    -p:FileVersion=$assemblyVersion `
    -o $PublishDir
Assert-NativeSuccess "dotnet publish SerpiumVPN"

Write-Step "Publishing updater as a standalone single file"
dotnet publish $UpdaterProjectFile `
    -c Release `
    -r $Runtime `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:DebugType=None `
    -p:DebugSymbols=false `
    -p:Version=$Version `
    -p:AssemblyVersion=$assemblyVersion `
    -p:FileVersion=$assemblyVersion `
    -o $UpdaterPublishDir
Assert-NativeSuccess "dotnet publish SerpiumUpdater"

$UpdaterExe = Join-Path $UpdaterPublishDir "SerpiumUpdater.exe"
if (-not (Test-Path $UpdaterExe)) {
    throw "Single-file updater was not created: $UpdaterExe"
}

Copy-Item -LiteralPath $UpdaterExe -Destination (Join-Path $PublishDir "SerpiumUpdater.exe") -Force

Write-Step "Packing zip update"
if (Test-Path $ArchivePath) {
    Remove-Item -LiteralPath $ArchivePath -Force
}

Compress-Archive -Path (Join-Path $PublishDir "*") -DestinationPath $ArchivePath -CompressionLevel Optimal

$sha256 = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
$tag = "v$Version"
$zipUrl = "https://github.com/$GitHubRepo/releases/download/$tag/$ArchiveName"

$manifest = [ordered]@{
    version = $Version
    zipUrl = $zipUrl
    sha256 = $sha256
    notes = "SerpiumVPN $Version"
}

$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $ManifestPath -Encoding UTF8

Write-Step "Building Inno Setup installer"

if (-not (Test-Path $InstallerScript)) {
    throw "Inno Setup script not found: $InstallerScript"
}

$isccCandidates = @(
    "D:\Program\Inno Setup 6\ISCC.exe",
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 6\ISCC.exe"
)

$compil32Candidates = @(
    "D:\Program\Inno Setup 6\Compil32.exe",
    "C:\Program Files (x86)\Inno Setup 6\Compil32.exe",
    "C:\Program Files\Inno Setup 6\Compil32.exe"
)

$isccPath = $isccCandidates |
    Where-Object { Test-Path $_ } |
    Select-Object -First 1

$compil32Path = $compil32Candidates |
    Where-Object { Test-Path $_ } |
    Select-Object -First 1

if ($isccPath) {
    Write-Host "Using ISCC: $isccPath"
    & $isccPath "/DMyAppVersion=$Version" $InstallerScript
    Assert-NativeSuccess "Inno Setup ISCC"
}
elseif ($compil32Path) {
    Write-Host "Using Compil32: $compil32Path"
    & $compil32Path /cc "/DMyAppVersion=$Version" $InstallerScript
    Assert-NativeSuccess "Inno Setup Compil32"
}
else {
    throw "Inno Setup compiler not found. Expected ISCC.exe or Compil32.exe in D:\Program\Inno Setup 6 or Program Files."
}

$rawInstaller = Join-Path $InstallerDir "SerpiumVPN_Setup.exe"
if (-not (Test-Path $rawInstaller)) {
    throw "Installer was not created: $rawInstaller"
}

$versionedInstallerName = "SerpiumVPN_Setup-$Version.exe"
$versionedInstallerPath = Join-Path $InstallerDir $versionedInstallerName
Move-Item -LiteralPath $rawInstaller -Destination $versionedInstallerPath -Force

# Put a copy next to update.zip/update.json so GitHub publishing uploads it too.
Copy-Item -LiteralPath $versionedInstallerPath `
    -Destination (Join-Path $ReleaseDir $versionedInstallerName) `
    -Force

Write-Step "Release files"
Get-ChildItem -LiteralPath $ReleaseDir -File | Select-Object Name, Length

Write-Host ""
if (-not $PublishGitHub) {
    Write-Host "Upload these files to GitHub Releases:" -ForegroundColor Green
    Write-Host $ReleaseDir
    Write-Host ""
    Write-Host "Or publish automatically with:" -ForegroundColor Green
    Write-Host ".\release.ps1 -Version $Version -SelfContained -PublishGitHub"
    return
}

$releaseFiles = @(Get-ChildItem -LiteralPath $ReleaseDir -File | ForEach-Object { $_.FullName })
if ($releaseFiles.Count -eq 0) {
    throw "No release files found in: $ReleaseDir"
}

$isPrerelease = $Version.Contains("-")

Write-Step "Publishing GitHub release $tag to $GitHubRepo"

& gh release view $tag --repo $GitHubRepo *> $null
$releaseExists = $LASTEXITCODE -eq 0

if ($releaseExists) {
    Write-Step "Release $tag exists. Uploading assets with overwrite"
    $ghArgs = @("release", "upload", $tag) + $releaseFiles + @("--repo", $GitHubRepo, "--clobber")
    & gh @ghArgs
}
else {
    $ghArgs = @(
        "release",
        "create",
        $tag
    ) + $releaseFiles + @(
        "--repo",
        $GitHubRepo,
        "--title",
        "SerpiumVPN $Version",
        "--notes",
        "SerpiumVPN $Version"
    )

    if ($isPrerelease) {
        $ghArgs += "--prerelease"
    }

    if ($Draft) {
        $ghArgs += "--draft"
    }

    & gh @ghArgs
}

if ($LASTEXITCODE -ne 0) {
    throw "GitHub release publishing failed."
}

Write-Host ""
Write-Host "GitHub release published: $tag" -ForegroundColor Green