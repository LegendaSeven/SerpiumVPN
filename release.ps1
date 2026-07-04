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

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectFile = Join-Path $ProjectRoot "SerpiumVPN.csproj"
$UpdaterProjectFile = Join-Path $ProjectRoot "SerpiumUpdater\SerpiumUpdater.csproj"
$PublishDir = Join-Path $ProjectRoot "publish\app"
$UpdaterPublishDir = Join-Path $ProjectRoot "publish\updater"
$ReleaseDir = Join-Path $ProjectRoot "publish\releases"
$ArchiveName = "SerpiumVPN-$Version.zip"
$ArchivePath = Join-Path $ReleaseDir $ArchiveName
$ManifestPath = Join-Path $ReleaseDir "update.json"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
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
foreach ($dir in @($PublishDir, $UpdaterPublishDir, $ReleaseDir)) {
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

Write-Step "Publishing updater"
dotnet publish $UpdaterProjectFile `
    -c Release `
    -r $Runtime `
    --self-contained $selfContainedValue `
    -p:Version=$Version `
    -p:AssemblyVersion=$assemblyVersion `
    -p:FileVersion=$assemblyVersion `
    -o $UpdaterPublishDir

Copy-Item -LiteralPath (Join-Path $UpdaterPublishDir "SerpiumUpdater.exe") -Destination (Join-Path $PublishDir "SerpiumUpdater.exe") -Force
Get-ChildItem -LiteralPath $UpdaterPublishDir -Filter "SerpiumUpdater.*" -File | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $PublishDir $_.Name) -Force
}

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
