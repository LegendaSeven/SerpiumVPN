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
$PublishDir = Join-Path $ProjectRoot "publish\app"
$ReleaseDir = Join-Path $ProjectRoot "publish\releases"
$MainExe = "SerpiumVPN.exe"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

if (-not (Test-Path $ProjectFile)) {
    throw "Project file not found: $ProjectFile"
}

$vpkCommand = Get-Command "vpk" -ErrorAction SilentlyContinue
if ($null -eq $vpkCommand) {
    throw "Velopack CLI was not found. Install it for release builds with: dotnet tool install -g vpk"
}

if ($PublishGitHub) {
    $ghCommand = Get-Command "gh" -ErrorAction SilentlyContinue
    if ($null -eq $ghCommand) {
        throw "GitHub CLI was not found. Install it from https://cli.github.com/ and run: gh auth login"
    }
}

Write-Step "Cleaning release folders"
if (Test-Path $PublishDir) {
    Remove-Item -LiteralPath $PublishDir -Recurse -Force
}

if (Test-Path $ReleaseDir) {
    Remove-Item -LiteralPath $ReleaseDir -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $PublishDir | Out-Null
New-Item -ItemType Directory -Force -Path $ReleaseDir | Out-Null

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

Write-Step "Packing Velopack release"
vpk pack `
    -u SerpiumVPN `
    -v $Version `
    -p $PublishDir `
    -e $MainExe `
    -o $ReleaseDir

Write-Step "Release files"
Get-ChildItem -LiteralPath $ReleaseDir -File | Select-Object Name, Length

Write-Host ""
if (-not $PublishGitHub) {
    Write-Host "Upload all files from this folder to GitHub Releases:" -ForegroundColor Green
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

$tag = "v$Version"
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
