param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+(\.\d+)?(-[0-9A-Za-z.-]+)?$')]
    [string]$Version,

    [string]$Runtime = "win-x64",

    [switch]$SelfContained,

    [switch]$PublishGitHub,

    [string]$GitHubRepo = "LegendaSeven/SerpiumVPN",

    [string]$InnoCompiler,

    [string]$VisualStudioRoot = "D:\Program\Visual Studio\18",

    [ValidateSet("PackagedOnly", "RequireProductionTrust")]
    [string]$WfpDriverReleaseMode = "PackagedOnly",

    [switch]$Draft,

    [switch]$PublishOnly,

    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$TargetCommit,

    [string]$NotesFile
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
$WfpBuildScript = Join-Path $ProjectRoot "Native\Serpium.Flow\scripts\build_wfp1.ps1"
$WfpStageScript = Join-Path $ProjectRoot "Native\Serpium.Flow\scripts\stage_wfp_runtime.ps1"
$WfpRuntimeDir = Join-Path $ProjectRoot "bin_files\wfp\x64"
$WfpRuntimeManifest = Join-Path $WfpRuntimeDir "WFP_RUNTIME_MANIFEST.json"
$WfpProductionTrustScript = Join-Path $ProjectRoot "Native\Serpium.Flow\scripts\verify_wfp_production_trust.ps1"
$WfpProductionStageScript = Join-Path $ProjectRoot "Native\Serpium.Flow\scripts\stage_wfp_production_runtime.ps1"
$WfpProductionSignedRoot = Join-Path $ProjectRoot "Native\Serpium.Flow\production\x64\current"
$WfpProductQaScript = Join-Path $ProjectRoot "qa-wfp-product.ps1"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}


function Assert-ReleaseProcessesIdle {
    # A build must not kill an active user connection.
    $prefix = [IO.Path]::GetFullPath($ProjectRoot).TrimEnd('\') + '\'
    foreach ($process in @(Get-Process -Name 'SerpiumVPN','xray','xray-key-client','sing-box' -ErrorAction SilentlyContinue)) {
        if ($process.Path -and $process.Path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Close the project application before release: $($process.ProcessName), PID $($process.Id)."
        }
    }
}

function Assert-ReleaseOutputPath([string]$Path) {
    $prefix = [IO.Path]::GetFullPath((Join-Path $ProjectRoot 'publish')).TrimEnd('\') + '\'
    $full = [IO.Path]::GetFullPath($Path)
    if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Release output escapes publish directory: $full"
    }
    $current = $full
    while ($current.Length -ge $prefix.TrimEnd('\').Length) {
        if ((Test-Path -LiteralPath $current) -and
            ((Get-Item -LiteralPath $current).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Release output must not use a junction/symlink: $current"
        }
        $current = Split-Path -Parent $current
    }
}

function Get-Sha256Lower {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-WfpRuntimePackage {
    param([Parameter(Mandatory = $true)][string]$RuntimeDir)

    $manifestPath = Join-Path $RuntimeDir "WFP_RUNTIME_MANIFEST.json"
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "WFP runtime manifest not found: $manifestPath"
    }

    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ([int]$manifest.schema -ne 1) {
        throw "Unsupported WFP runtime manifest schema: $($manifest.schema)"
    }
    if ([string]$manifest.protocolAbi -ne "0x00040000") {
        throw "Unexpected WFP ABI: $($manifest.protocolAbi)"
    }
    if ([string]$manifest.platform -ne "x64") {
        throw "Unexpected WFP platform: $($manifest.platform)"
    }

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
            throw "WFP runtime manifest is missing $name"
        }

        $path = Join-Path $RuntimeDir $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "WFP runtime payload is missing $name"
        }

        $actual = Get-Sha256Lower -Path $path
        $expected = ([string]$entry[0].sha256).ToLowerInvariant()
        if ($actual -ne $expected) {
            throw "WFP runtime hash mismatch: $name"
        }
    }

    return $manifest
}

function Assert-WfpPublishedTree {
    param([Parameter(Mandatory = $true)][string]$PublishRoot)
    return Assert-WfpRuntimePackage -RuntimeDir (
        Join-Path $PublishRoot "bin_files\\wfp\\x64"
    )
}

function Assert-WfpZipPayload {
    param([Parameter(Mandatory = $true)][string]$ZipPath)

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($ZipPath)

    try {
        $expected = @(
            "bin_files/wfp/x64/WFP_RUNTIME_MANIFEST.json",
            "bin_files/wfp/x64/Serpium.Flow.Service.exe",
            "bin_files/wfp/x64/Serpium.Flow.Driver.sys",
            "bin_files/wfp/x64/Serpium.Flow.Driver.inf",
            "bin_files/wfp/x64/serpium.flow.driver.cat",
            "bin_files/wfp/x64/BUILD_MANIFEST.json"
        )

        $names = @($archive.Entries | ForEach-Object {
            $_.FullName.Replace("\\", "/")
        })

        foreach ($entry in $expected) {
            if ($names -notcontains $entry) {
                throw "Release ZIP is missing WFP payload entry: $entry"
            }
        }
    }
    finally {
        $archive.Dispose()
    }
}

function Assert-InnoOwnsPublishedWfp {
    param([Parameter(Mandatory = $true)][string]$ScriptPath)

    $content = [IO.File]::ReadAllText($ScriptPath).Replace("/", "\\")

    $explicitWfp = [regex]::IsMatch(
        $content,
        '(?im)^\s*Source\s*:\s*"[^"]*bin_files\\wfp\\(?:x64\\)?\*"')

    $recursivePublish = [regex]::IsMatch(
        $content,
        '(?im)^\s*Source\s*:\s*"[^"]*publish\\app\\\*"[^\r\n]*recursesubdirs')

    if (-not ($explicitWfp -or $recursivePublish)) {
        throw (
            "Inno Setup script does not prove ownership of the published WFP " +
            "payload. Add explicit bin_files\\wfp\\x64 or recursive publish\\app."
        )
    }
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

if (-not (Test-Path -LiteralPath $WfpProductQaScript -PathType Leaf)) {
    throw "WFP product QA script not found: $WfpProductQaScript"
}

if ($PublishGitHub) {
    $ghCommand = Get-Command "gh" -ErrorAction SilentlyContinue
    if ($null -eq $ghCommand) {
        throw "GitHub CLI was not found. Install it from https://cli.github.com/ and run: gh auth login"
    }
}

if ($PublishOnly -and -not $PublishGitHub) { throw 'PublishOnly requires PublishGitHub.' }
if ($PublishGitHub -and [string]::IsNullOrWhiteSpace($TargetCommit)) { throw 'TargetCommit must identify the checked source commit on GitHub.' }
$tag = "v$Version"
$ChecksumsPath = Join-Path $ProjectRoot 'publish/release-checksums.json'

if (-not $PublishOnly) {
Write-Step "Running consolidated WFP source QA"
& $WfpProductQaScript `
    -Root $ProjectRoot `
    -Phase Source `
    -ExpectedVersion $Version `
    -NoArchive

Assert-ReleaseProcessesIdle

Write-Step "Cleaning release folders"
foreach ($dir in @($PublishDir, $UpdaterPublishDir, $ReleaseDir, $InstallerDir)) {
    Assert-ReleaseOutputPath $dir
    if (Test-Path $dir) {
        Remove-Item -LiteralPath $dir -Recurse -Force
    }

    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

$selfContainedValue = if ($SelfContained) { "true" } else { "false" }
$assemblyVersion = ($Version -split "-")[0]

Write-Step "Building product-owned WFP runtime"

if (-not (Test-Path -LiteralPath $WfpBuildScript -PathType Leaf)) {
    throw "WFP build script not found: $WfpBuildScript"
}
if (-not (Test-Path -LiteralPath $WfpStageScript -PathType Leaf)) {
    throw "WFP stage script not found: $WfpStageScript"
}

& $WfpBuildScript `
    -VisualStudioRoot $VisualStudioRoot `
    -Configuration Release
Assert-NativeSuccess "Serpium WFP native build"

& $WfpStageScript `
    -Root $ProjectRoot `
    -Configuration Release
Assert-NativeSuccess "Serpium WFP runtime stage"

$wfpManifest = Assert-WfpRuntimePackage -RuntimeDir $WfpRuntimeDir
Write-Host (
    "WFP runtime ready: ABI=" +
    [string]$wfpManifest.protocolAbi +
    "; files=" +
    @($wfpManifest.files).Count
)

$wfpDriverTrustState = "PACKAGED_ONLY"
if ($WfpDriverReleaseMode -eq "RequireProductionTrust") {
    if (-not (Test-Path -LiteralPath $WfpProductionStageScript -PathType Leaf)) {
        throw "WFP production runtime stage script not found: $WfpProductionStageScript"
    }
    if (-not (Test-Path -LiteralPath $WfpProductionTrustScript -PathType Leaf)) {
        throw "WFP production trust verifier not found: $WfpProductionTrustScript"
    }

    & $WfpProductionStageScript `
        -Root $ProjectRoot `
        -Configuration Release `
        -ProductionSignedRoot $WfpProductionSignedRoot
    Assert-NativeSuccess "Serpium WFP production runtime stage"

    & $WfpProductionTrustScript -PackageRoot $WfpRuntimeDir
    Assert-NativeSuccess "Serpium WFP production trust verification"
    $wfpDriverTrustState = "PRODUCTION_VERIFIED"
}

Write-Step "Running consolidated WFP runtime QA"
& $WfpProductQaScript `
    -Root $ProjectRoot `
    -Phase Runtime `
    -NoArchive

Write-Step "Publishing SerpiumVPN $Version for $Runtime"
dotnet publish $ProjectFile `
    -c Release `
    -r $Runtime `
    --self-contained $selfContainedValue `
    -p:DebugType=None `
    -p:DebugSymbols=false `
    -p:ContinuousIntegrationBuild=true `
    "-p:PathMap=$ProjectRoot=/_/SerpiumVPN" `
    -p:Version=$Version `
    -p:AssemblyVersion=$assemblyVersion `
    -p:FileVersion=$assemblyVersion `
    -p:InformationalVersion=$Version `
    -p:IncludeSourceRevisionInInformationalVersion=false `
    -o $PublishDir
Assert-NativeSuccess "dotnet publish SerpiumVPN"

$publishedWfpManifest = Assert-WfpPublishedTree -PublishRoot $PublishDir
Write-Host (
    "Published WFP runtime verified: " +
    [string]$publishedWfpManifest.protocolAbi
)

Write-Step "Publishing updater as a standalone single file"
dotnet publish $UpdaterProjectFile `
    -c Release `
    -r $Runtime `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:DebugType=None `
    -p:DebugSymbols=false `
    -p:ContinuousIntegrationBuild=true `
    "-p:PathMap=$ProjectRoot=/_/SerpiumVPN" `
    -p:Version=$Version `
    -p:AssemblyVersion=$assemblyVersion `
    -p:FileVersion=$assemblyVersion `
    -p:InformationalVersion=$Version `
    -p:IncludeSourceRevisionInInformationalVersion=false `
    -o $UpdaterPublishDir
Assert-NativeSuccess "dotnet publish SerpiumUpdater"

$UpdaterExe = Join-Path $UpdaterPublishDir "SerpiumUpdater.exe"
if (-not (Test-Path $UpdaterExe)) {
    throw "Single-file updater was not created: $UpdaterExe"
}

Copy-Item -LiteralPath $UpdaterExe -Destination (Join-Path $PublishDir "SerpiumUpdater.exe") -Force

Write-Step "Running consolidated publish payload QA"
& $WfpProductQaScript `
    -Root $ProjectRoot `
    -Phase Published `
    -PublishRoot $PublishDir `
    -NoArchive

Write-Step "Packing zip update"
if (Test-Path $ArchivePath) {
    Remove-Item -LiteralPath $ArchivePath -Force
}

Compress-Archive -Path (Join-Path $PublishDir "*") -DestinationPath $ArchivePath -CompressionLevel Optimal
Assert-WfpZipPayload -ZipPath $ArchivePath

$sha256 = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
$tag = "v$Version"
$zipUrl = "https://github.com/$GitHubRepo/releases/download/$tag/$ArchiveName"

$wfpRuntimeManifestHash = Get-Sha256Lower -Path $WfpRuntimeManifest

$manifest = [ordered]@{
    version = $Version
    zipUrl = $zipUrl
    sha256 = $sha256
    notes = "SerpiumVPN $Version"
    wfp = [ordered]@{
        schema = 1
        protocolAbi = "0x00040000"
        platform = "x64"
        payloadRoot = "bin_files/wfp/x64"
        runtimeManifestSha256 = $wfpRuntimeManifestHash
        installState = "PACKAGED_NOT_INSTALLED"
        driverTrust = $wfpDriverTrustState
        driverOwnership = "SERPIUM_PRODUCT_STATE_V1"
    }
}

$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $ManifestPath -Encoding UTF8

Write-Step "Building Inno Setup installer"

if (-not (Test-Path $InstallerScript)) {
    throw "Inno Setup script not found: $InstallerScript"
}

Assert-InnoOwnsPublishedWfp -ScriptPath $InstallerScript

function Add-InnoCompilerCandidate {
    param(
        [System.Collections.ArrayList]$Candidates,
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return
    }

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return
    }

    $fullPath = [IO.Path]::GetFullPath($Path)
    if (-not $Candidates.Contains($fullPath)) {
        [void]$Candidates.Add($fullPath)
    }
}

function Get-InnoCompilerCandidates {
    $candidates = New-Object System.Collections.ArrayList

    Add-InnoCompilerCandidate $candidates $InnoCompiler
    Add-InnoCompilerCandidate $candidates $env:INNO_SETUP_COMPILER

    foreach ($commandName in @("ISCC.exe", "Compil32.exe")) {
        $command = Get-Command $commandName -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            Add-InnoCompilerCandidate $candidates $command.Source
        }
    }

    foreach ($programRoot in @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)}
    )) {
        if ([string]::IsNullOrWhiteSpace($programRoot)) {
            continue
        }

        Add-InnoCompilerCandidate $candidates (
            Join-Path $programRoot "Inno Setup 6\ISCC.exe"
        )
        Add-InnoCompilerCandidate $candidates (
            Join-Path $programRoot "Inno Setup 6\Compil32.exe"
        )
    }

    $registryKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 6_is1",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 6_is1",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 6_is1"
    )

    foreach ($registryKey in $registryKeys) {
        try {
            $installLocation = (
                Get-ItemProperty -LiteralPath $registryKey -ErrorAction Stop
            ).InstallLocation

            if ([string]::IsNullOrWhiteSpace($installLocation)) {
                continue
            }

            Add-InnoCompilerCandidate $candidates (
                Join-Path $installLocation "ISCC.exe"
            )
            Add-InnoCompilerCandidate $candidates (
                Join-Path $installLocation "Compil32.exe"
            )
        }
        catch {
        }
    }

    return @($candidates)
}

$innoCompilerPath = Get-InnoCompilerCandidates |
    Select-Object -First 1

if ([string]::IsNullOrWhiteSpace($innoCompilerPath)) {
    throw (
        "Inno Setup compiler was not found. Add ISCC.exe to PATH, " +
        "set INNO_SETUP_COMPILER, or pass -InnoCompiler <path>."
    )
}

$innoCompilerName = [IO.Path]::GetFileName($innoCompilerPath)

if ($innoCompilerName.Equals(
        "ISCC.exe",
        [StringComparison]::OrdinalIgnoreCase)) {
    Write-Host "Using ISCC: $innoCompilerPath"
    & $innoCompilerPath "/DMyAppVersion=$Version" $InstallerScript
    Assert-NativeSuccess "Inno Setup ISCC"
}
else {
    Write-Host "Using Compil32: $innoCompilerPath"
    & $innoCompilerPath /cc "/DMyAppVersion=$Version" $InstallerScript
    Assert-NativeSuccess "Inno Setup Compil32"
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

$checksums = [ordered]@{
    version = $Version
    files = @(Get-ChildItem -LiteralPath $ReleaseDir -File | ForEach-Object {
        [ordered]@{ name = $_.Name; sha256 = Get-Sha256Lower $_.FullName }
    })
}
$checksums | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ChecksumsPath -Encoding utf8
}

Write-Step "Release files"
Get-ChildItem -LiteralPath $ReleaseDir -File | Select-Object Name, Length

Write-Host ""
if (-not $PublishGitHub) {
    Write-Host "Upload these files to GitHub Releases:" -ForegroundColor Green
    Write-Host $ReleaseDir
    Write-Host ""
    Write-Host "Or publish automatically with:" -ForegroundColor Green
    Write-Host ".\release.ps1 -Version $Version -PublishOnly -PublishGitHub -TargetCommit <published-source-commit>"
    return
}

# Publish the exact checked artifacts. Never replace an existing public version.
$checksums = Get-Content -LiteralPath $ChecksumsPath -Raw | ConvertFrom-Json
if ($checksums.version -ne $Version) { throw 'Prepared release version does not match.' }
$expectedNames = @("SerpiumVPN-$Version.zip", "SerpiumVPN_Setup-$Version.exe", 'update.json')
$releaseFiles = @()
foreach ($name in $expectedNames) {
    $file = Join-Path $ReleaseDir $name
    $entry = @($checksums.files | Where-Object { $_.name -ceq $name })
    if ($entry.Count -ne 1 -or -not (Test-Path -LiteralPath $file -PathType Leaf) -or
        (Get-Sha256Lower $file) -ne $entry[0].sha256) { throw "Prepared artifact changed: $name" }
    $releaseFiles += $file
}
$prepared = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
if ($prepared.version -ne $Version -or $prepared.sha256 -ne (Get-Sha256Lower $ArchivePath) -or
    $prepared.zipUrl -cne "https://github.com/$GitHubRepo/releases/download/$tag/$ArchiveName") {
    throw 'Prepared update manifest does not match the release archive/repository.'
}
Assert-WfpZipPayload $ArchivePath
& gh api "repos/$GitHubRepo/commits/$TargetCommit" --jq '.sha' *> $null
Assert-NativeSuccess 'Verify source commit on GitHub'
& gh release view $tag --repo $GitHubRepo *> $null
if ($LASTEXITCODE -eq 0) { throw "Release $tag already exists; use a new version." }
$ghArgs = @('release','create',$tag) + $releaseFiles + @('--repo',$GitHubRepo,
    '--title',"SerpiumVPN $Version",'--target',$TargetCommit,'--draft')
if ($Version.Contains('-')) { $ghArgs += '--prerelease' }
if ($NotesFile) { $ghArgs += @('--notes-file',(Resolve-Path -LiteralPath $NotesFile).Path) }
else { $ghArgs += @('--notes',"SerpiumVPN $Version") }
Write-Step "Uploading checked GitHub release $tag"
& gh @ghArgs
Assert-NativeSuccess 'GitHub release upload'
if (-not $Draft) {
    $editArgs = @('release','edit',$tag,'--repo',$GitHubRepo,'--draft=false')
    if (-not $Version.Contains('-')) { $editArgs += '--latest' }
    & gh @editArgs
    Assert-NativeSuccess 'GitHub release publication'
}
Write-Host "GitHub release published: $tag" -ForegroundColor Green
