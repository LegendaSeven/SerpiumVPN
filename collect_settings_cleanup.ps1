param(
    [string]$Root = "D:\Program\Serpium\SerpiumVPN"
)

$ErrorActionPreference = "Stop"

$Root = [System.IO.Path]::GetFullPath($Root)

if (-not (Test-Path $Root)) {
    throw "Папка проекта не найдена: $Root"
}

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outDir = Join-Path $env:TEMP "Serpium_SettingsCleanup_$stamp"
$desktop = [Environment]::GetFolderPath("Desktop")
$zipPath = Join-Path $desktop "Serpium_SettingsCleanup_Source_$stamp.zip"

Remove-Item $outDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$excludedDirectories = @(
    "bin",
    "obj",
    ".git",
    ".vs",
    "packages",
    ".serpium_patch_backups"
)

$searchTerms = @(
    "AutoSwitchStrategies",
    "AutoUpdateFiles",
    "CheckAutoSwitchStrategies",
    "CheckAutoUpdateFiles",
    "SettingsWindow",
    "DisposeRelayAsync",
    "ForceClose",
    "UserRuntimeSettings",
    "UpdateFiles_ClickAsync",
    "CheckFilesUpdates"
)

$coreNames = @(
    "MainWindow.xaml",
    "MainWindow.xaml.cs",
    "SettingsWindow.xaml",
    "SettingsWindow.xaml.cs",
    "App.xaml",
    "App.xaml.cs",
    "UserRuntimeSettings.cs"
)

$allowedExtensions = @(
    ".cs",
    ".xaml",
    ".csproj",
    ".sln",
    ".slnx",
    ".json",
    ".props",
    ".targets"
)

$files = Get-ChildItem -Path $Root -Recurse -File | Where-Object {
    $relative = [System.IO.Path]::GetRelativePath($Root, $_.FullName)
    $parts = $relative -split '[\\/]'

    $insideExcludedDirectory = $false

    foreach ($part in $parts) {
        if ($excludedDirectories -contains $part) {
            $insideExcludedDirectory = $true
            break
        }
    }

    -not $insideExcludedDirectory -and
    $allowedExtensions -contains $_.Extension.ToLowerInvariant()
}

$selected = foreach ($file in $files) {
    $isCoreFile =
        $coreNames -contains $file.Name -or
        $file.Extension.ToLowerInvariant() -in @(".csproj", ".sln", ".slnx")

    $hasRelevantText = $false

    if (-not $isCoreFile -and $file.Extension.ToLowerInvariant() -in @(".cs", ".xaml")) {
        try {
            $content = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop

            foreach ($term in $searchTerms) {
                if ($content -match [regex]::Escape($term)) {
                    $hasRelevantText = $true
                    break
                }
            }
        }
        catch {
            Write-Warning "Не удалось прочитать файл: $($file.FullName)"
        }
    }

    if ($isCoreFile -or $hasRelevantText) {
        $file
    }
}

$selected = @($selected | Sort-Object FullName -Unique)

if ($selected.Count -eq 0) {
    throw "Подходящие файлы не найдены."
}

foreach ($file in $selected) {
    $relative = [System.IO.Path]::GetRelativePath($Root, $file.FullName)
    $destination = Join-Path $outDir $relative
    $destinationDir = Split-Path $destination -Parent

    New-Item -ItemType Directory -Path $destinationDir -Force | Out-Null
    Copy-Item -LiteralPath $file.FullName -Destination $destination -Force
}

$manifestLines = @(
    "Serpium VPN — Settings Cleanup source package"
    "Project root: $Root"
    "Created: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    ""
    "Included files:"
)

foreach ($file in $selected) {
    $manifestLines += [System.IO.Path]::GetRelativePath($Root, $file.FullName)
}

$manifestPath = Join-Path $outDir "FILES_INCLUDED.txt"
$manifestLines | Set-Content -LiteralPath $manifestPath -Encoding UTF8

Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
Compress-Archive -Path (Join-Path $outDir "*") -DestinationPath $zipPath -Force

Write-Host ""
Write-Host "Архив готов:" -ForegroundColor Green
Write-Host $zipPath -ForegroundColor Cyan
Write-Host ""
Write-Host "Файлов собрано: $($selected.Count)" -ForegroundColor DarkGray
