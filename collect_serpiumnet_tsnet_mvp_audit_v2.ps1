param(
    [string]$Root = (Get-Location).Path
)

$ErrorActionPreference = "Stop"
$Root = [IO.Path]::GetFullPath($Root)

$name = "SerpiumNet_tsnet_MVP_Audit"
$temp = Join-Path $env:TEMP $name
$zip = Join-Path ([Environment]::GetFolderPath("Desktop")) "$name.zip"

Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $temp | Out-Null

function Copy-Rel([string]$Path) {
    if (-not (Test-Path $Path -PathType Leaf)) { return }
    $full = [IO.Path]::GetFullPath($Path)
    $rel = [IO.Path]::GetRelativePath($Root, $full)
    $dst = Join-Path $temp $rel
    New-Item -ItemType Directory -Path (Split-Path $dst -Parent) -Force | Out-Null
    Copy-Item $full $dst -Force
}

$wanted = @(
    "SerpiumVPN.csproj",
    "MainWindow.xaml",
    "MainWindow.xaml.cs",
    "App.xaml",
    "App.xaml.cs",
    "TailscaleManager.cs",
    "RelayKeyParser.cs",
    "XrayGatewayManager.cs",
    "XrayClientManager.cs",
    "UserRuntimeSettings.cs",
    "app.manifest"
)

foreach ($file in $wanted) {
    Get-ChildItem $Root -Recurse -File -Filter $file -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\bin\\|\\obj\\|\\.git\\|\\.serpium_patch_backups\\' } |
        ForEach-Object { Copy-Rel $_.FullName }
}

Get-ChildItem $Root -Recurse -Directory -ErrorAction SilentlyContinue |
    Where-Object {
        $_.FullName -notmatch '\\bin\\|\\obj\\|\\.git\\|\\.serpium_patch_backups\\' -and
        $_.Name -match 'Relay|Xray|Tailscale|SerpiumNet'
    } |
    ForEach-Object {
        Get-ChildItem $_.FullName -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in @(".cs",".xaml",".json",".ps1",".csproj",".config",".md",".go",".mod",".sum") } |
            ForEach-Object { Copy-Rel $_.FullName }
    }

$envReport = Join-Path $temp "ENVIRONMENT.txt"
@(
    "Project root: $Root"
    "Created: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    ""
    "dotnet:"
    (& dotnet --info 2>&1 | Out-String)
    ""
    "go:"
    $(try {
        $go = Get-Command go -ErrorAction Stop
        (& $go.Source version 2>&1 | Out-String)
    } catch {
        "Go не установлен или отсутствует в PATH."
    })
    ""
    "where go:"
    $(try {
        (& where.exe go 2>&1 | Out-String)
    } catch {
        "go.exe не найден."
    })
    ""
    "Tailscale processes:"
    (Get-Process *tailscale* -ErrorAction SilentlyContinue | Format-Table Name,Id,Path -AutoSize | Out-String)
) | Set-Content $envReport -Encoding UTF8

$files = Join-Path $temp "FILES.txt"
Get-ChildItem $temp -Recurse -File |
    ForEach-Object { [IO.Path]::GetRelativePath($temp, $_.FullName) } |
    Sort-Object |
    Set-Content $files -Encoding UTF8

Remove-Item $zip -Force -ErrorAction SilentlyContinue
Compress-Archive "$temp\*" $zip -Force

Write-Host ""
Write-Host "Архив готов:" -ForegroundColor Green
Write-Host $zip -ForegroundColor Cyan
