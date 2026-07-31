param(
    [string]$Root = (Get-Location).Path
)

$ErrorActionPreference = "Stop"
$Root = [IO.Path]::GetFullPath($Root)

$outName = "Serpium_StatusRefactor"
$temp = Join-Path $env:TEMP $outName
$zip = Join-Path ([Environment]::GetFolderPath("Desktop")) "$outName.zip"

Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $temp | Out-Null

$coreFiles = @(
    "MainWindow.xaml",
    "MainWindow.xaml.cs",
    "App.xaml",
    "App.xaml.cs",
    "UserRuntimeSettings.cs",
    "UpdateManager.cs",
    "ProgramUpdateManager.cs",
    "FileUpdateManager.cs",
    "TelegramProxyManager.cs",
    "RelayKeyParser.cs",
    "XrayGatewayManager.cs",
    "SerpiumVPN.csproj"
)

foreach($name in $coreFiles){
    Get-ChildItem $Root -Recurse -File -Filter $name -ErrorAction SilentlyContinue |
    ForEach-Object{
        $rel=[IO.Path]::GetRelativePath($Root,$_.FullName)
        $dst=Join-Path $temp $rel
        New-Item -ItemType Directory -Path (Split-Path $dst -Parent) -Force | Out-Null
        Copy-Item $_.FullName $dst
    }
}

Get-ChildItem $temp -Recurse -File |
ForEach-Object{
    [IO.Path]::GetRelativePath($temp,$_.FullName)
} | Set-Content (Join-Path $temp "FILES.txt")

Remove-Item $zip -Force -ErrorAction SilentlyContinue
Compress-Archive "$temp\*" $zip -Force

Write-Host ""
Write-Host "Архив готов:" -ForegroundColor Green
Write-Host $zip -ForegroundColor Cyan
