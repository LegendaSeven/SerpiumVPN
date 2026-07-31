param([string]$Root=(Get-Location).Path)
$ErrorActionPreference="Stop"
$Root=[IO.Path]::GetFullPath($Root)
$outName="Serpium_Relay_Tailscale_Status_MVP_Audit"
$temp=Join-Path $env:TEMP $outName
$zip=Join-Path ([Environment]::GetFolderPath("Desktop")) "$outName.zip"
Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $temp | Out-Null

function Copy-Rel([string]$Path){
    if(-not (Test-Path $Path -PathType Leaf)){return}
    $full=[IO.Path]::GetFullPath($Path)
    $rel=[IO.Path]::GetRelativePath($Root,$full)
    $dst=Join-Path $temp $rel
    New-Item -ItemType Directory -Path (Split-Path $dst -Parent) -Force | Out-Null
    Copy-Item $full $dst -Force
}

$fixed=@(
"MainWindow.xaml","MainWindow.xaml.cs","App.xaml","App.xaml.cs",
"SerpiumVPN.csproj","UserRuntimeSettings.cs","RelayKeyParser.cs",
"XrayGatewayManager.cs","XrayClientManager.cs","set-version.ps1"
)

foreach($name in $fixed){
    Get-ChildItem $Root -Recurse -File -Filter $name -ErrorAction SilentlyContinue |
    Where-Object {$_.FullName -notmatch '\\bin\\|\\obj\\|\\.git\\|\\.serpium_patch_backups\\'} |
    ForEach-Object { Copy-Rel $_.FullName }
}

Get-ChildItem $Root -Recurse -Directory -ErrorAction SilentlyContinue |
Where-Object {
    $_.FullName -notmatch '\\bin\\|\\obj\\|\\.git\\|\\.serpium_patch_backups\\' -and
    $_.Name -match 'Relay|Xray|Tailscale'
} | ForEach-Object {
    Get-ChildItem $_.FullName -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object {$_.Extension -in @(".cs",".xaml",".json",".ps1",".csproj",".config",".txt")} |
    ForEach-Object { Copy-Rel $_.FullName }
}

$patterns=@(
"serpium://relay","RelayKey","XrayGateway","XrayClient","SOCKS5",
"127.0.0.1:10808","tailscale","tsnet","StartGateway","ConnectClient",
"StopGateway","DisconnectClient","Клиент подключён","Клиент запущен",
"Шлюз доступен","Шлюз недоступен","Не удалось подключиться",
"Ожидание соединения","RelayStatus","TcpClient","ProcessStartInfo"
)

$matches=Get-ChildItem $Root -Recurse -File -Include *.cs,*.xaml,*.json,*.ps1,*.csproj,*.config -ErrorAction SilentlyContinue |
Where-Object {$_.FullName -notmatch '\\bin\\|\\obj\\|\\.git\\|\\.serpium_patch_backups\\'} |
Select-String -Pattern $patterns -SimpleMatch -List -ErrorAction SilentlyContinue

foreach($m in $matches){Copy-Rel $m.Path}

$report=Join-Path $temp "AUDIT_REPORT.txt"
@(
"Serpium Relay + Tailscale + Status MVP audit",
"Project root: $Root",
"Created: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
"",
"Collected files:"
) | Set-Content $report -Encoding UTF8

Get-ChildItem $temp -Recurse -File |
Where-Object {$_.FullName -ne $report} |
ForEach-Object {[IO.Path]::GetRelativePath($temp,$_.FullName)} |
Sort-Object | Add-Content $report -Encoding UTF8

Remove-Item $zip -Force -ErrorAction SilentlyContinue
Compress-Archive "$temp\*" $zip -Force
Write-Host ""
Write-Host "Архив готов:" -ForegroundColor Green
Write-Host $zip -ForegroundColor Cyan
