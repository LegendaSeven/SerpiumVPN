param([string]$Root="D:\Program\Serpium\SerpiumVPN")
$ErrorActionPreference="Stop"
$Root=[IO.Path]::GetFullPath($Root)
if(-not(Test-Path $Root)){throw "Папка проекта не найдена: $Root"}
$stamp=Get-Date -Format "yyyyMMdd_HHmmss"
$out=Join-Path $env:TEMP "Serpium_StatusUpdateAudit_$stamp"
$zip=Join-Path ([Environment]::GetFolderPath("Desktop")) "Serpium_StatusUpdateAudit_$stamp.zip"
Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $out -Force|Out-Null
$terms=@("StatusTextBlock","SetStatus","UpdateStatus","CheckAppUpdatesAsync","CheckFilesUpdatesAsync","AutoUpdateProgram","AutoUpdateFiles","Download","UpdateManager","LocalUpdateRequested","AutoSelectDetails","AutoSelectTitle","ProgramSettingsToggle_Changed","UpdateFiles_ClickAsync","CheckAppPatch_ClickAsync")
$excluded='\\(bin|obj|\.git|\.vs|packages|\.serpium_patch_backups)\\'
$files=Get-ChildItem $Root -Recurse -File|Where-Object{$_.FullName-notmatch $excluded -and $_.Extension -in ".cs",".xaml",".csproj",".sln",".slnx",".json",".props",".targets"}
$selected=@()
foreach($f in $files){
  $core=$f.Name -in "MainWindow.xaml","MainWindow.xaml.cs","App.xaml","App.xaml.cs","UserRuntimeSettings.cs" -or $f.Extension -in ".csproj",".sln",".slnx"
  $matches=@()
  if($f.Extension -in ".cs",".xaml",".json",".props",".targets"){
    try{$c=Get-Content $f.FullName -Raw; foreach($t in $terms){if($c-match [regex]::Escape($t)){$matches+=$t}}}catch{}
  }
  if($core-or$matches.Count-gt0){$selected+=[pscustomobject]@{File=$f;Matches=$matches}}
}
if($selected.Count-eq0){throw "Подходящие файлы не найдены"}
foreach($i in $selected){
  $rel=[IO.Path]::GetRelativePath($Root,$i.File.FullName)
  $dst=Join-Path $out $rel
  New-Item -ItemType Directory -Path (Split-Path $dst -Parent) -Force|Out-Null
  Copy-Item $i.File.FullName $dst -Force
}
$report=@("Serpium VPN — Status / Update Audit","Project root: $Root","Created: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')","")
foreach($i in $selected){
  $rel=[IO.Path]::GetRelativePath($Root,$i.File.FullName)
  $report+=$rel
  $report+="  Matches: "+($(if($i.Matches.Count){$i.Matches -join ', '}else{'core file'}))
  $report+=""
}
$report|Set-Content (Join-Path $out "STATUS_UPDATE_AUDIT.txt") -Encoding UTF8
Remove-Item $zip -Force -ErrorAction SilentlyContinue
Compress-Archive -Path "$out\*" -DestinationPath $zip -Force
Write-Host "`nАрхив аудита готов:" -ForegroundColor Green
Write-Host $zip -ForegroundColor Cyan
Write-Host "`nФайлов собрано: $($selected.Count)" -ForegroundColor DarkGray
