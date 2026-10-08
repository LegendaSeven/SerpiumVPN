param(
    [string]$Root = $PSScriptRoot,
    [ValidateSet('Source','Published','Archive')][string]$Phase = 'Source',
    [string]$ExpectedVersion,
    [string]$PublishRoot,
    [string]$ArchivePath
)
$ErrorActionPreference = 'Stop'
$required = @('SerpiumVPN.exe','SerpiumVPN.dll','SerpiumUpdater.exe','Assets/Serpium.App.ico',
    'bin_files/relay/sing-box.exe','bin_files/relay/xray.exe','THIRD_PARTY_NOTICES.txt',
    'licenses/LICENSE_sing-box_GPL-3.0-or-later.txt','licenses/LICENSE_Xray-core_MPL-2.0.txt')
if ($Phase -eq 'Source') {
    [xml]$project = Get-Content -LiteralPath (Join-Path $Root 'SerpiumVPN.csproj') -Raw
    if ($ExpectedVersion -and $project.Project.PropertyGroup.Version -ne $ExpectedVersion) { throw 'Source version does not match release version.' }
    foreach ($relative in @('Assets/Serpium.App.ico','Assets/Serpium.png','bin_files/relay/sing-box.exe','bin_files/relay/xray.exe')) {
        if (-not (Test-Path -LiteralPath (Join-Path $Root $relative) -PathType Leaf)) { throw "Missing source asset: $relative" }
    }
    if ($project.Project.ItemGroup.ProjectReference) { throw 'Unexpected plugin project dependency.' }
} else {
    if ($Phase -eq 'Published') {
        if (-not $PublishRoot) { throw 'PublishRoot is required.' }
        $paths = @(Get-ChildItem -LiteralPath $PublishRoot -File -Recurse | ForEach-Object { [IO.Path]::GetRelativePath($PublishRoot, $_.FullName).Replace('\','/') })
    } else {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
        try { $paths = @($zip.Entries | Where-Object { $_.Name } | ForEach-Object { $_.FullName.Replace('\','/') }) }
        finally { $zip.Dispose() }
    }
    foreach ($relative in $required) { if ($relative -cnotin $paths) { throw "Missing release file: $relative" } }
    foreach ($relative in $paths) {
        if ($relative -match '(?i)(^|/)(Native|SerpiumNet|Plugins|Engines|SDK|tgws|wfp|logs|state|configs|cache|temp|tmp)(/|\.)|Serpium\.Engine|\.(pdb|log|tmp|sys|cat|inf)$|serpium\.runtime\.json|vendor_versions\.json') {
            throw "Unexpected release payload: $relative"
        }
        if ($relative.StartsWith('bin_files/relay/') -and $relative -notmatch '^bin_files/relay/(sing-box\.exe|xray\.exe|sing-box\.version\.txt|xray\.version\.json|README_XRAY\.txt)$') {
            throw "Unexpected transport file: $relative"
        }
    }
}
Write-Output "CORE_PACKAGE_PASS $Phase"
