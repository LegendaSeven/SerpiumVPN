param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version
)

$ErrorActionPreference = "Stop"

$projectFile = Join-Path $PSScriptRoot "SerpiumVPN.csproj"

if (-not (Test-Path $projectFile)) {
    throw "Не найден файл проекта: $projectFile"
}

Write-Host ""
Write-Host "Serpium VPN — установка локальной версии" -ForegroundColor Cyan
Write-Host "Новая версия: $Version" -ForegroundColor Yellow
Write-Host ""

$content = Get-Content $projectFile -Raw

function Set-VersionField {
    param(
        [string]$XmlTag,
        [string]$Value
    )

    $pattern = "<$XmlTag>[^<]*</$XmlTag>"
    $replacement = "<$XmlTag>$Value</$XmlTag>"

    if ($script:content -match $pattern) {
        $script:content = [regex]::Replace(
            $script:content,
            $pattern,
            $replacement,
            1
        )
    }
    else {
        $block = "    $replacement`r`n"
        $script:content = [regex]::Replace(
            $script:content,
            '</PropertyGroup>',
            $block + '</PropertyGroup>',
            1
        )
    }
}

Set-VersionField -XmlTag "Version" -Value $Version
Set-VersionField -XmlTag "VersionPrefix" -Value $Version
Set-VersionField -XmlTag "VersionSuffix" -Value ""
Set-VersionField -XmlTag "AssemblyVersion" -Value "$Version.0"
Set-VersionField -XmlTag "FileVersion" -Value "$Version.0"
Set-VersionField -XmlTag "InformationalVersion" -Value $Version

Set-Content $projectFile $content -Encoding UTF8

Write-Host "Версионные поля обновлены:" -ForegroundColor Green
Write-Host "  Version             = $Version"
Write-Host "  VersionPrefix       = $Version"
Write-Host "  VersionSuffix       = (пусто)"
Write-Host "  AssemblyVersion     = $Version.0"
Write-Host "  FileVersion         = $Version.0"
Write-Host "  InformationalVersion= $Version"
Write-Host ""

Write-Host "Проверка SerpiumVPN.csproj:" -ForegroundColor Cyan
Select-String `
    -Path $projectFile `
    -Pattern "<Version>|VersionPrefix|VersionSuffix|AssemblyVersion|FileVersion|InformationalVersion"

Write-Host ""
Write-Host "Локальная версия Serpium VPN установлена: $Version" -ForegroundColor Green
Write-Host "Теперь можно применять и тестировать патчи этой версии." -ForegroundColor DarkGray
Write-Host "Когда версия будет готова — запускай release.ps1." -ForegroundColor DarkGray

