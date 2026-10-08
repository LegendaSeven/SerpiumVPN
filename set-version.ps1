#requires -version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+(?:\.\d+)?$')]
    [string]$Version
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectFile = Join-Path $PSScriptRoot "SerpiumVPN.csproj"

if (-not (Test-Path -LiteralPath $projectFile -PathType Leaf)) {
    throw "Не найден файл проекта: $projectFile"
}

$numericParts = @($Version.Split("."))

if ($numericParts.Count -eq 3) {
    $assemblyVersion = "$Version.0"
}
elseif ($numericParts.Count -eq 4) {
    $assemblyVersion = $Version
}
else {
    throw "Версия должна содержать 3 или 4 числовых компонента."
}

Write-Host ""
Write-Host "Serpium VPN — синхронизация версии" `
    -ForegroundColor Cyan
Write-Host "Version: $Version" -ForegroundColor Yellow
Write-Host "Assembly/File: $assemblyVersion" `
    -ForegroundColor Yellow
Write-Host ""

$content = [IO.File]::ReadAllText($projectFile)

function Set-VersionField {
    param(
        [Parameter(Mandatory = $true)]
        [string]$XmlTag,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    $pattern = (
        "<" +
        [regex]::Escape($XmlTag) +
        ">[^<]*</" +
        [regex]::Escape($XmlTag) +
        ">"
    )

    $replacement = (
        "<" +
        $XmlTag +
        ">" +
        $Value +
        "</" +
        $XmlTag +
        ">"
    )

    if ([regex]::IsMatch(
            $script:content,
            $pattern,
            [Text.RegularExpressions.RegexOptions]::IgnoreCase
        )) {
        $script:content = [regex]::Replace(
            $script:content,
            $pattern,
            $replacement,
            [Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
        return
    }

    $propertyGroupClose = "</PropertyGroup>"
    $index = $script:content.IndexOf(
        $propertyGroupClose,
        [StringComparison]::OrdinalIgnoreCase
    )

    if ($index -lt 0) {
        throw "В SerpiumVPN.csproj не найден PropertyGroup."
    }

    if ($script:content.Contains("`r`n")) {
        $newline = "`r`n"
    }
    else {
        $newline = "`n"
    }

    $indent = "`t"
    $insertion = (
        $indent +
        $replacement +
        $newline
    )

    $script:content = (
        $script:content.Substring(0, $index) +
        $insertion +
        $script:content.Substring($index)
    )
}

Set-VersionField -XmlTag "Version" -Value $Version
Set-VersionField -XmlTag "VersionPrefix" -Value $Version
Set-VersionField -XmlTag "VersionSuffix" -Value ""
Set-VersionField `
    -XmlTag "AssemblyVersion" `
    -Value $assemblyVersion
Set-VersionField `
    -XmlTag "FileVersion" `
    -Value $assemblyVersion
Set-VersionField `
    -XmlTag "InformationalVersion" `
    -Value $Version

$hasBom = $false
[byte[]]$originalBytes = [IO.File]::ReadAllBytes($projectFile)

if (
    $originalBytes.Length -ge 3 -and
    $originalBytes[0] -eq 0xEF -and
    $originalBytes[1] -eq 0xBB -and
    $originalBytes[2] -eq 0xBF
) {
    $hasBom = $true
}

[IO.File]::WriteAllText(
    $projectFile,
    $content,
    (New-Object Text.UTF8Encoding($hasBom))
)

[xml]$xml = [IO.File]::ReadAllText($projectFile)
$properties = $xml.Project.PropertyGroup

function Get-ProjectValue {
    param([string]$Name)

    foreach ($group in @($properties)) {
        $node = $group.$Name

        if ($null -ne $node) {
            return [string]$node
        }
    }

    return ""
}

$expected = [ordered]@{
    Version = $Version
    VersionPrefix = $Version
    VersionSuffix = ""
    AssemblyVersion = $assemblyVersion
    FileVersion = $assemblyVersion
    InformationalVersion = $Version
}

foreach ($entry in $expected.GetEnumerator()) {
    $actual = Get-ProjectValue -Name $entry.Key

    if ($actual -ne $entry.Value) {
        throw (
            "Проверка версии не пройдена: " +
            $entry.Key +
            " = '" +
            $actual +
            "', ожидалось '" +
            $entry.Value +
            "'."
        )
    }
}

Write-Host "SET_VERSION_PASS" -ForegroundColor Green

foreach ($entry in $expected.GetEnumerator()) {
    Write-Host (
        "  " +
        $entry.Key.PadRight(20) +
        "= " +
        $entry.Value
    )
}
