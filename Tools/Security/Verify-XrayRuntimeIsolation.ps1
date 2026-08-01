#requires -version 5.1
[CmdletBinding()]
param(
    [string]$Root = "D:\Program\Serpium\SerpiumVPN",
    [int]$SocksPort = 10808
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$rootPath = [IO.Path]::GetFullPath($Root)
$localAppData = [IO.Path]::GetFullPath(
    [Environment]::GetFolderPath("LocalApplicationData")
)

$privateConfig = Join-Path $localAppData (
    "SerpiumVPN\Runtime\Xray\key-client.json"
)
$managedRuntimeDirectory = Join-Path $localAppData (
    "SerpiumVPN\Runtime\key-client"
)

$owner = $null
$configPassed = $false
$ownerPassed = $false
$hashRequired = $false
$hashPassed = $false
$aclPassed = $false

function Convert-ToSafePath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fullPath = [IO.Path]::GetFullPath($Path)

    if ($fullPath.StartsWith(
            $localAppData,
            [StringComparison]::OrdinalIgnoreCase)) {
        return "%LOCALAPPDATA%\" + $fullPath.Substring(
            $localAppData.Length
        ).TrimStart("\")
    }

    if ($fullPath.StartsWith(
            $rootPath,
            [StringComparison]::OrdinalIgnoreCase)) {
        return "<SERPIUM_ROOT>\" + $fullPath.Substring(
            $rootPath.Length
        ).TrimStart("\")
    }

    return [IO.Path]::GetFileName($fullPath)
}

function Test-IsManagedRuntimePath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fullPath = [IO.Path]::GetFullPath($Path)
    $runtimePrefix = [IO.Path]::GetFullPath(
        $managedRuntimeDirectory
    ).TrimEnd("\") + "\"

    return $fullPath.StartsWith(
        $runtimePrefix,
        [StringComparison]::OrdinalIgnoreCase)
}

function Get-SourceXrayCandidates {
    $candidates = @(
        Get-ChildItem -LiteralPath $rootPath `
            -Filter "*.exe" `
            -File -Force -Recurse `
            -ErrorAction SilentlyContinue |
            Where-Object {
                $path = $_.FullName
                $insideRelay =
                    $path -match '(?i)\\bin_files\\relay\\'
                $looksLikeXray =
                    $_.Name -match '(?i)xray' -or
                    $_.DirectoryName -match '(?i)\\key-client($|\\)'

                $insideRelay -and $looksLikeXray
            }
    )

    return @(
        $candidates |
            Sort-Object FullName -Unique
    )
}

function Find-MatchingSourceBySha256 {
    param(
        [Parameter(Mandatory = $true)][string]$RuntimePath,
        [Parameter(Mandatory = $true)][object[]]$Candidates
    )

    if (-not (Test-Path -LiteralPath $RuntimePath -PathType Leaf)) {
        return $null
    }

    $runtimeItem = Get-Item -LiteralPath $RuntimePath
    $sameSizeCandidates = @(
        $Candidates |
            Where-Object {
                $_.Length -eq $runtimeItem.Length -and
                -not [string]::Equals(
                    [IO.Path]::GetFullPath($_.FullName),
                    [IO.Path]::GetFullPath($RuntimePath),
                    [StringComparison]::OrdinalIgnoreCase)
            }
    )

    if ($sameSizeCandidates.Count -eq 0) {
        return $null
    }

    $runtimeHash = (
        Get-FileHash -LiteralPath $RuntimePath -Algorithm SHA256
    ).Hash

    foreach ($candidate in $sameSizeCandidates) {
        $candidateHash = (
            Get-FileHash -LiteralPath $candidate.FullName `
                -Algorithm SHA256
        ).Hash

        if ($candidateHash -eq $runtimeHash) {
            return $candidate
        }
    }

    return $null
}

Write-Host "=== Serpium Xray Runtime Isolation Check v1.3 ===" `
    -ForegroundColor Cyan
Write-Host ""

$legacyConfigs = @(
    Get-ChildItem -LiteralPath $rootPath `
        -Filter "key-client.json" `
        -File -Force -Recurse `
        -ErrorAction SilentlyContinue
)

$allConfigs = @($legacyConfigs)
if (Test-Path -LiteralPath $privateConfig -PathType Leaf) {
    if (-not ($allConfigs.FullName -contains $privateConfig)) {
        $allConfigs += Get-Item -LiteralPath $privateConfig
    }
}

$serpium = @(
    Get-CimInstance Win32_Process `
        -Filter "Name='SerpiumVPN.exe'" `
        -ErrorAction SilentlyContinue
)

$xray = @(
    Get-CimInstance Win32_Process `
        -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -in @(
                "xray.exe",
                "xray-client.exe",
                "xray-key-client.exe"
            )
        }
)

$listener = $null
try {
    $listener = Get-NetTCPConnection `
        -State Listen `
        -LocalPort $SocksPort `
        -ErrorAction Stop |
        Select-Object -First 1
}
catch { }

if ($serpium.Count -gt 0) {
    $version = try {
        (
            Get-Item -LiteralPath $serpium[0].ExecutablePath
        ).VersionInfo.FileVersion
    }
    catch {
        "не определена"
    }

    Write-Host "SerpiumVPN: запущен, версия $version" `
        -ForegroundColor Cyan
}
else {
    Write-Host "SerpiumVPN: остановлен" `
        -ForegroundColor DarkGray
}

if ($allConfigs.Count -eq 0) {
    $configPassed = $true
    Write-Host "PASS: key-client.json не найден." `
        -ForegroundColor Green
}
else {
    Write-Host "FAIL: найден plaintext key-client.json:" `
        -ForegroundColor Red

    $allConfigs |
        Select-Object @{
            Name = "SafePath"
            Expression = {
                Convert-ToSafePath -Path $_.FullName
            }
        }, Length, CreationTime, LastWriteTime |
        Format-Table -AutoSize
}

if ($null -eq $listener) {
    if ($xray.Count -eq 0) {
        Write-Host "INFO: SOCKS-порт и Xray не активны." `
            -ForegroundColor DarkGray
    }
    else {
        Write-Host "WARN: Xray запущен, но порт $SocksPort не найден." `
            -ForegroundColor Yellow
    }
}
else {
    $owner = $xray |
        Where-Object {
            [int]$_.ProcessId -eq [int]$listener.OwningProcess
        } |
        Select-Object -First 1

    if ($null -eq $owner) {
        Write-Host (
            "FAIL: порт 127.0.0.1:$SocksPort принадлежит PID " +
            "$($listener.OwningProcess), но это не разрешённый " +
            "Xray-бинарник Serpium."
        ) -ForegroundColor Red
    }
    else {
        $ownerPassed = $true

        Write-Host (
            "PASS: порт 127.0.0.1:$SocksPort принадлежит " +
            "$($owner.Name), PID $($owner.ProcessId)."
        ) -ForegroundColor Green

        $ownerPath = [IO.Path]::GetFullPath(
            $owner.ExecutablePath
        )
        $isManagedRuntime = Test-IsManagedRuntimePath `
            -Path $ownerPath

        if ($isManagedRuntime) {
            $hashRequired = $true
            $sourceCandidates = Get-SourceXrayCandidates
            $matchingSource = Find-MatchingSourceBySha256 `
                -RuntimePath $ownerPath `
                -Candidates $sourceCandidates

            if ($null -ne $matchingSource) {
                $hashPassed = $true

                Write-Host (
                    "PASS: runtime-копия Xray совпадает с " +
                    "упакованным бинарником Serpium по SHA-256."
                ) -ForegroundColor Green

                Write-Host (
                    "Совпавший источник: " +
                    (Convert-ToSafePath -Path $matchingSource.FullName)
                ) -ForegroundColor DarkGray
            }
            elseif ($sourceCandidates.Count -eq 0) {
                Write-Host (
                    "FAIL: внутри bin_files\relay не найдено ни одного " +
                    "кандидата Xray для независимого сравнения SHA-256."
                ) -ForegroundColor Red
            }
            else {
                Write-Host (
                    "FAIL: runtime-копия Xray не совпала ни с одним " +
                    "упакованным Xray-бинарником Serpium."
                ) -ForegroundColor Red

                Write-Host (
                    "Проверено кандидатов: " +
                    $sourceCandidates.Count
                ) -ForegroundColor DarkGray
            }
        }
        else {
            $hashPassed = $true

            Write-Host (
                "INFO: Xray запущен напрямую из папки приложения; " +
                "runtime SHA-256-сопоставление не требуется."
            ) -ForegroundColor DarkGray
        }

        Write-Host (
            "Путь владельца: " +
            (Convert-ToSafePath -Path $ownerPath)
        )
    }
}

$runtimeDirectory = Split-Path -Parent $privateConfig
if (Test-Path -LiteralPath $runtimeDirectory -PathType Container) {
    $acl = Get-Acl -LiteralPath $runtimeDirectory
    $broadPattern =
        '(?i)(^|\\)(Everyone|Users|Authenticated Users|Guests|' +
        'Все|Пользователи|Прошедшие проверку|Гости)$'

    $broad = @(
        $acl.Access |
            Where-Object {
                $_.AccessControlType -eq "Allow" -and
                $_.IdentityReference.Value -match $broadPattern
            }
    )

    if ($broad.Count -eq 0) {
        $aclPassed = $true

        Write-Host (
            "PASS: Runtime\Xray ACL не содержит широких групп."
        ) -ForegroundColor Green
    }
    else {
        Write-Host (
            "FAIL: Runtime\Xray ACL содержит широкие разрешения."
        ) -ForegroundColor Red

        $broad |
            Select-Object IdentityReference, FileSystemRights |
            Format-Table -AutoSize
    }
}
else {
    Write-Host (
        "FAIL: приватная Runtime\Xray папка не найдена."
    ) -ForegroundColor Red
}

$hashConditionPassed =
    (-not $hashRequired) -or $hashPassed

Write-Host ""
if ($configPassed -and
    $ownerPassed -and
    $hashConditionPassed -and
    $aclPassed) {
    Write-Host (
        "ИТОГ: PASS — Xray runtime-изоляция, очистка конфига, " +
        "владелец порта, SHA-256 и ACL подтверждены."
    ) -ForegroundColor Green
}
else {
    Write-Host (
        "ИТОГ: FAIL — одна или несколько обязательных проверок " +
        "не пройдены."
    ) -ForegroundColor Red
}
