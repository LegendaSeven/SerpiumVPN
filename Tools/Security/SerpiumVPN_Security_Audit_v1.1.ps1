#requires -version 5.1
[CmdletBinding()]
param(
    [string]$Root = "D:\Program\Serpium\SerpiumVPN"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = [IO.Path]::GetFullPath($Root)
$desktop = [Environment]::GetFolderPath("Desktop")
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportDirectory = Join-Path $desktop "SerpiumVPN_Security_Audit"
$reportPath = Join-Path $reportDirectory "Security_Audit_v1.1_$stamp.txt"
New-Item -ItemType Directory -Path $reportDirectory -Force | Out-Null

$findings = [System.Collections.Generic.List[object]]::new()

function Add-Finding {
    param(
        [ValidateSet("PASS", "WARN", "FAIL", "INFO")]
        [string]$Status,
        [string]$Area,
        [string]$Details
    )

    $findings.Add([pscustomobject]@{
        Status = $Status
        Area = $Area
        Details = $Details
    })
}

function Get-RelativeDisplayPath {
    param([string]$Path)

    try {
        $full = [IO.Path]::GetFullPath($Path)
        if ($full.StartsWith($projectRoot, [StringComparison]::OrdinalIgnoreCase)) {
            return "<PROJECT>\" + $full.Substring($projectRoot.Length).TrimStart('\')
        }

        $local = [Environment]::GetFolderPath("LocalApplicationData")
        if ($full.StartsWith($local, [StringComparison]::OrdinalIgnoreCase)) {
            return "<LOCALAPPDATA>\" + $full.Substring($local.Length).TrimStart('\')
        }

        $roaming = [Environment]::GetFolderPath("ApplicationData")
        if ($full.StartsWith($roaming, [StringComparison]::OrdinalIgnoreCase)) {
            return "<APPDATA>\" + $full.Substring($roaming.Length).TrimStart('\')
        }

        $temp = [IO.Path]::GetFullPath($env:TEMP)
        if ($full.StartsWith($temp, [StringComparison]::OrdinalIgnoreCase)) {
            return "<TEMP>\" + $full.Substring($temp.Length).TrimStart('\')
        }

        if ($full.StartsWith($desktop, [StringComparison]::OrdinalIgnoreCase)) {
            return "<DESKTOP>\" + $full.Substring($desktop.Length).TrimStart('\')
        }

        return $full
    }
    catch {
        return $Path
    }
}

function Test-SensitiveMarkers {
    param([string]$Path)

    $result = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)

    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($item.Length -gt 64MB) {
            $result.Add("Файл больше 64 МБ — содержимое не сканировалось") | Out-Null
            return @($result)
        }

        [byte[]]$bytes = [IO.File]::ReadAllBytes($Path)
        try {
            $representations = @(
                [Text.Encoding]::UTF8.GetString($bytes),
                [Text.Encoding]::Unicode.GetString($bytes),
                [Text.Encoding]::BigEndianUnicode.GetString($bytes),
                [Text.Encoding]::ASCII.GetString($bytes)
            )

            $patterns = [ordered]@{
                "VPN URI" = '(?i)\b(vless|vmess|trojan|avo)://'
                "UUID" = '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b'
                "Durev/Base64 VLESS prefix" = '(?i)\bdmxlc3M6Ly8'
                "Base64 VMess prefix" = '(?i)\bdm1lc3M6Ly8'
                "Base64 Trojan prefix" = '(?i)\bdHJvamFuOi8v'
                "Base64 AVO prefix" = '(?i)\bYXZvOi8v'
                "Sensitive query parameter" = '(?i)\b(pbk|sid|shortid|password|passwd|token|secret|private_key|privatekey|uuid)\s*='
                "Sensitive JSON field" = '(?i)"(pbk|sid|shortid|short_id|password|passwd|token|secret|private_key|privatekey|uuid)"\s*:\s*"[^"]{4,}"'
            }

            foreach ($text in $representations) {
                foreach ($entry in $patterns.GetEnumerator()) {
                    if ([regex]::IsMatch($text, $entry.Value)) {
                        $result.Add($entry.Key) | Out-Null
                    }
                }
            }
        }
        finally {
            if ($bytes.Length -gt 0) {
                [Array]::Clear($bytes, 0, $bytes.Length)
            }
        }
    }
    catch {
        $result.Add("Не удалось прочитать файл: " + $_.Exception.Message) | Out-Null
    }

    return @($result)
}

function Test-Acl {
    param(
        [string]$Path,
        [string]$Area
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Add-Finding "INFO" $Area "Объект не найден: $(Get-RelativeDisplayPath $Path)"
        return
    }

    try {
        $acl = Get-Acl -LiteralPath $Path
        $broadPattern = '(?i)(^|\\)(Everyone|Users|Authenticated Users|Guests|Все|Пользователи|Прошедшие проверку|Гости)$'
        $broad = @(
            $acl.Access | Where-Object {
                $_.AccessControlType -eq "Allow" -and
                $_.IdentityReference.Value -match $broadPattern
            }
        )

        if ($broad.Count -gt 0) {
            $identities = ($broad | ForEach-Object {
                $_.IdentityReference.Value
            } | Sort-Object -Unique) -join ", "

            Add-Finding "FAIL" $Area (
                "Обнаружены широкие разрешения: $identities. " +
                "Путь: $(Get-RelativeDisplayPath $Path)"
            )
        }
        else {
            Add-Finding "PASS" $Area (
                "Широких ACE для Everyone/Users/Authenticated Users/Guests не найдено. " +
                "Владелец: $($acl.Owner). Путь: $(Get-RelativeDisplayPath $Path)"
            )
        }
    }
    catch {
        Add-Finding "WARN" $Area (
            "Не удалось проверить ACL: $($_.Exception.Message). " +
            "Путь: $(Get-RelativeDisplayPath $Path)"
        )
    }
}

function Add-CandidateFile {
    param(
        [System.Collections.Generic.HashSet[string]]$Set,
        [string]$Path
    )

    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            $Set.Add([IO.Path]::GetFullPath($Path)) | Out-Null
        }
    }
    catch { }
}

function Add-FilesFromRoot {
    param(
        [System.Collections.Generic.HashSet[string]]$Set,
        [string]$Path,
        [switch]$AllFiles
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return
    }

    try {
        Get-ChildItem -LiteralPath $Path -File -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object {
                $AllFiles -or
                $_.Name -ieq "key-client.json" -or
                $_.Extension -in @(
                    ".json", ".txt", ".log", ".conf", ".config",
                    ".yaml", ".yml", ".xml", ".svault", ".sroutes",
                    ".serpiumenc", ".db", ".cache"
                )
            } |
            ForEach-Object {
                $Set.Add($_.FullName) | Out-Null
            }
    }
    catch { }
}

Write-Host "=== SerpiumVPN Security Audit v1.1 ===" -ForegroundColor Cyan
Write-Host "Проверка только читает файлы и создаёт безопасный отчёт." -ForegroundColor DarkGray
Write-Host ""

# 1. Process state.
$running = @(
    Get-Process -Name @("SerpiumVPN", "xray", "sing-box", "SerpiumNet") `
        -ErrorAction SilentlyContinue
)

if ($running.Count -eq 0) {
    Add-Finding "PASS" "Состояние процессов" (
        "SerpiumVPN, Xray, sing-box и SerpiumNet остановлены. " +
        "Проверка остаточных runtime-файлов достовернее."
    )
}
else {
    Add-Finding "WARN" "Состояние процессов" (
        "Во время аудита запущены: " +
        (($running | Select-Object -ExpandProperty ProcessName -Unique) -join ", ") +
        ". Повторите аудит после полного отключения и закрытия Serpium."
    )
}

$processesStopped = $running.Count -eq 0

# 2. Source-level DPAPI evidence.
$vaultSource = Get-ChildItem -LiteralPath $projectRoot `
    -Filter "SecureProfileVault.cs" -File -Recurse -ErrorAction SilentlyContinue |
    Select-Object -First 1
$routingSource = Get-ChildItem -LiteralPath $projectRoot `
    -Filter "SecureRoutingRegistry.cs" -File -Recurse -ErrorAction SilentlyContinue |
    Select-Object -First 1

foreach ($source in @($vaultSource, $routingSource)) {
    if ($null -eq $source) {
        continue
    }

    $text = [IO.File]::ReadAllText($source.FullName)
    $usesManagedDpapi = $text.Contains("ProtectedData.Protect")
    $usesNativeDpapi = $text.Contains("CryptProtectData")
    $hasManagedCurrentUser = $text.Contains("DataProtectionScope.CurrentUser")
    $usesMachineScope = (
        $text.Contains("DataProtectionScope.LocalMachine") -or
        $text.Contains("CRYPTPROTECT_LOCAL_MACHINE") -or
        $text.Contains("CryptProtectLocalMachine")
    )

    if ($usesManagedDpapi -and $hasManagedCurrentUser -and -not $usesMachineScope) {
        Add-Finding "PASS" "DPAPI в исходниках" (
            "$($source.Name): подтверждён Managed DPAPI CurrentUser."
        )
    }
    elseif ($usesNativeDpapi -and -not $usesMachineScope) {
        Add-Finding "PASS" "DPAPI в исходниках" (
            "$($source.Name): подтверждён CryptProtectData без флага LOCAL_MACHINE; " +
            "это пользовательская область Windows DPAPI."
        )
    }
    elseif (($usesManagedDpapi -or $usesNativeDpapi) -and $usesMachineScope) {
        Add-Finding "FAIL" "DPAPI в исходниках" (
            "$($source.Name): обнаружен признак машинной области DPAPI."
        )
    }
    else {
        Add-Finding "FAIL" "DPAPI в исходниках" (
            "$($source.Name): не найдены ProtectedData.Protect/CryptProtectData."
        )
    }
}

if ($null -eq $vaultSource) {
    Add-Finding "WARN" "DPAPI в исходниках" "SecureProfileVault.cs не найден."
}
if ($null -eq $routingSource) {
    Add-Finding "WARN" "DPAPI в исходниках" "SecureRoutingRegistry.cs не найден."
}

# 3. Known storage paths.
$localAppData = [Environment]::GetFolderPath("LocalApplicationData")
$appData = [Environment]::GetFolderPath("ApplicationData")

$vaultPath = Join-Path $localAppData "SerpiumVPN\Vault\profiles.svault"
$routingPath = Join-Path $localAppData "SerpiumVPN\Routing\routing.sroutes"
$vaultDirectory = Split-Path -Parent $vaultPath
$routingDirectory = Split-Path -Parent $routingPath
$runtimeDirectory = Join-Path $localAppData "SerpiumVPN\Runtime\Xray"
$runtimeConfigPath = Join-Path $runtimeDirectory "key-client.json"

foreach ($entry in @(
    @{ Path = $vaultPath; Area = "Vault plaintext scan" },
    @{ Path = $routingPath; Area = "Routing registry plaintext scan" }
)) {
    if (-not (Test-Path -LiteralPath $entry.Path -PathType Leaf)) {
        Add-Finding "INFO" $entry.Area "Файл не найден: $(Get-RelativeDisplayPath $entry.Path)"
        continue
    }

    $markers = @(Test-SensitiveMarkers -Path $entry.Path)
    $realMarkers = @($markers | Where-Object {
        $_ -notlike "Не удалось*" -and $_ -notlike "Файл больше*"
    })

    if ($realMarkers.Count -eq 0) {
        Add-Finding "PASS" $entry.Area (
            "В зашифрованном файле не найдены читаемые VPN URI, UUID, " +
            "Durev/Base64-префиксы или секретные поля. " +
            "Путь: $(Get-RelativeDisplayPath $entry.Path)"
        )
    }
    else {
        Add-Finding "FAIL" $entry.Area (
            "Найдены читаемые маркеры: $($realMarkers -join ', '). " +
            "Содержимое в отчёт не выводилось. " +
            "Путь: $(Get-RelativeDisplayPath $entry.Path)"
        )
    }
}

Test-Acl -Path $vaultDirectory -Area "ACL Vault"
Test-Acl -Path $routingDirectory -Area "ACL Routing"
Test-Acl -Path $runtimeDirectory -Area "ACL Runtime Xray"

if ($processesStopped -and (Test-Path -LiteralPath $runtimeConfigPath -PathType Leaf)) {
    Add-Finding "FAIL" "Private runtime cleanup" (
        "После остановки процессов остался приватный runtime-конфиг: " +
        "$(Get-RelativeDisplayPath $runtimeConfigPath)"
    )
}
elseif ($processesStopped) {
    Add-Finding "PASS" "Private runtime cleanup" (
        "В приватной Runtime\Xray папке key-client.json отсутствует."
    )
}

# 4. Runtime, logs, temp and diagnostics.
$candidates = [System.Collections.Generic.HashSet[string]]::new(
    [StringComparer]::OrdinalIgnoreCase)

Add-FilesFromRoot -Set $candidates -Path (Join-Path $localAppData "SerpiumVPN") -AllFiles
Add-FilesFromRoot -Set $candidates -Path (Join-Path $appData "SerpiumVPN") -AllFiles
Add-FilesFromRoot -Set $candidates -Path (Join-Path $projectRoot "bin")
Add-FilesFromRoot -Set $candidates -Path (Join-Path $projectRoot "bin_files\relay")
Add-FilesFromRoot -Set $candidates -Path (Join-Path $desktop "SerpiumVPN_Diagnostics")
Add-FilesFromRoot -Set $candidates -Path (Join-Path $desktop "SerpiumVPN_Backups")

try {
    Get-ChildItem -LiteralPath $env:TEMP -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "SerpiumVPN*" -or $_.Name -like "Serpium*" } |
        ForEach-Object {
            Add-FilesFromRoot -Set $candidates -Path $_.FullName
        }
}
catch { }

foreach ($file in $candidates) {
    if ($file -ieq $vaultPath -or $file -ieq $routingPath) {
        continue
    }

    $markers = @(Test-SensitiveMarkers -Path $file)
    $realMarkers = @($markers | Where-Object {
        $_ -notlike "Не удалось*" -and $_ -notlike "Файл больше*"
    })

    $isRuntimeConfig = [IO.Path]::GetFileName($file) -ieq "key-client.json" -or
        $file -match '(?i)\\relay\\configs\\'

    if ($isRuntimeConfig -and $processesStopped) {
        if ($realMarkers.Count -gt 0) {
            Add-Finding "FAIL" "Остаточный runtime-конфиг" (
                "После остановки процессов остался runtime-файл с чувствительными " +
                "маркерами: $($realMarkers -join ', '). " +
                "Путь: $(Get-RelativeDisplayPath $file)"
            )
        }
        else {
            Add-Finding "WARN" "Остаточный runtime-конфиг" (
                "После остановки процессов остался runtime-файл. Даже без найденных " +
                "маркеров его следует удалять после отключения. " +
                "Путь: $(Get-RelativeDisplayPath $file)"
            )
        }
        continue
    }

    if ($realMarkers.Count -gt 0) {
        $status = $isRuntimeConfig -and -not $processesStopped ? "WARN" : "FAIL"
        Add-Finding $status "Plaintext вне Vault" (
            "Найдены чувствительные маркеры: $($realMarkers -join ', '). " +
            "Содержимое в отчёт не выводилось. " +
            "Путь: $(Get-RelativeDisplayPath $file)"
        )
    }
}

# 5. Explicit known runtime config lookup.
$keyConfigs = @(
    Get-ChildItem -LiteralPath $projectRoot -Filter "key-client.json" `
        -File -Recurse -Force -ErrorAction SilentlyContinue
)

if ($keyConfigs.Count -eq 0) {
    Add-Finding "PASS" "key-client.json cleanup" (
        "В дереве проекта key-client.json не найден."
    )
}
elseif ($processesStopped) {
    Add-Finding "FAIL" "key-client.json cleanup" (
        "Serpium/Xray остановлены, но найдено файлов key-client.json: " +
        $keyConfigs.Count + "."
    )
}
else {
    Add-Finding "WARN" "key-client.json cleanup" (
        "Во время активного подключения найден key-client.json: " +
        $keyConfigs.Count +
        ". Проверьте повторно после отключения и полного выхода."
    )
}

# 6. Build safe report.
$failCount = @($findings | Where-Object Status -eq "FAIL").Count
$warnCount = @($findings | Where-Object Status -eq "WARN").Count
$passCount = @($findings | Where-Object Status -eq "PASS").Count

$overall = if ($failCount -gt 0) {
    "FAIL — обнаружены проблемы, требующие исправления"
}
elseif ($warnCount -gt 0) {
    "WARN — явной утечки не доказано, но остались проверки/риски"
}
else {
    "PASS — базовые автоматические проверки пройдены"
}

$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add("SerpiumVPN Security Audit v1.1")
$lines.Add("Created: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')")
$lines.Add("Project: $projectRoot")
$lines.Add("")
$lines.Add("RESULT: $overall")
$lines.Add("PASS: $passCount | WARN: $warnCount | FAIL: $failCount")
$lines.Add("")
$lines.Add("Важно: отчёт никогда не включает найденные ключи, UUID или содержимое файлов.")
$lines.Add("Аудит v1.1 не считает обычные manifest-поля "id" секретами. Автотест не заменяет cross-account тест и проверку памяти активного процесса.")
$lines.Add("")

foreach ($group in $findings | Group-Object Status) {
    $lines.Add("=== $($group.Name) ===")
    foreach ($finding in $group.Group) {
        $lines.Add("[$($finding.Area)] $($finding.Details)")
    }
    $lines.Add("")
}

$lines.Add("=== Ручной обязательный тест DPAPI ===")
$lines.Add("1. Полностью отключите и закройте Serpium.")
$lines.Add("2. Скопируйте profiles.svault в отдельную тестовую учётную запись Windows.")
$lines.Add("3. Запустите Serpium под этой учётной записью.")
$lines.Add("4. Сохранённые профили не должны расшифроваться или появиться.")
$lines.Add("5. Возврат профилей под исходной учётной записью должен работать.")
$lines.Add("")
$lines.Add("=== Ограничение модели угроз ===")
$lines.Add("DPAPI CurrentUser защищает файл от другой обычной учётной записи и простого")
$lines.Add("копирования, но не от вредоносного процесса, уже работающего от имени того")
$lines.Add("же пользователя, администратора или дампа памяти во время подключения.")

[IO.File]::WriteAllLines(
    $reportPath,
    $lines,
    (New-Object Text.UTF8Encoding($true))
)

Write-Host ""
Write-Host "Результат: $overall" -ForegroundColor $(
    if ($failCount -gt 0) { "Red" }
    elseif ($warnCount -gt 0) { "Yellow" }
    else { "Green" }
)
Write-Host "PASS: $passCount | WARN: $warnCount | FAIL: $failCount"
Write-Host "Безопасный отчёт: $reportPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "Ключи и совпавшие строки в консоль и отчёт не выводились." -ForegroundColor DarkGray
