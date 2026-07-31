$ErrorActionPreference = "Continue"

$Out = Join-Path $PSScriptRoot "Serpium_Headscale_Preflight.txt"
$lines = New-Object System.Collections.Generic.List[string]

function Add-Line([string]$Text = "") {
    $lines.Add($Text)
    Write-Host $Text
}

function Test-Command([string]$Name) {
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -eq $cmd) {
        Add-Line "[NO]  $Name"
        return $false
    }

    Add-Line "[OK]  $Name -> $($cmd.Source)"
    return $true
}

Add-Line "=== Serpium Coordinator / Headscale preflight ==="
Add-Line "Date: $(Get-Date -Format o)"
Add-Line "Computer: $env:COMPUTERNAME"
Add-Line "User: $env:USERNAME"
Add-Line ""

$hasDocker = Test-Command "docker"
$hasWsl = Test-Command "wsl"
$hasGit = Test-Command "git"
$hasGo = Test-Command "go"
$hasCurl = Test-Command "curl.exe"

Add-Line ""

if ($hasDocker) {
    Add-Line "--- Docker ---"
    try {
        $dockerVersion = docker version --format '{{.Server.Version}}' 2>&1
        if ($LASTEXITCODE -eq 0) {
            Add-Line "[OK] Docker daemon: $dockerVersion"
        } else {
            Add-Line "[WARN] Docker CLI найден, но daemon недоступен:"
            Add-Line ($dockerVersion | Out-String)
        }
    } catch {
        Add-Line "[WARN] Docker check failed: $($_.Exception.Message)"
    }
    Add-Line ""
}

if ($hasWsl) {
    Add-Line "--- WSL ---"
    try {
        $wslStatus = wsl --status 2>&1
        Add-Line ($wslStatus | Out-String)
        $distros = wsl -l -q 2>&1
        Add-Line "Distributions:"
        Add-Line ($distros | Out-String)
    } catch {
        Add-Line "[WARN] WSL check failed: $($_.Exception.Message)"
    }
    Add-Line ""
}

if ($hasGo) {
    Add-Line "--- Go ---"
    try {
        Add-Line ((go version 2>&1) | Out-String)
    } catch {
        Add-Line "[WARN] Go check failed: $($_.Exception.Message)"
    }
    Add-Line ""
}

Add-Line "--- Ports ---"
foreach ($port in 8080, 9090, 3478) {
    try {
        $used = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
        if ($used) {
            Add-Line "[BUSY] TCP $port"
        } else {
            Add-Line "[FREE] TCP $port"
        }
    } catch {
        Add-Line "[INFO] TCP $port could not be checked"
    }
}

try {
    $udp3478 = Get-NetUDPEndpoint -LocalPort 3478 -ErrorAction SilentlyContinue
    if ($udp3478) {
        Add-Line "[BUSY] UDP 3478"
    } else {
        Add-Line "[FREE] UDP 3478"
    }
} catch {
    Add-Line "[INFO] UDP 3478 could not be checked"
}

Add-Line ""
Add-Line "--- Recommendation ---"

if ($hasDocker) {
    try {
        docker info *> $null
        if ($LASTEXITCODE -eq 0) {
            Add-Line "RESULT: READY_DOCKER"
            Add-Line "Можно запускать локальный Headscale MVP через Docker Compose."
        } elseif ($hasWsl) {
            Add-Line "RESULT: READY_WSL"
            Add-Line "Docker daemon не запущен, но WSL доступен. Можно развернуть Headscale внутри WSL."
        } else {
            Add-Line "RESULT: DOCKER_NOT_RUNNING"
            Add-Line "Запусти Docker Desktop либо установи WSL."
        }
    } catch {
        Add-Line "RESULT: DOCKER_CHECK_FAILED"
    }
} elseif ($hasWsl) {
    Add-Line "RESULT: READY_WSL"
    Add-Line "Можно развернуть Headscale внутри WSL."
} else {
    Add-Line "RESULT: NEED_RUNTIME"
    Add-Line "Нужен Docker Desktop или WSL2 для локального тестового Headscale."
}

Add-Line ""
Add-Line "Важно: локальный сервер подойдёт для первого теста на одном ПК/локальной сети."
Add-Line "Для соединения устройств из разных сетей позже понадобится публично доступный сервер или туннель."

$lines | Set-Content -Path $Out -Encoding UTF8
Write-Host ""
Write-Host "Saved: $Out"
