param(
    [string]$Output = "$env:USERPROFILE\Desktop\SerpiumNet_tsnet_preflight.txt"
)

$ErrorActionPreference = "Stop"
$work = Join-Path $env:TEMP "SerpiumNet_tsnet_preflight"

Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $work | Out-Null
Set-Location $work

$log = New-Object System.Collections.Generic.List[string]

function Add-Log([string]$text) {
    $log.Add($text)
    Write-Host $text
}

try {
    Add-Log "=== SerpiumNet / tsnet preflight ==="
    Add-Log "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Add-Log ""

    $go = Get-Command go -ErrorAction Stop
    Add-Log "Go path: $($go.Source)"
    Add-Log ((& $go.Source version 2>&1) | Out-String).Trim()
    Add-Log ""

    @'
package main

import (
    "fmt"
    "tailscale.com/tsnet"
)

func main() {
    s := &tsnet.Server{
        Hostname: "serpium-preflight",
        Dir:      "./state",
    }
    fmt.Printf("tsnet ready: %T\n", s)
}
'@ | Set-Content (Join-Path $work "main.go") -Encoding UTF8

    & $go.Source mod init serpium.local/preflight 2>&1 |
        ForEach-Object { Add-Log $_ }

    Add-Log ""
    Add-Log "Downloading tsnet dependency..."
    & $go.Source get tailscale.com/tsnet@latest 2>&1 |
        ForEach-Object { Add-Log $_ }

    if ($LASTEXITCODE -ne 0) {
        throw "go get завершился с кодом $LASTEXITCODE"
    }

    Add-Log ""
    Add-Log "Building test helper..."
    & $go.Source build -trimpath -o (Join-Path $work "SerpiumNetPreflight.exe") . 2>&1 |
        ForEach-Object { Add-Log $_ }

    if ($LASTEXITCODE -ne 0) {
        throw "go build завершился с кодом $LASTEXITCODE"
    }

    $exe = Join-Path $work "SerpiumNetPreflight.exe"
    Add-Log ""
    Add-Log "Running test helper..."
    & $exe 2>&1 | ForEach-Object { Add-Log $_ }

    Add-Log ""
    Add-Log "RESULT: OK"
    Add-Log "Go и tsnet готовы к сборке SerpiumNet."
}
catch {
    Add-Log ""
    Add-Log "RESULT: FAILED"
    Add-Log $_.Exception.Message
}
finally {
    $log | Set-Content $Output -Encoding UTF8
    Write-Host ""
    Write-Host "Отчёт сохранён:" -ForegroundColor Cyan
    Write-Host $Output -ForegroundColor Cyan
}
