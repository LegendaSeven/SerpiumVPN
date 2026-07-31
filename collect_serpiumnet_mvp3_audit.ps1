param(
    [string]$ProjectRoot = (Get-Location).Path,
    [string]$OutputDirectory = "$env:USERPROFILE\Desktop"
)

$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path $ProjectRoot).Path
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$archiveName = "SerpiumNet_MVP3_Audit_$timestamp.zip"
$outputZip = Join-Path $OutputDirectory $archiveName
$tempRoot = Join-Path $env:TEMP "SerpiumNet_MVP3_Audit_$timestamp"
$payloadRoot = Join-Path $tempRoot "SerpiumVPN"

$requiredFiles = @(
    "MainWindow.xaml",
    "MainWindow.xaml.cs",
    "SerpiumVPN.csproj",
    "App.xaml",
    "App.xaml.cs",

    "Relay\TailscaleManager.cs",
    "Relay\SerpiumNetManager.cs",
    "Relay\SerpiumNetAuthWindow.cs",
    "Relay\SerpiumNetAuthWindow.xaml",
    "Relay\SerpiumNetAuthWindow.xaml.cs",
    "Relay\XrayGatewayManager.cs",
    "Relay\XrayClientManager.cs",
    "Relay\RelayGatewayState.cs",
    "Relay\RelayStatus.cs",
    "Relay\RelayTransport.cs",
    "Relay\RelayKey.cs",
    "Relay\RelayKeyBuilder.cs",
    "Relay\RelayKeyParser.cs",
    "Relay\RelayConnectionProbe.cs",
    "Relay\XrayGatewayConfigBuilder.cs",
    "Relay\XrayClientConfigBuilder.cs",

    "SerpiumNet\main.go",
    "SerpiumNet\go.mod",
    "SerpiumNet\go.sum"
)

function Copy-WithStructure {
    param(
        [Parameter(Mandatory = $true)][string]$RelativePath
    )

    $source = Join-Path $ProjectRoot $RelativePath
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        return $false
    }

    $destination = Join-Path $payloadRoot $RelativePath
    $destinationDirectory = Split-Path $destination -Parent
    New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
    Copy-Item -LiteralPath $source -Destination $destination -Force
    return $true
}

try {
    Write-Host "=== SerpiumNet MVP3 audit collector ===" -ForegroundColor Cyan
    Write-Host "Project root: $ProjectRoot"

    if (-not (Test-Path -LiteralPath (Join-Path $ProjectRoot "SerpiumVPN.csproj"))) {
        throw "SerpiumVPN.csproj не найден. Запусти скрипт из корня проекта или передай -ProjectRoot."
    }

    Remove-Item $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $payloadRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

    $copied = New-Object System.Collections.Generic.List[string]
    $missing = New-Object System.Collections.Generic.List[string]

    foreach ($relativePath in $requiredFiles) {
        if (Copy-WithStructure -RelativePath $relativePath) {
            $copied.Add($relativePath)
            Write-Host "[OK]      $relativePath" -ForegroundColor Green
        }
        else {
            $missing.Add($relativePath)
            Write-Host "[MISSING] $relativePath" -ForegroundColor Yellow
        }
    }

    $info = @()
    $info += "SerpiumNet MVP3 audit"
    $info += "Created: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $info += "Project root: $ProjectRoot"
    $info += ""
    $info += "COPIED FILES:"
    $info += $copied
    $info += ""
    $info += "MISSING / NOT PRESENT:"
    $info += $missing
    $info | Set-Content (Join-Path $payloadRoot "AUDIT_INFO.txt") -Encoding UTF8

    if (Test-Path -LiteralPath $outputZip) {
        Remove-Item -LiteralPath $outputZip -Force
    }

    Compress-Archive -Path (Join-Path $tempRoot "*") -DestinationPath $outputZip -CompressionLevel Optimal

    Write-Host ""
    Write-Host "ARCHIVE RESULT: OK" -ForegroundColor Green
    Write-Host "Archive: $outputZip" -ForegroundColor Cyan
    Write-Host "Copied: $($copied.Count)"
    Write-Host "Missing: $($missing.Count)"
}
catch {
    Write-Host ""
    Write-Host "ARCHIVE RESULT: FAILED" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
finally {
    Remove-Item $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
