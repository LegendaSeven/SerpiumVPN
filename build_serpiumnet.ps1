param(
    [string]$ProjectRoot = (Split-Path -Parent $MyInvocation.MyCommand.Path),
    [switch]$SkipTidy
)

$ErrorActionPreference = 'Stop'
$netDir = Join-Path $ProjectRoot 'SerpiumNet'
$outDir = Join-Path $ProjectRoot 'bin_files\relay'
$outExe = Join-Path $outDir 'SerpiumNet.exe'

if (-not (Test-Path (Join-Path $netDir 'go.mod'))) {
    throw "SerpiumNet/go.mod не найден: $netDir"
}

$go = Get-Command go -ErrorAction Stop
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

Push-Location $netDir
try {
    if (-not $SkipTidy) {
        & $go.Source mod tidy
        if ($LASTEXITCODE -ne 0) { throw "go mod tidy завершился с кодом $LASTEXITCODE" }
    }

    & $go.Source build -trimpath -ldflags '-s -w' -o $outExe .
    if ($LASTEXITCODE -ne 0) { throw "go build завершился с кодом $LASTEXITCODE" }
}
finally {
    Pop-Location
}

if (-not (Test-Path $outExe)) { throw "SerpiumNet.exe не создан" }
Write-Host "SerpiumNet собран: $outExe" -ForegroundColor Green
& $outExe version
