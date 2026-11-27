$ErrorActionPreference='Stop'
Push-Location -LiteralPath $PSScriptRoot
try {
    & go mod verify
    if($LASTEXITCODE -ne 0){throw 'Outline dependency verification failed.'}
    & go test ./...
    if($LASTEXITCODE -ne 0){throw 'Outline transport checks failed.'}
    $env:CGO_ENABLED='0'
    & go build -trimpath -buildvcs=false -ldflags '-s -w' -o ../../bin_files/relay/Serpium.Outline.exe .
    if($LASTEXITCODE -ne 0){throw 'Outline transport build failed.'}
} finally { Pop-Location }
