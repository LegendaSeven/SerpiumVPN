#requires -version 5.1
[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [Parameter(Mandatory = $true)]
    [ValidateSet("RUN")]
    [string]$ConfirmLifecycle
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "wfp2_common.ps1")

Assert-Wfp2Administrator

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$stage = Join-Path $env:TEMP ("Serpium_WFP2_Lifecycle_" + $stamp)
New-Item -ItemType Directory -Path $stage -Force | Out-Null

$report = New-Object 'System.Collections.Generic.List[string]'
$failure = $null
$driverCreated = $false
$userServiceCreated = $false
$runtimeMutationStarted = $false
$runId = [guid]::NewGuid().ToString("N")
$installRoot = Get-Wfp2InstallRoot
$driverTarget = Join-Path $installRoot "Driver\Serpium.Flow.Driver.sys"
$serviceTarget = Join-Path $installRoot "Service\Serpium.Flow.Service.exe"
$ownershipMarker = Join-Path $installRoot "WFP2_INSTALL_STATE.json"
$serviceLog = Get-Wfp2ServiceLogPath
$programDataFlowRoot = Split-Path -Parent $serviceLog
$programDataSerpiumRoot = Split-Path -Parent $programDataFlowRoot
$programDataFlowExistedBefore = Test-Path -LiteralPath $programDataFlowRoot
$programDataSerpiumExistedBefore = Test-Path -LiteralPath $programDataSerpiumRoot
$state = $null
$stateIdentity = $null

function Test-Wfp2ServicePathOwned {
    param(
        [AllowNull()]
        [object]$Record,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedPath
    )

    if ($null -eq $Record) {
        return $false
    }

    $actual = [string]$Record.PathName
    return $actual.IndexOf($ExpectedPath, [StringComparison]::OrdinalIgnoreCase) -ge 0
}

function Remove-Wfp2OwnedInstallRoot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExpectedRunId
    )

    if (-not (Test-Path -LiteralPath $installRoot -PathType Container)) {
        return
    }

    if (-not (Test-Path -LiteralPath $ownershipMarker -PathType Leaf)) {
        throw "Install root exists without the WFP-2 ownership marker: $installRoot"
    }

    $marker = Get-Content -LiteralPath $ownershipMarker -Raw | ConvertFrom-Json

    if ([string]$marker.runId -ne $ExpectedRunId) {
        throw "Install ownership marker does not match this lifecycle run."
    }

    Remove-Item -LiteralPath $installRoot -Recurse -Force -ErrorAction Stop
}

function Remove-Wfp2OwnedEmptyTelemetryDirectories {
    if (-not $programDataFlowExistedBefore -and (Test-Path -LiteralPath $programDataFlowRoot -PathType Container)) {
        $flowChildren = @(Get-ChildItem -LiteralPath $programDataFlowRoot -Force -ErrorAction Stop)

        if ($flowChildren.Count -eq 0) {
            Remove-Item -LiteralPath $programDataFlowRoot -Force -ErrorAction Stop
        }
    }

    if (-not $programDataSerpiumExistedBefore -and (Test-Path -LiteralPath $programDataSerpiumRoot -PathType Container)) {
        $serpiumChildren = @(Get-ChildItem -LiteralPath $programDataSerpiumRoot -Force -ErrorAction Stop)

        if ($serpiumChildren.Count -eq 0) {
            Remove-Item -LiteralPath $programDataSerpiumRoot -Force -ErrorAction Stop
        }
    }
}

function Read-Wfp2ExactBytes {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.Stream]$Stream,

        [Parameter(Mandatory = $true)]
        [int]$Count
    )

    [byte[]]$buffer = New-Object byte[] $Count
    $offset = 0

    while ($offset -lt $Count) {
        $read = $Stream.Read($buffer, $offset, ($Count - $offset))

        if ($read -le 0) {
            throw "Loopback stream closed before the complete test payload was received."
        }

        $offset += $read
    }

    Write-Output -NoEnumerate $buffer
}

function Test-Wfp2ByteArraysEqual {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Left,

        [Parameter(Mandatory = $true)]
        [byte[]]$Right
    )

    if ($Left.Length -ne $Right.Length) {
        return $false
    }

    for ($index = 0; $index -lt $Left.Length; $index++) {
        if ($Left[$index] -ne $Right[$index]) {
            return $false
        }
    }

    return $true
}

function Invoke-Wfp2LoopbackRoundTrip {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("V4", "V6")]
        [string]$Family
    )

    $address = if ($Family -eq "V4") { [Net.IPAddress]::Loopback } else { [Net.IPAddress]::IPv6Loopback }
    $addressFamily = if ($Family -eq "V4") { [Net.Sockets.AddressFamily]::InterNetwork } else { [Net.Sockets.AddressFamily]::InterNetworkV6 }
    $listener = New-Object Net.Sockets.TcpListener -ArgumentList $address, 0
    $client = $null
    $server = $null

    try {
        $listener.Start(1)
        $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
        $acceptTask = $listener.AcceptTcpClientAsync()
        $client = New-Object Net.Sockets.TcpClient -ArgumentList $addressFamily
        $client.Connect($address, $port)
        $server = $acceptTask.GetAwaiter().GetResult()

        $token = "SERPIUM-WFP2-" + $Family + "-" + [guid]::NewGuid().ToString("N")
        [byte[]]$payload = [Text.Encoding]::UTF8.GetBytes($token)
        $clientStream = $client.GetStream()
        $serverStream = $server.GetStream()

        $clientStream.Write($payload, 0, $payload.Length)
        $clientStream.Flush()
        [byte[]]$received = Read-Wfp2ExactBytes -Stream $serverStream -Count $payload.Length

        if (-not (Test-Wfp2ByteArraysEqual -Left $payload -Right $received)) {
            throw "$Family loopback server received modified bytes."
        }

        $serverStream.Write($received, 0, $received.Length)
        $serverStream.Flush()
        [byte[]]$echo = Read-Wfp2ExactBytes -Stream $clientStream -Count $payload.Length

        if (-not (Test-Wfp2ByteArraysEqual -Left $payload -Right $echo)) {
            throw "$Family loopback client received modified bytes."
        }

        $algorithm = [Security.Cryptography.SHA256]::Create()

        try {
            $payloadSha256 = [BitConverter]::ToString($algorithm.ComputeHash($payload)).Replace("-", "").ToLowerInvariant()
        }
        finally {
            $algorithm.Dispose()
        }

        return [pscustomobject]@{
            Family = $Family
            Port = $port
            PayloadLength = $payload.Length
            PayloadSha256 = $payloadSha256
            RoundTrip = $true
        }
    }
    finally {
        if ($null -ne $server) {
            $server.Dispose()
        }

        if ($null -ne $client) {
            $client.Dispose()
        }

        $listener.Stop()
    }
}

function Invoke-Wfp2LifecycleRollback {
    $rollbackLines = New-Object 'System.Collections.Generic.List[string]'

    try {
        $userRecord = Get-Wfp2UserService

        if ($null -ne $userRecord) {
            if (-not (Test-Wfp2ServicePathOwned -Record $userRecord -ExpectedPath $serviceTarget)) {
                throw "Refusing to remove SerpiumFlowService because its binary path is not owned by this run."
            }

            if (Test-Path -LiteralPath $serviceTarget -PathType Leaf) {
                Invoke-Wfp2Native -FilePath $serviceTarget -Arguments @("stop") -LogPath (Join-Path $stage "rollback-user-stop.log") -AllowFailure | Out-Null
                Invoke-Wfp2Native -FilePath $serviceTarget -Arguments @("uninstall") -LogPath (Join-Path $stage "rollback-user-delete.log") -AllowFailure | Out-Null
            }
            else {
                $sc = Join-Path $env:SystemRoot "System32\sc.exe"
                Invoke-Wfp2Native -FilePath $sc -Arguments @("stop", $script:Wfp2UserServiceName) -LogPath (Join-Path $stage "rollback-user-stop.log") -AllowFailure | Out-Null
                Invoke-Wfp2Native -FilePath $sc -Arguments @("delete", $script:Wfp2UserServiceName) -LogPath (Join-Path $stage "rollback-user-delete.log") -AllowFailure | Out-Null
            }

            Wait-Wfp2ServiceState -Kind User -State Absent -TimeoutSeconds 20
        }

        $rollbackLines.Add("UserServiceRollback: PASS")
    }
    catch {
        $rollbackLines.Add("UserServiceRollback: FAIL - " + $_.Exception.Message)
    }

    try {
        $driverRecord = Get-Wfp2DriverService

        if ($null -ne $driverRecord) {
            if (-not (Test-Wfp2ServicePathOwned -Record $driverRecord -ExpectedPath $driverTarget)) {
                throw "Refusing to remove SerpiumFlow because its binary path is not owned by this run."
            }

            $sc = Join-Path $env:SystemRoot "System32\sc.exe"
            Invoke-Wfp2Native -FilePath $sc -Arguments @("stop", $script:Wfp2DriverServiceName) -LogPath (Join-Path $stage "rollback-driver-stop.log") -AllowFailure | Out-Null
            Invoke-Wfp2Native -FilePath $sc -Arguments @("delete", $script:Wfp2DriverServiceName) -LogPath (Join-Path $stage "rollback-driver-delete.log") -AllowFailure | Out-Null
            Wait-Wfp2ServiceState -Kind Driver -State Absent -TimeoutSeconds 20
        }

        $rollbackLines.Add("DriverServiceRollback: PASS")
    }
    catch {
        $rollbackLines.Add("DriverServiceRollback: FAIL - " + $_.Exception.Message)
    }

    try {
        Remove-Wfp2OwnedInstallRoot -ExpectedRunId $runId
        $rollbackLines.Add("InstallFilesRollback: PASS")
    }
    catch {
        $rollbackLines.Add("InstallFilesRollback: FAIL - " + $_.Exception.Message)
    }

    try {
        if (Test-Path -LiteralPath $serviceLog) {
            Remove-Item -LiteralPath $serviceLog -Force -ErrorAction Stop
        }

        if (Test-Path -LiteralPath $serviceLog) {
            throw "Service log still exists after rollback."
        }

        Remove-Wfp2OwnedEmptyTelemetryDirectories

        $rollbackLines.Add("ServiceLogRollback: PASS")
    }
    catch {
        $rollbackLines.Add("ServiceLogRollback: FAIL - " + $_.Exception.Message)
    }

    try {
        $wfp = Get-Wfp2WfpNameSummary

        if (-not $wfp.Available -or $wfp.MatchCount -ne 0) {
            throw "Serpium WFP objects remain after driver rollback."
        }

        $rollbackLines.Add("WfpObjectsRollback: PASS")
    }
    catch {
        $rollbackLines.Add("WfpObjectsRollback: FAIL - " + $_.Exception.Message)
    }

    return $rollbackLines.ToArray()
}

try {
    $state = Get-Wfp2State

    if ($null -eq $state) {
        throw "WFP-2 state is missing. Run prepare_wfp2_test_package.ps1 first."
    }

    $stateIdentity = Assert-Wfp2StateIdentity -State $state

    if ([int]$state.schema -ne 2 -or [string]$state.configuration -ne $Configuration) {
        throw "WFP-2 state does not match schema 2 and configuration $Configuration."
    }

    if ([string]$state.stage -notin @("TestSigningConfigured", "TestSigningActive")) {
        throw "WFP-2 state is not ready for lifecycle testing (stage: $($state.stage))."
    }

    $secureBoot = Get-Wfp2SecureBootState

    if ($secureBoot.State -ne "Disabled") {
        throw "Secure Boot must be Disabled for this test (actual: $($secureBoot.State))."
    }

    $codeIntegrity = Get-Wfp2CodeIntegrityState

    if (-not $codeIntegrity.Available -or -not $codeIntegrity.TestSigningRuntime) {
        throw "Windows Test Signing is not active in the current boot. Run enable_wfp2_testsigning.ps1 and reboot first."
    }

    $bfe = Get-Service -Name "BFE" -ErrorAction SilentlyContinue

    if ($null -eq $bfe -or [string]$bfe.Status -ne "Running") {
        throw "Base Filtering Engine is not running."
    }

    Assert-Wfp2ServicesAbsent

    if (Test-Path -LiteralPath $installRoot) {
        throw "The isolated WFP-2 install root already exists: $installRoot"
    }

    if (Test-Path -LiteralPath $serviceLog) {
        throw "A pre-existing service log would be modified by the WFP-2 lifecycle test: $serviceLog"
    }

    $packageResult = Test-Wfp2UnsignedPackage -Configuration $Configuration
    $signedDirectory = [string]$stateIdentity.SignedPackageDirectory
    $signedManifestPath = Join-Path $signedDirectory "WFP2_SIGNING_MANIFEST.json"

    if (-not (Test-Path -LiteralPath $signedManifestPath -PathType Leaf)) {
        throw "Signed package manifest is missing: $signedManifestPath"
    }

    $signedManifest = Get-Content -LiteralPath $signedManifestPath -Raw | ConvertFrom-Json

    if (
        [int]$signedManifest.schema -ne 2 -or
        [string]$signedManifest.runId -ne [string]$state.runId -or
        [string]$signedManifest.configuration -ne $Configuration -or
        -not [bool]$signedManifest.wfpEnabled -or
        [string]$signedManifest.wfpMode -ne "observe-only" -or
        [string]$signedManifest.filterAction -ne "FWP_ACTION_CALLOUT_INSPECTION" -or
        [string]$signedManifest.classifyAction -ne "FWP_ACTION_CONTINUE" -or
        [bool]$signedManifest.trafficModification -or
        [bool]$signedManifest.blockingEnabled -or
        [bool]$signedManifest.redirectEnabled
    ) {
        throw "Signed package manifest violates the WFP-2 observe-only contract."
    }

    [string[]]$layers = @($signedManifest.wfpLayers | ForEach-Object { [string]$_ })

    if (
        $layers.Count -ne 2 -or
        $layers -notcontains "ALE_AUTH_CONNECT_V4" -or
        $layers -notcontains "ALE_AUTH_CONNECT_V6"
    ) {
        throw "Signed package manifest does not contain exactly the V4/V6 ALE connect layers."
    }

    $buildManifestPath = Join-Path $signedDirectory "BUILD_MANIFEST.json"

    if ((Get-FileHash -LiteralPath $buildManifestPath -Algorithm SHA256).Hash -ine [string]$signedManifest.sourceBuildManifestSha256) {
        throw "Signed package build manifest hash mismatch."
    }

    $currentBuildManifestPath = Join-Path $packageResult.PackageDirectory "BUILD_MANIFEST.json"

    if ((Get-FileHash -LiteralPath $currentBuildManifestPath -Algorithm SHA256).Hash -ine [string]$signedManifest.sourceBuildManifestSha256) {
        throw "The unsigned build package changed after WFP-2 preparation."
    }

    $driverSource = Join-Path $signedDirectory "Serpium.Flow.Driver.sys"
    $serviceSource = Join-Path $signedDirectory "Serpium.Flow.Service.exe"
    $catalogSource = Join-Path $signedDirectory "Serpium.Flow.Driver.cat"
    $infSource = Join-Path $signedDirectory "Serpium.Flow.Driver.inf"
    $certificateSource = Join-Path $signedDirectory "Serpium.Flow.WFP2.Test.cer"

    $hashChecks = @(
        [pscustomobject]@{ Path = $driverSource; Expected = [string]$signedManifest.package.driverSha256 },
        [pscustomobject]@{ Path = $serviceSource; Expected = [string]$signedManifest.package.serviceSha256 },
        [pscustomobject]@{ Path = $catalogSource; Expected = [string]$signedManifest.package.catalogSha256 },
        [pscustomobject]@{ Path = $infSource; Expected = [string]$signedManifest.package.infSha256 }
    )

    foreach ($check in $hashChecks) {
        if (-not (Test-Path -LiteralPath $check.Path -PathType Leaf)) {
            throw "Signed package file is missing: $($check.Path)"
        }

        $actual = (Get-FileHash -LiteralPath $check.Path -Algorithm SHA256).Hash

        if ($actual -ine $check.Expected) {
            throw "Signed package hash mismatch: $($check.Path)"
        }
    }

    if (-not (Test-Path -LiteralPath $certificateSource -PathType Leaf)) {
        throw "Exported WFP-2 test certificate is missing."
    }

    $certificateThumbprint = [string]$state.certificateThumbprint

    if ([string]$signedManifest.certificate.thumbprint -ine $certificateThumbprint) {
        throw "Signed manifest certificate thumbprint does not match WFP-2 state."
    }

    foreach ($store in @("My", "Root", "TrustedPublisher")) {
        if (-not (Test-Path -LiteralPath ("Cert:\LocalMachine\$store\" + $certificateThumbprint))) {
            throw "WFP-2 certificate is missing from LocalMachine\$store."
        }
    }

    $buildManifest = Get-Content -LiteralPath $buildManifestPath -Raw | ConvertFrom-Json
    $signTool = Find-Wfp2SdkTool -Name "signtool.exe" -PreferredVersion ([string]$buildManifest.sdkWdkVersion)

    Invoke-Wfp2Native -FilePath $signTool -Arguments @("verify", "/pa", "/ph", "/v", $driverSource) -LogPath (Join-Path $stage "01-verify-driver.log") | Out-Null
    Invoke-Wfp2Native -FilePath $signTool -Arguments @("verify", "/pa", "/v", $catalogSource) -LogPath (Join-Path $stage "02-verify-catalog.log") | Out-Null
    Invoke-Wfp2Native -FilePath $signTool -Arguments @("verify", "/pa", "/v", $serviceSource) -LogPath (Join-Path $stage "03-verify-service.log") | Out-Null
    Invoke-Wfp2Native -FilePath $signTool -Arguments @("verify", "/pa", "/v", "/c", $catalogSource, $driverSource) -LogPath (Join-Path $stage "04-verify-catalog-membership.log") | Out-Null

    Assert-Wfp2TestSigner -Path $driverSource -ExpectedThumbprint $certificateThumbprint
    Assert-Wfp2TestSigner -Path $serviceSource -ExpectedThumbprint $certificateThumbprint

    $wfpBefore = Get-Wfp2WfpNameSummary

    if (-not $wfpBefore.Available -or $wfpBefore.MatchCount -ne 0) {
        throw "WFP state is not clean before lifecycle installation."
    }

    try {
        Write-Wfp2JsonFile -Path $ownershipMarker -Value ([ordered]@{
            schema = 2
            runId = $runId
            createdUtc = (Get-Date).ToUniversalTime().ToString("o")
            stage = "Initialized"
        }) -Depth 5
    }
    catch {
        Remove-Item -LiteralPath $installRoot -Recurse -Force -ErrorAction SilentlyContinue
        throw
    }

    $runtimeMutationStarted = $true
    New-Item -ItemType Directory -Path (Split-Path -Parent $driverTarget) -Force | Out-Null
    New-Item -ItemType Directory -Path (Split-Path -Parent $serviceTarget) -Force | Out-Null

    Copy-Item -LiteralPath $driverSource -Destination $driverTarget -Force
    Copy-Item -LiteralPath $serviceSource -Destination $serviceTarget -Force
    Copy-Item -LiteralPath $catalogSource -Destination (Join-Path $installRoot "Driver\Serpium.Flow.Driver.cat") -Force
    Copy-Item -LiteralPath $infSource -Destination (Join-Path $installRoot "Driver\Serpium.Flow.Driver.inf") -Force
    Copy-Item -LiteralPath $certificateSource -Destination (Join-Path $installRoot "Driver\Serpium.Flow.WFP2.Test.cer") -Force

    Write-Wfp2JsonFile -Path $ownershipMarker -Value ([ordered]@{
        schema = 2
        runId = $runId
        createdUtc = (Get-Date).ToUniversalTime().ToString("o")
        stage = "InstalledFiles"
        driverSha256 = (Get-FileHash -LiteralPath $driverTarget -Algorithm SHA256).Hash.ToLowerInvariant()
        serviceSha256 = (Get-FileHash -LiteralPath $serviceTarget -Algorithm SHA256).Hash.ToLowerInvariant()
    }) -Depth 5

    $state.installRunId = $runId
    $state.stage = "LifecycleRunning"
    $state.programDataFlowExistedBefore = [bool]$programDataFlowExistedBefore
    $state.programDataSerpiumExistedBefore = [bool]$programDataSerpiumExistedBefore
    Save-Wfp2State -State $state

    $sc = Join-Path $env:SystemRoot "System32\sc.exe"
    Invoke-Wfp2Native -FilePath $sc -Arguments @(
        "create", $script:Wfp2DriverServiceName,
        "type=", "kernel",
        "start=", "demand",
        "error=", "normal",
        "binPath=", $driverTarget,
        "DisplayName=", "Serpium Flow WFP-2 Observe Driver"
    ) -LogPath (Join-Path $stage "05-driver-create.log") | Out-Null
    $driverCreated = $true

    $driverRecord = Get-Wfp2DriverService

    if (-not (Test-Wfp2ServicePathOwned -Record $driverRecord -ExpectedPath $driverTarget)) {
        throw "Created driver service path does not match the isolated WFP-2 install path."
    }

    Invoke-Wfp2Native -FilePath $sc -Arguments @("start", $script:Wfp2DriverServiceName) -LogPath (Join-Path $stage "06-driver-start.log") | Out-Null
    Wait-Wfp2ServiceState -Kind Driver -State Running -TimeoutSeconds 20

    $statusResult = Invoke-Wfp2Native -FilePath $serviceTarget -Arguments @("status") -LogPath (Join-Path $stage "07-driver-status.log")
    $statusText = $statusResult.Output -join "`n"

    if ($statusText -notmatch 'SERPIUM_WFP2_OBSERVE_READY') {
        throw "Driver status did not return SERPIUM_WFP2_OBSERVE_READY."
    }

    if ($statusText -notmatch '(?im)^Flags:\s+0x000000FB\s*$') {
        throw "Driver status flags do not prove complete fail-open WFP-2 observe-only state."
    }

    $pingResult = Invoke-Wfp2Native -FilePath $serviceTarget -Arguments @("ping") -LogPath (Join-Path $stage "08-driver-ping.log")

    if (($pingResult.Output -join "`n") -notmatch 'SERPIUM_WFP2_PING_PASS') {
        throw "Driver ping did not return SERPIUM_WFP2_PING_PASS."
    }

    $wfpDuring = Get-Wfp2WfpNameSummary

    if (-not $wfpDuring.Available -or $wfpDuring.MatchCount -le 0) {
        throw "Serpium WFP objects were not visible while the WFP-2 driver was running."
    }

    $probeProcessId = [uint64]$PID
    $probeV4 = Invoke-Wfp2LoopbackRoundTrip -Family V4
    $probeV6 = Invoke-Wfp2LoopbackRoundTrip -Family V6

    $v4Pattern = 'Observe\s+seq=\d+\s+layer=ALE_CONNECT_V4\s+pid=' + [regex]::Escape([string]$probeProcessId) + '\s+app=.+?\s+appIdPresent=true\s+remote=127\.0\.0\.1:' + [regex]::Escape([string]$probeV4.Port) + '\s+protocol=TCP\(6\)'
    $v6Pattern = 'Observe\s+seq=\d+\s+layer=ALE_CONNECT_V6\s+pid=' + [regex]::Escape([string]$probeProcessId) + '\s+app=.+?\s+appIdPresent=true\s+remote=[0-9A-Fa-f:]+:' + [regex]::Escape([string]$probeV6.Port) + '\s+protocol=TCP\(6\)'
    # Keep raw observations in memory only. They can include unrelated flows
    # that occurred during the short driver window and must not enter the ZIP.
    $observeResult = Invoke-Wfp2Native -FilePath $serviceTarget -Arguments @("observe", "2") -LogPath $null
    $observationText = $observeResult.Output -join "`n"

    if ($observationText -notmatch 'SERPIUM_WFP2_OBSERVE_PASS') {
        throw "The service observe command did not return SERPIUM_WFP2_OBSERVE_PASS."
    }

    $v4Matched = [regex]::IsMatch($observationText, $v4Pattern)
    $v6Matched = [regex]::IsMatch($observationText, $v6Pattern)

    if (-not $v4Matched) {
        throw "No exact V4 observation matched the probe PID, AppId presence, loopback destination, port, and TCP protocol."
    }

    if (-not $v6Matched) {
        throw "No exact V6 observation matched the probe PID, AppId presence, loopback destination, port, and TCP protocol."
    }

    $statusAfterResult = Invoke-Wfp2Native -FilePath $serviceTarget -Arguments @("status") -LogPath (Join-Path $stage "11-driver-status-after-observe.log")
    $statusAfterText = $statusAfterResult.Output -join "`n"

    if ($statusAfterText -notmatch 'SERPIUM_WFP2_OBSERVE_READY') {
        throw "Driver did not remain in observe-only ready state after telemetry collection."
    }

    if ($statusAfterText -notmatch '(?im)^Dropped:\s+0\s*$') {
        throw "The bounded observation queue reported dropped events during the controlled test."
    }

    $totalMatch = [regex]::Match($statusAfterText, '(?im)^Total observed:\s+(\d+)\s*$')

    if (-not $totalMatch.Success -or [uint64]$totalMatch.Groups[1].Value -lt 2) {
        throw "Driver status does not prove at least two observed connection events."
    }

    Write-Wfp2Utf8File -Path (Join-Path $stage "OBSERVATION_EVIDENCE.txt") -Lines @(
        "EvidencePolicy: sanitized exact-match summary; raw observations retained in memory only and excluded",
        ("ProbeProcessId: " + $probeProcessId),
        ("V4: PASS; layer=ALE_CONNECT_V4; pidMatched=True; appIdPresent=True; destination=127.0.0.1:" + $probeV4.Port + "; protocol=TCP(6)"),
        ("V4RoundTrip: PASS; bytes=" + $probeV4.PayloadLength + "; payloadSha256=" + $probeV4.PayloadSha256),
        ("V6: PASS; layer=ALE_CONNECT_V6; pidMatched=True; appIdPresent=True; destination=[::1]:" + $probeV6.Port + "; protocol=TCP(6)"),
        ("V6RoundTrip: PASS; bytes=" + $probeV6.PayloadLength + "; payloadSha256=" + $probeV6.PayloadSha256),
        ("DriverTotalObserved: " + $totalMatch.Groups[1].Value),
        "DriverDropped: 0",
        "ExternalConnections: none",
        "NetworkConfigurationChanges: none"
    )

    Invoke-Wfp2Native -FilePath $serviceTarget -Arguments @("install") -LogPath (Join-Path $stage "09-user-service-install.log") | Out-Null
    $userServiceCreated = $true

    $userRecord = Get-Wfp2UserService

    if (-not (Test-Wfp2ServicePathOwned -Record $userRecord -ExpectedPath $serviceTarget)) {
        throw "Created user service path does not match the isolated WFP-2 install path."
    }

    Invoke-Wfp2Native -FilePath $serviceTarget -Arguments @("start") -LogPath (Join-Path $stage "10-user-service-start.log") | Out-Null
    Wait-Wfp2ServiceState -Kind User -State Running -TimeoutSeconds 20
    Start-Sleep -Seconds 4
    Wait-Wfp2ServiceState -Kind User -State Running -TimeoutSeconds 5
    Wait-Wfp2ServiceState -Kind Driver -State Running -TimeoutSeconds 5

    Invoke-Wfp2Native -FilePath $serviceTarget -Arguments @("stop") -LogPath (Join-Path $stage "12-user-service-stop.log") | Out-Null
    Wait-Wfp2ServiceState -Kind User -State Stopped -TimeoutSeconds 20
    Invoke-Wfp2Native -FilePath $serviceTarget -Arguments @("uninstall") -LogPath (Join-Path $stage "13-user-service-delete.log") | Out-Null
    Wait-Wfp2ServiceState -Kind User -State Absent -TimeoutSeconds 20
    $userServiceCreated = $false

    Invoke-Wfp2Native -FilePath $sc -Arguments @("stop", $script:Wfp2DriverServiceName) -LogPath (Join-Path $stage "14-driver-stop.log") | Out-Null
    Wait-Wfp2ServiceState -Kind Driver -State Stopped -TimeoutSeconds 20
    Invoke-Wfp2Native -FilePath $sc -Arguments @("delete", $script:Wfp2DriverServiceName) -LogPath (Join-Path $stage "15-driver-delete.log") | Out-Null
    Wait-Wfp2ServiceState -Kind Driver -State Absent -TimeoutSeconds 20
    $driverCreated = $false

    Remove-Wfp2OwnedInstallRoot -ExpectedRunId $runId
    Remove-Item -LiteralPath $serviceLog -Force -ErrorAction SilentlyContinue

    if (Test-Path -LiteralPath $serviceLog) {
        throw "WFP-2 service log remained after lifecycle cleanup."
    }

    Remove-Wfp2OwnedEmptyTelemetryDirectories

    $wfpAfter = Get-Wfp2WfpNameSummary

    if (-not $wfpAfter.Available -or $wfpAfter.MatchCount -ne 0) {
        throw "Dynamic WFP objects remain after driver removal."
    }

    Assert-Wfp2ServicesAbsent

    $state.installRunId = $null
    $state.stage = "LifecyclePassed"
    Save-Wfp2State -State $state

    $report.Add("State: PASS")
    $report.Add("Stage: WFP-2 guarded observe-only lifecycle")
    $report.Add("RunId: " + $runId)
    $report.Add("SecureBoot: " + [string]$secureBoot.State)
    $report.Add("MemoryIntegrity: " + (Get-Wfp2MemoryIntegrityState))
    $report.Add("CodeIntegrityOptions: " + ("0x{0:X8}" -f [uint32]$codeIntegrity.Options))
    $report.Add("TestSigningRuntime: True")
    $report.Add("VerificationPolicy: Authenticode test-signing policy (/pa)")
    $report.Add("SignerThumbprintMatched: True")
    $report.Add("DriverStatus: PASS")
    $report.Add("DriverPing: PASS")
    $report.Add("ExpectedStatusFlags: 0x000000FB")
    $report.Add("WfpMode: observe-only")
    $report.Add("FilterAction: FWP_ACTION_CALLOUT_INSPECTION")
    $report.Add("ClassifyAction: FWP_ACTION_CONTINUE")
    $report.Add("TrafficModification: False")
    $report.Add("BlockingEnabled: False")
    $report.Add("RedirectEnabled: False")
    $report.Add("V4MetadataObservation: PASS")
    $report.Add("V6MetadataObservation: PASS")
    $report.Add("V4LoopbackRoundTrip: PASS")
    $report.Add("V6LoopbackRoundTrip: PASS")
    $report.Add("ObservationDrops: 0")
    $report.Add("SerpiumWfpMatchesBefore: " + $wfpBefore.MatchCount)
    $report.Add("SerpiumWfpMatchesDuring: " + $wfpDuring.MatchCount)
    $report.Add("SerpiumWfpMatchesAfter: " + $wfpAfter.MatchCount)
    $report.Add("DriverServiceAfter: Absent")
    $report.Add("UserServiceAfter: Absent")
    $report.Add("InstallFilesAfter: Absent")
    $report.Add("ServiceLogAfter: Absent")
    $report.Add("RawTelemetryInArchive: False")
    $report.Add("ExternalConnections: none")
    $report.Add("NetworkConfigurationChanges: none")
    $report.Add("CertificateAfter: Present (remove with cleanup_wfp2_runtime.ps1)")
    $report.Add("BcdAfter: Preserved (restore with cleanup_wfp2_runtime.ps1)")
}
catch {
    $failure = $_.Exception.Message
    $report.Add("State: FAIL")
    $report.Add("Stage: WFP-2 guarded observe-only lifecycle")
    $report.Add("RunId: " + $runId)
    $report.Add("Error: " + $failure)
}
finally {
    $rollbackSucceeded = $true

    if ($null -ne $failure -and $runtimeMutationStarted) {
        $rollback = Invoke-Wfp2LifecycleRollback

        foreach ($line in $rollback) {
            $report.Add([string]$line)

            if ([string]$line -match ': FAIL') {
                $rollbackSucceeded = $false
            }
        }
    }

    if ($null -ne $failure -and $null -ne $stateIdentity) {
        try {
            Remove-Wfp2CertificateByThumbprint -Thumbprint ([string]$stateIdentity.CertificateThumbprint)
            $report.Add("CertificateFailureRollback: PASS")
        }
        catch {
            $rollbackSucceeded = $false
            $report.Add("CertificateFailureRollback: FAIL - " + $_.Exception.Message)
        }

        if ([bool]$state.bcdChangedByScript) {
            try {
                $bcdedit = Join-Path $env:SystemRoot "System32\bcdedit.exe"
                Invoke-Wfp2Native -FilePath $bcdedit -Arguments @("-set", "TESTSIGNING", "OFF") -LogPath (Join-Path $stage "failure-bcd-rollback.log") | Out-Null
                $report.Add("BcdFailureRollback: PASS_REBOOT_REQUIRED")
            }
            catch {
                $rollbackSucceeded = $false
                $report.Add("BcdFailureRollback: FAIL - " + $_.Exception.Message)
            }
        }

        if ($rollbackSucceeded) {
            Remove-Item -LiteralPath ([string]$stateIdentity.SignedPackageDirectory) -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath (Get-Wfp2StatePath) -Force -ErrorAction SilentlyContinue
            $report.Add("FailureStateCleanup: PASS")
        }
        else {
            $report.Add("FailureStateCleanup: PRESERVED_FOR_RECOVERY")
        }
    }
}

Write-Wfp2Utf8File -Path (Join-Path $stage "LIFECYCLE_RESULT.txt") -Lines ($report.ToArray())
$archive = New-Wfp2ResultArchive -Prefix "Serpium_WFP2_Lifecycle_Result" -StageDirectory $stage

Write-Host ""

if ($null -eq $failure) {
    Write-Host "SERPIUM_WFP2_LIFECYCLE_PASS" -ForegroundColor Green
    Write-Host ("Result archive: " + $archive) -ForegroundColor Cyan
    exit 0
}

Write-Host "SERPIUM_WFP2_LIFECYCLE_FAIL" -ForegroundColor Red
Write-Host $failure -ForegroundColor Red
Write-Host ("Result archive: " + $archive) -ForegroundColor Yellow
exit 1
