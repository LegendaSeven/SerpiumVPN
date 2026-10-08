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

. (Join-Path $PSScriptRoot "wfp3_common.ps1")

Assert-Wfp3Administrator

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$stage = Join-Path $env:TEMP ("Serpium_WFP3_Lifecycle_" + $stamp)
New-Item -ItemType Directory -Path $stage -Force | Out-Null

$report = New-Object 'System.Collections.Generic.List[string]'
$failure = $null
$driverCreated = $false
$userServiceCreated = $false
$runtimeMutationStarted = $false
$runId = [guid]::NewGuid().ToString("N")
$installRoot = Get-Wfp3InstallRoot
$driverTarget = Join-Path $installRoot "Driver\Serpium.Flow.Driver.sys"
$serviceTarget = Join-Path $installRoot "Service\Serpium.Flow.Service.exe"
$ownershipMarker = Join-Path $installRoot "WFP3_INSTALL_STATE.json"
$serviceLog = Get-Wfp3ServiceLogPath
$programDataFlowRoot = Split-Path -Parent $serviceLog
$programDataSerpiumRoot = Split-Path -Parent $programDataFlowRoot
$programDataFlowExistedBefore = Test-Path -LiteralPath $programDataFlowRoot
$programDataSerpiumExistedBefore = Test-Path -LiteralPath $programDataSerpiumRoot
$state = $null
$stateIdentity = $null

function Test-Wfp3ServicePathOwned {
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

function Remove-Wfp3OwnedInstallRoot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExpectedRunId
    )

    if (-not (Test-Path -LiteralPath $installRoot -PathType Container)) {
        return
    }

    if (-not (Test-Path -LiteralPath $ownershipMarker -PathType Leaf)) {
        throw "Install root exists without the WFP-3 ownership marker: $installRoot"
    }

    $marker = Get-Content -LiteralPath $ownershipMarker -Raw | ConvertFrom-Json

    if ([string]$marker.runId -ne $ExpectedRunId) {
        throw "Install ownership marker does not match this lifecycle run."
    }

    Remove-Item -LiteralPath $installRoot -Recurse -Force -ErrorAction Stop
}

function Remove-Wfp3OwnedEmptyTelemetryDirectories {
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

function Read-Wfp3ExactBytes {
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

function Test-Wfp3ByteArraysEqual {
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

function Invoke-Wfp3LoopbackRoundTrip {
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

        $token = "SERPIUM-WFP3-" + $Family + "-" + [guid]::NewGuid().ToString("N")
        [byte[]]$payload = [Text.Encoding]::UTF8.GetBytes($token)
        $clientStream = $client.GetStream()
        $serverStream = $server.GetStream()

        $clientStream.Write($payload, 0, $payload.Length)
        $clientStream.Flush()
        [byte[]]$received = Read-Wfp3ExactBytes -Stream $serverStream -Count $payload.Length

        if (-not (Test-Wfp3ByteArraysEqual -Left $payload -Right $received)) {
            throw "$Family loopback server received modified bytes."
        }

        $serverStream.Write($received, 0, $received.Length)
        $serverStream.Flush()
        [byte[]]$echo = Read-Wfp3ExactBytes -Stream $clientStream -Count $payload.Length

        if (-not (Test-Wfp3ByteArraysEqual -Left $payload -Right $echo)) {
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

function Get-Wfp3UnsignedLineValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $pattern = '(?im)^' + [regex]::Escape($Name) + ':\s+(\d+)\s*$'
    $match = [regex]::Match($Text, $pattern)

    if (-not $match.Success) {
        throw "Required numeric output field is missing: $Name"
    }

    return [uint64]$match.Groups[1].Value
}

function Assert-Wfp3MutationResult {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text,

        [Parameter(Mandatory = $true)]
        [string]$Marker,

        [Parameter(Mandatory = $true)]
        [bool]$Changed,

        [Parameter(Mandatory = $true)]
        [uint32]$Generation,

        [Parameter(Mandatory = $true)]
        [uint32]$RuleCount
    )

    if ($Text -notmatch ('(?m)^' + [regex]::Escape($Marker) + '\s*$')) {
        throw "Policy mutation marker is missing: $Marker"
    }

    $expectedChanged = if ($Changed) { "true" } else { "false" }

    if ($Text -notmatch ('(?im)^Changed:\s+' + $expectedChanged + '\s*$')) {
        throw "Policy mutation Changed field did not equal $expectedChanged."
    }

    if ((Get-Wfp3UnsignedLineValue -Text $Text -Name "Policy generation") -ne $Generation) {
        throw "Policy mutation generation did not equal $Generation."
    }

    $rulesMatch = [regex]::Match($Text, '(?im)^Rules:\s+(\d+)/128\s*$')

    if (-not $rulesMatch.Success -or [uint32]$rulesMatch.Groups[1].Value -ne $RuleCount) {
        throw "Policy mutation rule count did not equal $RuleCount/128."
    }
}

function Invoke-Wfp3LifecycleRollback {
    $rollbackLines = New-Object 'System.Collections.Generic.List[string]'

    try {
        $userRecord = Get-Wfp3UserService

        if ($null -ne $userRecord) {
            if (-not (Test-Wfp3ServicePathOwned -Record $userRecord -ExpectedPath $serviceTarget)) {
                throw "Refusing to remove SerpiumFlowService because its binary path is not owned by this run."
            }

            if (Test-Path -LiteralPath $serviceTarget -PathType Leaf) {
                Invoke-Wfp3Native -FilePath $serviceTarget -Arguments @("stop") -LogPath (Join-Path $stage "rollback-user-stop.log") -AllowFailure | Out-Null
                Invoke-Wfp3Native -FilePath $serviceTarget -Arguments @("uninstall") -LogPath (Join-Path $stage "rollback-user-delete.log") -AllowFailure | Out-Null
            }
            else {
                $sc = Join-Path $env:SystemRoot "System32\sc.exe"
                Invoke-Wfp3Native -FilePath $sc -Arguments @("stop", $script:Wfp3UserServiceName) -LogPath (Join-Path $stage "rollback-user-stop.log") -AllowFailure | Out-Null
                Invoke-Wfp3Native -FilePath $sc -Arguments @("delete", $script:Wfp3UserServiceName) -LogPath (Join-Path $stage "rollback-user-delete.log") -AllowFailure | Out-Null
            }

            Wait-Wfp3ServiceState -Kind User -State Absent -TimeoutSeconds 20
        }

        $rollbackLines.Add("UserServiceRollback: PASS")
    }
    catch {
        $rollbackLines.Add("UserServiceRollback: FAIL - " + $_.Exception.Message)
    }

    try {
        $driverRecord = Get-Wfp3DriverService

        if ($null -ne $driverRecord) {
            if (-not (Test-Wfp3ServicePathOwned -Record $driverRecord -ExpectedPath $driverTarget)) {
                throw "Refusing to remove SerpiumFlow because its binary path is not owned by this run."
            }

            $sc = Join-Path $env:SystemRoot "System32\sc.exe"
            Invoke-Wfp3Native -FilePath $sc -Arguments @("stop", $script:Wfp3DriverServiceName) -LogPath (Join-Path $stage "rollback-driver-stop.log") -AllowFailure | Out-Null
            Invoke-Wfp3Native -FilePath $sc -Arguments @("delete", $script:Wfp3DriverServiceName) -LogPath (Join-Path $stage "rollback-driver-delete.log") -AllowFailure | Out-Null
            Wait-Wfp3ServiceState -Kind Driver -State Absent -TimeoutSeconds 20
        }

        $rollbackLines.Add("DriverServiceRollback: PASS")
    }
    catch {
        $rollbackLines.Add("DriverServiceRollback: FAIL - " + $_.Exception.Message)
    }

    try {
        Remove-Wfp3OwnedInstallRoot -ExpectedRunId $runId
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

        Remove-Wfp3OwnedEmptyTelemetryDirectories

        $rollbackLines.Add("ServiceLogRollback: PASS")
    }
    catch {
        $rollbackLines.Add("ServiceLogRollback: FAIL - " + $_.Exception.Message)
    }

    try {
        $wfp = Get-Wfp3WfpNameSummary

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
    $state = Get-Wfp3State

    if ($null -eq $state) {
        throw "WFP-3 state is missing. Run prepare_wfp3_policy_test_package.ps1 first."
    }

    $stateIdentity = Assert-Wfp3StateIdentity -State $state

    if ([int]$state.schema -ne 3 -or [string]$state.configuration -ne $Configuration) {
        throw "WFP-3 state does not match schema 3 and configuration $Configuration."
    }

    if ([string]$state.stage -notin @("TestSigningConfigured", "TestSigningActive")) {
        throw "WFP-3 state is not ready for lifecycle testing (stage: $($state.stage))."
    }

    $secureBoot = Get-Wfp3SecureBootState

    if ($secureBoot.State -ne "Disabled") {
        throw "Secure Boot must be Disabled for this test (actual: $($secureBoot.State))."
    }

    $codeIntegrity = Get-Wfp3CodeIntegrityState

    if (-not $codeIntegrity.Available -or -not $codeIntegrity.TestSigningRuntime) {
        throw "Windows Test Signing is not active in the current boot. Run enable_wfp3_testsigning.ps1 and reboot first."
    }

    $bfe = Get-Service -Name "BFE" -ErrorAction SilentlyContinue

    if ($null -eq $bfe -or [string]$bfe.Status -ne "Running") {
        throw "Base Filtering Engine is not running."
    }

    Assert-Wfp3ServicesAbsent

    if (Test-Path -LiteralPath $installRoot) {
        throw "The isolated WFP-3 install root already exists: $installRoot"
    }

    if (Test-Path -LiteralPath $serviceLog) {
        throw "A pre-existing service log would be modified by the WFP-3 lifecycle test: $serviceLog"
    }

    $packageResult = Test-Wfp3UnsignedPackage -Configuration $Configuration
    $signedDirectory = [string]$stateIdentity.SignedPackageDirectory
    $signedManifestPath = Join-Path $signedDirectory "WFP3_SIGNING_MANIFEST.json"

    if (-not (Test-Path -LiteralPath $signedManifestPath -PathType Leaf)) {
        throw "Signed package manifest is missing: $signedManifestPath"
    }

    $signedManifest = Get-Content -LiteralPath $signedManifestPath -Raw | ConvertFrom-Json

    if (
        [int]$signedManifest.schema -ne 3 -or
        [string]$signedManifest.runId -ne [string]$state.runId -or
        [string]$signedManifest.configuration -ne $Configuration -or
        -not [bool]$signedManifest.wfpEnabled -or
        [string]$signedManifest.wfpMode -ne "observe-only-policy-transport" -or
        [string]$signedManifest.protocolVersion -ne "0x00030000" -or
        -not [bool]$signedManifest.policyTransportEnabled -or
        [string]$signedManifest.filterAction -ne "FWP_ACTION_CALLOUT_INSPECTION" -or
        [string]$signedManifest.classifyAction -ne "FWP_ACTION_CONTINUE" -or
        [bool]$signedManifest.trafficModification -or
        [bool]$signedManifest.blockingEnabled -or
        [bool]$signedManifest.redirectEnabled -or
        [bool]$signedManifest.injectionEnabled -or
        [bool]$signedManifest.routeEnforcementEnabled -or
        [bool]$signedManifest.existingFlowMutation -or
        [int]$signedManifest.applicationRuleCapacity -ne 128 -or
        [int]$signedManifest.observedFlowCapacity -ne 256
    ) {
        throw "Signed package manifest violates the WFP-3 fail-open policy-transport contract."
    }

    [string[]]$signedCommands = @($signedManifest.policyCommands | ForEach-Object { [string]$_ })

    if (
        $signedCommands.Count -ne 5 -or
        $signedCommands -notcontains "ADD_RULE" -or
        $signedCommands -notcontains "REMOVE_RULE" -or
        $signedCommands -notcontains "CLEAR_RULES" -or
        $signedCommands -notcontains "ENUM_RULES" -or
        $signedCommands -notcontains "ENUM_FLOWS"
    ) {
        throw "Signed package manifest does not contain the exact WFP-3 policy command set."
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
        throw "The unsigned build package changed after WFP-3 preparation."
    }

    $driverSource = Join-Path $signedDirectory "Serpium.Flow.Driver.sys"
    $serviceSource = Join-Path $signedDirectory "Serpium.Flow.Service.exe"
    $catalogSource = Join-Path $signedDirectory "Serpium.Flow.Driver.cat"
    $infSource = Join-Path $signedDirectory "Serpium.Flow.Driver.inf"
    $certificateSource = Join-Path $signedDirectory "Serpium.Flow.WFP3.Test.cer"

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
        throw "Exported WFP-3 test certificate is missing."
    }

    $certificateThumbprint = [string]$state.certificateThumbprint

    if ([string]$signedManifest.certificate.thumbprint -ine $certificateThumbprint) {
        throw "Signed manifest certificate thumbprint does not match WFP-3 state."
    }

    foreach ($store in @("My", "Root", "TrustedPublisher")) {
        if (-not (Test-Path -LiteralPath ("Cert:\LocalMachine\$store\" + $certificateThumbprint))) {
            throw "WFP-3 certificate is missing from LocalMachine\$store."
        }
    }

    $buildManifest = Get-Content -LiteralPath $buildManifestPath -Raw | ConvertFrom-Json
    $signTool = Find-Wfp3SdkTool -Name "signtool.exe" -PreferredVersion ([string]$buildManifest.sdkWdkVersion)

    Invoke-Wfp3Native -FilePath $signTool -Arguments @("verify", "/pa", "/ph", "/v", $driverSource) -LogPath (Join-Path $stage "01-verify-driver.log") | Out-Null
    Invoke-Wfp3Native -FilePath $signTool -Arguments @("verify", "/pa", "/v", $catalogSource) -LogPath (Join-Path $stage "02-verify-catalog.log") | Out-Null
    Invoke-Wfp3Native -FilePath $signTool -Arguments @("verify", "/pa", "/v", $serviceSource) -LogPath (Join-Path $stage "03-verify-service.log") | Out-Null
    Invoke-Wfp3Native -FilePath $signTool -Arguments @("verify", "/pa", "/v", "/c", $catalogSource, $driverSource) -LogPath (Join-Path $stage "04-verify-catalog-membership.log") | Out-Null

    Assert-Wfp3TestSigner -Path $driverSource -ExpectedThumbprint $certificateThumbprint
    Assert-Wfp3TestSigner -Path $serviceSource -ExpectedThumbprint $certificateThumbprint

    $wfpBefore = Get-Wfp3WfpNameSummary

    if (-not $wfpBefore.Available -or $wfpBefore.MatchCount -ne 0) {
        throw "WFP state is not clean before lifecycle installation."
    }

    try {
        Write-Wfp3JsonFile -Path $ownershipMarker -Value ([ordered]@{
            schema = 3
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
    Copy-Item -LiteralPath $certificateSource -Destination (Join-Path $installRoot "Driver\Serpium.Flow.WFP3.Test.cer") -Force

    Write-Wfp3JsonFile -Path $ownershipMarker -Value ([ordered]@{
        schema = 3
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
    Save-Wfp3State -State $state

    $sc = Join-Path $env:SystemRoot "System32\sc.exe"
    Invoke-Wfp3Native -FilePath $sc -Arguments @(
        "create", $script:Wfp3DriverServiceName,
        "type=", "kernel",
        "start=", "demand",
        "error=", "normal",
        "binPath=", $driverTarget,
        "DisplayName=", "Serpium Flow WFP-3 Policy Driver"
    ) -LogPath (Join-Path $stage "05-driver-create.log") | Out-Null
    $driverCreated = $true

    $driverRecord = Get-Wfp3DriverService

    if (-not (Test-Wfp3ServicePathOwned -Record $driverRecord -ExpectedPath $driverTarget)) {
        throw "Created driver service path does not match the isolated WFP-3 install path."
    }

    Invoke-Wfp3Native -FilePath $sc -Arguments @("start", $script:Wfp3DriverServiceName) -LogPath (Join-Path $stage "06-driver-start.log") | Out-Null
    Wait-Wfp3ServiceState -Kind Driver -State Running -TimeoutSeconds 20

    $statusResult = Invoke-Wfp3Native -FilePath $serviceTarget -Arguments @("status") -LogPath (Join-Path $stage "07-driver-status.log")
    $statusText = $statusResult.Output -join "`n"

    if ($statusText -notmatch 'SERPIUM_WFP3_POLICY_READY') {
        throw "Driver status did not return SERPIUM_WFP3_POLICY_READY."
    }

    if ($statusText -notmatch '(?im)^Protocol:\s+0x00030000\s*$') {
        throw "Driver status did not prove protocol version 0x00030000."
    }

    if ($statusText -notmatch '(?im)^Flags:\s+0x00000FFB\s*$') {
        throw "Driver status flags do not prove complete fail-open WFP-3 policy-transport state."
    }

    if ($statusText -notmatch '(?im)^Route enforcement:\s+disabled\s*$') {
        throw "Driver status did not prove route enforcement is disabled."
    }

    $initialGeneration = [uint32](Get-Wfp3UnsignedLineValue -Text $statusText -Name "Policy generation")
    $initialRulesMatch = [regex]::Match($statusText, '(?im)^Rules:\s+(\d+)/128\s*$')

    if (-not $initialRulesMatch.Success -or [uint32]$initialRulesMatch.Groups[1].Value -ne 0) {
        throw "Driver did not start with an empty application-rule table."
    }

    $pingResult = Invoke-Wfp3Native -FilePath $serviceTarget -Arguments @("ping") -LogPath (Join-Path $stage "08-driver-ping.log")

    if (($pingResult.Output -join "`n") -notmatch 'SERPIUM_WFP3_PING_PASS') {
        throw "Driver ping did not return SERPIUM_WFP3_PING_PASS."
    }

    $wfpDuring = Get-Wfp3WfpNameSummary

    if (-not $wfpDuring.Available -or $wfpDuring.MatchCount -le 0) {
        throw "Serpium WFP objects were not visible while the WFP-3 driver was running."
    }

    $probeProcess = Get-Process -Id $PID -ErrorAction Stop
    $probeExecutable = [string]$probeProcess.Path

    if ([string]::IsNullOrWhiteSpace($probeExecutable)) {
        $probeExecutable = [string]$probeProcess.MainModule.FileName
    }

    if (
        [string]::IsNullOrWhiteSpace($probeExecutable) -or
        -not [IO.Path]::IsPathRooted($probeExecutable) -or
        -not (Test-Path -LiteralPath $probeExecutable -PathType Leaf)
    ) {
        throw "The lifecycle harness could not resolve its own absolute executable path for WFP AppId testing."
    }

    $clearInitial = Invoke-Wfp3Native -FilePath $serviceTarget -Arguments @("clear-rules") -LogPath $null
    Assert-Wfp3MutationResult -Text ($clearInitial.Output -join "`n") -Marker "SERPIUM_WFP3_CLEAR_RULES_PASS" -Changed $false -Generation $initialGeneration -RuleCount 0

    # Raw policy output contains a local path and therefore stays in memory.
    $addVpn = Invoke-Wfp3Native -FilePath $serviceTarget -Arguments @("add-rule", "VPN", $probeExecutable) -LogPath $null
    $addVpnText = $addVpn.Output -join "`n"
    $generationAfterAdd = $initialGeneration + 1
    Assert-Wfp3MutationResult -Text $addVpnText -Marker "SERPIUM_WFP3_ADD_RULE_PASS" -Changed $true -Generation $generationAfterAdd -RuleCount 1
    $ruleId = Get-Wfp3UnsignedLineValue -Text $addVpnText -Name "Rule id"

    if ($ruleId -eq 0 -or $addVpnText -notmatch '(?im)^Route intent:\s+VPN\s*$') {
        throw "ADD_RULE did not return a stable nonzero VPN rule identifier."
    }

    $addVpnAgain = Invoke-Wfp3Native -FilePath $serviceTarget -Arguments @("add-rule", "VPN", $probeExecutable) -LogPath $null
    Assert-Wfp3MutationResult -Text ($addVpnAgain.Output -join "`n") -Marker "SERPIUM_WFP3_ADD_RULE_PASS" -Changed $false -Generation $generationAfterAdd -RuleCount 1

    $updateDirect = Invoke-Wfp3Native -FilePath $serviceTarget -Arguments @("add-rule", "DIRECT", $probeExecutable) -LogPath $null
    $updateDirectText = $updateDirect.Output -join "`n"
    $generationForMatchedFlows = $generationAfterAdd + 1
    Assert-Wfp3MutationResult -Text $updateDirectText -Marker "SERPIUM_WFP3_ADD_RULE_PASS" -Changed $true -Generation $generationForMatchedFlows -RuleCount 1

    if (
        (Get-Wfp3UnsignedLineValue -Text $updateDirectText -Name "Rule id") -ne $ruleId -or
        $updateDirectText -notmatch '(?im)^Route intent:\s+DIRECT\s*$'
    ) {
        throw "ADD_RULE update did not preserve RuleId while changing the route intent to DIRECT."
    }

    $listRules = Invoke-Wfp3Native -FilePath $serviceTarget -Arguments @("list-rules") -LogPath $null
    $listRulesText = $listRules.Output -join "`n"

    if (
        $listRulesText -notmatch '(?m)^SERPIUM_WFP3_LIST_RULES_PASS\s*$' -or
        (Get-Wfp3UnsignedLineValue -Text $listRulesText -Name "Policy generation") -ne $generationForMatchedFlows -or
        (Get-Wfp3UnsignedLineValue -Text $listRulesText -Name "Rules listed") -ne 1 -or
        $listRulesText -notmatch ('(?im)^Rule id=' + [regex]::Escape([string]$ruleId) + '\s+route=DIRECT\s+')
    ) {
        throw "ENUM_RULES did not return exactly the updated DIRECT rule."
    }

    $probeProcessId = [uint64]$PID
    $probeV4 = Invoke-Wfp3LoopbackRoundTrip -Family V4
    $probeV6 = Invoke-Wfp3LoopbackRoundTrip -Family V6
    $matchedSuffix = '\s+policyGeneration=' + [regex]::Escape([string]$generationForMatchedFlows) + '\s+route=DIRECT\s+ruleId=' + [regex]::Escape([string]$ruleId) + '\s+matched=true'
    $v4Pattern = 'Observe\s+seq=\d+\s+layer=ALE_CONNECT_V4\s+pid=' + [regex]::Escape([string]$probeProcessId) + '\s+app=.+?\s+appIdPresent=true\s+localPort=\d+\s+remote=127\.0\.0\.1:' + [regex]::Escape([string]$probeV4.Port) + '\s+protocol=TCP\(6\)' + $matchedSuffix
    $v6Pattern = 'Observe\s+seq=\d+\s+layer=ALE_CONNECT_V6\s+pid=' + [regex]::Escape([string]$probeProcessId) + '\s+app=.+?\s+appIdPresent=true\s+localPort=\d+\s+remote=[0-9A-Fa-f:]+:' + [regex]::Escape([string]$probeV6.Port) + '\s+protocol=TCP\(6\)' + $matchedSuffix
    $observeResult = Invoke-Wfp3Native -FilePath $serviceTarget -Arguments @("observe", "2") -LogPath $null
    $observationText = $observeResult.Output -join "`n"

    if ($observationText -notmatch '(?m)^SERPIUM_WFP3_OBSERVE_PASS\s*$') {
        throw "The service observe command did not return SERPIUM_WFP3_OBSERVE_PASS."
    }

    if (-not [regex]::IsMatch($observationText, $v4Pattern) -or -not [regex]::IsMatch($observationText, $v6Pattern)) {
        throw "Exact V4/V6 observations did not prove the DIRECT rule snapshot for the probe AppId."
    }

    $flowList = Invoke-Wfp3Native -FilePath $serviceTarget -Arguments @("list-flows") -LogPath $null
    $flowText = $flowList.Output -join "`n"
    $flowV4Pattern = 'Flow id=\d+\s+pid=' + [regex]::Escape([string]$probeProcessId) + '\s+app=.+?\s+localPort=\d+\s+remote=127\.0\.0\.1:' + [regex]::Escape([string]$probeV4.Port) + '\s+protocol=6\s+route=DIRECT\s+ruleId=' + [regex]::Escape([string]$ruleId) + '\s+generation=' + [regex]::Escape([string]$generationForMatchedFlows) + '\s+seen=\d+'
    $flowV6Pattern = 'Flow id=\d+\s+pid=' + [regex]::Escape([string]$probeProcessId) + '\s+app=.+?\s+localPort=\d+\s+remote=[0-9A-Fa-f:]+:' + [regex]::Escape([string]$probeV6.Port) + '\s+protocol=6\s+route=DIRECT\s+ruleId=' + [regex]::Escape([string]$ruleId) + '\s+generation=' + [regex]::Escape([string]$generationForMatchedFlows) + '\s+seen=\d+'

    if (
        $flowText -notmatch '(?m)^SERPIUM_WFP3_LIST_FLOWS_PASS\s*$' -or
        -not [regex]::IsMatch($flowText, $flowV4Pattern) -or
        -not [regex]::IsMatch($flowText, $flowV6Pattern)
    ) {
        throw "FlowTable did not retain exact V4/V6 DIRECT snapshots for the controlled probes."
    }

    $removeRule = Invoke-Wfp3Native -FilePath $serviceTarget -Arguments @("remove-rule", $probeExecutable) -LogPath $null
    $generationAfterRemove = $generationForMatchedFlows + 1
    Assert-Wfp3MutationResult -Text ($removeRule.Output -join "`n") -Marker "SERPIUM_WFP3_REMOVE_RULE_PASS" -Changed $true -Generation $generationAfterRemove -RuleCount 0

    $removeAgain = Invoke-Wfp3Native -FilePath $serviceTarget -Arguments @("remove-rule", $probeExecutable) -LogPath $null
    Assert-Wfp3MutationResult -Text ($removeAgain.Output -join "`n") -Marker "SERPIUM_WFP3_REMOVE_RULE_PASS" -Changed $false -Generation $generationAfterRemove -RuleCount 0

    $listRulesEmpty = Invoke-Wfp3Native -FilePath $serviceTarget -Arguments @("list-rules") -LogPath $null
    $listRulesEmptyText = $listRulesEmpty.Output -join "`n"

    if (
        $listRulesEmptyText -notmatch '(?m)^SERPIUM_WFP3_LIST_RULES_PASS\s*$' -or
        (Get-Wfp3UnsignedLineValue -Text $listRulesEmptyText -Name "Policy generation") -ne $generationAfterRemove -or
        (Get-Wfp3UnsignedLineValue -Text $listRulesEmptyText -Name "Rules listed") -ne 0
    ) {
        throw "ENUM_RULES did not prove the table was empty after REMOVE_RULE."
    }

    $probeAfterRemove = Invoke-Wfp3LoopbackRoundTrip -Family V4
    $observeAfterRemove = Invoke-Wfp3Native -FilePath $serviceTarget -Arguments @("observe", "2") -LogPath $null
    $observeAfterRemoveText = $observeAfterRemove.Output -join "`n"
    $missPattern = 'Observe\s+seq=\d+\s+layer=ALE_CONNECT_V4\s+pid=' + [regex]::Escape([string]$probeProcessId) + '\s+app=.+?\s+appIdPresent=true\s+localPort=\d+\s+remote=127\.0\.0\.1:' + [regex]::Escape([string]$probeAfterRemove.Port) + '\s+protocol=TCP\(6\)\s+policyGeneration=' + [regex]::Escape([string]$generationAfterRemove) + '\s+route=UNSPECIFIED\s+ruleId=0\s+matched=false'

    if ($observeAfterRemoveText -notmatch '(?m)^SERPIUM_WFP3_OBSERVE_PASS\s*$' -or -not [regex]::IsMatch($observeAfterRemoveText, $missPattern)) {
        throw "A new V4 flow after REMOVE_RULE did not prove the expected fail-open policy miss."
    }

    $flowListAfterRemove = Invoke-Wfp3Native -FilePath $serviceTarget -Arguments @("list-flows") -LogPath $null
    $flowAfterRemoveText = $flowListAfterRemove.Output -join "`n"
    $missFlowPattern = 'Flow id=\d+\s+pid=' + [regex]::Escape([string]$probeProcessId) + '\s+app=.+?\s+localPort=\d+\s+remote=127\.0\.0\.1:' + [regex]::Escape([string]$probeAfterRemove.Port) + '\s+protocol=6\s+route=UNSPECIFIED\s+ruleId=0\s+generation=' + [regex]::Escape([string]$generationAfterRemove) + '\s+seen=\d+'

    if (
        $flowAfterRemoveText -notmatch '(?m)^SERPIUM_WFP3_LIST_FLOWS_PASS\s*$' -or
        -not [regex]::IsMatch($flowAfterRemoveText, $flowV4Pattern) -or
        -not [regex]::IsMatch($flowAfterRemoveText, $flowV6Pattern) -or
        -not [regex]::IsMatch($flowAfterRemoveText, $missFlowPattern)
    ) {
        throw "FlowTable snapshot invariants failed after policy removal."
    }

    $addServiceRule = Invoke-Wfp3Native -FilePath $serviceTarget -Arguments @("add-rule", "VPN", $serviceTarget) -LogPath $null
    $generationBeforeClear = $generationAfterRemove + 1
    Assert-Wfp3MutationResult -Text ($addServiceRule.Output -join "`n") -Marker "SERPIUM_WFP3_ADD_RULE_PASS" -Changed $true -Generation $generationBeforeClear -RuleCount 1

    $clearRules = Invoke-Wfp3Native -FilePath $serviceTarget -Arguments @("clear-rules") -LogPath $null
    $finalGeneration = $generationBeforeClear + 1
    Assert-Wfp3MutationResult -Text ($clearRules.Output -join "`n") -Marker "SERPIUM_WFP3_CLEAR_RULES_PASS" -Changed $true -Generation $finalGeneration -RuleCount 0

    $clearAgain = Invoke-Wfp3Native -FilePath $serviceTarget -Arguments @("clear-rules") -LogPath $null
    Assert-Wfp3MutationResult -Text ($clearAgain.Output -join "`n") -Marker "SERPIUM_WFP3_CLEAR_RULES_PASS" -Changed $false -Generation $finalGeneration -RuleCount 0

    $statusAfterResult = Invoke-Wfp3Native -FilePath $serviceTarget -Arguments @("status") -LogPath (Join-Path $stage "09-driver-status-after-policy.log")
    $statusAfterText = $statusAfterResult.Output -join "`n"

    if (
        $statusAfterText -notmatch 'SERPIUM_WFP3_POLICY_READY' -or
        $statusAfterText -notmatch '(?im)^Flags:\s+0x00000FFB\s*$' -or
        $statusAfterText -notmatch '(?im)^Route enforcement:\s+disabled\s*$' -or
        $statusAfterText -notmatch '(?im)^Dropped:\s+0\s*$' -or
        (Get-Wfp3UnsignedLineValue -Text $statusAfterText -Name "Policy generation") -ne $finalGeneration
    ) {
        throw "Driver did not remain in the fail-open WFP-3 policy state after the controlled test."
    }

    $finalRulesMatch = [regex]::Match($statusAfterText, '(?im)^Rules:\s+(\d+)/128\s*$')
    $finalFlowsMatch = [regex]::Match($statusAfterText, '(?im)^Observed flows:\s+(\d+)/256\s*$')
    $policyMatches = Get-Wfp3UnsignedLineValue -Text $statusAfterText -Name "Policy matches"
    $totalMatch = [regex]::Match($statusAfterText, '(?im)^Total observed:\s+(\d+)\s*$')

    if (
        -not $finalRulesMatch.Success -or [uint32]$finalRulesMatch.Groups[1].Value -ne 0 -or
        -not $finalFlowsMatch.Success -or [uint32]$finalFlowsMatch.Groups[1].Value -lt 3 -or
        $policyMatches -lt 2 -or
        -not $totalMatch.Success -or [uint64]$totalMatch.Groups[1].Value -lt 3
    ) {
        throw "Final policy counters do not prove the controlled matched and unmatched flows."
    }

    Write-Wfp3Utf8File -Path (Join-Path $stage "POLICY_EVIDENCE.txt") -Lines @(
        "EvidencePolicy: sanitized exact-match summary; raw observations, rule lists, flow lists, and local application paths excluded",
        ("ProbeProcessId: " + $probeProcessId),
        ("StableRuleId: " + $ruleId),
        ("InitialPolicyGeneration: " + $initialGeneration),
        ("MatchedFlowGeneration: " + $generationForMatchedFlows),
        ("AfterRemoveGeneration: " + $generationAfterRemove),
        ("FinalPolicyGeneration: " + $finalGeneration),
        "AddRule: PASS; changed=True; rules=1",
        "AddRuleIdempotent: PASS; changed=False; generationStable=True",
        "UpdateRule: PASS; route=DIRECT; ruleIdStable=True; rules=1",
        "EnumerateRules: PASS; exactRuleCount=1; route=DIRECT",
        ("MatchedV4: PASS; destination=127.0.0.1:" + $probeV4.Port + "; protocol=TCP(6); route=DIRECT"),
        ("MatchedV4RoundTrip: PASS; bytes=" + $probeV4.PayloadLength + "; payloadSha256=" + $probeV4.PayloadSha256),
        ("MatchedV6: PASS; destination=[::1]:" + $probeV6.Port + "; protocol=TCP(6); route=DIRECT"),
        ("MatchedV6RoundTrip: PASS; bytes=" + $probeV6.PayloadLength + "; payloadSha256=" + $probeV6.PayloadSha256),
        "EnumerateFlows: PASS; exactMatchedV4=True; exactMatchedV6=True",
        "RemoveRule: PASS; changed=True; rules=0",
        "RemoveRuleIdempotent: PASS; changed=False; generationStable=True",
        ("PostRemoveV4: PASS; destination=127.0.0.1:" + $probeAfterRemove.Port + "; route=UNSPECIFIED; matched=False"),
        ("PostRemoveV4RoundTrip: PASS; bytes=" + $probeAfterRemove.PayloadLength + "; payloadSha256=" + $probeAfterRemove.PayloadSha256),
        "ExistingFlowMutation: False; original DIRECT snapshots remained unchanged after REMOVE_RULE",
        "ClearRules: PASS; nonEmptyChanged=True; emptyChanged=False",
        ("DriverTotalObserved: " + $totalMatch.Groups[1].Value),
        ("DriverPolicyMatches: " + $policyMatches),
        ("DriverObservedFlows: " + $finalFlowsMatch.Groups[1].Value),
        "DriverDropped: 0",
        "ClassifyAction: FWP_ACTION_CONTINUE",
        "RouteEnforcementEnabled: False",
        "ExternalConnections: none",
        "NetworkConfigurationChanges: none"
    )

    Invoke-Wfp3Native -FilePath $serviceTarget -Arguments @("install") -LogPath (Join-Path $stage "09-user-service-install.log") | Out-Null
    $userServiceCreated = $true

    $userRecord = Get-Wfp3UserService

    if (-not (Test-Wfp3ServicePathOwned -Record $userRecord -ExpectedPath $serviceTarget)) {
        throw "Created user service path does not match the isolated WFP-3 install path."
    }

    Invoke-Wfp3Native -FilePath $serviceTarget -Arguments @("start") -LogPath (Join-Path $stage "10-user-service-start.log") | Out-Null
    Wait-Wfp3ServiceState -Kind User -State Running -TimeoutSeconds 20
    Start-Sleep -Seconds 4
    Wait-Wfp3ServiceState -Kind User -State Running -TimeoutSeconds 5
    Wait-Wfp3ServiceState -Kind Driver -State Running -TimeoutSeconds 5

    Invoke-Wfp3Native -FilePath $serviceTarget -Arguments @("stop") -LogPath (Join-Path $stage "12-user-service-stop.log") | Out-Null
    Wait-Wfp3ServiceState -Kind User -State Stopped -TimeoutSeconds 20
    Invoke-Wfp3Native -FilePath $serviceTarget -Arguments @("uninstall") -LogPath (Join-Path $stage "13-user-service-delete.log") | Out-Null
    Wait-Wfp3ServiceState -Kind User -State Absent -TimeoutSeconds 20
    $userServiceCreated = $false

    Invoke-Wfp3Native -FilePath $sc -Arguments @("stop", $script:Wfp3DriverServiceName) -LogPath (Join-Path $stage "14-driver-stop.log") | Out-Null
    Wait-Wfp3ServiceState -Kind Driver -State Stopped -TimeoutSeconds 20
    Invoke-Wfp3Native -FilePath $sc -Arguments @("delete", $script:Wfp3DriverServiceName) -LogPath (Join-Path $stage "15-driver-delete.log") | Out-Null
    Wait-Wfp3ServiceState -Kind Driver -State Absent -TimeoutSeconds 20
    $driverCreated = $false

    Remove-Wfp3OwnedInstallRoot -ExpectedRunId $runId
    Remove-Item -LiteralPath $serviceLog -Force -ErrorAction SilentlyContinue

    if (Test-Path -LiteralPath $serviceLog) {
        throw "WFP-3 service log remained after lifecycle cleanup."
    }

    Remove-Wfp3OwnedEmptyTelemetryDirectories

    $wfpAfter = Get-Wfp3WfpNameSummary

    if (-not $wfpAfter.Available -or $wfpAfter.MatchCount -ne 0) {
        throw "Dynamic WFP objects remain after driver removal."
    }

    Assert-Wfp3ServicesAbsent

    $state.installRunId = $null
    $state.stage = "LifecyclePassed"
    Save-Wfp3State -State $state

    $report.Add("State: PASS")
    $report.Add("Stage: WFP-3 guarded fail-open policy lifecycle")
    $report.Add("RunId: " + $runId)
    $report.Add("SecureBoot: " + [string]$secureBoot.State)
    $report.Add("MemoryIntegrity: " + (Get-Wfp3MemoryIntegrityState))
    $report.Add("CodeIntegrityOptions: " + ("0x{0:X8}" -f [uint32]$codeIntegrity.Options))
    $report.Add("TestSigningRuntime: True")
    $report.Add("VerificationPolicy: Authenticode test-signing policy (/pa)")
    $report.Add("SignerThumbprintMatched: True")
    $report.Add("DriverStatus: PASS")
    $report.Add("DriverPing: PASS")
    $report.Add("ExpectedStatusFlags: 0x00000FFB")
    $report.Add("WfpMode: observe-only-policy-transport")
    $report.Add("ProtocolVersion: 0x00030000")
    $report.Add("PolicyTransportEnabled: True")
    $report.Add("FilterAction: FWP_ACTION_CALLOUT_INSPECTION")
    $report.Add("ClassifyAction: FWP_ACTION_CONTINUE")
    $report.Add("TrafficModification: False")
    $report.Add("BlockingEnabled: False")
    $report.Add("RedirectEnabled: False")
    $report.Add("InjectionEnabled: False")
    $report.Add("RouteEnforcementEnabled: False")
    $report.Add("AddRule: PASS")
    $report.Add("AddRuleIdempotence: PASS")
    $report.Add("UpdateRule: PASS")
    $report.Add("RemoveRule: PASS")
    $report.Add("RemoveRuleIdempotence: PASS")
    $report.Add("ClearRules: PASS")
    $report.Add("ClearRulesIdempotence: PASS")
    $report.Add("EnumerateRules: PASS")
    $report.Add("EnumerateFlows: PASS")
    $report.Add("PolicyGenerationInvariant: PASS")
    $report.Add("ExistingFlowMutation: False")
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
    $report.Add("RawPolicyDataInArchive: False")
    $report.Add("ExternalConnections: none")
    $report.Add("NetworkConfigurationChanges: none")
    $report.Add("CertificateAfter: Present (remove with cleanup_wfp3_policy_runtime.ps1)")
    $report.Add("BcdAfter: Preserved (restore with cleanup_wfp3_policy_runtime.ps1)")
}
catch {
    $failure = $_.Exception.Message
    $report.Add("State: FAIL")
    $report.Add("Stage: WFP-3 guarded fail-open policy lifecycle")
    $report.Add("RunId: " + $runId)
    $report.Add("Error: " + $failure)
}
finally {
    $rollbackSucceeded = $true

    if ($null -ne $failure -and $runtimeMutationStarted) {
        $rollback = Invoke-Wfp3LifecycleRollback

        foreach ($line in $rollback) {
            $report.Add([string]$line)

            if ([string]$line -match ': FAIL') {
                $rollbackSucceeded = $false
            }
        }
    }

    if ($null -ne $failure -and $null -ne $stateIdentity) {
        try {
            Remove-Wfp3CertificateByThumbprint -Thumbprint ([string]$stateIdentity.CertificateThumbprint)
            $report.Add("CertificateFailureRollback: PASS")
        }
        catch {
            $rollbackSucceeded = $false
            $report.Add("CertificateFailureRollback: FAIL - " + $_.Exception.Message)
        }

        if ([bool]$state.bcdChangedByScript) {
            try {
                $bcdedit = Join-Path $env:SystemRoot "System32\bcdedit.exe"
                Invoke-Wfp3Native -FilePath $bcdedit -Arguments @("-set", "TESTSIGNING", "OFF") -LogPath (Join-Path $stage "failure-bcd-rollback.log") | Out-Null
                $report.Add("BcdFailureRollback: PASS_REBOOT_REQUIRED")
            }
            catch {
                $rollbackSucceeded = $false
                $report.Add("BcdFailureRollback: FAIL - " + $_.Exception.Message)
            }
        }

        if ($rollbackSucceeded) {
            Remove-Item -LiteralPath ([string]$stateIdentity.SignedPackageDirectory) -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath (Get-Wfp3StatePath) -Force -ErrorAction SilentlyContinue
            $report.Add("FailureStateCleanup: PASS")
        }
        else {
            $report.Add("FailureStateCleanup: PRESERVED_FOR_RECOVERY")
        }
    }
}

Write-Wfp3Utf8File -Path (Join-Path $stage "LIFECYCLE_RESULT.txt") -Lines ($report.ToArray())
$archive = New-Wfp3ResultArchive -Prefix "Serpium_WFP3_PolicyLifecycle_Result" -StageDirectory $stage

Write-Host ""

if ($null -eq $failure) {
    Write-Host "SERPIUM_WFP3_POLICY_LIFECYCLE_PASS" -ForegroundColor Green
    Write-Host ("Result archive: " + $archive) -ForegroundColor Cyan
    exit 0
}

Write-Host "SERPIUM_WFP3_POLICY_LIFECYCLE_FAIL" -ForegroundColor Red
Write-Host $failure -ForegroundColor Red
Write-Host ("Result archive: " + $archive) -ForegroundColor Yellow
exit 1
