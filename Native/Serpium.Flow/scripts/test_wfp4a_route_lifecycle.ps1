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

. (Join-Path $PSScriptRoot "wfp4a_common.ps1")

Assert-Wfp4aAdministrator

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$stage = Join-Path $env:TEMP ("Serpium_WFP4A_RouteLifecycle_" + $stamp)
New-Item -ItemType Directory -Path $stage -Force | Out-Null

$report = New-Object 'System.Collections.Generic.List[string]'
$failure = $null
$runtimeMutationStarted = $false
$runId = [guid]::NewGuid().ToString("N")
$installRoot = Get-Wfp4aInstallRoot
$driverTarget = Join-Path $installRoot "Driver\Serpium.Flow.Driver.sys"
$serviceTarget = Join-Path $installRoot "Service\Serpium.Flow.Service.exe"
$ownershipMarker = Join-Path $installRoot "WFP4A_INSTALL_STATE.json"
$serviceLog = Get-Wfp4aServiceLogPath
$programDataFlowRoot = Split-Path -Parent $serviceLog
$programDataSerpiumRoot = Split-Path -Parent $programDataFlowRoot
$programDataFlowExistedBefore = Test-Path -LiteralPath $programDataFlowRoot
$programDataSerpiumExistedBefore = Test-Path -LiteralPath $programDataSerpiumRoot
$state = $null
$stateIdentity = $null
$backendProcess = $null
$bridgeProcess = $null
$backendReadyPath = Join-Path $stage "local-backend-ready.json"
$backendStopPath = $backendReadyPath + ".stop"
$persistentClient = $null

function Test-Wfp4aServicePathOwned {
    param(
        [AllowNull()][object]$Record,
        [Parameter(Mandatory = $true)][string]$ExpectedPath
    )

    if ($null -eq $Record) {
        return $false
    }

    return ([string]$Record.PathName).IndexOf(
        $ExpectedPath,
        [StringComparison]::OrdinalIgnoreCase
    ) -ge 0
}

function Remove-Wfp4aOwnedInstallRoot {
    param([Parameter(Mandatory = $true)][string]$ExpectedRunId)

    if (-not (Test-Path -LiteralPath $installRoot -PathType Container)) {
        return
    }

    if (-not (Test-Path -LiteralPath $ownershipMarker -PathType Leaf)) {
        throw "Install root exists without the WFP-4A ownership marker: $installRoot"
    }

    $marker = Get-Content -LiteralPath $ownershipMarker -Raw | ConvertFrom-Json

    if ([string]$marker.runId -ne $ExpectedRunId) {
        throw "Install ownership marker does not match this lifecycle run."
    }

    Remove-Item -LiteralPath $installRoot -Recurse -Force -ErrorAction Stop
}

function Remove-Wfp4aOwnedEmptyTelemetryDirectories {
    if (-not $programDataFlowExistedBefore -and (Test-Path -LiteralPath $programDataFlowRoot -PathType Container)) {
        if (@(Get-ChildItem -LiteralPath $programDataFlowRoot -Force -ErrorAction Stop).Count -eq 0) {
            Remove-Item -LiteralPath $programDataFlowRoot -Force -ErrorAction Stop
        }
    }

    if (-not $programDataSerpiumExistedBefore -and (Test-Path -LiteralPath $programDataSerpiumRoot -PathType Container)) {
        if (@(Get-ChildItem -LiteralPath $programDataSerpiumRoot -Force -ErrorAction Stop).Count -eq 0) {
            Remove-Item -LiteralPath $programDataSerpiumRoot -Force -ErrorAction Stop
        }
    }
}

function Get-Wfp4aUnsignedLineValue {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $pattern = '(?im)^' + [regex]::Escape($Name) + ':\s+(\d+)\s*$'
    $match = [regex]::Match($Text, $pattern)

    if (-not $match.Success) {
        throw "Required numeric output field is missing: $Name"
    }

    return [uint64]$match.Groups[1].Value
}

function Get-Wfp4aStatusFlags {
    param([Parameter(Mandatory = $true)][string]$Text)

    $match = [regex]::Match($Text, '(?im)^Flags:\s+0x([0-9A-F]{8})\s*$')

    if (-not $match.Success) {
        throw "Driver status flags are missing."
    }

    return [Convert]::ToUInt32($match.Groups[1].Value, 16)
}

function Assert-Wfp4aStatus {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][ValidateSet("Armed", "Disarmed")][string]$RouteState
    )

    if (
        $Text -notmatch '(?m)^SERPIUM_WFP4A_ROUTE_CORE_READY\s*$' -or
        $Text -notmatch '(?im)^Protocol:\s+0x00040000\s*$'
    ) {
        throw "Driver status did not prove the WFP-4A route core and ABI 0x00040000."
    }

    foreach ($name in @("Callout V4", "Callout V6", "Redirect callout V4", "Redirect callout V6")) {
        if ((Get-Wfp4aUnsignedLineValue -Text $Text -Name $name) -eq 0) {
            throw "Driver status reported a zero identifier for $Name."
        }
    }

    $expectedFlags = if ($RouteState -eq "Armed") { [uint32]0x0000FDDB } else { [uint32]0x00005FDB }
    $actualFlags = Get-Wfp4aStatusFlags -Text $Text

    if ($actualFlags -ne $expectedFlags) {
        throw ("Unexpected WFP-4A status flags for {0}: 0x{1:X8}" -f $RouteState, $actualFlags)
    }

    $expectedRouteText = if ($RouteState -eq "Armed") { "armed" } else { "disarmed" }

    if ($Text -notmatch ('(?im)^Route enforcement:\s+' + $expectedRouteText + '\s*$')) {
        throw "Driver status did not report route enforcement as $expectedRouteText."
    }

    $leaseMatch = [regex]::Match($Text, '(?im)^Route lease remaining:\s+(\d+)\s+ms\s*$')

    if (-not $leaseMatch.Success) {
        throw "Route lease remaining field is missing."
    }

    $lease = [uint64]$leaseMatch.Groups[1].Value

    if (($RouteState -eq "Armed" -and $lease -eq 0) -or ($RouteState -eq "Disarmed" -and $lease -ne 0)) {
        throw "Route lease state is inconsistent with $RouteState."
    }
}

function Wait-Wfp4aRouteState {
    param(
        [Parameter(Mandatory = $true)][ValidateSet("Armed", "Disarmed")][string]$RouteState,
        [int]$TimeoutSeconds = 15
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastText = ""

    do {
        $result = Invoke-Wfp4aNative -FilePath $serviceTarget -Arguments @("status") -LogPath $null -AllowFailure
        $lastText = $result.Output -join "`n"

        if ($result.ExitCode -eq 0) {
            try {
                Assert-Wfp4aStatus -Text $lastText -RouteState $RouteState
                return $lastText
            }
            catch {
            }
        }

        Start-Sleep -Milliseconds 250
    }
    while ((Get-Date) -lt $deadline)

    throw "WFP-4A route did not reach $RouteState within $TimeoutSeconds seconds. Last status: $lastText"
}

function Read-Wfp4aExactBytes {
    param(
        [Parameter(Mandatory = $true)][IO.Stream]$Stream,
        [Parameter(Mandatory = $true)][int]$Count
    )

    [byte[]]$buffer = New-Object byte[] $Count
    $offset = 0

    while ($offset -lt $Count) {
        $read = $Stream.Read($buffer, $offset, ($Count - $offset))

        if ($read -le 0) {
            throw "Controlled local echo connection closed before the complete payload returned."
        }

        $offset += $read
    }

    Write-Output -NoEnumerate $buffer
}

function Test-Wfp4aByteArraysEqual {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Left,
        [Parameter(Mandatory = $true)][byte[]]$Right
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

function New-Wfp4aEchoClient {
    param(
        [Parameter(Mandatory = $true)][string]$Address,
        [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$Port
    )

    $ip = [Net.IPAddress]::Parse($Address)
    $client = New-Object Net.Sockets.TcpClient -ArgumentList $ip.AddressFamily
    $client.NoDelay = $true
    $client.ReceiveTimeout = 5000
    $client.SendTimeout = 5000

    try {
        $connectTask = $client.ConnectAsync($ip, $Port)

        if (-not $connectTask.Wait(5000)) {
            throw "Controlled local echo connect timed out."
        }

        $connectTask.GetAwaiter().GetResult()
        return $client
    }
    catch {
        $client.Dispose()
        throw
    }
}

function Invoke-Wfp4aEchoOnClient {
    param(
        [Parameter(Mandatory = $true)][Net.Sockets.TcpClient]$Client,
        [Parameter(Mandatory = $true)][string]$Label
    )

    [byte[]]$payload = [Text.Encoding]::UTF8.GetBytes(
        "SERPIUM-WFP4A-" + $Label + "-" + [guid]::NewGuid().ToString("N")
    )
    $stream = $Client.GetStream()
    $stream.Write($payload, 0, $payload.Length)
    $stream.Flush()
    [byte[]]$echo = Read-Wfp4aExactBytes -Stream $stream -Count $payload.Length

    if (-not (Test-Wfp4aByteArraysEqual -Left $payload -Right $echo)) {
        throw "Controlled local $Label payload was modified."
    }

    $algorithm = [Security.Cryptography.SHA256]::Create()

    try {
        $hash = [BitConverter]::ToString($algorithm.ComputeHash($payload)).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
    }

    return [pscustomobject]@{
        Label = $Label
        Length = $payload.Length
        Sha256 = $hash
    }
}

function Invoke-Wfp4aEchoRoundTrip {
    param(
        [Parameter(Mandatory = $true)][string]$Address,
        [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$Port,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $client = New-Wfp4aEchoClient -Address $Address -Port $Port

    try {
        return Invoke-Wfp4aEchoOnClient -Client $client -Label $Label
    }
    finally {
        $client.Dispose()
    }
}

function Assert-Wfp4aMutationResult {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Marker,
        [Parameter(Mandatory = $true)][bool]$Changed,
        [Parameter(Mandatory = $true)][uint32]$Generation,
        [Parameter(Mandatory = $true)][uint32]$RuleCount
    )

    if ($Text -notmatch ('(?m)^' + [regex]::Escape($Marker) + '\s*$')) {
        throw "Policy mutation marker is missing: $Marker"
    }

    $expectedChanged = if ($Changed) { "true" } else { "false" }

    if ($Text -notmatch ('(?im)^Changed:\s+' + $expectedChanged + '\s*$')) {
        throw "Policy mutation Changed field did not equal $expectedChanged."
    }

    if ((Get-Wfp4aUnsignedLineValue -Text $Text -Name "Policy generation") -ne $Generation) {
        throw "Policy generation did not equal $Generation."
    }

    $rules = [regex]::Match($Text, '(?im)^Rules:\s+(\d+)/128\s*$')

    if (-not $rules.Success -or [uint32]$rules.Groups[1].Value -ne $RuleCount) {
        throw "Policy rule count did not equal $RuleCount/128."
    }
}

function Stop-Wfp4aOwnedProcess {
    param(
        [AllowNull()][Diagnostics.Process]$Process,
        [switch]$BestEffort
    )

    if ($null -eq $Process) {
        return
    }

    try {
        if (-not $Process.HasExited) {
            $Process.Kill()

            if (-not $Process.WaitForExit(5000)) {
                throw "Owned process did not exit after termination: $($Process.Id)"
            }
        }
    }
    catch {
        if (-not $BestEffort) {
            throw
        }
    }
}

function Invoke-Wfp4aLifecycleRollback {
    $lines = New-Object 'System.Collections.Generic.List[string]'

    try {
        if (
            $null -ne (Get-Wfp4aDriverService) -and
            (Test-Path -LiteralPath $serviceTarget -PathType Leaf)
        ) {
            $rollbackDisarm = Invoke-Wfp4aNative -FilePath $serviceTarget -Arguments @("disarm-route") -LogPath (Join-Path $stage "rollback-route-disarm.log") -AllowFailure

            if (
                $rollbackDisarm.ExitCode -ne 0 -or
                ($rollbackDisarm.Output -join "`n") -notmatch '(?m)^SERPIUM_WFP4A_ROUTE_DISARMED\s*$'
            ) {
                throw "Guarded route disarm did not complete during lifecycle rollback."
            }
        }

        $lines.Add("RouteDisarmRollback: PASS")
    }
    catch {
        $lines.Add("RouteDisarmRollback: FAIL - " + $_.Exception.Message)
    }

    Stop-Wfp4aOwnedProcess -Process $bridgeProcess -BestEffort

    try {
        Write-Wfp4aUtf8File -Path $backendStopPath -Lines @("stop")
    }
    catch {
    }

    Stop-Wfp4aOwnedProcess -Process $backendProcess -BestEffort

    try {
        $userRecord = Get-Wfp4aUserService

        if ($null -ne $userRecord) {
            if (-not (Test-Wfp4aServicePathOwned -Record $userRecord -ExpectedPath $serviceTarget)) {
                throw "Refusing to remove an unowned SerpiumFlowService."
            }

            Invoke-Wfp4aNative -FilePath $serviceTarget -Arguments @("stop") -LogPath (Join-Path $stage "rollback-user-stop.log") -AllowFailure | Out-Null
            Invoke-Wfp4aNative -FilePath $serviceTarget -Arguments @("uninstall") -LogPath (Join-Path $stage "rollback-user-delete.log") -AllowFailure | Out-Null
            Wait-Wfp4aServiceState -Kind User -State Absent -TimeoutSeconds 20
        }

        $lines.Add("UserServiceRollback: PASS")
    }
    catch {
        $lines.Add("UserServiceRollback: FAIL - " + $_.Exception.Message)
    }

    try {
        $driverRecord = Get-Wfp4aDriverService

        if ($null -ne $driverRecord) {
            if (-not (Test-Wfp4aServicePathOwned -Record $driverRecord -ExpectedPath $driverTarget)) {
                throw "Refusing to remove an unowned SerpiumFlow driver."
            }

            $sc = Join-Path $env:SystemRoot "System32\sc.exe"
            Invoke-Wfp4aNative -FilePath $sc -Arguments @("stop", $script:Wfp4aDriverServiceName) -LogPath (Join-Path $stage "rollback-driver-stop.log") -AllowFailure | Out-Null
            Invoke-Wfp4aNative -FilePath $sc -Arguments @("delete", $script:Wfp4aDriverServiceName) -LogPath (Join-Path $stage "rollback-driver-delete.log") -AllowFailure | Out-Null
            Wait-Wfp4aServiceState -Kind Driver -State Absent -TimeoutSeconds 20
        }

        $lines.Add("DriverServiceRollback: PASS")
    }
    catch {
        $lines.Add("DriverServiceRollback: FAIL - " + $_.Exception.Message)
    }

    try {
        Remove-Wfp4aOwnedInstallRoot -ExpectedRunId $runId
        Remove-Item -LiteralPath $serviceLog -Force -ErrorAction SilentlyContinue
        Remove-Wfp4aOwnedEmptyTelemetryDirectories
        $lines.Add("OwnedFilesRollback: PASS")
    }
    catch {
        $lines.Add("OwnedFilesRollback: FAIL - " + $_.Exception.Message)
    }

    try {
        $wfp = Get-Wfp4aWfpNameSummary

        if (-not $wfp.Available -or $wfp.MatchCount -ne 0) {
            throw "Serpium WFP objects remain after rollback."
        }

        $lines.Add("WfpObjectsRollback: PASS")
    }
    catch {
        $lines.Add("WfpObjectsRollback: FAIL - " + $_.Exception.Message)
    }

    return $lines.ToArray()
}

try {
    $state = Get-Wfp4aState

    if ($null -eq $state) {
        throw "WFP-4A state is missing. Run prepare_wfp4a_route_test_package.ps1 first."
    }

    $stateIdentity = Assert-Wfp4aStateIdentity -State $state

    if ([int]$state.schema -ne 4 -or [string]$state.configuration -ne $Configuration) {
        throw "WFP-4A state does not match schema 4 and configuration $Configuration."
    }

    if ([string]$state.stage -notin @("TestSigningConfigured", "TestSigningActive")) {
        throw "WFP-4A state is not ready for lifecycle testing (stage: $($state.stage))."
    }

    $secureBoot = Get-Wfp4aSecureBootState

    if ($secureBoot.State -ne "Disabled") {
        throw "Secure Boot must be Disabled for this test (actual: $($secureBoot.State))."
    }

    $codeIntegrity = Get-Wfp4aCodeIntegrityState

    if (-not $codeIntegrity.Available -or -not $codeIntegrity.TestSigningRuntime) {
        throw "Windows Test Signing is not active. Run enable_wfp4a_testsigning.ps1 and reboot first."
    }

    $bfe = Get-Service -Name "BFE" -ErrorAction SilentlyContinue

    if ($null -eq $bfe -or [string]$bfe.Status -ne "Running") {
        throw "Base Filtering Engine is not running."
    }

    Assert-Wfp4aServicesAbsent

    if (Test-Path -LiteralPath $installRoot) {
        throw "The isolated WFP-4A install root already exists: $installRoot"
    }

    if (Test-Path -LiteralPath $serviceLog) {
        throw "A pre-existing service log would be modified: $serviceLog"
    }

    $packageResult = Test-Wfp4aUnsignedPackage -Configuration $Configuration
    $signedDirectory = [string]$stateIdentity.SignedPackageDirectory
    $signedManifestPath = Join-Path $signedDirectory "WFP4A_SIGNING_MANIFEST.json"

    if (-not (Test-Path -LiteralPath $signedManifestPath -PathType Leaf)) {
        throw "Signed package manifest is missing: $signedManifestPath"
    }

    $signedManifest = Get-Content -LiteralPath $signedManifestPath -Raw | ConvertFrom-Json
    [string[]]$filterActions = @($signedManifest.filterActions | ForEach-Object { [string]$_ })
    [string[]]$classifyActions = @($signedManifest.classifyActions | ForEach-Object { [string]$_ })
    [string[]]$layers = @($signedManifest.wfpLayers | ForEach-Object { [string]$_ })

    if (
        [int]$signedManifest.schema -ne 4 -or
        [string]$signedManifest.runId -ne [string]$state.runId -or
        [string]$signedManifest.configuration -ne $Configuration -or
        [string]$signedManifest.wfpMode -ne "guarded-tcp-route-enforcement" -or
        [string]$signedManifest.protocolVersion -ne "0x00040000" -or
        $filterActions.Count -ne 2 -or
        $filterActions -notcontains "FWP_ACTION_CALLOUT_INSPECTION" -or
        $filterActions -notcontains "FWP_ACTION_CALLOUT_TERMINATING" -or
        $classifyActions.Count -ne 2 -or
        $classifyActions -notcontains "FWP_ACTION_CONTINUE" -or
        $classifyActions -notcontains "FWP_ACTION_PERMIT" -or
        $layers.Count -ne 4 -or
        $layers -notcontains "ALE_AUTH_CONNECT_V4" -or
        $layers -notcontains "ALE_AUTH_CONNECT_V6" -or
        $layers -notcontains "ALE_CONNECT_REDIRECT_V4" -or
        $layers -notcontains "ALE_CONNECT_REDIRECT_V6" -or
        -not [bool]$signedManifest.trafficModification -or
        [bool]$signedManifest.blockingEnabled -or
        -not [bool]$signedManifest.redirectEnabled -or
        [bool]$signedManifest.injectionEnabled -or
        -not [bool]$signedManifest.routeEnforcementEnabled -or
        [bool]$signedManifest.routeEnforcementDefaultArmed -or
        [int]$signedManifest.routeLeaseMilliseconds -ne 5000 -or
        -not [bool]$signedManifest.routeLeaseFailOpen -or
        -not [bool]$signedManifest.tcpOnly -or
        [bool]$signedManifest.udpQuicIncluded -or
        [bool]$signedManifest.killSwitchIncluded -or
        [bool]$signedManifest.existingFlowMutation -or
        [string]$signedManifest.runtimeTestNetworkScope -ne "local-machine-only"
    ) {
        throw "Signed package manifest violates the guarded WFP-4A route contract."
    }

    $buildManifestPath = Join-Path $signedDirectory "BUILD_MANIFEST.json"
    $currentBuildManifestPath = Join-Path $packageResult.PackageDirectory "BUILD_MANIFEST.json"

    foreach ($path in @($buildManifestPath, $currentBuildManifestPath)) {
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine [string]$signedManifest.sourceBuildManifestSha256) {
            throw "A guarded WFP-4A build manifest hash changed after preparation: $path"
        }
    }

    $driverSource = Join-Path $signedDirectory "Serpium.Flow.Driver.sys"
    $serviceSource = Join-Path $signedDirectory "Serpium.Flow.Service.exe"
    $catalogSource = Join-Path $signedDirectory "Serpium.Flow.Driver.cat"
    $infSource = Join-Path $signedDirectory "Serpium.Flow.Driver.inf"
    $certificateSource = Join-Path $signedDirectory "Serpium.Flow.WFP4A.Test.cer"

    foreach ($check in @(
        [pscustomobject]@{ Path = $driverSource; Expected = [string]$signedManifest.package.driverSha256 },
        [pscustomobject]@{ Path = $serviceSource; Expected = [string]$signedManifest.package.serviceSha256 },
        [pscustomobject]@{ Path = $catalogSource; Expected = [string]$signedManifest.package.catalogSha256 },
        [pscustomobject]@{ Path = $infSource; Expected = [string]$signedManifest.package.infSha256 }
    )) {
        if (-not (Test-Path -LiteralPath $check.Path -PathType Leaf)) {
            throw "Signed package file is missing: $($check.Path)"
        }

        if ((Get-FileHash -LiteralPath $check.Path -Algorithm SHA256).Hash -ine $check.Expected) {
            throw "Signed package hash mismatch: $($check.Path)"
        }
    }

    if (-not (Test-Path -LiteralPath $certificateSource -PathType Leaf)) {
        throw "Exported WFP-4A test certificate is missing."
    }

    $certificateThumbprint = [string]$state.certificateThumbprint

    foreach ($store in @("My", "Root", "TrustedPublisher")) {
        if (-not (Test-Path -LiteralPath ("Cert:\LocalMachine\$store\" + $certificateThumbprint))) {
            throw "WFP-4A certificate is missing from LocalMachine\$store."
        }
    }

    $buildManifest = Get-Content -LiteralPath $buildManifestPath -Raw | ConvertFrom-Json
    $signTool = Find-Wfp4aSdkTool -Name "signtool.exe" -PreferredVersion ([string]$buildManifest.sdkWdkVersion)

    Invoke-Wfp4aNative -FilePath $signTool -Arguments @("verify", "/pa", "/ph", "/v", $driverSource) -LogPath (Join-Path $stage "01-verify-driver.log") | Out-Null
    Invoke-Wfp4aNative -FilePath $signTool -Arguments @("verify", "/pa", "/v", $catalogSource) -LogPath (Join-Path $stage "02-verify-catalog.log") | Out-Null
    Invoke-Wfp4aNative -FilePath $signTool -Arguments @("verify", "/pa", "/v", $serviceSource) -LogPath (Join-Path $stage "03-verify-service.log") | Out-Null
    Invoke-Wfp4aNative -FilePath $signTool -Arguments @("verify", "/pa", "/v", "/c", $catalogSource, $driverSource) -LogPath (Join-Path $stage "04-verify-driver-membership.log") | Out-Null
    Assert-Wfp4aTestSigner -Path $driverSource -ExpectedThumbprint $certificateThumbprint
    Assert-Wfp4aTestSigner -Path $serviceSource -ExpectedThumbprint $certificateThumbprint

    $wfpBefore = Get-Wfp4aWfpNameSummary

    if (-not $wfpBefore.Available -or $wfpBefore.MatchCount -ne 0) {
        throw "WFP state is not clean before lifecycle installation."
    }

    Write-Wfp4aJsonFile -Path $ownershipMarker -Value ([ordered]@{
        schema = 4
        runId = $runId
        createdUtc = (Get-Date).ToUniversalTime().ToString("o")
        stage = "Initialized"
    }) -Depth 5

    $runtimeMutationStarted = $true
    New-Item -ItemType Directory -Path (Split-Path -Parent $driverTarget) -Force | Out-Null
    New-Item -ItemType Directory -Path (Split-Path -Parent $serviceTarget) -Force | Out-Null
    Copy-Item -LiteralPath $driverSource -Destination $driverTarget -Force
    Copy-Item -LiteralPath $serviceSource -Destination $serviceTarget -Force
    Copy-Item -LiteralPath $catalogSource -Destination (Join-Path $installRoot "Driver\Serpium.Flow.Driver.cat") -Force
    Copy-Item -LiteralPath $infSource -Destination (Join-Path $installRoot "Driver\Serpium.Flow.Driver.inf") -Force
    Copy-Item -LiteralPath $certificateSource -Destination (Join-Path $installRoot "Driver\Serpium.Flow.WFP4A.Test.cer") -Force

    Write-Wfp4aJsonFile -Path $ownershipMarker -Value ([ordered]@{
        schema = 4
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
    Save-Wfp4aState -State $state

    $sc = Join-Path $env:SystemRoot "System32\sc.exe"
    Invoke-Wfp4aNative -FilePath $sc -Arguments @(
        "create", $script:Wfp4aDriverServiceName,
        "type=", "kernel", "start=", "demand", "error=", "normal",
        "binPath=", $driverTarget,
        "DisplayName=", "Serpium Flow WFP-4A Route Driver"
    ) -LogPath (Join-Path $stage "06-driver-create.log") | Out-Null

    $driverRecord = Get-Wfp4aDriverService

    if (-not (Test-Wfp4aServicePathOwned -Record $driverRecord -ExpectedPath $driverTarget)) {
        throw "Created driver service path is not owned by this run."
    }

    Invoke-Wfp4aNative -FilePath $sc -Arguments @("start", $script:Wfp4aDriverServiceName) -LogPath (Join-Path $stage "07-driver-start.log") | Out-Null
    Wait-Wfp4aServiceState -Kind Driver -State Running -TimeoutSeconds 20

    $statusInitial = Invoke-Wfp4aNative -FilePath $serviceTarget -Arguments @("status") -LogPath (Join-Path $stage "08-status-initial-disarmed.log")
    $statusInitialText = $statusInitial.Output -join "`n"
    Assert-Wfp4aStatus -Text $statusInitialText -RouteState Disarmed

    if (
        (Get-Wfp4aUnsignedLineValue -Text $statusInitialText -Name "Route config generation") -ne 1 -or
        (Get-Wfp4aUnsignedLineValue -Text $statusInitialText -Name "Redirected") -ne 0 -or
        (Get-Wfp4aUnsignedLineValue -Text $statusInitialText -Name "Redirect failures") -ne 0 -or
        (Get-Wfp4aUnsignedLineValue -Text $statusInitialText -Name "Route fail-open") -ne 0
    ) {
        throw "Driver did not start in a pristine disarmed route state."
    }

    $ping = Invoke-Wfp4aNative -FilePath $serviceTarget -Arguments @("ping") -LogPath (Join-Path $stage "09-ping.log")

    if (($ping.Output -join "`n") -notmatch '(?m)^SERPIUM_WFP4A_PING_PASS\s*$') {
        throw "Driver ping marker is missing."
    }

    $wfpDuring = Get-Wfp4aWfpNameSummary

    if (-not $wfpDuring.Available -or $wfpDuring.MatchCount -le 0) {
        throw "Serpium WFP objects were not visible while the driver was running."
    }

    $probeProcess = Get-Process -Id $PID -ErrorAction Stop
    $probeExecutable = [string]$probeProcess.Path

    if ([string]::IsNullOrWhiteSpace($probeExecutable)) {
        $probeExecutable = [string]$probeProcess.MainModule.FileName
    }

    if ([string]::IsNullOrWhiteSpace($probeExecutable) -or -not [IO.Path]::IsPathRooted($probeExecutable)) {
        throw "Lifecycle harness could not resolve its own AppId path."
    }

    $helperPath = Join-Path $PSScriptRoot "wfp4a_local_route_test_backend.ps1"

    if (-not (Test-Path -LiteralPath $helperPath -PathType Leaf)) {
        throw "Local route test backend is missing: $helperPath"
    }

    foreach ($path in @($helperPath, $backendReadyPath)) {
        if ($path.Contains('"')) {
            throw "A controlled test path contains an unsupported quote character."
        }
    }

    $powershellExe = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    $backendArgumentLine = '-NoProfile -ExecutionPolicy Bypass -File "' + $helperPath + '" -ReadyPath "' + $backendReadyPath + '" -ParentPid ' + $PID + ' -RunToken ' + $runId
    $backendProcess = Start-Process -FilePath $powershellExe `
        -ArgumentList $backendArgumentLine `
        -PassThru `
        -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $stage "10-local-backend.stdout.log") `
        -RedirectStandardError (Join-Path $stage "10-local-backend.stderr.log")

    $backendDeadline = (Get-Date).AddSeconds(30)

    while (-not (Test-Path -LiteralPath $backendReadyPath -PathType Leaf)) {
        if ($backendProcess.HasExited) {
            throw "Local route test backend exited before readiness (exit code: $($backendProcess.ExitCode))."
        }

        if ((Get-Date) -ge $backendDeadline) {
            throw "Local route test backend did not become ready within 30 seconds."
        }

        Start-Sleep -Milliseconds 200
    }

    $backend = Get-Content -LiteralPath $backendReadyPath -Raw | ConvertFrom-Json

    if (
        [int]$backend.schema -ne 1 -or
        [string]$backend.runToken -ine $runId -or
        [int]$backend.processId -ne $backendProcess.Id -or
        [int]$backend.parentProcessId -ne $PID -or
        [string]$backend.networkScope -ne "local-machine-only" -or
        [string]$backend.socksPolicy -ne "no-auth-exact-test-endpoints-only" -or
        [int]$backend.socksPort -lt 1 -or [int]$backend.socksPort -gt 65535 -or
        [int]$backend.echoV4Port -lt 1 -or [int]$backend.echoV4Port -gt 65535 -or
        [string]::IsNullOrWhiteSpace([string]$backend.addressV4)
    ) {
        throw "Local route test backend readiness contract is invalid."
    }

    $initialPolicyGeneration = [uint32](Get-Wfp4aUnsignedLineValue -Text $statusInitialText -Name "Policy generation")
    $addDirect = Invoke-Wfp4aNative -FilePath $serviceTarget -Arguments @("add-rule", "DIRECT", $probeExecutable) -LogPath $null
    $directText = $addDirect.Output -join "`n"
    $directGeneration = $initialPolicyGeneration + 1
    Assert-Wfp4aMutationResult -Text $directText -Marker "SERPIUM_WFP4A_ADD_RULE_PASS" -Changed $true -Generation $directGeneration -RuleCount 1
    $ruleId = Get-Wfp4aUnsignedLineValue -Text $directText -Name "Rule id"

    if ($ruleId -eq 0 -or $directText -notmatch '(?im)^Route intent:\s+DIRECT\s*$') {
        throw "DIRECT rule creation did not return a stable rule identifier."
    }

    $bridgeProcess = Start-Process -FilePath $serviceTarget `
        -ArgumentList @("bridge", [string]$backend.socksPort, [string]$backendProcess.Id) `
        -PassThru `
        -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $stage "11-bridge-lease.stdout.log") `
        -RedirectStandardError (Join-Path $stage "11-bridge-lease.stderr.log")

    $statusArmedText = Wait-Wfp4aRouteState -RouteState Armed -TimeoutSeconds 15

    if ($bridgeProcess.HasExited) {
        throw "Bridge exited before the first armed route test."
    }

    $persistentClient = New-Wfp4aEchoClient -Address ([string]$backend.addressV4) -Port ([int]$backend.echoV4Port)
    $directBefore = Invoke-Wfp4aEchoOnClient -Client $persistentClient -Label "DIRECT-BEFORE-SWITCH"

    $updateVpn = Invoke-Wfp4aNative -FilePath $serviceTarget -Arguments @("add-rule", "VPN", $probeExecutable) -LogPath $null
    $vpnText = $updateVpn.Output -join "`n"
    $vpnGeneration = $directGeneration + 1
    Assert-Wfp4aMutationResult -Text $vpnText -Marker "SERPIUM_WFP4A_ADD_RULE_PASS" -Changed $true -Generation $vpnGeneration -RuleCount 1

    if (
        (Get-Wfp4aUnsignedLineValue -Text $vpnText -Name "Rule id") -ne $ruleId -or
        $vpnText -notmatch '(?im)^Route intent:\s+VPN\s*$'
    ) {
        throw "DIRECT-to-VPN update did not preserve the rule identifier."
    }

    $directExisting = Invoke-Wfp4aEchoOnClient -Client $persistentClient -Label "EXISTING-FLOW-AFTER-SWITCH"
    $redirectV4 = Invoke-Wfp4aEchoRoundTrip -Address ([string]$backend.addressV4) -Port ([int]$backend.echoV4Port) -Label "VPN-REDIRECT-V4"
    $v6Tested = $false
    $redirectV6 = $null

    if (
        -not [string]::IsNullOrWhiteSpace([string]$backend.addressV6) -and
        [int]$backend.echoV6Port -ge 1 -and
        [int]$backend.echoV6Port -le 65535
    ) {
        $redirectV6 = Invoke-Wfp4aEchoRoundTrip -Address ([string]$backend.addressV6) -Port ([int]$backend.echoV6Port) -Label "VPN-REDIRECT-V6"
        $v6Tested = $true
    }

    $observation = Invoke-Wfp4aNative -FilePath $serviceTarget -Arguments @("observe", "2") -LogPath $null
    $observationText = $observation.Output -join "`n"

    if ($observationText -notmatch '(?m)^SERPIUM_WFP4A_OBSERVE_PASS\s*$') {
        throw "Observation drain did not return the WFP-4A PASS marker."
    }

    $pidPattern = [regex]::Escape([string]$PID)
    $rulePattern = [regex]::Escape([string]$ruleId)
    $v4AddressPattern = [regex]::Escape([string]$backend.addressV4)
    $directPattern = 'Observe\s+seq=\d+\s+layer=ALE_CONNECT_V4\s+pid=' + $pidPattern + '\s+app=.+?\s+appIdPresent=true\s+localPort=\d+\s+remote=' + $v4AddressPattern + ':' + [regex]::Escape([string]$backend.echoV4Port) + '\s+protocol=TCP\(6\)\s+policyGeneration=' + $directGeneration + '\s+route=DIRECT\s+ruleId=' + $rulePattern + '\s+matched=true\s+redirected=false\s+failOpen=false'
    $redirectV4Pattern = 'Observe\s+seq=\d+\s+layer=ALE_CONNECT_V4\s+pid=' + $pidPattern + '\s+app=.+?\s+appIdPresent=true\s+localPort=\d+\s+remote=' + $v4AddressPattern + ':' + [regex]::Escape([string]$backend.echoV4Port) + '\s+protocol=TCP\(6\)\s+policyGeneration=' + $vpnGeneration + '\s+route=VPN\s+ruleId=' + $rulePattern + '\s+matched=true\s+redirected=true\s+failOpen=false'

    if (-not [regex]::IsMatch($observationText, $directPattern) -or -not [regex]::IsMatch($observationText, $redirectV4Pattern)) {
        throw "Exact DIRECT and redirected VPN V4 observations were not both present."
    }

    if ($v6Tested) {
        $v6Pattern = 'Observe\s+seq=\d+\s+layer=ALE_CONNECT_V6\s+pid=' + $pidPattern + '\s+app=.+?\s+appIdPresent=true\s+localPort=\d+\s+remote=[0-9A-Fa-f:]+:' + [regex]::Escape([string]$backend.echoV6Port) + '\s+protocol=TCP\(6\)\s+policyGeneration=' + $vpnGeneration + '\s+route=VPN\s+ruleId=' + $rulePattern + '\s+matched=true\s+redirected=true\s+failOpen=false'

        if (-not [regex]::IsMatch($observationText, $v6Pattern)) {
            throw "Exact redirected VPN V6 observation was not present."
        }
    }

    $statusBeforeCrash = Invoke-Wfp4aNative -FilePath $serviceTarget -Arguments @("status") -LogPath (Join-Path $stage "12-status-before-lease-expiry.log")
    $statusBeforeCrashText = $statusBeforeCrash.Output -join "`n"
    Assert-Wfp4aStatus -Text $statusBeforeCrashText -RouteState Armed
    $redirectedBeforeCrash = Get-Wfp4aUnsignedLineValue -Text $statusBeforeCrashText -Name "Redirected"

    if ($redirectedBeforeCrash -lt $(if ($v6Tested) { 2 } else { 1 })) {
        throw "Redirect counter did not prove the controlled routed flows."
    }

    if ((Get-Wfp4aUnsignedLineValue -Text $statusBeforeCrashText -Name "Redirect failures") -ne 0) {
        throw "Redirect failures were recorded during the controlled bridge test."
    }

    Stop-Wfp4aOwnedProcess -Process $bridgeProcess
    $bridgeProcess = $null
    $statusExpiredText = Wait-Wfp4aRouteState -RouteState Disarmed -TimeoutSeconds 12
    $failOpenV4 = Invoke-Wfp4aEchoRoundTrip -Address ([string]$backend.addressV4) -Port ([int]$backend.echoV4Port) -Label "LEASE-EXPIRED-FAIL-OPEN"
    $observeFailOpen = Invoke-Wfp4aNative -FilePath $serviceTarget -Arguments @("observe", "2") -LogPath $null
    $observeFailOpenText = $observeFailOpen.Output -join "`n"
    $failOpenPattern = 'Observe\s+seq=\d+\s+layer=ALE_CONNECT_V4\s+pid=' + $pidPattern + '\s+app=.+?\s+appIdPresent=true\s+localPort=\d+\s+remote=' + $v4AddressPattern + ':' + [regex]::Escape([string]$backend.echoV4Port) + '\s+protocol=TCP\(6\)\s+policyGeneration=' + $vpnGeneration + '\s+route=DIRECT\s+ruleId=' + $rulePattern + '\s+matched=true\s+redirected=false\s+failOpen=true'

    if (-not [regex]::IsMatch($observeFailOpenText, $failOpenPattern)) {
        throw "Lease expiry did not prove an exact fail-open DIRECT observation."
    }

    $statusAfterFailOpen = Invoke-Wfp4aNative -FilePath $serviceTarget -Arguments @("status") -LogPath (Join-Path $stage "13-status-after-lease-fail-open.log")
    $statusAfterFailOpenText = $statusAfterFailOpen.Output -join "`n"
    Assert-Wfp4aStatus -Text $statusAfterFailOpenText -RouteState Disarmed

    if ((Get-Wfp4aUnsignedLineValue -Text $statusAfterFailOpenText -Name "Route fail-open") -lt 1) {
        throw "Route fail-open counter did not increase after lease expiry."
    }

    $clearRules = Invoke-Wfp4aNative -FilePath $serviceTarget -Arguments @("clear-rules") -LogPath $null
    $clearText = $clearRules.Output -join "`n"
    $fullTunnelGeneration = $vpnGeneration + 1
    Assert-Wfp4aMutationResult -Text $clearText -Marker "SERPIUM_WFP4A_CLEAR_RULES_PASS" -Changed $true -Generation $fullTunnelGeneration -RuleCount 0

    $bridgeProcess = Start-Process -FilePath $serviceTarget `
        -ArgumentList @("bridge", [string]$backend.socksPort, [string]$backendProcess.Id) `
        -PassThru `
        -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $stage "14-bridge-emergency.stdout.log") `
        -RedirectStandardError (Join-Path $stage "14-bridge-emergency.stderr.log")

    $statusRearmedText = Wait-Wfp4aRouteState -RouteState Armed -TimeoutSeconds 15

    if ($bridgeProcess.HasExited) {
        throw "Second bridge exited before the full-tunnel test."
    }

    $fullTunnelV4 = Invoke-Wfp4aEchoRoundTrip -Address ([string]$backend.addressV4) -Port ([int]$backend.echoV4Port) -Label "FULL-TUNNEL-V4"
    Stop-Wfp4aOwnedProcess -Process $bridgeProcess
    $bridgeProcess = $null
    $disarm = Invoke-Wfp4aNative -FilePath $serviceTarget -Arguments @("disarm-route") -LogPath (Join-Path $stage "15-emergency-disarm.log")

    if (($disarm.Output -join "`n") -notmatch '(?m)^SERPIUM_WFP4A_ROUTE_DISARMED\s*$') {
        throw "Emergency disarm marker is missing."
    }

    $statusDisarmedText = Wait-Wfp4aRouteState -RouteState Disarmed -TimeoutSeconds 8
    $emergencyFailOpenV4 = Invoke-Wfp4aEchoRoundTrip -Address ([string]$backend.addressV4) -Port ([int]$backend.echoV4Port) -Label "EMERGENCY-DISARM-FAIL-OPEN"
    $observeEmergency = Invoke-Wfp4aNative -FilePath $serviceTarget -Arguments @("observe", "2") -LogPath $null
    $observeEmergencyText = $observeEmergency.Output -join "`n"
    $fullTunnelRedirectPattern = 'Observe\s+seq=\d+\s+layer=ALE_CONNECT_V4\s+pid=' + $pidPattern + '\s+app=.+?\s+appIdPresent=true\s+localPort=\d+\s+remote=' + $v4AddressPattern + ':' + [regex]::Escape([string]$backend.echoV4Port) + '\s+protocol=TCP\(6\)\s+policyGeneration=' + $fullTunnelGeneration + '\s+route=VPN\s+ruleId=0\s+matched=false\s+redirected=true\s+failOpen=false'
    $emergencyFailOpenPattern = 'Observe\s+seq=\d+\s+layer=ALE_CONNECT_V4\s+pid=' + $pidPattern + '\s+app=.+?\s+appIdPresent=true\s+localPort=\d+\s+remote=' + $v4AddressPattern + ':' + [regex]::Escape([string]$backend.echoV4Port) + '\s+protocol=TCP\(6\)\s+policyGeneration=' + $fullTunnelGeneration + '\s+route=DIRECT\s+ruleId=0\s+matched=false\s+redirected=false\s+failOpen=true'

    if (
        -not [regex]::IsMatch($observeEmergencyText, $fullTunnelRedirectPattern) -or
        -not [regex]::IsMatch($observeEmergencyText, $emergencyFailOpenPattern)
    ) {
        throw "Full-tunnel redirect and emergency fail-open observations were not both present."
    }

    if ($null -ne $persistentClient) {
        $persistentClient.Dispose()
        $persistentClient = $null
    }

    Write-Wfp4aUtf8File -Path $backendStopPath -Lines @("stop")

    if (-not $backendProcess.WaitForExit(8000)) {
        Stop-Wfp4aOwnedProcess -Process $backendProcess
    }

    $backendProcess = $null

    Write-Wfp4aUtf8File -Path (Join-Path $stage "ROUTE_EVIDENCE.txt") -Lines @(
        "EvidencePolicy: sanitized exact-match summary; raw observations, AppIds, local addresses, and ports excluded",
        "NetworkScope: local-machine-only",
        "ExternalConnections: none",
        "SocksPolicy: no-auth-exact-test-endpoints-only",
        "InitialRouteState: disarmed",
        "InitialRouteConfigGeneration: 1",
        "DirectRule: PASS",
        "DirectV4RoundTrip: PASS; bytes=$($directBefore.Length); payloadSha256=$($directBefore.Sha256)",
        "ExistingFlowAfterDirectToVpnSwitch: PASS; bytes=$($directExisting.Length); payloadSha256=$($directExisting.Sha256)",
        "NewVpnV4Redirect: PASS; bytes=$($redirectV4.Length); payloadSha256=$($redirectV4.Sha256)",
        $(if ($v6Tested) { "NewVpnV6Redirect: PASS; bytes=$($redirectV6.Length); payloadSha256=$($redirectV6.Sha256)" } else { "NewVpnV6Redirect: SKIPPED_NO_LOCAL_NONLOOPBACK_IPV6" }),
        "LeaseExpiryDisarm: PASS",
        "LeaseExpiryFailOpenV4: PASS; bytes=$($failOpenV4.Length); payloadSha256=$($failOpenV4.Sha256)",
        "FullTunnelEmptyRulesV4: PASS; bytes=$($fullTunnelV4.Length); payloadSha256=$($fullTunnelV4.Sha256)",
        "EmergencyOwnedBridgeTermination: PASS",
        "EmergencyDisarm: PASS",
        "EmergencyDisarmFailOpenV4: PASS; bytes=$($emergencyFailOpenV4.Length); payloadSha256=$($emergencyFailOpenV4.Sha256)",
        "RedirectFailures: 0",
        "BlockingEnabled: False",
        "InjectionEnabled: False",
        "KillSwitchIncluded: False",
        "ExistingFlowMutation: False"
    )

    Invoke-Wfp4aNative -FilePath $serviceTarget -Arguments @("install") -LogPath (Join-Path $stage "16-user-service-install.log") | Out-Null
    $userRecord = Get-Wfp4aUserService

    if (-not (Test-Wfp4aServicePathOwned -Record $userRecord -ExpectedPath $serviceTarget)) {
        throw "Created user service path is not owned by this run."
    }

    Invoke-Wfp4aNative -FilePath $serviceTarget -Arguments @("start") -LogPath (Join-Path $stage "17-user-service-start.log") | Out-Null
    Wait-Wfp4aServiceState -Kind User -State Running -TimeoutSeconds 20
    Start-Sleep -Seconds 3
    Wait-Wfp4aServiceState -Kind User -State Running -TimeoutSeconds 5
    Wait-Wfp4aServiceState -Kind Driver -State Running -TimeoutSeconds 5
    Invoke-Wfp4aNative -FilePath $serviceTarget -Arguments @("stop") -LogPath (Join-Path $stage "18-user-service-stop.log") | Out-Null
    Wait-Wfp4aServiceState -Kind User -State Stopped -TimeoutSeconds 20
    Invoke-Wfp4aNative -FilePath $serviceTarget -Arguments @("uninstall") -LogPath (Join-Path $stage "19-user-service-delete.log") | Out-Null
    Wait-Wfp4aServiceState -Kind User -State Absent -TimeoutSeconds 20

    Invoke-Wfp4aNative -FilePath $sc -Arguments @("stop", $script:Wfp4aDriverServiceName) -LogPath (Join-Path $stage "20-driver-stop.log") | Out-Null
    Wait-Wfp4aServiceState -Kind Driver -State Stopped -TimeoutSeconds 20
    Invoke-Wfp4aNative -FilePath $sc -Arguments @("delete", $script:Wfp4aDriverServiceName) -LogPath (Join-Path $stage "21-driver-delete.log") | Out-Null
    Wait-Wfp4aServiceState -Kind Driver -State Absent -TimeoutSeconds 20

    Remove-Wfp4aOwnedInstallRoot -ExpectedRunId $runId
    Remove-Item -LiteralPath $serviceLog -Force -ErrorAction SilentlyContinue
    Remove-Wfp4aOwnedEmptyTelemetryDirectories

    $wfpAfter = Get-Wfp4aWfpNameSummary

    if (-not $wfpAfter.Available -or $wfpAfter.MatchCount -ne 0) {
        throw "Dynamic WFP objects remain after driver removal."
    }

    Assert-Wfp4aServicesAbsent
    $state.installRunId = $null
    $state.stage = "LifecyclePassed"
    Save-Wfp4aState -State $state

    $report.Add("State: PASS")
    $report.Add("Stage: WFP-4A guarded TCP route lifecycle")
    $report.Add("RunId: " + $runId)
    $report.Add("ProtocolVersion: 0x00040000")
    $report.Add("WfpMode: guarded-tcp-route-enforcement")
    $report.Add("InitialRouteState: disarmed")
    $report.Add("TcpRedirectV4: PASS")
    $report.Add("TcpRedirectV6: " + $(if ($v6Tested) { "PASS" } else { "SKIPPED_NO_LOCAL_NONLOOPBACK_IPV6" }))
    $report.Add("DirectToVpnNewFlowSwitch: PASS")
    $report.Add("ExistingTcpFlowPreserved: PASS")
    $report.Add("FullTunnelEmptyRules: PASS")
    $report.Add("LeaseExpiryFailOpen: PASS")
    $report.Add("EmergencyOwnedBridgeTermination: PASS")
    $report.Add("EmergencyDisarm: PASS")
    $report.Add("RedirectFailures: 0")
    $report.Add("BlockingEnabled: False")
    $report.Add("InjectionEnabled: False")
    $report.Add("UdpQuicIncluded: False")
    $report.Add("KillSwitchIncluded: False")
    $report.Add("ExternalConnections: none")
    $report.Add("NetworkConfigurationChanges: none")
    $report.Add("SerpiumWfpMatchesBefore: " + $wfpBefore.MatchCount)
    $report.Add("SerpiumWfpMatchesDuring: " + $wfpDuring.MatchCount)
    $report.Add("SerpiumWfpMatchesAfter: " + $wfpAfter.MatchCount)
    $report.Add("DriverServiceAfter: Absent")
    $report.Add("UserServiceAfter: Absent")
    $report.Add("InstallFilesAfter: Absent")
    $report.Add("ServiceLogAfter: Absent")
    $report.Add("CertificateAfter: Present (remove with cleanup_wfp4a_route_runtime.ps1)")
    $report.Add("BcdAfter: Preserved (restore with cleanup_wfp4a_route_runtime.ps1)")
}
catch {
    $failure = $_.Exception.Message
    $report.Add("State: FAIL")
    $report.Add("Stage: WFP-4A guarded TCP route lifecycle")
    $report.Add("RunId: " + $runId)
    $report.Add("Error: " + $failure)
}
finally {
    if ($null -ne $persistentClient) {
        try { $persistentClient.Dispose() } catch { }
    }

    $rollbackSucceeded = $true

    if ($null -ne $failure -and $runtimeMutationStarted) {
        foreach ($line in Invoke-Wfp4aLifecycleRollback) {
            $report.Add([string]$line)

            if ([string]$line -match ': FAIL') {
                $rollbackSucceeded = $false
            }
        }
    }

    if ($null -ne $failure -and $null -ne $stateIdentity) {
        try {
            Remove-Wfp4aCertificateByThumbprint -Thumbprint ([string]$stateIdentity.CertificateThumbprint)
            $report.Add("CertificateFailureRollback: PASS")
        }
        catch {
            $rollbackSucceeded = $false
            $report.Add("CertificateFailureRollback: FAIL - " + $_.Exception.Message)
        }

        if ([bool]$state.bcdChangedByScript) {
            try {
                $bcdedit = Join-Path $env:SystemRoot "System32\bcdedit.exe"
                Invoke-Wfp4aNative -FilePath $bcdedit -Arguments @("-set", "TESTSIGNING", "OFF") -LogPath (Join-Path $stage "failure-bcd-rollback.log") | Out-Null
                $report.Add("BcdFailureRollback: PASS_REBOOT_REQUIRED")
            }
            catch {
                $rollbackSucceeded = $false
                $report.Add("BcdFailureRollback: FAIL - " + $_.Exception.Message)
            }
        }

        if ($rollbackSucceeded) {
            Remove-Item -LiteralPath ([string]$stateIdentity.SignedPackageDirectory) -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath (Get-Wfp4aStatePath) -Force -ErrorAction SilentlyContinue
            $report.Add("FailureStateCleanup: PASS")
        }
        else {
            $report.Add("FailureStateCleanup: PRESERVED_FOR_RECOVERY")
        }
    }
}

Write-Wfp4aUtf8File -Path (Join-Path $stage "LIFECYCLE_RESULT.txt") -Lines ($report.ToArray())
$archive = New-Wfp4aResultArchive -Prefix "Serpium_WFP4A_RouteLifecycle_Result" -StageDirectory $stage

Write-Host ""

if ($null -eq $failure) {
    Write-Host "SERPIUM_WFP4A_ROUTE_LIFECYCLE_PASS" -ForegroundColor Green
    Write-Host ("Result archive: " + $archive) -ForegroundColor Cyan
    exit 0
}

Write-Host "SERPIUM_WFP4A_ROUTE_LIFECYCLE_FAIL" -ForegroundColor Red
Write-Host $failure -ForegroundColor Red
Write-Host ("Result archive: " + $archive) -ForegroundColor Yellow
exit 1
