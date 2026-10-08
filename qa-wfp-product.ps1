#requires -version 5.1
[CmdletBinding()]
param(
    [string]$Root = "D:\Program\Serpium\SerpiumVPN",

    [ValidateSet("Source", "Runtime", "Published", "SourceRuntime", "All")]
    [string]$Phase = "SourceRuntime",

    [string]$PublishRoot = "",

    [string]$ExpectedVersion = "",

    [switch]$NoArchive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$stamp = Get-Date -Format "MMdd_HHmm"
$resultRoot = Join-Path $env:TEMP ("WFP_QA_v1_RESULT_" + $stamp)
$resultTxt = Join-Path $resultRoot "RESULT.txt"
$qaLog = Join-Path $resultRoot "qa.log"
$resultZip = Join-Path $env:USERPROFILE ("Downloads\WFP_QA_v1_RESULT_" + $stamp + ".zip")

New-Item -ItemType Directory -Path $resultRoot -Force | Out-Null

$script:Checks = New-Object System.Collections.ArrayList
$script:Warnings = New-Object System.Collections.ArrayList

function Add-Pass {
    param([string]$Name, [string]$Detail = "")
    [void]$script:Checks.Add(
        [pscustomobject]@{
            State = "PASS"
            Name = $Name
            Detail = $Detail
        })
    Write-Host ("[PASS] " + $Name + $(if($Detail){" — $Detail"}else{""})) -ForegroundColor Green
}

function Add-Warn {
    param([string]$Name, [string]$Detail)
    [void]$script:Warnings.Add(
        [pscustomobject]@{
            State = "WARN"
            Name = $Name
            Detail = $Detail
        })
    Write-Host ("[WARN] " + $Name + " — " + $Detail) -ForegroundColor Yellow
}

function Assert-Condition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Name,
        [string]$Failure,
        [string]$Detail = ""
    )

    if (-not $Condition) {
        if ([string]::IsNullOrWhiteSpace($Failure)) {
            $Failure = $Name
        }
        throw $Failure
    }

    Add-Pass -Name $Name -Detail $Detail
}

function Get-Sha256Lower {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Read-Json {
    param([Parameter(Mandatory = $true)][string]$Path)
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Assert-FileContainsMarkers {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Markers,
        [Parameter(Mandatory = $true)][string]$Label
    )

    Assert-Condition `
        -Condition (Test-Path -LiteralPath $Path -PathType Leaf) `
        -Name "$Label exists" `
        -Failure "$Label not found: $Path"

    $text = [IO.File]::ReadAllText($Path)
    foreach ($marker in $Markers) {
        Assert-Condition `
            -Condition ($text.IndexOf($marker, [StringComparison]::Ordinal) -ge 0) `
            -Name "$Label marker" `
            -Detail $marker `
            -Failure "$Label is missing required marker: $marker"
    }
}

function Assert-WfpRuntime {
    param([Parameter(Mandatory = $true)][string]$RuntimeRoot)

    $manifestPath = Join-Path $RuntimeRoot "WFP_RUNTIME_MANIFEST.json"
    Assert-Condition `
        -Condition (Test-Path -LiteralPath $manifestPath -PathType Leaf) `
        -Name "WFP runtime manifest" `
        -Detail $manifestPath `
        -Failure "WFP runtime manifest is missing: $manifestPath"

    $manifest = Read-Json -Path $manifestPath

    Assert-Condition `
        -Condition ([int]$manifest.schema -eq 1) `
        -Name "WFP runtime schema" `
        -Detail "1" `
        -Failure "Unsupported WFP runtime schema: $($manifest.schema)"

    Assert-Condition `
        -Condition ([string]$manifest.protocolAbi -eq "0x00040000") `
        -Name "WFP runtime ABI" `
        -Detail "0x00040000" `
        -Failure "Unexpected WFP runtime ABI: $($manifest.protocolAbi)"

    Assert-Condition `
        -Condition ([string]$manifest.platform -eq "x64") `
        -Name "WFP runtime platform" `
        -Detail "x64" `
        -Failure "Unexpected WFP runtime platform: $($manifest.platform)"

    $required = @(
        "Serpium.Flow.Service.exe",
        "Serpium.Flow.Driver.sys",
        "Serpium.Flow.Driver.inf",
        "serpium.flow.driver.cat",
        "BUILD_MANIFEST.json"
    )

    foreach ($name in $required) {
        $entry = @(
            $manifest.files |
                Where-Object { [string]$_.name -ieq $name } |
                Select-Object -First 1
        )

        Assert-Condition `
            -Condition ($entry.Count -eq 1) `
            -Name "WFP manifest entry" `
            -Detail $name `
            -Failure "WFP runtime manifest is missing entry: $name"

        $path = Join-Path $RuntimeRoot $name
        Assert-Condition `
            -Condition (Test-Path -LiteralPath $path -PathType Leaf) `
            -Name "WFP runtime file" `
            -Detail $name `
            -Failure "WFP runtime file is missing: $name"

        $actual = Get-Sha256Lower -Path $path
        $expected = ([string]$entry[0].sha256).ToLowerInvariant()

        Assert-Condition `
            -Condition ($actual -eq $expected) `
            -Name "WFP runtime hash" `
            -Detail $name `
            -Failure "WFP runtime SHA-256 mismatch: $name"
    }

    return $manifest
}

function Assert-NativeBuildManifest {
    param([Parameter(Mandatory = $true)][string]$RuntimeRoot)

    $path = Join-Path $RuntimeRoot "BUILD_MANIFEST.json"
    $manifest = Read-Json -Path $path

    Assert-Condition `
        -Condition ([int]$manifest.schema -eq 4) `
        -Name "Native build manifest schema" `
        -Detail "4" `
        -Failure "Unexpected native build manifest schema: $($manifest.schema)"

    Assert-Condition `
        -Condition ([string]$manifest.buildMode -eq "direct-cl-link") `
        -Name "Native direct toolchain" `
        -Detail "cl.exe + link.exe" `
        -Failure "Native package was not produced by direct-cl-link."

    Assert-Condition `
        -Condition ([string]$manifest.protocolVersion -eq "0x00040000") `
        -Name "Native protocol ABI" `
        -Detail "0x00040000" `
        -Failure "Native ABI mismatch: $($manifest.protocolVersion)"

    Assert-Condition `
        -Condition ([bool]$manifest.wfpEnabled) `
        -Name "Native WFP enabled" `
        -Failure "Native manifest says WFP is disabled."

    Assert-Condition `
        -Condition ([bool]$manifest.routeEnforcementEnabled) `
        -Name "Route enforcement source" `
        -Failure "Route enforcement is not enabled in native manifest."

    Assert-Condition `
        -Condition (-not [bool]$manifest.routeEnforcementDefaultArmed) `
        -Name "Disarmed by default" `
        -Failure "Native route enforcement unexpectedly defaults to armed."

    Assert-Condition `
        -Condition ([bool]$manifest.routeLeaseFailOpen) `
        -Name "Lease fail-open" `
        -Failure "Native route lease is not fail-open."

    Assert-Condition `
        -Condition (-not [bool]$manifest.killSwitchIncluded) `
        -Name "No kill switch" `
        -Failure "Unexpected kill-switch behavior is included."

    Assert-Condition `
        -Condition (-not [bool]$manifest.injectionEnabled) `
        -Name "Datagram packet injection remains disabled" `
        -Detail "connected UDP runtime remains separate/unproven" `
        -Failure "Packet injection unexpectedly became enabled without a dedicated runtime gate."

    Assert-Condition `
        -Condition ([bool]$manifest.domainRoutingEnabled) `
        -Name "TCP domain routing" `
        -Detail ([string]$manifest.domainRoutingMatch) `
        -Failure "Native domain routing is missing."

    Assert-Condition `
        -Condition ([bool]$manifest.udpApplicationRoutingIncluded) `
        -Name "UDP app routing source" `
        -Detail ([string]$manifest.udpProxyTransport) `
        -Failure "UDP application routing source is missing."

    Assert-Condition `
        -Condition ([bool]$manifest.quicTcpFallbackIncluded) `
        -Name "QUIC TCP fallback source" `
        -Failure "QUIC TCP fallback is missing."

    if ([string]$manifest.udpConnectedSocketCompatibility -ne "SOURCE_IMPLEMENTED_RUNTIME_NOT_PROVEN") {
        Add-Warn `
            -Name "Connected UDP status changed" `
            -Detail ([string]$manifest.udpConnectedSocketCompatibility)
    } else {
        Add-Pass `
            -Name "Connected UDP boundary remains explicit" `
            -Detail "SOURCE_IMPLEMENTED_RUNTIME_NOT_PROVEN"
    }
}

function Assert-ProjectVersion {
    if ([string]::IsNullOrWhiteSpace($ExpectedVersion)) {
        return
    }

    $projectPath = Join-Path $Root "SerpiumVPN.csproj"
    Assert-Condition `
        -Condition (Test-Path -LiteralPath $projectPath -PathType Leaf) `
        -Name "SerpiumVPN.csproj exists" `
        -Failure "Project file not found: $projectPath"

    [xml]$project = Get-Content -LiteralPath $projectPath -Raw
    $versions = @(
        $project.Project.PropertyGroup.Version |
            Where-Object { $null -ne $_ }
    )

    Assert-Condition `
        -Condition ($versions.Count -gt 0) `
        -Name "Project version declared" `
        -Failure "SerpiumVPN.csproj has no <Version>."

    $actual = [string]$versions[0]

    Assert-Condition `
        -Condition ($actual -eq $ExpectedVersion) `
        -Name "Release version matches source" `
        -Detail $actual `
        -Failure (
            "release.ps1 requested version '$ExpectedVersion' but " +
            "SerpiumVPN.csproj is '$actual'. Run set-version.ps1 first."
        )
}

function Test-SourcePhase {
    Assert-ProjectVersion

    Assert-FileContainsMarkers `
        -Path (Join-Path $Root "Relay\Routing\WfpRoutingController.cs") `
        -Label "WFP routing controller" `
        -Markers @(
            "WfpProductReadiness.Inspect(force: true)",
            "readiness.PackagePresent && !readiness.CanUseWfp",
            "SyncApplicationRulesAsync",
            "sync-vpn-rules",
            "SERPIUM_WFP4A_SYNC_RULES_PASS"
        )

    Assert-FileContainsMarkers `
        -Path (Join-Path $Root "Relay\Routing\WfpProductReadiness.cs") `
        -Label "WFP product readiness" `
        -Markers @(
            "WfpProductReadinessKind.InstalledReady",
            "runtimeManifestSha256",
            "OwnershipConflict",
            "RecoveryRequired"
        )

    Assert-FileContainsMarkers `
        -Path (Join-Path $Root "MainWindow.xaml.cs") `
        -Label "WFP product integration" `
        -Markers @(
            "TryRecoverActiveWfpToTunFallbackAsync",
            "WFP → TUN automatic fallback",
            "Авто-fallback активирован",
            "WfpProductReadinessSnapshot readiness"
        )

    Assert-FileContainsMarkers `
        -Path (Join-Path $Root "SerpiumUpdater\Program.cs") `
        -Label "Updater WFP ownership" `
        -Markers @(
            "ValidateStagedWfpPackage",
            "VerifyInstalledWfpPackage",
            "StopOwnedWfpUserModeProcesses",
            "WFP_RUNTIME_MANIFEST.json"
        )

    Assert-FileContainsMarkers `
        -Path (Join-Path $Root "release.ps1") `
        -Label "Release WFP delivery" `
        -Markers @(
            "Assert-WfpRuntimePackage",
            "Assert-WfpZipPayload",
            "Assert-InnoOwnsPublishedWfp",
            "RequireProductionTrust",
            "stage_wfp_production_runtime.ps1"
        )

    $driverScripts = @(
        "verify_wfp_production_trust.ps1",
        "install_wfp_product_driver.ps1",
        "uninstall_wfp_product_driver.ps1",
        "update_wfp_product_driver.ps1",
        "get_wfp_product_driver_state.ps1",
        "prepare_wfp_partner_submission.ps1",
        "import_wfp_microsoft_signed_return.ps1",
        "stage_wfp_production_runtime.ps1"
    )

    foreach ($name in $driverScripts) {
        Assert-Condition `
            -Condition (
                Test-Path -LiteralPath (
                    Join-Path $Root ("Native\Serpium.Flow\scripts\" + $name)
                ) -PathType Leaf
            ) `
            -Name "Product lifecycle/signing entry point" `
            -Detail $name `
            -Failure "Required WFP product script is missing: $name"
    }
}

function Test-RuntimePhase {
    $runtimeRoot = Join-Path $Root "bin_files\wfp\x64"
    [void](Assert-WfpRuntime -RuntimeRoot $runtimeRoot)
    Assert-NativeBuildManifest -RuntimeRoot $runtimeRoot
}

function Test-PublishedPhase {
    if ([string]::IsNullOrWhiteSpace($PublishRoot)) {
        $PublishRoot = Join-Path $Root "publish\app"
    }

    Assert-Condition `
        -Condition (Test-Path -LiteralPath $PublishRoot -PathType Container) `
        -Name "Publish root" `
        -Detail $PublishRoot `
        -Failure "Publish root does not exist: $PublishRoot"

    foreach ($required in @(
        "SerpiumVPN.exe",
        "SerpiumVPN.dll",
        "SerpiumUpdater.exe"
    )) {
        Assert-Condition `
            -Condition (Test-Path -LiteralPath (Join-Path $PublishRoot $required) -PathType Leaf) `
            -Name "Published product file" `
            -Detail $required `
            -Failure "Published product file is missing: $required"
    }

    foreach ($engineManifest in @(Get-ChildItem -LiteralPath (Join-Path $PublishRoot 'Engines') -Filter manifest.json -File -Recurse)) {
        $engine = Read-Json -Path $engineManifest.FullName
        $entryPath = Join-Path $engineManifest.DirectoryName ([string]$engine.assembly)
        Assert-Condition -Condition (Test-Path -LiteralPath $entryPath -PathType Leaf) `
            -Name 'Published engine entry assembly' -Detail $engineManifest.Directory.Name `
            -Failure "Published engine entry assembly is missing: $entryPath"
    }

    $forbiddenExact = @(
        "profiles.svault",
        "routing.sroutes",
        "driver-state.json",
        "key-client.json",
        "WFP_SUBMISSION.json"
    )

    $bad = New-Object System.Collections.ArrayList

    Get-ChildItem -LiteralPath $PublishRoot -File -Recurse | ForEach-Object {
        $name = $_.Name
        $relative = $_.FullName.Substring(
            [IO.Path]::GetFullPath($PublishRoot).TrimEnd('\').Length
        ).TrimStart('\')

        if ($forbiddenExact -contains $name) {
            [void]$bad.Add("$relative [private/runtime state]")
            return
        }

        if ($_.Extension -ieq ".pdb") {
            [void]$bad.Add("$relative [PDB]")
            return
        }

        if ($_.Extension -ieq ".log") {
            [void]$bad.Add("$relative [log]")
            return
        }

        if ($name -match '(?i)_RESULT_.*\.zip$') {
            [void]$bad.Add("$relative [diagnostic result]")
            return
        }
    }

    Assert-Condition `
        -Condition ($bad.Count -eq 0) `
        -Name "Publish private/generated-state scan" `
        -Detail "no PDB/log/profile/routing/state/result artifacts" `
        -Failure ("Forbidden publish artifact(s): " + ($bad -join "; "))

    [void](Assert-WfpRuntime -RuntimeRoot (
        Join-Path $PublishRoot "bin_files\wfp\x64"
    ))
}

function Export-Result {
    param(
        [string]$State,
        [string]$Message
    )

    $passCount = @($script:Checks).Count
    $warnCount = @($script:Warnings).Count

    @(
        "Patch: WFP_Consolidated_Product_QA_v1",
        "State: $State",
        "Phase: $Phase",
        "Message: $Message",
        "Pass: $passCount",
        "Warn: $warnCount",
        "Fail: $(if($State -eq 'PASS'){0}else{1})",
        "ProtocolAbi: 0x00040000",
        "DriverLifecycle: NOT_RUN",
        "Signing: NOT_RUN",
        "NetworkTests: NOT_RUN",
        "BCD/TestSigning: NOT_TOUCHED",
        "HyperV: NOT_TOUCHED",
        "ResultName: WFP_QA_v1_RESULT_MMDD_HHmm.zip",
        "Created: $(Get-Date -Format o)"
    ) | Set-Content -LiteralPath $resultTxt -Encoding utf8

    @(
        $script:Checks |
            ForEach-Object {
                "[PASS] $($_.Name)$(if($_.Detail){' — '+$_.Detail}else{''})"
            }
        $script:Warnings |
            ForEach-Object {
                "[WARN] $($_.Name) — $($_.Detail)"
            }
    ) | Set-Content -LiteralPath $qaLog -Encoding utf8

    if (-not $NoArchive) {
        Compress-Archive `
            -LiteralPath @($resultTxt, $qaLog) `
            -DestinationPath $resultZip `
            -CompressionLevel Optimal `
            -Force
    }
}

try {
    $runSource = $Phase -in @("Source", "SourceRuntime", "All")
    $runRuntime = $Phase -in @("Runtime", "SourceRuntime", "All")
    $runPublished = $Phase -in @("Published", "All")

    if ($runSource) {
        Write-Host ""
        Write-Host "=== WFP Product QA: source contracts ===" -ForegroundColor Cyan
        Test-SourcePhase
    }

    if ($runRuntime) {
        Write-Host ""
        Write-Host "=== WFP Product QA: packaged runtime ===" -ForegroundColor Cyan
        Test-RuntimePhase
    }

    if ($runPublished) {
        Write-Host ""
        Write-Host "=== WFP Product QA: publish payload ===" -ForegroundColor Cyan
        Test-PublishedPhase
    }

    Export-Result `
        -State "PASS" `
        -Message "Consolidated source/runtime/publish QA completed for requested phase."

    Write-Host ""
    Write-Host "SERPIUM_WFP_CONSOLIDATED_PRODUCT_QA_V1_PASS" -ForegroundColor Green
    if (-not $NoArchive) {
        Write-Host ("Result: " + $resultZip) -ForegroundColor Cyan
    }
}
catch {
    $message = $_.Exception.Message
    try {
        Export-Result -State "FAIL" -Message $message
    } catch { }

    Write-Host ""
    Write-Host "SERPIUM_WFP_CONSOLIDATED_PRODUCT_QA_V1_FAILED" -ForegroundColor Red
    Write-Host $message -ForegroundColor Red
    if (-not $NoArchive) {
        Write-Host ("Result: " + $resultZip) -ForegroundColor Yellow
    }
    throw
}
