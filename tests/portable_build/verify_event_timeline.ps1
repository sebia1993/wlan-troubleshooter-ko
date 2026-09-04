[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageOutputPath,

    [Parameter()]
    [string]$PythonPath = "python"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Restore-EnvironmentValue {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()][string]$Value
    )
    if ($null -eq $Value) {
        Remove-Item ("Env:" + $Name) -ErrorAction SilentlyContinue
    }
    else {
        [Environment]::SetEnvironmentVariable($Name, $Value, "Process")
    }
}

function Assert-ContainsAll {
    param(
        [Parameter(Mandatory = $true)]$Observed,
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )
    foreach ($Value in $Expected) {
        if ($Observed -notcontains $Value) {
            throw "$Label is missing: $Value"
        }
    }
}

function Invoke-PortableAnalysis {
    param(
        [Parameter(Mandatory = $true)][string]$Application,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$Capture,
        [Parameter(Mandatory = $true)][string]$Output
    )

    $Arguments = @(
        ('--analyze-capture="' + $Capture + '"'),
        ('--analysis-output="' + $Output + '"')
    )
    $Process = Start-Process -FilePath $Application -ArgumentList $Arguments -WorkingDirectory $WorkingDirectory -Wait -PassThru
    if ($Process.ExitCode -ne 0) {
        if (Test-Path -LiteralPath $Output -PathType Leaf) {
            try {
                $Failure = Get-Content -LiteralPath $Output -Raw | ConvertFrom-Json -Depth 96
                Write-Host ("Portable event state: " + [string]$Failure.protocol_inventory_state)
                Write-Host ("Portable event message: " + [string]$Failure.protocol_inventory_message)
            }
            catch {
                Write-Host "Portable event result could not be parsed safely."
            }
        }
        throw "Portable event analysis process failed with exit code $($Process.ExitCode)."
    }
    if (-not (Test-Path -LiteralPath $Output -PathType Leaf)) {
        throw "Portable event analysis did not create its result."
    }
}

function Read-CompletedAnalysis {
    param(
        [Parameter(Mandatory = $true)][string]$Output,
        [Parameter(Mandatory = $true)][int]$ExpectedFrames
    )

    $Raw = Get-Content -LiteralPath $Output -Raw
    $Result = $Raw | ConvertFrom-Json -Depth 96
    if ($Result.schema_version -ne 2 -or $Result.protocol_inventory_state -ne "completed") {
        throw "Portable event analysis did not complete with schema version 2."
    }
    if ($Result.protocol_inventory.inventory.frames_observed -ne $ExpectedFrames) {
        throw "Portable event analysis observed an unexpected frame count."
    }
    if (
        $Result.protocol_inventory.inventory.complete -ne $true -or
        $Result.protocol_inventory.event_timeline.complete -ne $true
    ) {
        throw "Portable event analysis was not marked complete."
    }
    return [pscustomobject]@{
        Raw = $Raw
        Result = $Result
    }
}

function Assert-NoForbiddenText {
    param(
        [Parameter(Mandatory = $true)][string]$Raw,
        [Parameter(Mandatory = $true)][string[]]$Forbidden
    )
    foreach ($Value in $Forbidden) {
        if ($Raw.Contains($Value, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Portable event result exposed a forbidden path or identifier."
        }
    }
}

$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$ProjectText = Get-Content -LiteralPath (Join-Path $RepositoryRoot "pyproject.toml") -Raw
$ReleaseTag = [regex]::Match($ProjectText, '(?m)^release-tag\s*=\s*"([^"]+)"').Groups[1].Value
if ([string]::IsNullOrWhiteSpace($ReleaseTag)) {
    throw "Release tag is missing."
}
$ExpectedProductVersion = $ReleaseTag.Substring(1)
$ExpectedArchiveName = "WlanTroubleshooterKO-$ReleaseTag-win64-portable.zip"

$PackageOutputPath = [System.IO.Path]::GetFullPath($PackageOutputPath)
if (-not (Test-Path -LiteralPath $PackageOutputPath -PathType Leaf)) {
    throw "Portable package metadata is missing."
}
$Package = Get-Content -LiteralPath $PackageOutputPath -Raw | ConvertFrom-Json -Depth 32
$Archive = [System.IO.Path]::GetFullPath([string]$Package.archive)
if (-not (Test-Path -LiteralPath $Archive -PathType Leaf)) {
    throw "Portable archive is missing."
}
if ((Split-Path -Leaf $Archive) -ne $ExpectedArchiveName) {
    throw "Portable archive name does not match release metadata."
}

$WorkRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("wlan-event-test-" + [guid]::NewGuid().ToString("N"))
$Expanded = Join-Path $WorkRoot "portable"
$EthernetCapture = Join-Path $WorkRoot "private-event-integration-capture.pcap"
$EthernetOutput = Join-Path $WorkRoot "ethernet-analysis-result.json"
$WirelessCapture = Join-Path $WorkRoot "private-wireless-event-capture.pcap"
$WirelessOutput = Join-Path $WorkRoot "wireless-analysis-result.json"
New-Item -ItemType Directory -Path $Expanded -Force | Out-Null
try {
    Expand-Archive -LiteralPath $Archive -DestinationPath $Expanded
    $BuildInfo = Get-Content -LiteralPath (Join-Path $Expanded "BUILD_INFO.json") -Raw | ConvertFrom-Json -Depth 32
    if (
        $BuildInfo.product_version -ne $ExpectedProductVersion -or
        $BuildInfo.protocol_inventory_runtime -ne "enabled" -or
        $BuildInfo.event_timeline_runtime -ne "enabled"
    ) {
        throw "Portable BUILD_INFO does not describe the enabled event runtime."
    }

    & $PythonPath (Join-Path $PSScriptRoot "generate_event_fixture.py") --output $EthernetCapture
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $EthernetCapture -PathType Leaf)) {
        throw "Synthetic Portable Ethernet event capture generation failed."
    }
    & $PythonPath (Join-Path $PSScriptRoot "generate_wireless_event_fixture.py") --output $WirelessCapture
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $WirelessCapture -PathType Leaf)) {
        throw "Synthetic Portable wireless event capture generation failed."
    }

    $BeforeFiles = @(Get-ChildItem -LiteralPath $Expanded -Recurse -File | ForEach-Object {
        [System.IO.Path]::GetRelativePath($Expanded, $_.FullName).Replace("\", "/")
    } | Sort-Object)

    $OldPath = $env:PATH
    $OldPythonPath = [Environment]::GetEnvironmentVariable("PYTHONPATH", "Process")
    $OldPythonHome = [Environment]::GetEnvironmentVariable("PYTHONHOME", "Process")
    try {
        Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
        Remove-Item Env:PYTHONHOME -ErrorAction SilentlyContinue
        $env:PATH = (Join-Path $env:SystemRoot "System32") + ";" + $env:SystemRoot
        $Application = Join-Path $Expanded "WlanTroubleshooterKO.exe"
        Invoke-PortableAnalysis -Application $Application -WorkingDirectory $Expanded -Capture $EthernetCapture -Output $EthernetOutput
        Invoke-PortableAnalysis -Application $Application -WorkingDirectory $Expanded -Capture $WirelessCapture -Output $WirelessOutput
    }
    finally {
        $env:PATH = $OldPath
        Restore-EnvironmentValue -Name "PYTHONPATH" -Value $OldPythonPath
        Restore-EnvironmentValue -Name "PYTHONHOME" -Value $OldPythonHome
    }

    $EthernetAnalysis = Read-CompletedAnalysis -Output $EthernetOutput -ExpectedFrames 16
    $EthernetResult = $EthernetAnalysis.Result
    $EthernetRaw = $EthernetAnalysis.Raw

    $Groups = @($EthernetResult.protocol_inventory.inventory.observations | ForEach-Object { $_.group_id })
    Write-Host ("Ethernet protocol groups: " + ($Groups -join ", "))
    Assert-ContainsAll -Observed $Groups -Expected @("eapol", "radius", "dhcp", "dns", "arp", "tcp") -Label "Ethernet protocol group"

    $EventTypes = @($EthernetResult.protocol_inventory.event_timeline.events | ForEach-Object { $_.event_type })
    Write-Host ("Ethernet event types: " + ($EventTypes -join ", "))
    Assert-ContainsAll -Observed $EventTypes -Expected @(
        "arp_request",
        "arp_reply",
        "radius_access_request",
        "radius_access_accept",
        "dhcp_discover",
        "dhcp_offer",
        "dhcp_request",
        "dhcp_ack",
        "dns_query",
        "dns_response_success",
        "tcp_syn",
        "tcp_syn_ack",
        "tcp_reset"
    ) -Label "Ethernet event type"

    $Stages = @{}
    foreach ($Stage in $EthernetResult.protocol_inventory.event_timeline.stages) {
        $Stages[[string]$Stage.stage_id] = [string]$Stage.state
    }
    foreach ($StageId in @("radius", "dhcp", "dns", "tcp")) {
        if ($Stages[$StageId] -ne "success-observed") {
            throw "Expected Ethernet success-observed stage was not produced: $StageId"
        }
    }

    Assert-NoForbiddenText -Raw $EthernetRaw -Forbidden @(
        $EthernetCapture,
        (Split-Path -Leaf $EthernetCapture),
        "192.0.2.10",
        "198.51.100.10",
        "020000000010",
        "02:00:00:00:00:10",
        "0x01020304",
        "0x1234",
        "1700000000"
    )

    $Aliases = @($EthernetResult.protocol_inventory.event_timeline.events | ForEach-Object { $_.correlation_alias } | Where-Object { $_ })
    Assert-ContainsAll -Observed $Aliases -Expected @("RADIUS-1", "DHCP-1", "DNS-1", "TCP-1") -Label "Ethernet correlation alias"

    $WirelessAnalysis = Read-CompletedAnalysis -Output $WirelessOutput -ExpectedFrames 8
    $WirelessResult = $WirelessAnalysis.Result
    $WirelessRaw = $WirelessAnalysis.Raw

    $WirelessGroups = @($WirelessResult.protocol_inventory.inventory.observations | ForEach-Object { $_.group_id })
    Write-Host ("Wireless protocol groups: " + ($WirelessGroups -join ", "))
    Assert-ContainsAll -Observed $WirelessGroups -Expected @("wlan", "eapol", "eap") -Label "Wireless protocol group"

    $WirelessEventTypes = @($WirelessResult.protocol_inventory.event_timeline.events | ForEach-Object { $_.event_type })
    Write-Host ("Wireless event types: " + ($WirelessEventTypes -join ", "))
    Assert-ContainsAll -Observed $WirelessEventTypes -Expected @(
        "wlan_auth_request",
        "wlan_auth_response_success",
        "wlan_assoc_request",
        "wlan_assoc_response_success",
        "eap_request",
        "eap_response",
        "eap_success",
        "wlan_deauthentication"
    ) -Label "Wireless event type"

    $WirelessStages = @{}
    foreach ($Stage in $WirelessResult.protocol_inventory.event_timeline.stages) {
        $WirelessStages[[string]$Stage.stage_id] = [string]$Stage.state
    }
    foreach ($StageId in @("wlan-management", "eap")) {
        if ($WirelessStages[$StageId] -ne "success-observed") {
            throw "Expected wireless success-observed stage was not produced: $StageId"
        }
    }

    $WirelessAliases = @($WirelessResult.protocol_inventory.event_timeline.events | ForEach-Object { $_.correlation_alias } | Where-Object { $_ })
    Assert-ContainsAll -Observed $WirelessAliases -Expected @("EAP-1") -Label "Wireless correlation alias"

    Assert-NoForbiddenText -Raw $WirelessRaw -Forbidden @(
        $WirelessCapture,
        (Split-Path -Leaf $WirelessCapture),
        "0200000000a1",
        "0200000000b1",
        "02:00:00:00:00:a1",
        "02:00:00:00:00:b1",
        "1700000100"
    )

    $AfterFiles = @(Get-ChildItem -LiteralPath $Expanded -Recurse -File | ForEach-Object {
        [System.IO.Path]::GetRelativePath($Expanded, $_.FullName).Replace("\", "/")
    } | Sort-Object)
    if (($BeforeFiles -join "|") -ne ($AfterFiles -join "|")) {
        throw "Portable event analysis modified its distribution directory."
    }
    Write-Host "Portable Ethernet and IEEE 802.11 event timeline integration tests passed."
}
finally {
    Remove-Item -LiteralPath $WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
}
