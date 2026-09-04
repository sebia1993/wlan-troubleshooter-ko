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
$Capture = Join-Path $WorkRoot "private-event-integration-capture.pcap"
$Output = Join-Path $WorkRoot "analysis-result.json"
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

    & $PythonPath (Join-Path $PSScriptRoot "generate_event_fixture.py") --output $Capture
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $Capture -PathType Leaf)) {
        throw "Synthetic Portable event capture generation failed."
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
        $Arguments = @(
            ('--analyze-capture="' + $Capture + '"'),
            ('--analysis-output="' + $Output + '"')
        )
        $Process = Start-Process -FilePath $Application -ArgumentList $Arguments -WorkingDirectory $Expanded -Wait -PassThru
        if ($Process.ExitCode -ne 0) {
            if (Test-Path -LiteralPath $Output -PathType Leaf) {
                $Failure = Get-Content -LiteralPath $Output -Raw | ConvertFrom-Json -Depth 64
                Write-Host ("Portable event state: " + [string]$Failure.protocol_inventory_state)
                Write-Host ("Portable event message: " + [string]$Failure.protocol_inventory_message)
            }
            throw "Portable event analysis process failed with exit code $($Process.ExitCode)."
        }
    }
    finally {
        $env:PATH = $OldPath
        Restore-EnvironmentValue -Name "PYTHONPATH" -Value $OldPythonPath
        Restore-EnvironmentValue -Name "PYTHONHOME" -Value $OldPythonHome
    }

    if (-not (Test-Path -LiteralPath $Output -PathType Leaf)) {
        throw "Portable event analysis did not create its result."
    }
    $Raw = Get-Content -LiteralPath $Output -Raw
    $Result = $Raw | ConvertFrom-Json -Depth 96
    if ($Result.schema_version -ne 2 -or $Result.protocol_inventory_state -ne "completed") {
        throw "Portable event analysis did not complete with schema version 2."
    }
    if ($Result.protocol_inventory.inventory.frames_observed -ne 16) {
        throw "Portable event analysis observed an unexpected frame count."
    }
    if (
        $Result.protocol_inventory.inventory.complete -ne $true -or
        $Result.protocol_inventory.event_timeline.complete -ne $true
    ) {
        throw "Portable event analysis was not marked complete."
    }

    $Groups = @($Result.protocol_inventory.inventory.observations | ForEach-Object { $_.group_id })
    Assert-ContainsAll -Observed $Groups -Expected @("eapol", "eap", "radius", "dhcp", "dns", "arp", "tcp") -Label "Protocol group"

    $EventTypes = @($Result.protocol_inventory.event_timeline.events | ForEach-Object { $_.event_type })
    Assert-ContainsAll -Observed $EventTypes -Expected @(
        "arp_request",
        "arp_reply",
        "eap_request",
        "eap_response",
        "eap_success",
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
    ) -Label "Event type"

    $Stages = @{}
    foreach ($Stage in $Result.protocol_inventory.event_timeline.stages) {
        $Stages[[string]$Stage.stage_id] = [string]$Stage.state
    }
    foreach ($StageId in @("eap", "radius", "dhcp", "dns", "tcp")) {
        if ($Stages[$StageId] -ne "success-observed") {
            throw "Expected success-observed stage was not produced: $StageId"
        }
    }

    foreach ($Forbidden in @(
        $Capture,
        (Split-Path -Leaf $Capture),
        "192.0.2.10",
        "198.51.100.10",
        "020000000010",
        "0x01020304",
        "0x1234",
        "1700000000"
    )) {
        if ($Raw.Contains($Forbidden, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Portable event result exposed a forbidden path or identifier."
        }
    }

    $Aliases = @($Result.protocol_inventory.event_timeline.events | ForEach-Object { $_.correlation_alias } | Where-Object { $_ })
    Assert-ContainsAll -Observed $Aliases -Expected @("EAP-1", "RADIUS-1", "DHCP-1", "DNS-1", "TCP-1") -Label "Correlation alias"

    $AfterFiles = @(Get-ChildItem -LiteralPath $Expanded -Recurse -File | ForEach-Object {
        [System.IO.Path]::GetRelativePath($Expanded, $_.FullName).Replace("\", "/")
    } | Sort-Object)
    if (($BeforeFiles -join "|") -ne ($AfterFiles -join "|")) {
        throw "Portable event analysis modified its distribution directory."
    }
    Write-Host "Portable event timeline integration test passed."
}
finally {
    Remove-Item -LiteralPath $WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
}
