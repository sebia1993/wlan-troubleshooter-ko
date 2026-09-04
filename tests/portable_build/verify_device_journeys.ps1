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

function Assert-NoForbiddenText {
    param(
        [Parameter(Mandatory = $true)][string]$Raw,
        [Parameter(Mandatory = $true)][string[]]$Forbidden
    )

    foreach ($Value in $Forbidden) {
        if ($Raw.Contains($Value, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Device-journey result exposed a forbidden identifier."
        }
    }
}

function Get-Stage {
    param(
        [Parameter(Mandatory = $true)]$Journey,
        [Parameter(Mandatory = $true)][string]$Protocol
    )

    $Stage = @($Journey.stages | Where-Object { $_.protocol -eq $Protocol }) |
        Select-Object -First 1
    if ($null -eq $Stage) {
        throw "Expected device-journey stage was not observed: $Protocol"
    }
    return $Stage
}

$PackageOutputPath = [System.IO.Path]::GetFullPath($PackageOutputPath)
if (-not (Test-Path -LiteralPath $PackageOutputPath -PathType Leaf)) {
    throw "Portable package metadata is missing."
}
$Package = Get-Content -LiteralPath $PackageOutputPath -Raw | ConvertFrom-Json -Depth 32
$Archive = [System.IO.Path]::GetFullPath([string]$Package.archive)
if (-not (Test-Path -LiteralPath $Archive -PathType Leaf)) {
    throw "Portable archive is missing."
}

$WorkRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("wlan-device-journey-test-" + [guid]::NewGuid().ToString("N"))
$Expanded = Join-Path $WorkRoot "portable"
$Capture = Join-Path $WorkRoot "private-device-journey.pcap"
$Output = Join-Path $WorkRoot "device-journey.json"
New-Item -ItemType Directory -Path $Expanded -Force | Out-Null

try {
    Expand-Archive -LiteralPath $Archive -DestinationPath $Expanded

    $BuildInfo = Get-Content -LiteralPath (Join-Path $Expanded "BUILD_INFO.json") -Raw | ConvertFrom-Json -Depth 32
    if (
        $BuildInfo.device_session_runtime -ne "enabled" -or
        $BuildInfo.device_journey_runtime -ne "enabled" -or
        $BuildInfo.raw_identifier_serialization -ne "disabled" -or
        $BuildInfo.alias_secret_persistence -ne "disabled" -or
        $BuildInfo.cross_run_alias_stability -ne "disabled"
    ) {
        throw "Portable BUILD_INFO does not preserve the device-journey privacy boundary."
    }

    & $PythonPath (Join-Path $PSScriptRoot "generate_event_fixture.py") --output $Capture
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $Capture -PathType Leaf)) {
        throw "Synthetic device-journey fixture generation failed."
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
            throw "Portable device-journey analysis failed with exit code $($Process.ExitCode)."
        }
    }
    finally {
        $env:PATH = $OldPath
        Restore-EnvironmentValue -Name "PYTHONPATH" -Value $OldPythonPath
        Restore-EnvironmentValue -Name "PYTHONHOME" -Value $OldPythonHome
    }

    if (-not (Test-Path -LiteralPath $Output -PathType Leaf)) {
        throw "Portable device-journey analysis did not create its result."
    }
    $Raw = Get-Content -LiteralPath $Output -Raw
    $Result = $Raw | ConvertFrom-Json -Depth 160
    if ($Result.schema_version -ne 2 -or $Result.protocol_inventory_state -ne "completed") {
        throw "Portable device-journey analysis did not complete with schema version 2."
    }

    $Report = $Result.protocol_inventory.device_journeys
    if (
        $null -eq $Report -or
        $Report.schema_version -ne 1 -or
        $Report.journeys_total -ne 1 -or
        $Report.source_complete -ne $true -or
        $Report.linkage_complete -ne $false -or
        $Report.complete -ne $false -or
        [int]$Report.unassigned_attempts -lt 1 -or
        $Report.raw_identifiers_serialized -ne $false -or
        $Report.aliases_stable_across_runs -ne $false -or
        $Report.device_identity_confirmed -ne $false -or
        $Report.cross_protocol_session_confirmed -ne $false -or
        $Report.root_cause_confirmed -ne $false
    ) {
        throw "Portable device-journey report is missing or violated its conservative linkage/privacy boundary."
    }

    $Journey = @($Report.journeys)[0]
    if (
        $Journey.device_alias -ne "DEVICE-1" -or
        $Journey.state -ne "mixed" -or
        $Journey.first_failure_stage -ne "tcp" -or
        $Journey.last_positive_stage -ne "tcp" -or
        $Journey.device_identity_confirmed -ne $false -or
        $Journey.cross_protocol_session_confirmed -ne $false -or
        $Journey.root_cause_confirmed -ne $false -or
        [string]::IsNullOrWhiteSpace([string]$Journey.display_filter)
    ) {
        throw "Portable DEVICE-1 journey has an unexpected conservative state."
    }

    $ObservedOrder = @($Journey.observed_stage_order)
    foreach ($ExpectedProtocol in @("dhcp", "dns", "tcp")) {
        if ($ObservedOrder -notcontains $ExpectedProtocol) {
            throw "Portable DEVICE-1 journey is missing a stage: $ExpectedProtocol"
        }
    }
    if ($ObservedOrder[0] -ne "dhcp" -or $ObservedOrder[-1] -ne "tcp") {
        throw "Portable DEVICE-1 stage order does not follow observed packet order."
    }
    if ($ObservedOrder -contains "eap" -or $ObservedOrder -contains "radius") {
        throw "A protocol without direct L2 device evidence was linked to DEVICE-1."
    }

    $DhcpStage = Get-Stage -Journey $Journey -Protocol "dhcp"
    $DnsStage = Get-Stage -Journey $Journey -Protocol "dns"
    $TcpStage = Get-Stage -Journey $Journey -Protocol "tcp"
    if (
        $DhcpStage.state -ne "complete" -or
        $DnsStage.state -ne "complete" -or
        $TcpStage.state -ne "mixed"
    ) {
        throw "Portable DEVICE-1 stage aggregation is unexpected."
    }
    if (
        @($TcpStage.attempt_ids).Count -lt 2 -or
        @($Journey.evidence_frames).Count -lt 1
    ) {
        throw "Portable DEVICE-1 journey lacks transaction or frame evidence."
    }

    Assert-NoForbiddenText -Raw $Raw -Forbidden @(
        $Capture,
        (Split-Path -Leaf $Capture),
        "192.0.2.10",
        "198.51.100.10",
        "02:00:00:00:00:10",
        "02:00:00:00:00:20",
        "020000000010",
        "020000000020",
        "0x01020304",
        "0x1234",
        "example.test",
        "1700000000"
    )

    $AfterFiles = @(Get-ChildItem -LiteralPath $Expanded -Recurse -File | ForEach-Object {
        [System.IO.Path]::GetRelativePath($Expanded, $_.FullName).Replace("\", "/")
    } | Sort-Object)
    if (($BeforeFiles -join "|") -ne ($AfterFiles -join "|")) {
        throw "Portable device-journey analysis modified its distribution directory."
    }

    Write-Host "Portable DEVICE-1 DHCP/DNS/TCP conservative journey integration test passed."
}
finally {
    Remove-Item -LiteralPath $WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
}
