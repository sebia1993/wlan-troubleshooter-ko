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
            throw "EAPOL handshake result exposed forbidden key material or an identifier."
        }
    }
}

function Assert-ExactIntegerSequence {
    param(
        [Parameter(Mandatory = $true)]$Actual,
        [Parameter(Mandatory = $true)][int[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $Values = @($Actual | ForEach-Object { [int]$_ })
    if (($Values -join ",") -ne ($Expected -join ",")) {
        throw "$Label sequence is unexpected."
    }
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

$WorkRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("wlan-eapol-handshake-test-" + [guid]::NewGuid().ToString("N"))
$Expanded = Join-Path $WorkRoot "portable"
$Capture = Join-Path $WorkRoot "private-eapol-handshake.pcap"
$Output = Join-Path $WorkRoot "eapol-handshake-result.json"
New-Item -ItemType Directory -Path $Expanded -Force | Out-Null

try {
    Expand-Archive -LiteralPath $Archive -DestinationPath $Expanded

    $BuildInfo = Get-Content -LiteralPath (Join-Path $Expanded "BUILD_INFO.json") -Raw | ConvertFrom-Json -Depth 32
    if (
        $BuildInfo.eapol_handshake_runtime -ne "enabled" -or
        $BuildInfo.raw_identifier_serialization -ne "disabled" -or
        $BuildInfo.alias_secret_persistence -ne "disabled" -or
        $BuildInfo.cross_run_alias_stability -ne "disabled"
    ) {
        throw "Portable BUILD_INFO does not preserve the EAPOL handshake privacy boundary."
    }

    & $PythonPath (Join-Path $PSScriptRoot "generate_eapol_handshake_fixture.py") --output $Capture
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $Capture -PathType Leaf)) {
        throw "Synthetic EAPOL handshake fixture generation failed."
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
            throw "Portable EAPOL handshake analysis failed with exit code $($Process.ExitCode)."
        }
    }
    finally {
        $env:PATH = $OldPath
        Restore-EnvironmentValue -Name "PYTHONPATH" -Value $OldPythonPath
        Restore-EnvironmentValue -Name "PYTHONHOME" -Value $OldPythonHome
    }

    if (-not (Test-Path -LiteralPath $Output -PathType Leaf)) {
        throw "Portable EAPOL handshake analysis did not create its result."
    }
    $Raw = Get-Content -LiteralPath $Output -Raw
    $Result = $Raw | ConvertFrom-Json -Depth 192
    if ($Result.schema_version -ne 2 -or $Result.protocol_inventory_state -ne "completed") {
        throw "Portable EAPOL handshake analysis did not complete with schema version 2."
    }

    $Report = $Result.eapol_handshakes
    if (
        $null -eq $Report -or
        $Report.schema_version -ne 1 -or
        $Report.field_available -ne $true -or
        $Report.source_timeline_complete -ne $true -or
        $Report.device_report_complete -ne $true -or
        $Report.device_evidence_complete -ne $true -or
        $Report.linkage_complete -ne $true -or
        $Report.complete -ne $true -or
        $Report.source_key_events_total -ne 5 -or
        $Report.linked_key_events -ne 5 -or
        $Report.unassigned_key_events -ne 0 -or
        $Report.ambiguous_key_events -ne 0 -or
        $Report.timeline_events_omitted -ne 0 -or
        $Report.observations_total -ne 1 -or
        $Report.replay_counter_correlation_available -ne $false -or
        $Report.raw_key_material_serialized -ne $false -or
        $Report.raw_identifiers_serialized -ne $false -or
        $Report.same_handshake_confirmed -ne $false -or
        $Report.key_installation_confirmed -ne $false -or
        $Report.cryptographic_success_confirmed -ne $false -or
        $Report.root_cause_confirmed -ne $false
    ) {
        throw "Portable EAPOL handshake report is missing or violated its conservative boundary."
    }

    $Observation = @($Report.observations)[0]
    if (
        $Observation.observation_id -ne "EAPOL-HS-1" -or
        $Observation.device_alias -ne "DEVICE-1" -or
        $Observation.ap_alias -ne "AP-1" -or
        $Observation.state -ne "message-repetition-observed" -or
        $Observation.event_count -ne 5 -or
        $Observation.first_frame -ne 5 -or
        $Observation.last_frame -ne 9 -or
        $Observation.evidence_frames_omitted -ne 0 -or
        $Observation.replay_counter_correlation_available -ne $false -or
        $Observation.raw_key_material_serialized -ne $false -or
        $Observation.raw_identifiers_serialized -ne $false -or
        $Observation.same_handshake_confirmed -ne $false -or
        $Observation.key_installation_confirmed -ne $false -or
        $Observation.cryptographic_success_confirmed -ne $false -or
        $Observation.root_cause_confirmed -ne $false -or
        [string]::IsNullOrWhiteSpace([string]$Observation.display_filter)
    ) {
        throw "Portable EAPOL-HS-1 observation is unexpected."
    }

    Assert-ExactIntegerSequence -Actual $Observation.observed_message_numbers -Expected @(1, 2, 3, 3, 4) -Label "Observed EAPOL message"
    Assert-ExactIntegerSequence -Actual $Observation.first_observed_order -Expected @(1, 2, 3, 4) -Label "First EAPOL message"
    Assert-ExactIntegerSequence -Actual $Observation.missing_message_numbers -Expected @() -Label "Missing EAPOL message"
    Assert-ExactIntegerSequence -Actual $Observation.repeated_message_numbers -Expected @(3) -Label "Repeated EAPOL message"
    Assert-ExactIntegerSequence -Actual $Observation.retry_flag_frames -Expected @(8) -Label "Retry-bit frame"
    Assert-ExactIntegerSequence -Actual $Observation.evidence_frames -Expected @(5, 6, 7, 8, 9) -Label "EAPOL evidence frame"

    Assert-NoForbiddenText -Raw $Raw -Forbidden @(
        $Capture,
        (Split-Path -Leaf $Capture),
        "02:00:00:00:00:c1",
        "02:00:00:00:00:d1",
        "0200000000c1",
        "0200000000d1",
        "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
        "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3",
        "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
        "cccccccccccccccccccccccccccccccc",
        '"replay_counter":',
        '"nonce":',
        '"key_mic":',
        '"key_data":',
        "1700002000"
    )

    $AfterFiles = @(Get-ChildItem -LiteralPath $Expanded -Recurse -File | ForEach-Object {
        [System.IO.Path]::GetRelativePath($Expanded, $_.FullName).Replace("\", "/")
    } | Sort-Object)
    if (($BeforeFiles -join "|") -ne ($AfterFiles -join "|")) {
        throw "Portable EAPOL handshake analysis modified its distribution directory."
    }

    Write-Host "Portable EAPOL M1/M2/M3/repeated-M3/M4 conservative observation test passed."
}
finally {
    Remove-Item -LiteralPath $WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
}
