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

function Write-SafeFailureSummary {
    param([Parameter(Mandatory = $true)][string]$ResultPath)

    if (-not (Test-Path -LiteralPath $ResultPath -PathType Leaf)) {
        Write-Host "Capture-time state: result file was not created"
        return
    }
    try {
        $Failure = Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json -Depth 64
        $State = [string]$Failure.protocol_inventory_state
        $Message = [string]$Failure.protocol_inventory_message
        if ($State -notin @("completed", "unavailable", "failed")) {
            $State = "invalid-result"
        }
        if ($Message.Length -gt 500) {
            $Message = $Message.Substring(0, 500)
        }
        Write-Host "Capture-time state: $State"
        Write-Host "Capture-time message: $Message"
    }
    catch {
        Write-Host "Capture-time state: unreadable-result"
    }
}

function Assert-NoForbiddenText {
    param(
        [Parameter(Mandatory = $true)][string]$Raw,
        [Parameter(Mandatory = $true)][string[]]$Forbidden
    )
    foreach ($Value in $Forbidden) {
        if ($Raw.Contains($Value, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Capture-time result exposed an absolute time, private metadata, identifier, or path."
        }
    }
}

function Assert-ExactIntegerSequence {
    param(
        [Parameter(Mandatory = $true)]$Actual,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][int[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $Values = @($Actual | ForEach-Object { [int]$_ })
    if (($Values -join ",") -ne ($Expected -join ",")) {
        throw "$Label sequence is unexpected."
    }
}

function Get-Boundary {
    param(
        [Parameter(Mandatory = $true)]$Report,
        [Parameter(Mandatory = $true)][string]$AttemptId
    )
    $Value = @($Report.transaction_boundaries | Where-Object {
        $_.attempt_id -eq $AttemptId
    }) | Select-Object -First 1
    if ($null -eq $Value) {
        throw "Expected transaction time boundary is missing: $AttemptId"
    }
    return $Value
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

$WorkRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("wlan-capture-time-test-" + [guid]::NewGuid().ToString("N"))
$Expanded = Join-Path $WorkRoot "portable"
$Capture = Join-Path $WorkRoot "private-capture-time.pcapng"
$Output = Join-Path $WorkRoot "capture-time-result.json"
New-Item -ItemType Directory -Path $Expanded -Force | Out-Null

try {
    Expand-Archive -LiteralPath $Archive -DestinationPath $Expanded
    $BuildInfo = Get-Content -LiteralPath (Join-Path $Expanded "BUILD_INFO.json") -Raw | ConvertFrom-Json -Depth 32
    if (
        $BuildInfo.capture_time_boundary_runtime -ne "enabled" -or
        $BuildInfo.absolute_timestamp_serialization -ne "disabled" -or
        $BuildInfo.response_absence_confirmation -ne "disabled" -or
        $BuildInfo.raw_identifier_serialization -ne "disabled"
    ) {
        throw "Portable BUILD_INFO does not preserve the capture-time privacy boundary."
    }

    & $PythonPath (Join-Path $PSScriptRoot "generate_capture_time_fixture.py") --output $Capture
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $Capture -PathType Leaf)) {
        throw "Synthetic capture-time fixture generation failed."
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
            Write-SafeFailureSummary -ResultPath $Output
            throw "Portable capture-time analysis failed with exit code $($Process.ExitCode)."
        }
    }
    finally {
        $env:PATH = $OldPath
        Restore-EnvironmentValue -Name "PYTHONPATH" -Value $OldPythonPath
        Restore-EnvironmentValue -Name "PYTHONHOME" -Value $OldPythonHome
    }

    if (-not (Test-Path -LiteralPath $Output -PathType Leaf)) {
        throw "Portable capture-time analysis did not create its result."
    }
    $Raw = Get-Content -LiteralPath $Output -Raw
    $Result = $Raw | ConvertFrom-Json -Depth 192
    $Report = $Result.capture_time_boundaries
    if (
        $Result.schema_version -ne 2 -or
        $Result.protocol_inventory_state -ne "completed" -or
        $null -eq $Report -or
        $Report.schema_version -ne 1 -or
        $Report.profile_id -ne "capture-time-boundaries" -or
        $Report.profile_version -ne "0.6.0" -or
        $Report.frames_observed -ne 4 -or
        $Report.expected_frames -ne 4 -or
        $Report.complete -ne $true -or
        $Report.first_frame -ne 1 -or
        $Report.last_frame -ne 4 -or
        $Report.first_to_last_relative_ms -ne 3000 -or
        $Report.minimum_relative_ms -ne 0 -or
        $Report.maximum_relative_ms -ne 3000 -or
        $Report.observed_span_ms -ne 3000 -or
        $Report.timestamp_regressions -ne 0 -or
        $Report.regression_evidence_frames_omitted -ne 0 -or
        $Report.boundary_threshold_ms -ne 1000 -or
        $Report.transaction_source_complete -ne $true -or
        $Report.transaction_attempts_total -ne 2 -or
        $Report.transaction_boundaries_total -ne 2 -or
        $Report.absolute_timestamps_serialized -ne $false -or
        $Report.capture_start_proven -ne $false -or
        $Report.capture_end_proven -ne $false -or
        $Report.incident_window_fully_covered -ne $false -or
        $Report.response_wait_sufficiency_assessed -ne $false -or
        $Report.response_absence_confirmed -ne $false -or
        $Report.capture_loss_excluded -ne $false -or
        $Report.root_cause_confirmed -ne $false
    ) {
        Write-SafeFailureSummary -ResultPath $Output
        throw "Portable capture-time report is missing or violated its conservative boundary."
    }

    Assert-ExactIntegerSequence -Actual $Report.regression_evidence_frames -Expected @() -Label "Timestamp regression evidence"

    $First = Get-Boundary -Report $Report -AttemptId "DNS-1-A1"
    if (
        $First.protocol -ne "dns" -or
        $First.attempt_state -ne "incomplete" -or
        $First.boundary_state -ne "near-analysis-start" -or
        $First.first_frame -ne 2 -or
        $First.last_frame -ne 2 -or
        $First.start_distance_ms -ne 250 -or
        $First.end_observation_window_ms -ne 2750 -or
        $First.observed_attempt_duration_ms -ne 0 -or
        $First.start_near_boundary -ne $true -or
        $First.end_near_boundary -ne $false -or
        $First.response_wait_sufficiency_assessed -ne $false -or
        $First.response_absence_confirmed -ne $false -or
        $First.root_cause_confirmed -ne $false -or
        [string]::IsNullOrWhiteSpace([string]$First.display_filter)
    ) {
        throw "Portable DNS-1-A1 relative boundary is unexpected."
    }

    $Second = Get-Boundary -Report $Report -AttemptId "DNS-2-A1"
    if (
        $Second.protocol -ne "dns" -or
        $Second.attempt_state -ne "incomplete" -or
        $Second.boundary_state -ne "at-analysis-end" -or
        $Second.first_frame -ne 4 -or
        $Second.last_frame -ne 4 -or
        $Second.start_distance_ms -ne 3000 -or
        $Second.end_observation_window_ms -ne 0 -or
        $Second.observed_attempt_duration_ms -ne 0 -or
        $Second.start_near_boundary -ne $false -or
        $Second.end_near_boundary -ne $true -or
        $Second.response_wait_sufficiency_assessed -ne $false -or
        $Second.response_absence_confirmed -ne $false -or
        $Second.root_cause_confirmed -ne $false
    ) {
        throw "Portable DNS-2-A1 relative boundary is unexpected."
    }

    Assert-NoForbiddenText -Raw $Raw -Forbidden @(
        $Capture,
        (Split-Path -Leaf $Capture),
        "1700005000",
        "1700005000250000",
        "1700005001500000",
        "1700005003000000",
        "private-time-section-phase4l",
        "private-time-hardware-phase4l",
        "private-time-os-phase4l",
        "private-time-application-phase4l",
        "private-time-interface-phase4l",
        "private-time-description-phase4l",
        "private-time-packet-phase4l",
        "192.0.2.10",
        "192.0.2.53",
        "02:00:00:00:00:10",
        "02:00:00:00:00:35",
        "020000000010",
        "020000000035",
        "observability.invalid",
        "0x2001",
        "0x2002",
        '"time_epoch":',
        '"timestamp_raw":'
    )

    $AfterFiles = @(Get-ChildItem -LiteralPath $Expanded -Recurse -File | ForEach-Object {
        [System.IO.Path]::GetRelativePath($Expanded, $_.FullName).Replace("\", "/")
    } | Sort-Object)
    if (($BeforeFiles -join "|") -ne ($AfterFiles -join "|")) {
        throw "Portable capture-time analysis modified its distribution directory."
    }

    Write-Host "Portable relative capture time and DNS transaction boundary integration test passed."
}
finally {
    Remove-Item -LiteralPath $WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
}
