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
            throw "Capture-observability result exposed a forbidden identifier."
        }
    }
}

function Get-Attempt {
    param(
        [Parameter(Mandatory = $true)]$Report,
        [Parameter(Mandatory = $true)][string]$AttemptId
    )
    $Value = @($Report.incomplete_attempts | Where-Object {
        $_.attempt_id -eq $AttemptId
    }) | Select-Object -First 1
    if ($null -eq $Value) {
        throw "Expected incomplete attempt is missing: $AttemptId"
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

$WorkRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("wlan-observability-test-" + [guid]::NewGuid().ToString("N"))
$Expanded = Join-Path $WorkRoot "portable"
$Capture = Join-Path $WorkRoot "private-observability.pcap"
$Output = Join-Path $WorkRoot "observability-result.json"
New-Item -ItemType Directory -Path $Expanded -Force | Out-Null

try {
    Expand-Archive -LiteralPath $Archive -DestinationPath $Expanded
    $BuildInfo = Get-Content -LiteralPath (Join-Path $Expanded "BUILD_INFO.json") -Raw | ConvertFrom-Json -Depth 32
    if (
        $BuildInfo.capture_observability_runtime -ne "enabled" -or
        $BuildInfo.raw_identifier_serialization -ne "disabled" -or
        $BuildInfo.alias_secret_persistence -ne "disabled" -or
        $BuildInfo.cross_run_alias_stability -ne "disabled"
    ) {
        throw "Portable BUILD_INFO does not preserve the observability privacy boundary."
    }

    & $PythonPath (Join-Path $PSScriptRoot "generate_observability_fixture.py") --output $Capture
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $Capture -PathType Leaf)) {
        throw "Synthetic observability fixture generation failed."
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
            throw "Portable capture-observability analysis failed with exit code $($Process.ExitCode)."
        }
    }
    finally {
        $env:PATH = $OldPath
        Restore-EnvironmentValue -Name "PYTHONPATH" -Value $OldPythonPath
        Restore-EnvironmentValue -Name "PYTHONHOME" -Value $OldPythonHome
    }

    if (-not (Test-Path -LiteralPath $Output -PathType Leaf)) {
        throw "Portable capture-observability analysis did not create its result."
    }
    $Raw = Get-Content -LiteralPath $Output -Raw
    $Result = $Raw | ConvertFrom-Json -Depth 160
    if ($Result.schema_version -ne 2 -or $Result.protocol_inventory_state -ne "completed") {
        throw "Portable capture-observability analysis did not complete with schema version 2."
    }

    $Report = $Result.capture_observability
    if (
        $null -eq $Report -or
        $Report.schema_version -ne 1 -or
        $Report.packets_scanned -ne 4 -or
        $Report.frames_observed -ne 4 -or
        $Report.analysis_input_complete -ne $true -or
        $Report.container_scan_complete -ne $true -or
        $Report.event_timeline_complete -ne $true -or
        $Report.transaction_report_complete -ne $true -or
        $Report.truncated_packets_observed -ne 0 -or
        $Report.event_details_omitted -ne 0 -or
        $Report.incomplete_attempts_total -ne 2 -or
        $Report.capture_start_proven -ne $false -or
        $Report.capture_end_proven -ne $false -or
        $Report.capture_loss_excluded -ne $false -or
        $Report.directionality_proven -ne $false -or
        $Report.absence_can_confirm_failure -ne $false
    ) {
        throw "Portable capture-observability report has an unexpected conservative boundary."
    }

    $DnsVisibility = @($Report.protocol_visibility | Where-Object {
        $_.protocol -eq "dns"
    }) | Select-Object -First 1
    if (
        $null -eq $DnsVisibility -or
        $DnsVisibility.request_event_observed -ne $true -or
        $DnsVisibility.reply_event_observed -ne $false -or
        $DnsVisibility.bidirectional_event_classes_observed -ne $false -or
        $DnsVisibility.directionality_proven -ne $false
    ) {
        throw "Portable DNS visibility summary is unexpected."
    }

    $Middle = Get-Attempt -Report $Report -AttemptId "DNS-1-A1"
    if (
        $Middle.assessment -ne "response-not-observed" -or
        $Middle.first_frame -ne 2 -or
        $Middle.last_frame -ne 2 -or
        @($Middle.risk_flags).Count -ne 0 -or
        $Middle.request_event_observed -ne $true -or
        $Middle.reply_event_observed -ne $false -or
        $Middle.absence_is_failure -ne $false -or
        $Middle.capture_loss_excluded -ne $false -or
        $Middle.directionality_proven -ne $false -or
        [string]::IsNullOrWhiteSpace([string]$Middle.display_filter)
    ) {
        throw "Middle DNS query was not classified as response-not-observed."
    }

    $Boundary = Get-Attempt -Report $Report -AttemptId "DNS-2-A1"
    if (
        $Boundary.assessment -ne "capture-boundary-risk" -or
        $Boundary.first_frame -ne 4 -or
        $Boundary.last_frame -ne 4 -or
        @($Boundary.risk_flags) -notcontains "capture-end-boundary-risk" -or
        $Boundary.absence_is_failure -ne $false
    ) {
        throw "Final-frame DNS query was not classified as a capture boundary risk."
    }

    Assert-NoForbiddenText -Raw $Raw -Forbidden @(
        $Capture,
        (Split-Path -Leaf $Capture),
        "192.0.2.10",
        "192.0.2.53",
        "02:00:00:00:00:10",
        "02:00:00:00:00:35",
        "020000000010",
        "020000000035",
        "observability.invalid",
        "0x2001",
        "0x2002",
        "1700001000"
    )

    $AfterFiles = @(Get-ChildItem -LiteralPath $Expanded -Recurse -File | ForEach-Object {
        [System.IO.Path]::GetRelativePath($Expanded, $_.FullName).Replace("\", "/")
    } | Sort-Object)
    if (($BeforeFiles -join "|") -ne ($AfterFiles -join "|")) {
        throw "Portable capture-observability analysis modified its distribution directory."
    }

    Write-Host "Portable unanswered DNS and capture-boundary observability integration test passed."
}
finally {
    Remove-Item -LiteralPath $WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
}
