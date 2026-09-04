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
        Write-Host "Portable analysis state: result file was not created"
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
        Write-Host "Portable analysis state: $State"
        Write-Host "Portable analysis message: $Message"
    }
    catch {
        Write-Host "Portable analysis state: unreadable-result"
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
$Capture = Join-Path $WorkRoot "private-integration-capture.pcap"
$Output = Join-Path $WorkRoot "analysis-result.json"
New-Item -ItemType Directory -Path $Expanded -Force | Out-Null
try {
    Expand-Archive -LiteralPath $Archive -DestinationPath $Expanded
    $BuildInfo = Get-Content -LiteralPath (Join-Path $Expanded "BUILD_INFO.json") -Raw | ConvertFrom-Json -Depth 32
    if ($BuildInfo.product_version -ne $ExpectedProductVersion -or $BuildInfo.protocol_inventory_runtime -ne "enabled") {
        throw "Portable BUILD_INFO does not describe the enabled analysis runtime."
    }

    & $PythonPath (Join-Path $PSScriptRoot "generate_inventory_fixture.py") --output $Capture
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $Capture -PathType Leaf)) {
        throw "Synthetic Portable integration capture generation failed."
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
            throw "Portable connection analysis process failed with exit code $($Process.ExitCode)."
        }
    }
    finally {
        $env:PATH = $OldPath
        Restore-EnvironmentValue -Name "PYTHONPATH" -Value $OldPythonPath
        Restore-EnvironmentValue -Name "PYTHONHOME" -Value $OldPythonHome
    }

    if (-not (Test-Path -LiteralPath $Output -PathType Leaf)) {
        throw "Portable connection analysis did not create its result."
    }
    $Raw = Get-Content -LiteralPath $Output -Raw
    $Result = $Raw | ConvertFrom-Json -Depth 96
    if ($Result.schema_version -ne 3 -or $Result.protocol_inventory_state -ne "completed") {
        Write-SafeFailureSummary -ResultPath $Output
        throw "Portable connection analysis did not complete with schema version 3."
    }
    if ($Result.protocol_inventory.inventory.frames_observed -ne 5) {
        throw "Portable protocol inventory observed an unexpected frame count."
    }
    if ($Result.protocol_inventory.inventory.complete -ne $true) {
        throw "Portable protocol inventory was not marked complete."
    }
    $Groups = @($Result.protocol_inventory.inventory.observations | ForEach-Object { $_.group_id })
    foreach ($ExpectedGroup in @("arp", "dns", "tcp")) {
        if ($Groups -notcontains $ExpectedGroup) {
            throw "Portable protocol inventory did not observe the expected group: $ExpectedGroup"
        }
    }

    $Correlation = $Result.protocol_inventory.event_correlation
    if ($null -eq $Correlation -or $Correlation.complete -ne $true -or $Correlation.frames_scanned -ne 5) {
        throw "Portable event correlation did not process the complete synthetic capture."
    }
    $Findings = @($Correlation.findings)
    $FindingIds = @($Findings | ForEach-Object { $_.rule_id })
    foreach ($ExpectedFinding in @("DNS-ERROR-RESPONSE", "TCP-RST")) {
        if ($FindingIds -notcontains $ExpectedFinding) {
            throw "Portable event correlation did not create the expected Finding: $ExpectedFinding"
        }
        $Finding = $Findings | Where-Object { $_.rule_id -eq $ExpectedFinding } | Select-Object -First 1
        if ($Finding.classification -ne "확정") {
            throw "Portable explicit failure Finding is not classified as confirmed: $ExpectedFinding"
        }
        if ([string]::IsNullOrWhiteSpace([string]$Finding.display_filter) -or @($Finding.evidence_frames).Count -lt 1) {
            throw "Portable Finding does not contain packet evidence: $ExpectedFinding"
        }
    }

    $Sessions = $Result.protocol_inventory.transaction_sessions
    if (
        $null -eq $Sessions -or
        $Sessions.schema_version -ne 1 -or
        $Sessions.complete -ne $true -or
        $Sessions.attempts_total -ne 2
    ) {
        throw "Portable transaction session report is missing or incomplete."
    }
    $Attempts = @($Sessions.attempts)
    foreach ($ExpectedAttemptId in @("DNS-1-A1", "TCP-1-A1")) {
        $Attempt = $Attempts | Where-Object { $_.attempt_id -eq $ExpectedAttemptId } | Select-Object -First 1
        if ($null -eq $Attempt) {
            throw "Portable transaction session is missing: $ExpectedAttemptId"
        }
        if ($Attempt.state -ne "failure-observed") {
            throw "Portable explicit failure transaction has an unexpected state: $ExpectedAttemptId"
        }
        if (
            $Attempt.root_cause_confirmed -ne $false -or
            $Attempt.device_session_confirmed -ne $false -or
            [string]::IsNullOrWhiteSpace([string]$Attempt.display_filter) -or
            @($Attempt.evidence_frames).Count -lt 1
        ) {
            throw "Portable transaction session violated the conservative evidence boundary: $ExpectedAttemptId"
        }
    }

    if (
        $Raw.Contains($Capture, [System.StringComparison]::OrdinalIgnoreCase) -or
        $Raw.Contains((Split-Path -Leaf $Capture), [System.StringComparison]::OrdinalIgnoreCase) -or
        $Raw.Contains("192.0.2.1", [System.StringComparison]::OrdinalIgnoreCase) -or
        $Raw.Contains("example.test", [System.StringComparison]::OrdinalIgnoreCase) -or
        $Raw.Contains("0x1234", [System.StringComparison]::OrdinalIgnoreCase)
    ) {
        throw "Portable analysis result exposed a capture path, name, address, DNS query, or transaction identifier."
    }

    $AfterFiles = @(Get-ChildItem -LiteralPath $Expanded -Recurse -File | ForEach-Object {
        [System.IO.Path]::GetRelativePath($Expanded, $_.FullName).Replace("\", "/")
    } | Sort-Object)
    if (($BeforeFiles -join "|") -ne ($AfterFiles -join "|")) {
        throw "Portable analysis modified its distribution directory."
    }
    Write-Host "Portable DNS and TCP failure Finding plus transaction-session integration test passed."
}
finally {
    Remove-Item -LiteralPath $WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
}
