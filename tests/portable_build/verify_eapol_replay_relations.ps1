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
    param([Parameter(Mandatory = $true)][string]$Name,[AllowNull()][string]$Value)
    if ($null -eq $Value) { Remove-Item ("Env:" + $Name) -ErrorAction SilentlyContinue }
    else { [Environment]::SetEnvironmentVariable($Name, $Value, "Process") }
}
function Assert-ExactIntegerSequence {
    param([Parameter(Mandatory = $true)]$Actual,[Parameter(Mandatory = $true)][AllowEmptyCollection()][int[]]$Expected,[Parameter(Mandatory = $true)][string]$Label)
    $Values = @($Actual | ForEach-Object { [int]$_ })
    if (($Values -join ",") -ne ($Expected -join ",")) { throw "$Label sequence is unexpected." }
}
function Assert-NoForbiddenText {
    param([Parameter(Mandatory = $true)][string]$Raw,[Parameter(Mandatory = $true)][string[]]$Forbidden)
    foreach ($Value in $Forbidden) {
        if ($Raw.Contains($Value, [System.StringComparison]::OrdinalIgnoreCase)) { throw "Replay relation result exposed a raw counter, key value, or identifier." }
    }
}
$PackageOutputPath = [System.IO.Path]::GetFullPath($PackageOutputPath)
if (-not (Test-Path -LiteralPath $PackageOutputPath -PathType Leaf)) { throw "Portable package metadata is missing." }
$Package = Get-Content -LiteralPath $PackageOutputPath -Raw | ConvertFrom-Json -Depth 32
$Archive = [System.IO.Path]::GetFullPath([string]$Package.archive)
if (-not (Test-Path -LiteralPath $Archive -PathType Leaf)) { throw "Portable archive is missing." }
$WorkRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("wlan-eapol-replay-test-" + [guid]::NewGuid().ToString("N"))
$Expanded = Join-Path $WorkRoot "portable"
$Capture = Join-Path $WorkRoot "private-eapol-replay.pcap"
$Output = Join-Path $WorkRoot "eapol-replay-result.json"
New-Item -ItemType Directory -Path $Expanded -Force | Out-Null
try {
    Expand-Archive -LiteralPath $Archive -DestinationPath $Expanded
    $BuildInfo = Get-Content -LiteralPath (Join-Path $Expanded "BUILD_INFO.json") -Raw | ConvertFrom-Json -Depth 32
    if ($BuildInfo.eapol_handshake_runtime -ne "enabled" -or $BuildInfo.eapol_replay_relation_runtime -ne "enabled" -or $BuildInfo.raw_replay_counter_serialization -ne "disabled" -or $BuildInfo.replay_counter_persistence -ne "disabled" -or $BuildInfo.raw_identifier_serialization -ne "disabled") { throw "Portable BUILD_INFO does not preserve the Replay Counter relation boundary." }
    & $PythonPath (Join-Path $PSScriptRoot "generate_eapol_replay_fixture.py") --output $Capture
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $Capture -PathType Leaf)) { throw "Synthetic Replay Counter fixture generation failed." }
    $BeforeFiles = @(Get-ChildItem -LiteralPath $Expanded -Recurse -File | ForEach-Object { [System.IO.Path]::GetRelativePath($Expanded, $_.FullName).Replace("\", "/") } | Sort-Object)
    $OldPath = $env:PATH
    $OldPythonPath = [Environment]::GetEnvironmentVariable("PYTHONPATH", "Process")
    $OldPythonHome = [Environment]::GetEnvironmentVariable("PYTHONHOME", "Process")
    try {
        Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
        Remove-Item Env:PYTHONHOME -ErrorAction SilentlyContinue
        $env:PATH = (Join-Path $env:SystemRoot "System32") + ";" + $env:SystemRoot
        $Process = Start-Process -FilePath (Join-Path $Expanded "WlanTroubleshooterKO.exe") -ArgumentList @(("--analyze-capture=`"" + $Capture + "`""),("--analysis-output=`"" + $Output + "`"")) -WorkingDirectory $Expanded -Wait -PassThru
        if ($Process.ExitCode -ne 0) { throw "Portable Replay Counter relation analysis failed with exit code $($Process.ExitCode)." }
    }
    finally {
        $env:PATH = $OldPath
        Restore-EnvironmentValue -Name "PYTHONPATH" -Value $OldPythonPath
        Restore-EnvironmentValue -Name "PYTHONHOME" -Value $OldPythonHome
    }
    $Raw = Get-Content -LiteralPath $Output -Raw
    $Result = $Raw | ConvertFrom-Json -Depth 192
    $Report = $Result.eapol_replay_relations
    if ($Result.schema_version -ne 2 -or $Result.protocol_inventory_state -ne "completed" -or $null -eq $Report -or $Report.schema_version -ne 1 -or $Report.profile_version -ne "0.6.0" -or $Report.field_available -ne $true -or $Report.rows_observed -ne 9 -or $Report.key_rows_observed -ne 5 -or $Report.observations_total -ne 1 -or $Report.complete -ne $true -or $Report.raw_replay_counters_serialized -ne $false -or $Report.replay_counter_values_persisted -ne $false -or $Report.same_handshake_confirmed -ne $false -or $Report.retransmission_confirmed -ne $false -or $Report.key_installation_confirmed -ne $false -or $Report.cryptographic_success_confirmed -ne $false -or $Report.root_cause_confirmed -ne $false) { throw "Portable Replay Counter relation report is missing or violated its conservative boundary." }
    $Observation = @($Report.observations)[0]
    if ($Observation.observation_id -ne "EAPOL-HS-1" -or $Observation.device_alias -ne "DEVICE-1" -or $Observation.ap_alias -ne "AP-1" -or $Observation.state -ne "expected-relations-observed" -or $Observation.m1_m2_relation -ne "equal-observed" -or $Observation.m3_m4_relation -ne "equal-observed" -or $Observation.m1_m3_progression -ne "increased-observed" -or $Observation.retransmission_confirmed -ne $false -or [string]::IsNullOrWhiteSpace([string]$Observation.display_filter)) { throw "Portable EAPOL-HS-1 Replay Counter relationship is unexpected." }
    Assert-ExactIntegerSequence -Actual $Observation.evidence_frames -Expected @(5,6,7,8,9) -Label "Replay relation evidence"
    Assert-ExactIntegerSequence -Actual $Observation.frames_with_counter -Expected @(5,6,7,8,9) -Label "Replay counter frames"
    Assert-ExactIntegerSequence -Actual $Observation.missing_counter_frames -Expected @() -Label "Missing Replay counter frames"
    $Repeated = @($Observation.repeated_message_relations)
    if ($Repeated.Count -ne 1 -or $Repeated[0].message_number -ne 3 -or $Repeated[0].state -ne "same-counter-observed") { throw "Repeated M3 Replay Counter relation is unexpected." }
    Assert-ExactIntegerSequence -Actual $Repeated[0].evidence_frames -Expected @(7,8) -Label "Repeated M3 frames"
    Assert-NoForbiddenText -Raw $Raw -Forbidden @($Capture,(Split-Path -Leaf $Capture),"18446744073709551000","18446744073709551001","eapol.keydes.replay_counter",'"replay_counter":','"nonce":','"key_mic":','"key_data":',"02:00:00:00:00:c1","02:00:00:00:00:d1","1700003000")
    $AfterFiles = @(Get-ChildItem -LiteralPath $Expanded -Recurse -File | ForEach-Object { [System.IO.Path]::GetRelativePath($Expanded, $_.FullName).Replace("\", "/") } | Sort-Object)
    if (($BeforeFiles -join "|") -ne ($AfterFiles -join "|")) { throw "Portable Replay Counter relation analysis modified its distribution directory." }
    Write-Host "Portable EAPOL Replay Counter relationship-only integration test passed."
}
finally { Remove-Item -LiteralPath $WorkRoot -Recurse -Force -ErrorAction SilentlyContinue }
