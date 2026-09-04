[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PackageOutputPath,
    [Parameter()][string]$PythonPath = "python"
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Restore-EnvironmentValue {
    param([Parameter(Mandatory = $true)][string]$Name,[AllowNull()][string]$Value)
    if ($null -eq $Value) { Remove-Item ("Env:" + $Name) -ErrorAction SilentlyContinue }
    else { [Environment]::SetEnvironmentVariable($Name, $Value, "Process") }
}

function Assert-NoForbiddenText {
    param([Parameter(Mandatory = $true)][string]$Raw,[Parameter(Mandatory = $true)][string[]]$Forbidden)
    foreach ($Value in $Forbidden) {
        if ($Raw.Contains($Value, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "PCAPNG statistics result exposed an interface identity or absolute timestamp."
        }
    }
}

$PackageOutputPath = [System.IO.Path]::GetFullPath($PackageOutputPath)
if (-not (Test-Path -LiteralPath $PackageOutputPath -PathType Leaf)) { throw "Portable package metadata is missing." }
$Package = Get-Content -LiteralPath $PackageOutputPath -Raw | ConvertFrom-Json -Depth 32
$Archive = [System.IO.Path]::GetFullPath([string]$Package.archive)
if (-not (Test-Path -LiteralPath $Archive -PathType Leaf)) { throw "Portable archive is missing." }

$WorkRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("wlan-pcapng-statistics-test-" + [guid]::NewGuid().ToString("N"))
$Expanded = Join-Path $WorkRoot "portable"
$Capture = Join-Path $WorkRoot "private-interface-statistics.pcapng"
$Output = Join-Path $WorkRoot "interface-statistics-result.json"
New-Item -ItemType Directory -Path $Expanded -Force | Out-Null
try {
    Expand-Archive -LiteralPath $Archive -DestinationPath $Expanded
    $BuildInfo = Get-Content -LiteralPath (Join-Path $Expanded "BUILD_INFO.json") -Raw | ConvertFrom-Json -Depth 32
    if (
        $BuildInfo.pcapng_interface_statistics_runtime -ne "enabled" -or
        $BuildInfo.absolute_timestamp_serialization -ne "disabled" -or
        $BuildInfo.raw_identifier_serialization -ne "disabled"
    ) {
        throw "Portable BUILD_INFO does not preserve the PCAPNG statistics privacy boundary."
    }

    & $PythonPath (Join-Path $PSScriptRoot "generate_pcapng_statistics_fixture.py") --output $Capture
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $Capture -PathType Leaf)) {
        throw "Synthetic PCAPNG Interface Statistics fixture generation failed."
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
            throw "Portable PCAPNG statistics analysis failed with exit code $($Process.ExitCode)."
        }
    }
    finally {
        $env:PATH = $OldPath
        Restore-EnvironmentValue -Name "PYTHONPATH" -Value $OldPythonPath
        Restore-EnvironmentValue -Name "PYTHONHOME" -Value $OldPythonHome
    }

    if (-not (Test-Path -LiteralPath $Output -PathType Leaf)) { throw "Portable PCAPNG statistics result is missing." }
    $Raw = Get-Content -LiteralPath $Output -Raw
    $Result = $Raw | ConvertFrom-Json -Depth 192
    $Structure = $Result.structure
    if (
        $Result.schema_version -ne 2 -or
        $Result.protocol_inventory_state -ne "completed" -or
        $Structure.capture_format -ne "pcapng" -or
        $Structure.records_scanned -ne 5 -or
        $Structure.packets_scanned -ne 2 -or
        $Structure.interface_statistics_state -ne "observed" -or
        @($Structure.interface_statistics).Count -ne 1
    ) {
        throw "Portable PCAPNG structure did not expose one statistics observation."
    }

    $Statistics = @($Structure.interface_statistics)[0]
    if (
        $Statistics.interface_alias -ne "IFACE-1" -or
        $Statistics.section_index -ne 0 -or
        $Statistics.interface_id -ne 0 -or
        $Statistics.observation_index -ne 1 -or
        $Statistics.counter_state -ne "reported-drop-observed" -or
        $Statistics.ifrecv -ne 2 -or
        $Statistics.ifdrop -ne 3 -or
        $Statistics.filteraccept -ne 2 -or
        $Statistics.osdrop -ne 1 -or
        $Statistics.usrdeliv -ne 2 -or
        $Statistics.block_timestamp_present -ne $true -or
        $Statistics.start_time_present -ne $true -or
        $Statistics.end_time_present -ne $true -or
        $Statistics.absolute_timestamps_serialized -ne $false -or
        $Statistics.capture_loss_excluded -ne $false -or
        $Statistics.root_cause_confirmed -ne $false
    ) {
        throw "Portable IFACE-1 statistics values or conservative flags are unexpected."
    }
    if ($Result.capture_observability.capture_loss_excluded -ne $false) {
        throw "A reported PCAPNG counter must not prove capture-loss exclusion."
    }

    Assert-NoForbiddenText -Raw $Raw -Forbidden @(
        $Capture,
        (Split-Path -Leaf $Capture),
        "Corp-WLAN-Private-Adapter",
        "Internal monitor path",
        "72623859790382856",
        "1230066625199609624",
        "2387509390608836392",
        "0102030405060708",
        "1112131415161718",
        "2122232425262728",
        "192.0.2.1",
        "02:00:00:00:00:01"
    )

    $AfterFiles = @(Get-ChildItem -LiteralPath $Expanded -Recurse -File | ForEach-Object {
        [System.IO.Path]::GetRelativePath($Expanded, $_.FullName).Replace("\", "/")
    } | Sort-Object)
    if (($BeforeFiles -join "|") -ne ($AfterFiles -join "|")) {
        throw "Portable PCAPNG statistics analysis modified its distribution directory."
    }
    Write-Host "Portable PCAPNG Interface Statistics conservative integration test passed."
}
finally {
    Remove-Item -LiteralPath $WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
}
