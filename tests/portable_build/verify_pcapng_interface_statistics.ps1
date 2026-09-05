[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PackageOutputPath,
    [Parameter()][string]$PythonPath = "python"
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
            throw "PCAPNG statistics result exposed an interface identity, absolute timestamp, address, or path."
        }
    }
}

function Get-Counter {
    param(
        [Parameter(Mandatory = $true)]$Interface,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $Value = @($Interface.counters | Where-Object { $_.name -eq $Name }) | Select-Object -First 1
    if ($null -eq $Value) {
        throw "PCAPNG statistics counter is missing: $Name"
    }
    return $Value
}

function Assert-SingleCounter {
    param(
        [Parameter(Mandatory = $true)]$Interface,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][long]$Expected
    )
    $Value = Get-Counter -Interface $Interface -Name $Name
    if (
        $Value.observations -ne 1 -or
        [long]$Value.first_value -ne $Expected -or
        [long]$Value.last_value -ne $Expected -or
        $Value.progression -ne "single-value-observed"
    ) {
        throw "PCAPNG statistics counter is unexpected: $Name"
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
        $BuildInfo.pcapng_string_option_serialization -ne "disabled" -or
        $BuildInfo.interface_name_serialization -ne "disabled" -or
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

    if (-not (Test-Path -LiteralPath $Output -PathType Leaf)) {
        throw "Portable PCAPNG statistics result is missing."
    }
    $Raw = Get-Content -LiteralPath $Output -Raw
    $Result = $Raw | ConvertFrom-Json -Depth 192
    $Report = $Result.pcapng_interface_statistics
    if (
        $Result.schema_version -ne 2 -or
        $Result.protocol_inventory_state -ne "completed" -or
        $Result.structure.capture_format -ne "pcapng" -or
        $Result.structure.records_scanned -ne 5 -or
        $Result.structure.packets_scanned -ne 2 -or
        $null -eq $Report -or
        $Report.schema_version -ne 1 -or
        $Report.supported_capture_format -ne $true -or
        $Report.complete -ne $true -or
        $Report.state -ne "reported-drop-observed" -or
        $Report.sections_observed -ne 1 -or
        $Report.interfaces_defined -ne 1 -or
        $Report.statistics_blocks_observed -ne 1 -or
        $Report.interfaces_with_statistics -ne 1 -or
        $Report.raw_interface_identifiers_serialized -ne $false -or
        $Report.absolute_timestamps_serialized -ne $false -or
        $Report.capture_loss_excluded -ne $false -or
        $Report.specific_packet_loss_confirmed -ne $false -or
        $Report.root_cause_confirmed -ne $false
    ) {
        throw "Portable PCAPNG statistics report is missing or violated its conservative boundary."
    }

    $Interfaces = @($Report.interfaces)
    if ($Interfaces.Count -ne 1) {
        throw "Portable PCAPNG statistics report must contain one anonymous interface."
    }
    $Interface = $Interfaces[0]
    if (
        $Interface.interface_alias -ne "IFACE-1" -or
        $Interface.section_index -ne 0 -or
        $Interface.interface_id -ne 0 -or
        $Interface.statistics_blocks -ne 1 -or
        $Interface.state -ne "reported-drop-observed" -or
        $Interface.raw_interface_identifiers_serialized -ne $false -or
        $Interface.absolute_timestamps_serialized -ne $false -or
        $Interface.specific_packet_loss_confirmed -ne $false -or
        $Interface.root_cause_confirmed -ne $false
    ) {
        throw "Portable IFACE-1 statistics summary is unexpected."
    }

    Assert-SingleCounter -Interface $Interface -Name "ifrecv" -Expected 2
    Assert-SingleCounter -Interface $Interface -Name "ifdrop" -Expected 3
    Assert-SingleCounter -Interface $Interface -Name "filteraccept" -Expected 2
    Assert-SingleCounter -Interface $Interface -Name "osdrop" -Expected 1
    Assert-SingleCounter -Interface $Interface -Name "usrdeliv" -Expected 2

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
        "02:00:00:00:00:01",
        "020000000001"
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
