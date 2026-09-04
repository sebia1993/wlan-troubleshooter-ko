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
    if ($Process.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $Output -PathType Leaf)) {
        throw "Portable device-alias analysis failed."
    }

    $Raw = Get-Content -LiteralPath $Output -Raw
    $Result = $Raw | ConvertFrom-Json -Depth 128
    if ($Result.schema_version -ne 2 -or $Result.protocol_inventory_state -ne "completed") {
        throw "Portable device-alias analysis did not complete with schema version 2."
    }
    if ($null -eq $Result.protocol_inventory.device_sessions) {
        throw "Portable device-alias report is missing."
    }
    return [pscustomobject]@{
        Raw = $Raw
        Result = $Result
        Report = $Result.protocol_inventory.device_sessions
    }
}

function Assert-NoForbiddenText {
    param(
        [Parameter(Mandatory = $true)][string]$Raw,
        [Parameter(Mandatory = $true)][string[]]$Forbidden
    )

    foreach ($Value in $Forbidden) {
        if ($Raw.Contains($Value, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Device-alias result exposed a forbidden identifier."
        }
    }
}

function Assert-PrivacyFlags {
    param([Parameter(Mandatory = $true)]$Report)

    if (
        $Report.schema_version -ne 1 -or
        $Report.raw_identifiers_serialized -ne $false -or
        $Report.alias_secret_persisted -ne $false -or
        $Report.aliases_stable_across_runs -ne $false
    ) {
        throw "Device-alias privacy flags are not fail-closed."
    }
}

function Assert-LinkedAttempt {
    param(
        [Parameter(Mandatory = $true)]$Report,
        [Parameter(Mandatory = $true)][string]$AttemptPrefix,
        [Parameter(Mandatory = $true)][string]$DeviceAlias
    )

    $Match = @($Report.attempt_links | Where-Object {
        $_.attempt_id.StartsWith($AttemptPrefix, [System.StringComparison]::Ordinal) -and
        $_.state -eq "linked" -and
        $_.device_alias -eq $DeviceAlias
    })
    if ($Match.Count -lt 1) {
        throw "Expected device-linked transaction was not observed: $AttemptPrefix"
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

$WorkRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("wlan-device-alias-test-" + [guid]::NewGuid().ToString("N"))
$Expanded = Join-Path $WorkRoot "portable"
$EthernetCapture = Join-Path $WorkRoot "private-device-ethernet.pcap"
$EthernetOutput = Join-Path $WorkRoot "device-ethernet.json"
$WirelessCapture = Join-Path $WorkRoot "private-device-wireless.pcap"
$WirelessOutput = Join-Path $WorkRoot "device-wireless.json"
New-Item -ItemType Directory -Path $Expanded -Force | Out-Null

try {
    Expand-Archive -LiteralPath $Archive -DestinationPath $Expanded

    $BuildInfo = Get-Content -LiteralPath (Join-Path $Expanded "BUILD_INFO.json") -Raw | ConvertFrom-Json -Depth 32
    if (
        $BuildInfo.device_session_runtime -ne "enabled" -or
        $BuildInfo.raw_identifier_serialization -ne "disabled" -or
        $BuildInfo.alias_secret_persistence -ne "disabled" -or
        $BuildInfo.cross_run_alias_stability -ne "disabled"
    ) {
        throw "Portable BUILD_INFO does not preserve the device-alias privacy boundary."
    }

    & $PythonPath (Join-Path $PSScriptRoot "generate_event_fixture.py") --output $EthernetCapture
    if ($LASTEXITCODE -ne 0) {
        throw "Ethernet device fixture generation failed."
    }
    & $PythonPath (Join-Path $PSScriptRoot "generate_wireless_event_fixture.py") --output $WirelessCapture
    if ($LASTEXITCODE -ne 0) {
        throw "Wireless device fixture generation failed."
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

        $Ethernet = Invoke-PortableAnalysis -Application $Application -WorkingDirectory $Expanded -Capture $EthernetCapture -Output $EthernetOutput
        $Wireless = Invoke-PortableAnalysis -Application $Application -WorkingDirectory $Expanded -Capture $WirelessCapture -Output $WirelessOutput
    }
    finally {
        $env:PATH = $OldPath
        Restore-EnvironmentValue -Name "PYTHONPATH" -Value $OldPythonPath
        Restore-EnvironmentValue -Name "PYTHONHOME" -Value $OldPythonHome
    }

    Assert-PrivacyFlags -Report $Ethernet.Report
    if ($Ethernet.Report.complete -ne $true -or $Ethernet.Report.devices_total -ne 1) {
        throw "Ethernet device-alias report did not produce one complete DEVICE alias."
    }
    $EthernetDevice = @($Ethernet.Report.devices)[0]
    if (
        $EthernetDevice.alias -ne "DEVICE-1" -or
        $EthernetDevice.device_identity_confirmed -ne $false -or
        $EthernetDevice.cross_protocol_session_confirmed -ne $false
    ) {
        throw "Ethernet device alias violated the conservative identity boundary."
    }
    foreach ($Protocol in @("dhcp", "dns", "tcp")) {
        if (@($EthernetDevice.protocols_observed) -notcontains $Protocol) {
            throw "Ethernet DEVICE-1 is missing an observed protocol: $Protocol"
        }
    }
    foreach ($Prefix in @("DHCP-", "DNS-", "TCP-")) {
        Assert-LinkedAttempt -Report $Ethernet.Report -AttemptPrefix $Prefix -DeviceAlias "DEVICE-1"
    }

    Assert-NoForbiddenText -Raw $Ethernet.Raw -Forbidden @(
        $EthernetCapture,
        (Split-Path -Leaf $EthernetCapture),
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

    Assert-PrivacyFlags -Report $Wireless.Report
    if ($Wireless.Report.complete -ne $true -or $Wireless.Report.devices_total -ne 1) {
        throw "Wireless device-alias report did not produce one complete DEVICE alias."
    }
    $WirelessDevice = @($Wireless.Report.devices)[0]
    if (
        $WirelessDevice.alias -ne "DEVICE-1" -or
        @($WirelessDevice.ap_aliases) -notcontains "AP-1" -or
        $WirelessDevice.device_identity_confirmed -ne $false -or
        $WirelessDevice.cross_protocol_session_confirmed -ne $false
    ) {
        throw "Wireless DEVICE-1/AP-1 alias result is invalid."
    }
    if (@($WirelessDevice.evidence_types).Count -lt 1) {
        throw "Wireless device alias has no packet-direction evidence."
    }

    Assert-NoForbiddenText -Raw $Wireless.Raw -Forbidden @(
        $WirelessCapture,
        (Split-Path -Leaf $WirelessCapture),
        "02:00:00:00:00:a1",
        "02:00:00:00:00:b1",
        "0200000000a1",
        "0200000000b1",
        "1700000100"
    )

    $AfterFiles = @(Get-ChildItem -LiteralPath $Expanded -Recurse -File | ForEach-Object {
        [System.IO.Path]::GetRelativePath($Expanded, $_.FullName).Replace("\", "/")
    } | Sort-Object)
    if (($BeforeFiles -join "|") -ne ($AfterFiles -join "|")) {
        throw "Portable device-alias analysis modified its distribution directory."
    }

    Write-Host "Portable Ethernet DEVICE-1 and IEEE 802.11 DEVICE-1/AP-1 privacy integration tests passed."
}
finally {
    Remove-Item -LiteralPath $WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
}
