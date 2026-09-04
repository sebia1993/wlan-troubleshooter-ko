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

function Write-SafeSchemaLines {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)]$Lines
    )

    $Safe = @($Lines | ForEach-Object {
        $Line = [string]$_
        if ($Line.Length -gt 400) {
            $Line = $Line.Substring(0, 400)
        }
        if ($Line -match '^[\x20-\x7E\t]+$') {
            $Line
        }
    })
    if ($Safe.Count -eq 0) {
        Write-Host "${Label}: none"
    }
    else {
        foreach ($Line in $Safe | Select-Object -First 30) {
            Write-Host "${Label}: $Line"
        }
    }
}

function Invoke-EapSchemaProbe {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$TShark,
        [Parameter(Mandatory = $true)][string]$Capture,
        [Parameter(Mandatory = $true)][string]$WorkRoot
    )

    $DecodeErrors = Join-Path $WorkRoot ($Label + "-decode-errors.txt")
    $Decodes = @(& $TShark -n -G decodes 2> $DecodeErrors)
    Write-Host "$Label -G decodes exit: $LASTEXITCODE"
    $DecodeMatches = @($Decodes | Where-Object {
        ([string]$_) -match '(^|\t)eapol\.type(\t|$)|(^|\t)eap(\t|$)'
    })
    Write-SafeSchemaLines -Label "$Label EAP decode" -Lines $DecodeMatches

    $ProtocolErrors = Join-Path $WorkRoot ($Label + "-protocol-errors.txt")
    $Protocols = @(& $TShark -n -G protocols 2> $ProtocolErrors)
    Write-Host "$Label -G protocols exit: $LASTEXITCODE"
    $ProtocolMatches = @($Protocols | Where-Object {
        ([string]$_) -match '(^|\t)(EAP|EAPOL|eap|eapol)(\t|$)'
    })
    Write-SafeSchemaLines -Label "$Label EAP protocol" -Lines $ProtocolMatches

    $FieldErrors = Join-Path $WorkRoot ($Label + "-field-errors.txt")
    $Rows = @(& $TShark -n -2 -r $Capture -T fields -E 'header=y' -E 'separator=/t' -E 'occurrence=f' -E 'quote=d' -e frame.number -e frame.protocols -e eapol.type -e eap.code -e eap.id -e eap.type 2> $FieldErrors)
    Write-Host "$Label synthetic field extraction exit: $LASTEXITCODE"
    Write-SafeSchemaLines -Label "$Label EAP synthetic row" -Lines $Rows
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

$WorkRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("wlan-eap-schema-" + [guid]::NewGuid().ToString("N"))
$Expanded = Join-Path $WorkRoot "portable"
$Capture = Join-Path $WorkRoot "synthetic-radiotap-eap.pcap"
New-Item -ItemType Directory -Path $Expanded -Force | Out-Null
try {
    Expand-Archive -LiteralPath $Archive -DestinationPath $Expanded
    & $PythonPath (Join-Path $PSScriptRoot "generate_wireless_event_fixture.py") --output $Capture
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $Capture -PathType Leaf)) {
        throw "Synthetic EAP diagnostic capture generation failed."
    }

    $TShark = Join-Path $Expanded "vendor\wireshark\tshark.exe"
    if (-not (Test-Path -LiteralPath $TShark -PathType Leaf)) {
        throw "Bundled TShark is missing."
    }

    $EnvironmentNames = @(
        "PATH",
        "PYTHONPATH",
        "PYTHONHOME",
        "WIRESHARK_CONFIG_DIR",
        "WIRESHARK_PLUGIN_DIR",
        "WIRESHARK_EXTCAP_DIR",
        "WIRESHARK_DATA_DIR",
        "TEMP",
        "TMP",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "TZ"
    )
    $OriginalEnvironment = @{}
    foreach ($Name in $EnvironmentNames) {
        $OriginalEnvironment[$Name] = [Environment]::GetEnvironmentVariable($Name, "Process")
    }
    try {
        Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
        Remove-Item Env:PYTHONHOME -ErrorAction SilentlyContinue
        $env:PATH = (Join-Path $env:SystemRoot "System32") + ";" + $env:SystemRoot

        Invoke-EapSchemaProbe -Label "default" -TShark $TShark -Capture $Capture -WorkRoot $WorkRoot

        $Isolation = Join-Path $WorkRoot "isolated"
        New-Item -ItemType Directory -Path $Isolation | Out-Null
        foreach ($Name in @("config", "plugins", "extcap", "data", "temp")) {
            New-Item -ItemType Directory -Path (Join-Path $Isolation $Name) | Out-Null
        }
        $env:WIRESHARK_CONFIG_DIR = Join-Path $Isolation "config"
        $env:WIRESHARK_PLUGIN_DIR = Join-Path $Isolation "plugins"
        $env:WIRESHARK_EXTCAP_DIR = Join-Path $Isolation "extcap"
        $env:WIRESHARK_DATA_DIR = Join-Path $Isolation "data"
        $env:TEMP = Join-Path $Isolation "temp"
        $env:TMP = Join-Path $Isolation "temp"
        $env:TMPDIR = Join-Path $Isolation "temp"
        $env:LANG = "C"
        $env:LC_ALL = "C"
        $env:TZ = "UTC"

        Invoke-EapSchemaProbe -Label "isolated" -TShark $TShark -Capture $Capture -WorkRoot $WorkRoot
    }
    finally {
        foreach ($Name in $EnvironmentNames) {
            Restore-EnvironmentValue -Name $Name -Value $OriginalEnvironment[$Name]
        }
    }
}
finally {
    Remove-Item -LiteralPath $WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
}
