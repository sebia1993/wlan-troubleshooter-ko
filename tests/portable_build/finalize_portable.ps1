[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageOutputPath,

    [Parameter()]
    [string]$PythonPath = "python"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-LowerSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Copy-RequiredLicense {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if ([string]::IsNullOrWhiteSpace($Source) -or -not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw "$Label license file is missing."
    }
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
}

function Find-TclTkLicense {
    param(
        [Parameter(Mandatory = $true)][string]$ExpandedRoot,
        [Parameter(Mandatory = $true)][string]$PythonRoot,
        [Parameter(Mandatory = $true)][ValidateSet("tcl", "tk")][string]$Component
    )

    $BundledSegment = [System.IO.Path]::DirectorySeparatorChar + "_" + $Component + "_data" + [System.IO.Path]::DirectorySeparatorChar
    $Bundled = Get-ChildItem -LiteralPath $ExpandedRoot -Recurse -File -Filter "license.terms" |
        Where-Object { $_.FullName.Contains($BundledSegment, [System.StringComparison]::OrdinalIgnoreCase) } |
        Sort-Object FullName |
        Select-Object -First 1
    if ($null -ne $Bundled) {
        return $Bundled.FullName
    }

    $PythonTclRoot = Join-Path $PythonRoot "tcl"
    if (Test-Path -LiteralPath $PythonTclRoot -PathType Container) {
        $InstalledSegment = [System.IO.Path]::DirectorySeparatorChar + $Component
        $Installed = Get-ChildItem -LiteralPath $PythonTclRoot -Recurse -File -Filter "license.terms" |
            Where-Object { $_.FullName.Contains($InstalledSegment, [System.StringComparison]::OrdinalIgnoreCase) } |
            Sort-Object FullName |
            Select-Object -First 1
        if ($null -ne $Installed) {
            return $Installed.FullName
        }
    }
    throw "Bundled Tcl/Tk license terms are missing."
}

function Find-PyInstallerLicense {
    param([Parameter(Mandatory = $true)][string]$PythonPath)

    $Script = @'
from importlib.metadata import distribution

value = distribution("pyinstaller")
candidates = []
for entry in value.files or ():
    lowered = entry.as_posix().casefold()
    if lowered.endswith("/copying.txt") or lowered == "copying.txt":
        candidates.append(entry.locate())
if not candidates:
    raise SystemExit(2)
print(sorted(str(item) for item in candidates)[0])
'@
    $Result = (& $PythonPath -c $Script).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($Result)) {
        throw "Could not locate the PyInstaller distribution license."
    }
    return $Result
}

$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$ProjectText = Get-Content -LiteralPath (Join-Path $RepositoryRoot "pyproject.toml") -Raw
$ReleaseTag = [regex]::Match($ProjectText, '(?m)^release-tag\s*=\s*"([^"]+)"').Groups[1].Value
if ([string]::IsNullOrWhiteSpace($ReleaseTag) -or $ReleaseTag -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+-[0-9A-Za-z.-]+$') {
    throw "Portable release tag is missing or invalid."
}
$ProductVersion = $ReleaseTag.Substring(1)

$PackageOutputPath = [System.IO.Path]::GetFullPath($PackageOutputPath)
if (-not (Test-Path -LiteralPath $PackageOutputPath -PathType Leaf)) {
    throw "Package output metadata is missing."
}
$Package = Get-Content -LiteralPath $PackageOutputPath -Raw | ConvertFrom-Json -Depth 32
$OriginalArchive = [System.IO.Path]::GetFullPath([string]$Package.archive)
$OriginalChecksum = [System.IO.Path]::GetFullPath([string]$Package.archive_checksum)
if (-not (Test-Path -LiteralPath $OriginalArchive -PathType Leaf)) {
    throw "Portable archive is missing."
}
$OutputDirectory = Split-Path -Parent $OriginalArchive
$FinalArchiveName = "WlanTroubleshooterKO-$ReleaseTag-win64-portable.zip"
$FinalArchive = Join-Path $OutputDirectory $FinalArchiveName
$FinalChecksum = $FinalArchive + ".sha256"

$WorkRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("wlan-finalize-" + [guid]::NewGuid().ToString("N"))
$Expanded = Join-Path $WorkRoot "expanded"
New-Item -ItemType Directory -Path $Expanded -Force | Out-Null
try {
    Expand-Archive -LiteralPath $OriginalArchive -DestinationPath $Expanded
    $Licenses = Join-Path $Expanded "licenses"
    New-Item -ItemType Directory -Path $Licenses -Force | Out-Null

    $PythonExecutable = (Get-Command $PythonPath -ErrorAction Stop).Source
    $PythonRoot = Split-Path -Parent $PythonExecutable
    Copy-RequiredLicense -Source (Join-Path $PythonRoot "LICENSE.txt") -Destination (Join-Path $Licenses "PYTHON-LICENSE.txt") -Label "Python"

    $TclLicense = Find-TclTkLicense -ExpandedRoot $Expanded -PythonRoot $PythonRoot -Component "tcl"
    $TkLicense = Find-TclTkLicense -ExpandedRoot $Expanded -PythonRoot $PythonRoot -Component "tk"
    Copy-RequiredLicense -Source $TclLicense -Destination (Join-Path $Licenses "TCL-LICENSE.txt") -Label "Tcl"
    Copy-RequiredLicense -Source $TkLicense -Destination (Join-Path $Licenses "TK-LICENSE.txt") -Label "Tk"

    $PyInstallerLicense = Find-PyInstallerLicense -PythonPath $PythonPath
    Copy-RequiredLicense -Source $PyInstallerLicense -Destination (Join-Path $Licenses "PYINSTALLER-COPYING.txt") -Label "PyInstaller"

    $RequiredEntries = @(
        "WlanTroubleshooterKO.exe",
        "BUILD_INFO.json",
        "vendor/wireshark/tshark.exe",
        "vendor/wireshark/manifest.json",
        "vendor/wireshark/COPYING",
        "licenses/PYTHON-LICENSE.txt",
        "licenses/TCL-LICENSE.txt",
        "licenses/TK-LICENSE.txt",
        "licenses/PYINSTALLER-COPYING.txt"
    )
    foreach ($Entry in $RequiredEntries) {
        if (-not (Test-Path -LiteralPath (Join-Path $Expanded ($Entry -replace "/", "\")))) {
            throw "Portable stage is missing a required entry: $Entry"
        }
    }

    $BuildInfoPath = Join-Path $Expanded "BUILD_INFO.json"
    $BuildInfo = Get-Content -LiteralPath $BuildInfoPath -Raw | ConvertFrom-Json -Depth 32
    $BuildInfo.product_version = $ProductVersion
    $RuntimeFlags = [ordered]@{
        protocol_inventory_runtime = "enabled"
        event_timeline_runtime = "enabled"
        transaction_session_runtime = "enabled"
        device_session_runtime = "enabled"
        device_journey_runtime = "enabled"
        capture_observability_runtime = "enabled"
        eapol_handshake_runtime = "enabled"
        eapol_replay_relation_runtime = "enabled"
        pcapng_interface_statistics_runtime = "enabled"
        capture_time_boundary_runtime = "enabled"
        raw_replay_counter_serialization = "disabled"
        replay_counter_persistence = "disabled"
        absolute_timestamp_serialization = "disabled"
        response_absence_confirmation = "disabled"
        pcapng_string_option_serialization = "disabled"
        interface_name_serialization = "disabled"
        raw_identifier_serialization = "disabled"
        alias_secret_persistence = "disabled"
        cross_run_alias_stability = "disabled"
    }
    foreach ($Entry in $RuntimeFlags.GetEnumerator()) {
        if ($BuildInfo.PSObject.Properties.Name -contains $Entry.Key) {
            $BuildInfo.($Entry.Key) = $Entry.Value
        }
        else {
            $BuildInfo | Add-Member -NotePropertyName $Entry.Key -NotePropertyValue $Entry.Value
        }
    }
    $BuildInfo | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $BuildInfoPath -Encoding utf8

    $Executables = @(Get-ChildItem -LiteralPath $Expanded -Recurse -File -Filter "*.exe" | ForEach-Object {
        [System.IO.Path]::GetRelativePath($Expanded, $_.FullName).Replace("\", "/")
    } | Sort-Object)
    $ExpectedExecutables = @("vendor/wireshark/tshark.exe", "WlanTroubleshooterKO.exe") | Sort-Object
    if (($Executables -join "|") -ne ($ExpectedExecutables -join "|")) {
        throw "Portable stage contains an unexpected executable."
    }

    foreach ($Path in @($OriginalArchive, $OriginalChecksum, $FinalArchive, $FinalChecksum) | Select-Object -Unique) {
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    }
    Compress-Archive -Path (Join-Path $Expanded "*") -DestinationPath $FinalArchive -CompressionLevel Optimal
    $Hash = Get-LowerSha256 -Path $FinalArchive
    "$Hash  $FinalArchiveName" | Set-Content -LiteralPath $FinalChecksum -Encoding ascii

    $Package.archive = $FinalArchive
    $Package.archive_checksum = $FinalChecksum
    $Package.archive_sha256 = $Hash
    if ($Package.PSObject.Properties.Name -contains "archive_size_bytes") {
        $Package.archive_size_bytes = (Get-Item -LiteralPath $FinalArchive).Length
    }
    else {
        $Package | Add-Member -NotePropertyName archive_size_bytes -NotePropertyValue (Get-Item -LiteralPath $FinalArchive).Length
    }
    $Package | Add-Member -NotePropertyName release_tag -NotePropertyValue $ReleaseTag -Force
    $Package | Add-Member -NotePropertyName product_version -NotePropertyValue $ProductVersion -Force
    $Package | Add-Member -NotePropertyName bundled_license_files -NotePropertyValue @(
        "PYTHON-LICENSE.txt",
        "TCL-LICENSE.txt",
        "TK-LICENSE.txt",
        "PYINSTALLER-COPYING.txt",
        "vendor/wireshark/COPYING"
    ) -Force
    $Package | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $PackageOutputPath -Encoding utf8
}
finally {
    Remove-Item -LiteralPath $WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
}
