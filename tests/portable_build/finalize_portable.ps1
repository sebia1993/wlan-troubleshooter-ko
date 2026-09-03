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
        [Parameter(Mandatory = $true)][string]$Destination
    )
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw "Required runtime license file is missing."
    }
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
}

function Find-TclTkLicense {
    param(
        [Parameter(Mandatory = $true)][string]$ExpandedRoot,
        [Parameter(Mandatory = $true)][string]$PythonRoot,
        [Parameter(Mandatory = $true)][ValidateSet("tcl", "tk")][string]$Component
    )

    $BundledDirectoryName = "_" + $Component + "_data"
    $Bundled = Get-ChildItem -LiteralPath $ExpandedRoot -Recurse -File -Filter "license.terms" |
        Where-Object { $_.Directory.Name -eq $BundledDirectoryName } |
        Select-Object -First 1
    if ($null -ne $Bundled) {
        return $Bundled.FullName
    }

    $PythonTclRoot = Join-Path $PythonRoot "tcl"
    if (Test-Path -LiteralPath $PythonTclRoot -PathType Container) {
        $Installed = Get-ChildItem -LiteralPath $PythonTclRoot -Recurse -File -Filter "license.terms" |
            Where-Object { $_.Directory.Name -like ($Component + "*") } |
            Select-Object -First 1
        if ($null -ne $Installed) {
            return $Installed.FullName
        }
    }
    throw "Bundled Tcl/Tk license terms are missing."
}

$PackageOutputPath = [System.IO.Path]::GetFullPath($PackageOutputPath)
if (-not (Test-Path -LiteralPath $PackageOutputPath -PathType Leaf)) {
    throw "Package output metadata is missing."
}
$Package = Get-Content -LiteralPath $PackageOutputPath -Raw | ConvertFrom-Json -Depth 32
$Archive = [System.IO.Path]::GetFullPath([string]$Package.archive)
$Checksum = [System.IO.Path]::GetFullPath([string]$Package.archive_checksum)
if (-not (Test-Path -LiteralPath $Archive -PathType Leaf)) {
    throw "Portable archive is missing."
}

$WorkRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("wlan-finalize-" + [guid]::NewGuid().ToString("N"))
$Expanded = Join-Path $WorkRoot "expanded"
New-Item -ItemType Directory -Path $Expanded -Force | Out-Null
try {
    Expand-Archive -LiteralPath $Archive -DestinationPath $Expanded
    $Licenses = Join-Path $Expanded "licenses"
    New-Item -ItemType Directory -Path $Licenses -Force | Out-Null

    $PythonExecutable = (Get-Command $PythonPath -ErrorAction Stop).Source
    $PythonRoot = Split-Path -Parent $PythonExecutable
    Copy-RequiredLicense -Source (Join-Path $PythonRoot "LICENSE.txt") -Destination (Join-Path $Licenses "PYTHON-LICENSE.txt")

    $TclLicense = Find-TclTkLicense -ExpandedRoot $Expanded -PythonRoot $PythonRoot -Component "tcl"
    $TkLicense = Find-TclTkLicense -ExpandedRoot $Expanded -PythonRoot $PythonRoot -Component "tk"
    Copy-RequiredLicense -Source $TclLicense -Destination (Join-Path $Licenses "TCL-LICENSE.txt")
    Copy-RequiredLicense -Source $TkLicense -Destination (Join-Path $Licenses "TK-LICENSE.txt")

    $PyInstallerLicense = (& $PythonPath -c "from pathlib import Path; import PyInstaller; print(Path(PyInstaller.__file__).resolve().parent / 'COPYING.txt')").Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "Could not locate the PyInstaller license."
    }
    Copy-RequiredLicense -Source $PyInstallerLicense -Destination (Join-Path $Licenses "PYINSTALLER-COPYING.txt")

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

    $Executables = @(Get-ChildItem -LiteralPath $Expanded -Recurse -File -Filter "*.exe" | ForEach-Object {
        [System.IO.Path]::GetRelativePath($Expanded, $_.FullName).Replace("\", "/")
    } | Sort-Object)
    $ExpectedExecutables = @("vendor/wireshark/tshark.exe", "WlanTroubleshooterKO.exe") | Sort-Object
    if (($Executables -join "|") -ne ($ExpectedExecutables -join "|")) {
        throw "Portable stage contains an unexpected executable."
    }

    Remove-Item -LiteralPath $Archive -Force
    Compress-Archive -Path (Join-Path $Expanded "*") -DestinationPath $Archive -CompressionLevel Optimal
    $Hash = Get-LowerSha256 -Path $Archive
    $ArchiveName = Split-Path -Leaf $Archive
    "$Hash  $ArchiveName" | Set-Content -LiteralPath $Checksum -Encoding ascii

    $Package.archive_sha256 = $Hash
    if ($Package.PSObject.Properties.Name -contains "archive_size_bytes") {
        $Package.archive_size_bytes = (Get-Item -LiteralPath $Archive).Length
    }
    else {
        $Package | Add-Member -NotePropertyName archive_size_bytes -NotePropertyValue (Get-Item -LiteralPath $Archive).Length
    }
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
