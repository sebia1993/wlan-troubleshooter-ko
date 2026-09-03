[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet("Discover", "Build")]
    [string]$Mode = "Build",

    [Parameter()]
    [string]$PythonPath = "python",

    [Parameter()]
    [string]$OutputDirectory = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Configuration = Get-Content -LiteralPath (Join-Path $PSScriptRoot "supply-chain.json") -Raw | ConvertFrom-Json -Depth 32
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $env:RUNNER_TEMP "wlan-troubleshooter-portable"
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$WorkRoot = Join-Path $env:RUNNER_TEMP ("wlan-portable-" + [guid]::NewGuid().ToString("N"))
$DownloadRoot = Join-Path $WorkRoot "downloads"
$ExtractRoot = Join-Path $WorkRoot "wireshark-extract"
$PyInstallerRoot = Join-Path $WorkRoot "pyinstaller"
$StageRoot = Join-Path $WorkRoot "stage"

function New-CleanDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $Path | Out-Null
}

function Get-LowerSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-OfficialFile {
    param(
        [Parameter(Mandatory = $true)]$Component,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    if ($Component.url -notlike "https://www.wireshark.org/download/*") {
        throw "Only the pinned official Wireshark host is allowed."
    }
    Invoke-WebRequest -Uri $Component.url -OutFile $Destination -MaximumRedirection 10
    if (-not (Test-Path -LiteralPath $Destination -PathType Leaf)) {
        throw "Official download did not create a regular file."
    }
    return Get-LowerSha256 -Path $Destination
}

function Assert-Hash {
    param(
        [Parameter(Mandatory = $true)][string]$Observed,
        [Parameter(Mandatory = $true)][string]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if ($Expected -eq "DISCOVER") {
        throw "$Label SHA-256 is not pinned."
    }
    if ($Observed -ne $Expected.ToLowerInvariant()) {
        throw "$Label SHA-256 mismatch."
    }
}

function Assert-WiresharkSignature {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$SubjectContains
    )
    $Signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($Signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "Wireshark Authenticode signature is invalid: $($Signature.Status)"
    }
    if ($null -eq $Signature.SignerCertificate -or $Signature.SignerCertificate.Subject -notlike "*$SubjectContains*") {
        throw "Wireshark Authenticode signer does not match the pinned subject."
    }
    return $Signature.SignerCertificate.Subject
}

function Remove-UnsafeVendorContent {
    param([Parameter(Mandatory = $true)][string]$VendorRoot)

    Get-ChildItem -LiteralPath $VendorRoot -Recurse -File -Filter "*.exe" |
        Where-Object { $_.Name -ne "tshark.exe" } |
        Remove-Item -Force
    Get-ChildItem -LiteralPath $VendorRoot -Recurse -File |
        Where-Object { $_.Extension -in @(".pdb", ".msi", ".msix", ".chm") } |
        Remove-Item -Force
    Get-ChildItem -LiteralPath $VendorRoot -Recurse -Directory |
        Where-Object { $_.Name -in @("extcap", "Npcap", "npcap", "plugins") } |
        Sort-Object { $_.FullName.Length } -Descending |
        Remove-Item -Recurse -Force

    Get-ChildItem -LiteralPath $VendorRoot -Recurse -File | ForEach-Object {
        $Relative = [System.IO.Path]::GetRelativePath($VendorRoot, $_.FullName).Replace("\", "/")
        if ($Relative -notmatch "^[A-Za-z0-9._/-]+$") {
            Remove-Item -LiteralPath $_.FullName -Force
        }
    }
    Get-ChildItem -LiteralPath $VendorRoot -Recurse -Directory |
        Sort-Object { $_.FullName.Length } -Descending |
        ForEach-Object {
            $Relative = [System.IO.Path]::GetRelativePath($VendorRoot, $_.FullName).Replace("\", "/")
            if ($Relative -notmatch "^[A-Za-z0-9._/-]+$") {
                Remove-Item -LiteralPath $_.FullName -Recurse -Force
            }
        }
}

function Restore-EnvironmentValue {
    param([Parameter(Mandatory = $true)][string]$Name, [AllowNull()][string]$Value)
    if ($null -eq $Value) {
        Remove-Item ("Env:" + $Name) -ErrorAction SilentlyContinue
    }
    else {
        [Environment]::SetEnvironmentVariable($Name, $Value, "Process")
    }
}

New-CleanDirectory -Path $OutputDirectory
New-CleanDirectory -Path $WorkRoot
New-Item -ItemType Directory -Path $DownloadRoot | Out-Null

try {
    $MsiPath = Join-Path $DownloadRoot $Configuration.wireshark.msi.filename
    $SourcePath = Join-Path $DownloadRoot $Configuration.wireshark.source.filename
    $MsiHash = Get-OfficialFile -Component $Configuration.wireshark.msi -Destination $MsiPath
    $SourceHash = Get-OfficialFile -Component $Configuration.wireshark.source -Destination $SourcePath
    $MsiSigner = Assert-WiresharkSignature -Path $MsiPath -SubjectContains $Configuration.wireshark.msi.signer_subject_contains

    $Observed = [ordered]@{
        schema_version = 1
        wireshark_version = $Configuration.wireshark.version
        msi_filename = $Configuration.wireshark.msi.filename
        msi_sha256 = $MsiHash
        msi_signer_subject = $MsiSigner
        source_filename = $Configuration.wireshark.source.filename
        source_sha256 = $SourceHash
    }
    $ObservedPath = Join-Path $OutputDirectory "supply-chain-observed.json"
    $Observed | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ObservedPath -Encoding utf8
    Write-Host "Observed Wireshark MSI SHA-256: $MsiHash"
    Write-Host "Observed Wireshark source SHA-256: $SourceHash"
    Write-Host "Observed Wireshark signer: $MsiSigner"
    if ($Mode -eq "Discover") {
        return
    }

    Assert-Hash -Observed $MsiHash -Expected $Configuration.wireshark.msi.sha256 -Label "Wireshark MSI"
    Assert-Hash -Observed $SourceHash -Expected $Configuration.wireshark.source.sha256 -Label "Wireshark source"

    $PyInstallerVersion = (& $PythonPath -m PyInstaller --version).Trim()
    if ($LASTEXITCODE -ne 0 -or $PyInstallerVersion -ne $Configuration.pyinstaller_version) {
        throw "Pinned PyInstaller version is not installed."
    }

    New-Item -ItemType Directory -Path $ExtractRoot | Out-Null
    $MsiArguments = "/a `"$MsiPath`" /qn TARGETDIR=`"$ExtractRoot`""
    $MsiProcess = Start-Process -FilePath (Join-Path $env:SystemRoot "System32\msiexec.exe") -ArgumentList $MsiArguments -Wait -PassThru
    if ($MsiProcess.ExitCode -ne 0) {
        throw "Wireshark MSI extraction failed with exit code $($MsiProcess.ExitCode)."
    }
    $TSharkCandidates = @(Get-ChildItem -LiteralPath $ExtractRoot -Recurse -File -Filter "tshark.exe")
    if ($TSharkCandidates.Count -ne 1) {
        throw "Exactly one extracted tshark.exe is required. Observed: $($TSharkCandidates.Count)"
    }
    $WiresharkInstallRoot = $TSharkCandidates[0].Directory.FullName
    Assert-WiresharkSignature -Path $TSharkCandidates[0].FullName -SubjectContains $Configuration.wireshark.msi.signer_subject_contains | Out-Null

    New-Item -ItemType Directory -Path $PyInstallerRoot | Out-Null
    $PyInstallerDist = Join-Path $PyInstallerRoot "dist"
    $EntryPoint = Join-Path $RepositoryRoot "src\wlan_troubleshooter_ko\__main__.py"
    $Resources = Join-Path $RepositoryRoot "src\wlan_troubleshooter_ko\resources"
    $PyInstallerArguments = @(
        "-m", "PyInstaller",
        "--noconfirm", "--clean", "--onedir", "--windowed",
        "--name", "WlanTroubleshooterKO",
        "--distpath", $PyInstallerDist,
        "--workpath", (Join-Path $PyInstallerRoot "work"),
        "--specpath", (Join-Path $PyInstallerRoot "spec"),
        "--paths", (Join-Path $RepositoryRoot "src"),
        "--add-data", ($Resources + ";wlan_troubleshooter_ko\resources"),
        $EntryPoint
    )
    & $PythonPath @PyInstallerArguments
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller build failed."
    }
    $BuiltApplication = Join-Path $PyInstallerDist "WlanTroubleshooterKO"
    if (-not (Test-Path -LiteralPath (Join-Path $BuiltApplication "WlanTroubleshooterKO.exe") -PathType Leaf)) {
        throw "PyInstaller did not create the expected executable."
    }

    New-Item -ItemType Directory -Path $StageRoot | Out-Null
    Get-ChildItem -LiteralPath $BuiltApplication -Force | Copy-Item -Destination $StageRoot -Recurse -Force

    $VendorRoot = Join-Path $StageRoot "vendor\wireshark"
    New-Item -ItemType Directory -Path $VendorRoot -Force | Out-Null
    Get-ChildItem -LiteralPath $WiresharkInstallRoot -Force | Copy-Item -Destination $VendorRoot -Recurse -Force
    Remove-UnsafeVendorContent -VendorRoot $VendorRoot

    $CopyingPath = Join-Path $VendorRoot "COPYING"
    if (-not (Test-Path -LiteralPath $CopyingPath -PathType Leaf)) {
        $CopyingCandidate = Get-ChildItem -LiteralPath $VendorRoot -File | Where-Object { $_.Name -like "COPYING*" } | Select-Object -First 1
        if ($null -ne $CopyingCandidate) {
            Copy-Item -LiteralPath $CopyingCandidate.FullName -Destination $CopyingPath
        }
        else {
            $LicenseExtract = Join-Path $WorkRoot "source-license"
            New-Item -ItemType Directory -Path $LicenseExtract | Out-Null
            & (Join-Path $env:SystemRoot "System32\tar.exe") -xf $SourcePath -C $LicenseExtract ("wireshark-" + $Configuration.wireshark.version + "/COPYING")
            if ($LASTEXITCODE -ne 0) {
                throw "Could not extract Wireshark COPYING from the pinned source archive."
            }
            Copy-Item -LiteralPath (Join-Path $LicenseExtract ("wireshark-" + $Configuration.wireshark.version + "\COPYING")) -Destination $CopyingPath
        }
    }

    foreach ($Name in @("README.md", "LICENSE", "THIRD_PARTY_NOTICES.md", "CHANGELOG.md", "RELEASE_NOTES.md", "IMPLEMENTATION_STATUS.md")) {
        Copy-Item -LiteralPath (Join-Path $RepositoryRoot $Name) -Destination $StageRoot
    }

    $ApprovalReference = "PROJECT-PINNED-WIRESHARK-" + $Configuration.wireshark.version
    & $PythonPath (Join-Path $PSScriptRoot "generate_tshark_manifest.py") --root $VendorRoot --version $Configuration.wireshark.version --approval-reference $ApprovalReference
    if ($LASTEXITCODE -ne 0) {
        throw "TShark runtime manifest generation failed."
    }

    $GitCommit = [Environment]::GetEnvironmentVariable("GITHUB_SHA", "Process")
    if ([string]::IsNullOrWhiteSpace($GitCommit)) { $GitCommit = "local" }
    $BuildInfo = [ordered]@{
        schema_version = 1
        product_version = "0.3.0-alpha.1"
        git_commit = $GitCommit
        python_build_version = (& $PythonPath --version 2>&1).ToString().Trim()
        pyinstaller_version = $PyInstallerVersion
        wireshark_version = $Configuration.wireshark.version
        wireshark_msi_sha256 = $MsiHash
        wireshark_source_sha256 = $SourceHash
        runtime_network_features = "none"
        external_python_required = $false
        external_wireshark_required = $false
    }
    $BuildInfo | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $StageRoot "BUILD_INFO.json") -Encoding utf8

    $OldPath = $env:PATH
    $OldPythonPath = [Environment]::GetEnvironmentVariable("PYTHONPATH", "Process")
    $OldPythonHome = [Environment]::GetEnvironmentVariable("PYTHONHOME", "Process")
    try {
        Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
        Remove-Item Env:PYTHONHOME -ErrorAction SilentlyContinue
        $env:PATH = (Join-Path $env:SystemRoot "System32") + ";" + $env:SystemRoot
        $SelfCheckPath = Join-Path $WorkRoot "portable-self-check.json"
        $SelfCheckProcess = Start-Process -FilePath (Join-Path $StageRoot "WlanTroubleshooterKO.exe") -ArgumentList ("--self-check-output=" + $SelfCheckPath) -Wait -PassThru
        if ($SelfCheckProcess.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $SelfCheckPath -PathType Leaf)) {
            throw "Portable executable self-check failed without external Python."
        }
        $SelfCheck = Get-Content -LiteralPath $SelfCheckPath -Raw | ConvertFrom-Json
        if ($SelfCheck.python_external_required -ne "false" -or $SelfCheck.tshark_external_required -ne "false") {
            throw "Portable executable did not confirm bundled runtimes."
        }
        if ($SelfCheck.portable_tshark -notlike "무결성 검증됨:*") {
            throw "Portable executable did not verify the TShark manifest."
        }
    }
    finally {
        $env:PATH = $OldPath
        Restore-EnvironmentValue -Name "PYTHONPATH" -Value $OldPythonPath
        Restore-EnvironmentValue -Name "PYTHONHOME" -Value $OldPythonHome
    }

    $SmokeRoot = Join-Path $WorkRoot "tshark-smoke"
    New-Item -ItemType Directory -Path $SmokeRoot | Out-Null
    $Saved = @{}
    foreach ($Name in @("WIRESHARK_CONFIG_DIR", "WIRESHARK_PLUGIN_DIR", "WIRESHARK_EXTCAP_DIR", "WIRESHARK_DATA_DIR", "TEMP", "TMP", "TMPDIR")) {
        $Saved[$Name] = [Environment]::GetEnvironmentVariable($Name, "Process")
    }
    try {
        foreach ($Name in @("config", "plugins", "extcap", "data", "temp")) {
            New-Item -ItemType Directory -Path (Join-Path $SmokeRoot $Name) | Out-Null
        }
        $env:WIRESHARK_CONFIG_DIR = Join-Path $SmokeRoot "config"
        $env:WIRESHARK_PLUGIN_DIR = Join-Path $SmokeRoot "plugins"
        $env:WIRESHARK_EXTCAP_DIR = Join-Path $SmokeRoot "extcap"
        $env:WIRESHARK_DATA_DIR = Join-Path $SmokeRoot "data"
        $env:TEMP = Join-Path $SmokeRoot "temp"
        $env:TMP = $env:TEMP
        $env:TMPDIR = $env:TEMP
        $BundledTShark = Join-Path $VendorRoot "tshark.exe"
        & $BundledTShark -n -v *> $null
        if ($LASTEXITCODE -ne 0) { throw "Bundled TShark version smoke test failed." }
        & $BundledTShark -n -G fields *> $null
        if ($LASTEXITCODE -ne 0) { throw "Bundled TShark field catalog smoke test failed." }
    }
    finally {
        foreach ($Name in $Saved.Keys) { Restore-EnvironmentValue -Name $Name -Value $Saved[$Name] }
    }

    $ArchiveName = "WlanTroubleshooterKO-v0.3.0-alpha.1-win64-portable.zip"
    $ArchivePath = Join-Path $OutputDirectory $ArchiveName
    Compress-Archive -Path (Join-Path $StageRoot "*") -DestinationPath $ArchivePath -CompressionLevel Optimal
    $ArchiveHash = Get-LowerSha256 -Path $ArchivePath
    $ArchiveChecksumPath = $ArchivePath + ".sha256"
    "$ArchiveHash  $ArchiveName" | Set-Content -LiteralPath $ArchiveChecksumPath -Encoding ascii

    $SourceOutput = Join-Path $OutputDirectory $Configuration.wireshark.source.filename
    Copy-Item -LiteralPath $SourcePath -Destination $SourceOutput
    $SourceChecksumPath = $SourceOutput + ".sha256"
    "$SourceHash  $($Configuration.wireshark.source.filename)" | Set-Content -LiteralPath $SourceChecksumPath -Encoding ascii

    $PackageResult = [ordered]@{
        schema_version = 1
        archive = $ArchivePath
        archive_sha256 = $ArchiveHash
        archive_checksum = $ArchiveChecksumPath
        wireshark_source = $SourceOutput
        wireshark_source_checksum = $SourceChecksumPath
        observed_supply_chain = $ObservedPath
    }
    $PackageResult | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputDirectory "package-output.json") -Encoding utf8
    Write-Host "Portable archive: $ArchivePath"
    Write-Host "Portable SHA-256: $ArchiveHash"
}
finally {
    Remove-Item -LiteralPath $WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
}
