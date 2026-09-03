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
$ConfigurationPath = Join-Path $PSScriptRoot "supply-chain.json"
$Configuration = Get-Content -LiteralPath $ConfigurationPath -Raw | ConvertFrom-Json -Depth 32

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

function Get-VerifiedDownload {
    param(
        [Parameter(Mandatory = $true)]$Component,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    if ($Component.url -notlike "https://www.wireshark.org/download/*") {
        throw "Only the pinned official Wireshark download host is allowed."
    }
    Invoke-WebRequest -Uri $Component.url -OutFile $Destination -MaximumRedirection 10
    if (-not (Test-Path -LiteralPath $Destination -PathType Leaf)) {
        throw "Pinned download did not create a regular file."
    }
    return Get-LowerSha256 -Path $Destination
}

function Assert-PinnedHash {
    param(
        [Parameter(Mandatory = $true)][string]$Observed,
        [Parameter(Mandatory = $true)][string]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if ($Expected -eq "DISCOVER") {
        throw "$Label SHA-256 is not pinned. Run discovery first."
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
        throw "Wireshark Authenticode signature is not valid: $($Signature.Status)"
    }
    if ($null -eq $Signature.SignerCertificate -or $Signature.SignerCertificate.Subject -notlike "*$SubjectContains*") {
        throw "Wireshark Authenticode signer does not match the pinned subject."
    }
    return $Signature.SignerCertificate.Subject
}

New-CleanDirectory -Path $OutputDirectory
New-CleanDirectory -Path $WorkRoot
New-Item -ItemType Directory -Path $DownloadRoot | Out-Null

try {
    $MsiPath = Join-Path $DownloadRoot $Configuration.wireshark.msi.filename
    $SourcePath = Join-Path $DownloadRoot $Configuration.wireshark.source.filename
    $MsiHash = Get-VerifiedDownload -Component $Configuration.wireshark.msi -Destination $MsiPath
    $SourceHash = Get-VerifiedDownload -Component $Configuration.wireshark.source -Destination $SourcePath
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

    Assert-PinnedHash -Observed $MsiHash -Expected $Configuration.wireshark.msi.sha256 -Label "Wireshark MSI"
    Assert-PinnedHash -Observed $SourceHash -Expected $Configuration.wireshark.source.sha256 -Label "Wireshark source"

    $PyInstallerVersion = (& $PythonPath -m PyInstaller --version).Trim()
    if ($LASTEXITCODE -ne 0 -or $PyInstallerVersion -ne $Configuration.pyinstaller_version) {
        throw "Pinned PyInstaller version is not installed."
    }

    New-Item -ItemType Directory -Path $ExtractRoot | Out-Null
    $MsiArguments = "/a `"$MsiPath`" /qn TARGETDIR=`"$ExtractRoot`""
    $MsiProcess = Start-Process -FilePath (Join-Path $env:SystemRoot "System32\msiexec.exe") -ArgumentList $MsiArguments -Wait -PassThru
    if ($MsiProcess.ExitCode -ne 0) {
        throw "Wireshark MSI administrative extraction failed with exit code $($MsiProcess.ExitCode)."
    }

    $TSharkCandidates = @(Get-ChildItem -LiteralPath $ExtractRoot -Recurse -File -Filter "tshark.exe")
    if ($TSharkCandidates.Count -ne 1) {
        throw "Exactly one extracted tshark.exe is required. Observed: $($TSharkCandidates.Count)"
    }
    $WiresharkInstallRoot = $TSharkCandidates[0].Directory.FullName
    Assert-WiresharkSignature -Path $TSharkCandidates[0].FullName -SubjectContains $Configuration.wireshark.msi.signer_subject_contains | Out-Null

    New-Item -ItemType Directory -Path $PyInstallerRoot | Out-Null
    $PyInstallerDist = Join-Path $PyInstallerRoot "dist"
    $PyInstallerWork = Join-Path $PyInstallerRoot "work"
    $PyInstallerSpec = Join-Path $PyInstallerRoot "spec"
    $EntryPoint = Join-Path $RepositoryRoot "src\wlan_troubleshooter_ko\__main__.py"
    $Resources = Join-Path $RepositoryRoot "src\wlan_troubleshooter_ko\resources"
    $AddData = "$Resources;wlan_troubleshooter_ko\resources"
    $SourceRoot = Join-Path $RepositoryRoot "src"
    $PyInstallerArguments = @(
        "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onedir",
        "--windowed",
        "--name", "WlanTroubleshooterKO",
        "--distpath", $PyInstallerDist,
        "--workpath", $PyInstallerWork,
        "--specpath", $PyInstallerSpec,
        "--paths", $SourceRoot,
        "--add-data", $AddData,
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
    Copy-Item -LiteralPath (Join-Path $BuiltApplication "*") -Destination $StageRoot -Recurse -Force

    $VendorRoot = Join-Path $StageRoot "vendor\wireshark"
    New-Item -ItemType Directory -Path $VendorRoot -Force | Out-Null
    Get-ChildItem -LiteralPath $WiresharkInstallRoot -Force | Copy-Item -Destination $VendorRoot -Recurse -Force

    Get-ChildItem -LiteralPath $VendorRoot -Recurse -File -Filter "*.exe" |
        Where-Object { $_.Name -ne "tshark.exe" } |
        Remove-Item -Force
    Get-ChildItem -LiteralPath $VendorRoot -Recurse -File -Include "*.pdb", "*.msi", "*.msix" |
        Remove-Item -Force
    Get-ChildItem -LiteralPath $VendorRoot -Recurse -Directory |
        Where-Object { $_.Name -in @("extcap", "Npcap", "npcap") } |
        Sort-Object { $_.FullName.Length } -Descending |
        Remove-Item -Recurse -Force

    $CopyingPath = Join-Path $VendorRoot "COPYING"
    if (-not (Test-Path -LiteralPath $CopyingPath -PathType Leaf)) {
        $CopyingCandidate = Get-ChildItem -LiteralPath $VendorRoot -File -Filter "COPYING*" | Select-Object -First 1
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

    @(
        "README.md",
        "LICENSE",
        "THIRD_PARTY_NOTICES.md",
        "CHANGELOG.md",
        "RELEASE_NOTES.md",
        "IMPLEMENTATION_STATUS.md"
    ) | ForEach-Object {
        Copy-Item -LiteralPath (Join-Path $RepositoryRoot $_) -Destination $StageRoot
    }

    $ApprovalReference = "PROJECT-PINNED-WIRESHARK-" + $Configuration.wireshark.version
    & $PythonPath (Join-Path $PSScriptRoot "generate_tshark_manifest.py") --root $VendorRoot --version $Configuration.wireshark.version --approval-reference $ApprovalReference
    if ($LASTEXITCODE -ne 0) {
        throw "TShark runtime manifest generation failed."
    }

    $BuildInfo = [ordered]@{
        schema_version = 1
        product_version = "0.3.0-alpha.1"
        git_commit = $env:GITHUB_SHA
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

    $OldPythonPath = $env:PYTHONPATH
    $OldPythonHome = $env:PYTHONHOME
    $OldPath = $env:PATH
    try {
        Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
        Remove-Item Env:PYTHONHOME -ErrorAction SilentlyContinue
        $env:PATH = (Join-Path $env:SystemRoot "System32") + ";" + $env:SystemRoot
        $SelfCheckPath = Join-Path $WorkRoot "portable-self-check.json"
        $ApplicationPath = Join-Path $StageRoot "WlanTroubleshooterKO.exe"
        $SelfCheckProcess = Start-Process -FilePath $ApplicationPath -ArgumentList ("--self-check-output=" + $SelfCheckPath) -Wait -PassThru
        if ($SelfCheckProcess.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $SelfCheckPath -PathType Leaf)) {
            throw "Portable executable self-check failed without external Python."
        }
        $SelfCheck = Get-Content -LiteralPath $SelfCheckPath -Raw | ConvertFrom-Json
        if ($SelfCheck.python_external_required -ne "false" -or $SelfCheck.portable_tshark -notlike "무결성 검증됨:*") {
            throw "Portable executable self-check did not confirm the bundled runtimes."
        }
    }
    finally {
        $env:PATH = $OldPath
        if ($null -eq $OldPythonPath) { Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue } else { $env:PYTHONPATH = $OldPythonPath }
        if ($null -eq $OldPythonHome) { Remove-Item Env:PYTHONHOME -ErrorAction SilentlyContinue } else { $env:PYTHONHOME = $OldPythonHome }
    }

    $SmokeRoot = Join-Path $WorkRoot "tshark-smoke"
    New-Item -ItemType Directory -Path $SmokeRoot | Out-Null
    foreach ($Name in @("config", "plugins", "extcap", "data", "temp")) {
        New-Item -ItemType Directory -Path (Join-Path $SmokeRoot $Name) | Out-Null
    }
    $OldEnvironment = @{}
    foreach ($Name in @("WIRESHARK_CONFIG_DIR", "WIRESHARK_PLUGIN_DIR", "WIRESHARK_EXTCAP_DIR", "WIRESHARK_DATA_DIR", "TEMP", "TMP", "TMPDIR")) {
        $OldEnvironment[$Name] = [Environment]::GetEnvironmentVariable($Name, "Process")
    }
    try {
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
        foreach ($Name in $OldEnvironment.Keys) {
            [Environment]::SetEnvironmentVariable($Name, $OldEnvironment[$Name], "Process")
        }
    }

    $ArchiveName = "WlanTroubleshooterKO-v0.3.0-alpha.1-win64-portable.zip"
    $ArchivePath = Join-Path $OutputDirectory $ArchiveName
    Compress-Archive -Path (Join-Path $StageRoot "*") -DestinationPath $ArchivePath -CompressionLevel Optimal
    $ArchiveHash = Get-LowerSha256 -Path $ArchivePath
    $ArchiveChecksumPath = $ArchivePath + ".sha256"
    "$ArchiveHash  $ArchiveName" | Set-Content -LiteralPath $ArchiveChecksumPath -Encoding ascii

    $SourceChecksumPath = Join-Path $OutputDirectory ($Configuration.wireshark.source.filename + ".sha256")
    "$SourceHash  $($Configuration.wireshark.source.filename)" | Set-Content -LiteralPath $SourceChecksumPath -Encoding ascii
    Copy-Item -LiteralPath $SourcePath -Destination (Join-Path $OutputDirectory $Configuration.wireshark.source.filename)

    $PackageResult = [ordered]@{
        schema_version = 1
        archive = $ArchivePath
        archive_sha256 = $ArchiveHash
        archive_checksum = $ArchiveChecksumPath
        wireshark_source = Join-Path $OutputDirectory $Configuration.wireshark.source.filename
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
