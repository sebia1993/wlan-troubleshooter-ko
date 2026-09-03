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
        Write-Host "Portable inventory state: result file was not created"
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
        Write-Host "Portable inventory state: $State"
        Write-Host "Portable inventory message: $Message"
    }
    catch {
        Write-Host "Portable inventory state: unreadable-result"
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

$WorkRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("wlan-inventory-test-" + [guid]::NewGuid().ToString("N"))
$Expanded = Join-Path $WorkRoot "portable"
$Capture = Join-Path $WorkRoot "private-integration-capture.pcap"
$Output = Join-Path $WorkRoot "analysis-result.json"
New-Item -ItemType Directory -Path $Expanded -Force | Out-Null
try {
    Expand-Archive -LiteralPath $Archive -DestinationPath $Expanded
    $BuildInfo = Get-Content -LiteralPath (Join-Path $Expanded "BUILD_INFO.json") -Raw | ConvertFrom-Json -Depth 32
    if ($BuildInfo.product_version -ne $ExpectedProductVersion -or $BuildInfo.protocol_inventory_runtime -ne "enabled") {
        throw "Portable BUILD_INFO does not describe the enabled protocol inventory runtime."
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
            throw "Portable protocol inventory process failed with exit code $($Process.ExitCode)."
        }
    }
    finally {
        $env:PATH = $OldPath
        Restore-EnvironmentValue -Name "PYTHONPATH" -Value $OldPythonPath
        Restore-EnvironmentValue -Name "PYTHONHOME" -Value $OldPythonHome
    }

    if (-not (Test-Path -LiteralPath $Output -PathType Leaf)) {
        throw "Portable protocol inventory did not create its result."
    }
    $Raw = Get-Content -LiteralPath $Output -Raw
    $Result = $Raw | ConvertFrom-Json -Depth 64
    if ($Result.protocol_inventory_state -ne "completed") {
        Write-SafeFailureSummary -ResultPath $Output
        throw "Portable protocol inventory did not complete."
    }
    if ($Result.protocol_inventory.inventory.frames_observed -ne 2) {
        throw "Portable protocol inventory observed an unexpected frame count."
    }
    if ($Result.protocol_inventory.inventory.complete -ne $true) {
        throw "Portable protocol inventory was not marked complete."
    }
    $Groups = @($Result.protocol_inventory.inventory.observations | ForEach-Object { $_.group_id })
    if ($Groups -notcontains "arp" -or $Groups -notcontains "dns") {
        throw "Portable protocol inventory did not observe the synthetic ARP and DNS frames."
    }
    if (
        $Raw.Contains($Capture, [System.StringComparison]::OrdinalIgnoreCase) -or
        $Raw.Contains((Split-Path -Leaf $Capture), [System.StringComparison]::OrdinalIgnoreCase) -or
        $Raw.Contains("192.0.2.1", [System.StringComparison]::OrdinalIgnoreCase)
    ) {
        throw "Portable analysis result exposed a capture path, name, or packet identifier."
    }

    $AfterFiles = @(Get-ChildItem -LiteralPath $Expanded -Recurse -File | ForEach-Object {
        [System.IO.Path]::GetRelativePath($Expanded, $_.FullName).Replace("\", "/")
    } | Sort-Object)
    if (($BeforeFiles -join "|") -ne ($AfterFiles -join "|")) {
        throw "Portable analysis modified its distribution directory."
    }
    Write-Host "Portable protocol inventory integration test passed."
}
finally {
    Remove-Item -LiteralPath $WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
}
