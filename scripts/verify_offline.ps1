[CmdletBinding()]
param(
    [Parameter()]
    [string]$PythonPath = "python"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$OriginalPythonPath = $env:PYTHONPATH

function Invoke-CheckedPython {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    & $PythonPath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Python command failed with exit code $LASTEXITCODE"
    }
}

Push-Location $RepositoryRoot
try {
    $env:PYTHONPATH = (Join-Path $RepositoryRoot "src")
    Invoke-CheckedPython -Arguments @("-m", "compileall", "-q", "src", "tests", "scripts")
    Invoke-CheckedPython -Arguments @("scripts/audit_source.py", "--root", ".")
    Invoke-CheckedPython -Arguments @("scripts/audit_repository.py", ".")
    Invoke-CheckedPython -Arguments @(
        "-m",
        "unittest",
        "discover",
        "-s",
        "tests",
        "-v"
    )
    Invoke-CheckedPython -Arguments @("-m", "wlan_troubleshooter_ko", "--self-check")
}
finally {
    if ($null -eq $OriginalPythonPath) {
        Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
    }
    else {
        $env:PYTHONPATH = $OriginalPythonPath
    }
    Pop-Location
}
