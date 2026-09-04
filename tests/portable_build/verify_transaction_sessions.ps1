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

function Write-SafeAnalysisFailure {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$Output
    )

    if (-not (Test-Path -LiteralPath $Output -PathType Leaf)) {
        Write-Host "$Label analysis did not create a result file."
        return
    }
    try {
        $Failure = Get-Content -LiteralPath $Output -Raw | ConvertFrom-Json -Depth 96
        $State = [string]$Failure.protocol_inventory_state
        $Message = [string]$Failure.protocol_inventory_message
        if ($State -notin @("completed", "unavailable", "failed")) {
            $State = "invalid-result"
        }
        if ($Message.Length -gt 500) {
            $Message = $Message.Substring(0, 500)
        }
        Write-Host "$Label analysis state: $State"
        Write-Host "$Label analysis message: $Message"
    }
    catch {
        Write-Host "$Label analysis result could not be parsed safely."
    }
}

function Invoke-PortableAnalysis {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
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
        Write-SafeAnalysisFailure -Label $Label -Output $Output
        throw "Portable transaction-session analysis failed: $Label"
    }
    $Raw = Get-Content -LiteralPath $Output -Raw
    $Result = $Raw | ConvertFrom-Json -Depth 96
    if ($Result.schema_version -ne 2 -or $Result.protocol_inventory_state -ne "completed") {
        Write-SafeAnalysisFailure -Label $Label -Output $Output
        throw "Portable transaction-session analysis did not complete with schema version 2: $Label"
    }
    return [pscustomobject]@{ Raw = $Raw; Result = $Result }
}

function Assert-Attempt {
    param(
        [Parameter(Mandatory = $true)]$Sessions,
        [Parameter(Mandatory = $true)][string]$Protocol,
        [Parameter(Mandatory = $true)][string]$State,
        [Parameter(Mandatory = $true)][string[]]$RequiredEvents
    )

    $Matches = @($Sessions.attempts | Where-Object {
        $_.protocol -eq $Protocol -and $_.state -eq $State
    })
    foreach ($Candidate in $Matches) {
        $Observed = @($Candidate.observed_event_types)
        $CompleteMatch = $true
        foreach ($EventType in $RequiredEvents) {
            if ($Observed -notcontains $EventType) {
                $CompleteMatch = $false
                break
            }
        }
        if ($CompleteMatch) {
            if (
                $Candidate.root_cause_confirmed -ne $false -or
                $Candidate.device_session_confirmed -ne $false -or
                @($Candidate.evidence_frames).Count -lt 1 -or
                [string]::IsNullOrWhiteSpace([string]$Candidate.display_filter)
            ) {
                throw "Transaction attempt violated its conservative evidence boundary."
            }
            return
        }
    }
    throw "Expected transaction attempt was not observed: $Protocol / $State"
}

function Assert-SafeOutput {
    param(
        [Parameter(Mandatory = $true)][string]$Raw,
        [Parameter(Mandatory = $true)][string[]]$Forbidden
    )

    foreach ($Value in $Forbidden) {
        if ($Raw.Contains($Value, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Transaction-session result exposed a forbidden identifier."
        }
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

$WorkRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("wlan-transaction-test-" + [guid]::NewGuid().ToString("N"))
$Expanded = Join-Path $WorkRoot "portable"
$EthernetCapture = Join-Path $WorkRoot "private-transaction-ethernet.pcap"
$EthernetOutput = Join-Path $WorkRoot "ethernet-transactions.json"
$EapCapture = Join-Path $WorkRoot "private-transaction-eap.pcap"
$EapOutput = Join-Path $WorkRoot "eap-transactions.json"
New-Item -ItemType Directory -Path $Expanded -Force | Out-Null
try {
    Expand-Archive -LiteralPath $Archive -DestinationPath $Expanded
    $BuildInfo = Get-Content -LiteralPath (Join-Path $Expanded "BUILD_INFO.json") -Raw | ConvertFrom-Json -Depth 32
    if (
        $BuildInfo.protocol_inventory_runtime -ne "enabled" -or
        $BuildInfo.event_timeline_runtime -ne "enabled" -or
        $BuildInfo.transaction_session_runtime -ne "enabled"
    ) {
        throw "Portable BUILD_INFO does not enable the transaction-session runtime."
    }

    & $PythonPath (Join-Path $PSScriptRoot "generate_event_fixture.py") --output $EthernetCapture
    if ($LASTEXITCODE -ne 0) { throw "Ethernet transaction fixture generation failed." }
    & $PythonPath (Join-Path $PSScriptRoot "generate_eap_fixture.py") --output $EapCapture
    if ($LASTEXITCODE -ne 0) { throw "EAP transaction fixture generation failed." }

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
        $Ethernet = Invoke-PortableAnalysis -Label "Ethernet" -Application $Application -WorkingDirectory $Expanded -Capture $EthernetCapture -Output $EthernetOutput
        $Eap = Invoke-PortableAnalysis -Label "PPP-EAP" -Application $Application -WorkingDirectory $Expanded -Capture $EapCapture -Output $EapOutput
    }
    finally {
        $env:PATH = $OldPath
        Restore-EnvironmentValue -Name "PYTHONPATH" -Value $OldPythonPath
        Restore-EnvironmentValue -Name "PYTHONHOME" -Value $OldPythonHome
    }

    $EthernetSessions = $Ethernet.Result.protocol_inventory.transaction_sessions
    if ($null -eq $EthernetSessions -or $EthernetSessions.schema_version -ne 1 -or $EthernetSessions.complete -ne $true) {
        throw "Ethernet transaction-session report is missing or incomplete."
    }
    Assert-Attempt -Sessions $EthernetSessions -Protocol "radius" -State "complete" -RequiredEvents @("radius_access_request", "radius_access_accept")
    Assert-Attempt -Sessions $EthernetSessions -Protocol "dhcp" -State "complete" -RequiredEvents @("dhcp_discover", "dhcp_offer", "dhcp_request", "dhcp_ack")
    Assert-Attempt -Sessions $EthernetSessions -Protocol "dns" -State "complete" -RequiredEvents @("dns_query", "dns_response_success")
    Assert-Attempt -Sessions $EthernetSessions -Protocol "tcp" -State "success-observed" -RequiredEvents @("tcp_syn", "tcp_syn_ack")
    Assert-Attempt -Sessions $EthernetSessions -Protocol "tcp" -State "failure-observed" -RequiredEvents @("tcp_reset")

    $EapSessions = $Eap.Result.protocol_inventory.transaction_sessions
    if ($null -eq $EapSessions -or $EapSessions.schema_version -ne 1 -or $EapSessions.complete -ne $true) {
        throw "EAP transaction-session report is missing or incomplete."
    }
    Assert-Attempt -Sessions $EapSessions -Protocol "eap" -State "complete" -RequiredEvents @("eap_request", "eap_response", "eap_success")

    Assert-SafeOutput -Raw $Ethernet.Raw -Forbidden @(
        $EthernetCapture,
        (Split-Path -Leaf $EthernetCapture),
        "192.0.2.10",
        "198.51.100.10",
        "02:00:00:00:00:10",
        "0x01020304",
        "0x1234",
        "example.test",
        "1700000000"
    )
    Assert-SafeOutput -Raw $Eap.Raw -Forbidden @(
        $EapCapture,
        (Split-Path -Leaf $EapCapture),
        "synthetic-user",
        "1700000200"
    )

    $AfterFiles = @(Get-ChildItem -LiteralPath $Expanded -Recurse -File | ForEach-Object {
        [System.IO.Path]::GetRelativePath($Expanded, $_.FullName).Replace("\", "/")
    } | Sort-Object)
    if (($BeforeFiles -join "|") -ne ($AfterFiles -join "|")) {
        throw "Portable transaction-session analysis modified its distribution directory."
    }
    Write-Host "Portable EAP, RADIUS, DHCP, DNS, and TCP transaction-session integration tests passed."
}
finally {
    Remove-Item -LiteralPath $WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
}
