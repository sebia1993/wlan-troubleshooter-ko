param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$ArchiveName = 'WlanTroubleshooterKO-v0.13.0-alpha.1-win64-portable.zip'
$ExpectedHash = 'c700bfbf4c23dc7118948ea81215cf2df5a4fd57adc04d41f3fba573bc8a605e'
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
gh release download v0.13.0-alpha.1 --repo sebia1993/wlan-troubleshooter-ko --pattern $ArchiveName --dir $OutputDirectory
if ($LASTEXITCODE -ne 0) { throw 'Cannot download the pinned public documentation fixture runtime.' }
$Archive = Join-Path $OutputDirectory $ArchiveName
if ((Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ExpectedHash) {
    throw 'The pinned public Portable archive SHA-256 does not match.'
}
Expand-Archive -LiteralPath $Archive -DestinationPath (Join-Path $OutputDirectory 'portable')
Write-Output 'Verified and extracted the pinned public Portable runtime for synthetic UI capture.'
