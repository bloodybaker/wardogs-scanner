[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][string]$ExpectedVersion,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{40}$')][string]$ExpectedSignerThumbprint
)
$ErrorActionPreference = 'Stop'
$exe = (Resolve-Path -LiteralPath $Path).Path
$signature = Get-AuthenticodeSignature -LiteralPath $exe
if ($signature.Status -ne 'Valid' -or -not $signature.TimeStamperCertificate) {
    throw 'Signature is not trusted or timestamp is missing. Do not publish.'
}
if ($signature.SignerCertificate.Thumbprint -ne $ExpectedSignerThumbprint) {
    throw 'Unexpected signing certificate. Do not publish.'
}
$info = [Diagnostics.FileVersionInfo]::GetVersionInfo($exe)
if ($info.ProductName -ne 'WARDOGS Scanner' -or $info.ProductVersion -ne $ExpectedVersion) {
    throw 'Signed artifact metadata mismatch. Do not publish.'
}
$hash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath (Join-Path (Split-Path -Parent $exe) 'WardogsScanner.sha256.txt') -Encoding ascii -Value "$hash  WardogsScanner.exe"
Write-Host "Verified signed artifact: $hash"
