[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{40}$')][string]$CertificateThumbprint,
    [uri]$TimestampServer = 'http://timestamp.digicert.com'
)
$ErrorActionPreference = 'Stop'
$exe = (Resolve-Path -LiteralPath $Path).Path
if ([IO.Path]::GetExtension($exe) -ne '.exe') { throw 'Signing target must be an EXE.' }
$certificate = @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My') |
    ForEach-Object { Get-ChildItem -LiteralPath $_ -CodeSigningCert } |
    Where-Object { $_.Thumbprint -eq $CertificateThumbprint -and $_.HasPrivateKey } |
    Select-Object -First 1
if (-not $certificate) { throw 'Code-signing certificate with private key was not found. Install a publicly trusted publisher certificate first.' }
if ($certificate.NotAfter -le (Get-Date) -or $certificate.NotBefore -gt (Get-Date)) { throw 'Code-signing certificate is outside its validity period.' }
if ($certificate.Subject -eq $certificate.Issuer) { throw 'Self-signed certificates do not establish a trusted publisher for public downloads.' }
$chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
try {
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
    if (-not $chain.Build($certificate)) { throw 'Publisher certificate chain validation failed.' }
} finally { $chain.Dispose() }
$signature = Set-AuthenticodeSignature -LiteralPath $exe -Certificate $certificate -HashAlgorithm SHA256 -TimestampServer $TimestampServer.AbsoluteUri
if ($signature.Status -ne 'Valid' -or -not $signature.TimeStamperCertificate) { throw 'Authenticode signing or timestamp verification failed. Do not publish this file.' }
$verified = Get-AuthenticodeSignature -LiteralPath $exe
if ($verified.Status -ne 'Valid' -or $verified.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) { throw 'Final signature verification failed. Do not publish this file.' }
Write-Host ('Verified publisher: ' + $verified.SignerCertificate.Subject)
