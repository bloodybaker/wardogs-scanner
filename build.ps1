param(
    [switch]$FrameworkDependent,
    [string]$CertificateThumbprint = '',
    [switch]$RequireSignature,
    [string]$OutputDirectory = '',
    [switch]$LockedRestore
)
$ErrorActionPreference = 'Stop'
if ($RequireSignature -and -not $CertificateThumbprint) {
    throw 'Release requires a trusted code-signing certificate. Provide -CertificateThumbprint.'
}
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$project = Join-Path $root 'src\Wardogs.Scanner.App\Wardogs.Scanner.App.csproj'
$output = if ($OutputDirectory) { [IO.Path]::GetFullPath($OutputDirectory) } else { Join-Path $root 'dist' }
$arguments = @('publish', $project, '-c', 'Release', '-r', 'win-x64', '-o', $output, '-p:PublishSingleFile=true')
if ($LockedRestore) {
    if ($FrameworkDependent) { throw 'LockedRestore supports the self-contained release configuration only.' }
    $arguments += @('-p:RestoreLockedMode=true', '-p:NuGetLockFilePath=packages.publish.lock.json')
}
if ($FrameworkDependent) {
    $arguments += '--no-self-contained'
} else {
    $arguments += @('--self-contained', 'true', '-p:IncludeNativeLibrariesForSelfExtract=true')
}
dotnet @arguments
if ($LASTEXITCODE -ne 0) { throw 'Scanner publish failed.' }
$exe = Join-Path $output 'WardogsScanner.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw 'WardogsScanner.exe was not created.' }
if ($CertificateThumbprint) {
    & (Join-Path $root 'sign.ps1') -Path $exe -CertificateThumbprint $CertificateThumbprint
}
$signature = Get-AuthenticodeSignature -LiteralPath $exe
if ($RequireSignature -and ($signature.Status -ne 'Valid' -or -not $signature.TimeStamperCertificate)) {
    throw 'Release signature is invalid or has no timestamp. Do not publish.'
}
if ($signature.Status -ne 'Valid') {
    Write-Warning 'Unsigned development build: Windows may show Unknown publisher / SmartScreen warnings. Use -CertificateThumbprint and -RequireSignature for a signed release.'
}
# Hash only the final signed bytes; Authenticode changes the file hash.
$hash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath (Join-Path $output 'WardogsScanner.sha256.txt') -Value ($hash + '  WardogsScanner.exe') -Encoding ascii
Write-Host "Scanner: $exe"
Write-Host "SHA-256: $hash"
