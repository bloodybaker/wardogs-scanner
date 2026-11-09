[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ArtifactDirectory)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$output = (Resolve-Path -LiteralPath $ArtifactDirectory).Path
$exe = Join-Path $output 'WardogsScanner.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw 'Release EXE missing.' }
foreach ($file in @('LICENSE', 'PRIVACY.md', 'CODE_SIGNING.md', 'THIRD_PARTY_NOTICES.md')) {
    Copy-Item -LiteralPath (Join-Path $root $file) -Destination $output -Force
}
Copy-Item -LiteralPath (Join-Path $root 'licenses') -Destination $output -Recurse -Force
$hash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath (Join-Path $output 'WardogsScanner.sha256.txt') -Value "$hash  WardogsScanner.exe" -Encoding ascii
Write-Host "Release package and notices ready: $output"
