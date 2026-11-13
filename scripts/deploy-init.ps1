<#
.SYNOPSIS
  Generates the local deployment secrets for the hardened stack (Phase 12B): the database password and a self-signed
  TLS certificate for localhost. Output goes to .local-data\deploy\ (git-ignored). Secret values are never printed.
  Existing files are NOT overwritten unless -Force is given.
#>
param([switch]$Force)

. "$PSScriptRoot\deploy-common.ps1"
Assert-Project

# The target folder must be ignored by git, otherwise stop.
& git -C $script:RepoRoot check-ignore -q -- '.local-data/deploy/secrets/db_password.txt'
if ($LASTEXITCODE -ne 0) {
    throw '.local-data/deploy/ is not git-ignored; refusing to write secrets there.'
}

$secretsDir = Join-Path $script:DeployDataDir 'secrets'
$tlsDir = Join-Path $script:DeployDataDir 'tls'
New-Item -ItemType Directory -Force -Path $secretsDir, $tlsDir | Out-Null

function Test-CanWrite {
    param([string]$Path)
    if ((Test-Path -LiteralPath $Path) -and -not $Force) {
        Write-Host "exists, not overwritten (use -Force): $Path"
        return $false
    }
    return $true
}

# 1. Database password: 32 random letters and digits. The file ends with ONE line feed, as a typical "echo secret > file"
#    would leave it; the services must cope with that (verified in docs/assurance/deployment-hardening.md).
$passwordFile = Join-Path $secretsDir 'db_password.txt'
if (Test-CanWrite $passwordFile) {
    $alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $bytes = New-Object byte[] 32
    $rng.GetBytes($bytes)
    $chars = foreach ($b in $bytes) { $alphabet[$b % $alphabet.Length] }
    $password = -join $chars
    [System.IO.File]::WriteAllText($passwordFile, $password + "`n", (New-Object System.Text.UTF8Encoding($false)))
    $password = $null
    Write-Host "created: $passwordFile (value not shown)"
}

# 2. Self-signed certificate for localhost (EC P-256, 365 days) with subject alternative names.
$crt = Join-Path $tlsDir 'tls.crt'
$key = Join-Path $tlsDir 'tls.key'
if ((Test-CanWrite $crt) -and (Test-CanWrite $key)) {
    $openssl = (Get-Command openssl -ErrorAction SilentlyContinue)
    if ($openssl) { $opensslPath = $openssl.Source } else { $opensslPath = 'C:\Program Files\Git\usr\bin\openssl.exe' }
    if (-not (Test-Path -LiteralPath $opensslPath)) {
        throw 'openssl was not found (PATH or Git for Windows). Install it, then run this script again.'
    }
    $opensslArgs = @(
        'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
        '-keyout', $key, '-out', $crt, '-days', '365', '-subj', '/CN=localhost',
        '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1',
        '-addext', 'basicConstraints=critical,CA:FALSE',
        '-addext', 'keyUsage=critical,digitalSignature',
        '-addext', 'extendedKeyUsage=serverAuth'
    )
    # openssl writes progress text to stderr; with ErrorActionPreference=Stop Windows PowerShell would treat that as an error.
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & $opensslPath @opensslArgs *> $null
    $opensslExit = $LASTEXITCODE
    $ErrorActionPreference = $previousPreference
    if ($opensslExit -ne 0) { throw "openssl failed with exit code $opensslExit" }
    Write-Host "created: $crt and $key (self-signed, localhost; the private key is not shown)"
}

Write-Host 'Done. Next: scripts\deploy-up.ps1 -Build -FirstRun'
