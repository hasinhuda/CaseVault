<#
.SYNOPSIS
  Consistent, encrypted backup of the stack casevault-rebuild: PostgreSQL dump + evidence volume (cvr_evidence) +
  key volume (cvr_keys: evidence keyset and audit HMAC key) into a timestamped folder under .local-data\backups\.
.DESCRIPTION
  1. cvr-app is stopped briefly (the database and the evidence files are then from the same moment); it is started again at the end.
  2. pg_dump runs INSIDE cvr-db over the local socket (the database password is never read or printed by this script).
  3. The two volumes are archived by helper containers (--rm, no network, no capabilities, 128 MB, one volume read-only each).
  4. The three parts are packed into one tar and encrypted with a passphrase (GnuPG AES-256 with integrity check if available,
     otherwise openssl enc AES-256-CBC, which is NOT authenticated - the manifest says which one was used).
  5. manifest.json records SHA-256 of the encrypted file and of each plaintext part. No secret is stored in it.
  The folder is under .local-data\ (git-ignored). Keys and data are in the same folder only in ENCRYPTED form; keep the passphrase
  somewhere else. Passphrase: prompted as a SecureString (never an argument, never a file).
.PARAMETER Passphrase
  Optional SecureString for automation inside one PowerShell session. If absent you are prompted.
#>
param([securestring]$Passphrase)

. "$PSScriptRoot\backup-common.ps1"
Assert-Project

$tool = Get-EncryptionTool
$pass = Read-BackupPassphrase -Passphrase $Passphrase -Confirm
foreach ($n in 'cvr-db', 'cvr-app') {
    $state = (& docker inspect -f '{{.State.Status}}' $n) 2>$null
    if ($state -ne 'running') { throw "$n is not running. Start the stack first (scripts\deploy-up.ps1)." }
}

$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss') + 'Z'
$dir = Join-Path $script:BackupRoot $stamp
$work = Join-Path $dir 'work'
New-Item -ItemType Directory -Force -Path $work | Out-Null
$appWasStopped = $false
try {
    Write-Host "Stopping cvr-app briefly for a consistent copy ..."
    Invoke-Compose -ComposeArgs @('stop', 'cvr-app')
    $appWasStopped = $true

    Write-Host 'Database dump (pg_dump, custom format, inside cvr-db) ...'
    Invoke-CmdRedirect ('docker exec cvr-db pg_dump -U casevault -d casevault --format=custom --no-owner > "' + (Join-Path $work 'db.dump') + '"')
    Write-Host 'Evidence volume (encrypted files) ...'
    Invoke-VolumeHelper -Name 'cvr-backup-evidence' -Mounts @('cvr_evidence:/data/evidence:ro') -Command @('tar', '-cf', '-', '-C', '/data/evidence', '.') -StdoutFile (Join-Path $work 'evidence.tar')
    Write-Host 'Key volume (keyset + audit key) ...'
    Invoke-VolumeHelper -Name 'cvr-backup-keys' -Mounts @('cvr_keys:/data/keys:ro') -Command @('tar', '-cf', '-', '-C', '/data/keys', '.') -StdoutFile (Join-Path $work 'keys.tar')

    $parts = [ordered]@{}
    foreach ($f in 'db.dump', 'evidence.tar', 'keys.tar') {
        $p = Join-Path $work $f
        if (-not (Test-Path -LiteralPath $p) -or (Get-Item -LiteralPath $p).Length -eq 0) { throw "$f is missing or empty; backup aborted." }
        $parts[$f] = @{ sha256 = (Get-Sha256 $p); bytes = (Get-Item -LiteralPath $p).Length }
    }
    $payloadTar = Join-Path $work 'payload.tar'
    # Relative names inside the work folder: works with both bsdtar and GNU tar (GNU tar reads "C:" as a host name).
    Push-Location -LiteralPath $work
    try { & tar.exe -cf payload.tar db.dump evidence.tar keys.tar } finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) { throw 'tar failed' }
    $enc = Join-Path $dir 'payload.tar.enc'
    Write-Host "Encrypting with $($tool.Name) ..."
    Protect-File -Tool $tool -InFile $payloadTar -OutFile $enc -Passphrase $pass

    $pgVersion = ((& docker exec cvr-db postgres --version) 2>$null) -join ' '
    $manifest = [ordered]@{
        format        = 'casevault-backup-1'
        createdUtc    = (Get-Date).ToUniversalTime().ToString('o')
        project       = $script:ProjectName
        encryption    = $(if ($tool.Authenticated) { 'gpg symmetric AES-256 (integrity protected)' } else { 'openssl enc AES-256-CBC PBKDF2 (NOT authenticated: only the SHA-256 checks detect tampering)' })
        encryptionTool = $tool.Name
        postgres      = $pgVersion
        appImageId    = ((& docker inspect -f '{{.Image}}' cvr-app) 2>$null) -join ''
        encryptedFile = @{ name = 'payload.tar.enc'; sha256 = (Get-Sha256 $enc); bytes = (Get-Item -LiteralPath $enc).Length }
        plaintextParts = $parts
        notRecorded   = 'database password, TLS key and certificate (kept in .local-data\deploy; back them up separately), passphrase'
    }
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $dir 'manifest.json') -Encoding ascii
    Write-Host "Backup written: .local-data\backups\$stamp (payload.tar.enc + manifest.json)"
}
finally {
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
    if ($appWasStopped) {
        Write-Host 'Starting cvr-app again ...'
        Invoke-Compose -ComposeArgs @('start', 'cvr-app')
        Wait-ContainerHealthy -Name 'cvr-app'
    }
}
