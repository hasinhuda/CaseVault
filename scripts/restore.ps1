<#
.SYNOPSIS
  Restores a backup made by scripts\backup.ps1 into the stack casevault-rebuild (and only into it).
.DESCRIPTION
  Refuses to run without -Confirm. Verifies manifest.json against the encrypted file BEFORE decrypting, then verifies every
  decrypted part against the manifest BEFORE touching Docker. It refuses to overwrite: the volumes cvr_pgdata, cvr_evidence and
  cvr_keys must not exist and no cvr- container may exist (run scripts\deploy-down.ps1 -RemoveData first - that deletes data,
  so do it only when you mean it). The application is started WITHOUT the first-run override, so no new accounts are created.
  The database password and TLS files are not part of the backup: .local-data\deploy must already exist (scripts\deploy-init.ps1).
.PARAMETER BackupFolder
  Folder name (or path) below .local-data\backups\, for example 20261113-180000Z.
.PARAMETER Confirm
  Required. Without it the script only explains what it would do.
.PARAMETER Passphrase
  Optional SecureString for automation; otherwise prompted.
#>
param(
    [Parameter(Mandatory = $true)][string]$BackupFolder,
    [switch]$Confirm,
    [securestring]$Passphrase
)

. "$PSScriptRoot\backup-common.ps1"
Assert-Project

$dir = if (Test-Path -LiteralPath $BackupFolder) { (Resolve-Path -LiteralPath $BackupFolder).Path } else { Join-Path $script:BackupRoot $BackupFolder }
$rootFull = [IO.Path]::GetFullPath($script:BackupRoot)
if (-not ([IO.Path]::GetFullPath($dir)).StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Refusing: the backup folder must be below .local-data\backups\.'
}
$manifestPath = Join-Path $dir 'manifest.json'
if (-not (Test-Path -LiteralPath $manifestPath)) { throw "No manifest.json in $BackupFolder." }
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.format -ne 'casevault-backup-1' -or $manifest.project -ne $script:ProjectName) { throw 'Refusing: this is not a casevault-rebuild backup.' }

if (-not $Confirm) {
    Write-Host "DRY RUN: would restore $BackupFolder into project casevault-rebuild (database, evidence, keys)."
    Write-Host 'Add -Confirm to proceed. Requirements: no cvr- containers and no cvr_pgdata / cvr_evidence / cvr_keys volumes (scripts\deploy-down.ps1 -RemoveData).'
    return
}

# 1. Manifest versus the encrypted file (before any decryption).
$enc = Join-Path $dir $manifest.encryptedFile.name
if (-not (Test-Path -LiteralPath $enc)) { throw 'The encrypted file named in the manifest is missing.' }
if ((Get-Sha256 $enc) -ne $manifest.encryptedFile.sha256) { throw 'MANIFEST CHECK FAILED: the encrypted file does not match its recorded SHA-256. Nothing was restored.' }
Write-Host 'Manifest check passed (encrypted file hash).'

# 2. Preconditions on Docker (read-only queries).
Assert-SecretFilesExist
$existing = @(& docker ps -a --filter 'name=cvr-' --format '{{.Names}}')
if ($existing.Count -gt 0) { throw "Refusing: cvr- containers exist ($($existing -join ', ')). Run scripts\deploy-down.ps1 first." }
$vols = @(& docker volume ls --format '{{.Name}}' | Where-Object { $_ -in 'cvr_pgdata', 'cvr_evidence', 'cvr_keys' })
if ($vols.Count -gt 0) { throw "Refusing to overwrite existing volumes: $($vols -join ', '). Run scripts\deploy-down.ps1 -RemoveData only if you really want to discard them." }

# 3. Decrypt into a work folder below the backup folder, verify the parts, then restore.
$tool = Get-EncryptionTool
if ($tool.Name -ne $manifest.encryptionTool) { throw "The backup was made with $($manifest.encryptionTool); that tool is not what this machine selected ($($tool.Name))." }
$pass = Read-BackupPassphrase -Passphrase $Passphrase
$work = Join-Path $dir 'work-restore'
New-Item -ItemType Directory -Force -Path $work | Out-Null
try {
    $payloadTar = Join-Path $work 'payload.tar'
    Unprotect-File -Tool $tool -InFile $enc -OutFile $payloadTar -Passphrase $pass
    Push-Location -LiteralPath $work
    try { & tar.exe -xf payload.tar } finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) { throw 'tar extraction failed' }
    foreach ($f in 'db.dump', 'evidence.tar', 'keys.tar') {
        $p = Join-Path $work $f
        if (-not (Test-Path -LiteralPath $p)) { throw "$f missing in the decrypted payload." }
        if ((Get-Sha256 $p) -ne $manifest.plaintextParts.$f.sha256) { throw "MANIFEST CHECK FAILED for $f after decryption. Nothing was restored." }
    }
    Write-Host 'Decryption and part hashes verified.'

    # 4. Create (not start) the project resources, restore the database, then the two volumes, then start everything.
    Invoke-Compose -ComposeArgs @('create', 'cvr-db', 'cvr-app', 'cvr-nginx')
    Invoke-Compose -ComposeArgs @('up', '-d', '--wait', '--wait-timeout', '240', 'cvr-db')
    Write-Host 'Restoring the database ...'
    Invoke-CmdRedirect ('docker exec -i cvr-db pg_restore -U casevault -d casevault --no-owner --exit-on-error < "' + (Join-Path $work 'db.dump') + '"')
    Write-Host 'Restoring evidence and key volumes ...'
    Invoke-VolumeHelper -Name 'cvr-restore-evidence' -Mounts @('cvr_evidence:/data/evidence') -Command @('tar', '-xf', '-', '-C', '/data/evidence') -StdinFile (Join-Path $work 'evidence.tar')
    Invoke-VolumeHelper -Name 'cvr-restore-keys' -Mounts @('cvr_keys:/data/keys') -Command @('tar', '-xf', '-', '-C', '/data/keys') -StdinFile (Join-Path $work 'keys.tar')
    # Base file only: NO first-run override, so no accounts are created and no credentials file exists.
    Invoke-Compose -ComposeArgs @('up', '-d', '--wait', '--wait-timeout', '300')
    Write-Host 'Restore finished. Check the application with scripts\deploy-verify.ps1 and by logging in.'
}
finally {
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
}
