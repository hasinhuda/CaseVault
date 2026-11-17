# Shared helpers for scripts\backup.ps1 and scripts\restore.ps1 (Final assurance, Stage B). Dot-source this file; do not run it.
# Everything here is scoped to the compose project "casevault-rebuild" (containers cvr-*, volumes cvr_*, image cvr-app:*).
# Passphrases are SecureString values; they are handed to the encryption tool through its standard input only (never as a
# command-line argument, never written to a file, never logged).

. "$PSScriptRoot\deploy-common.ps1"

$script:BackupRoot = Join-Path $script:RepoRoot '.local-data\backups'

function Get-EncryptionTool {
    # Preferred: GnuPG symmetric encryption (AES-256 with an integrity check, MDC). Fallback: openssl enc (AES-256-CBC with
    # PBKDF2), which is NOT authenticated: tampering with the ciphertext is only detected by the SHA-256 checks afterwards.
    $candidates = @()
    $cmd = Get-Command gpg -ErrorAction SilentlyContinue
    if ($cmd) { $candidates += $cmd.Source }
    $candidates += 'C:\Program Files\Git\usr\bin\gpg.exe'
    foreach ($c in $candidates) {
        if ($c -and (Test-Path -LiteralPath $c)) { return @{ Name = 'gpg'; Path = $c; Authenticated = $true } }
    }
    $candidates = @()
    $cmd = Get-Command openssl -ErrorAction SilentlyContinue
    if ($cmd) { $candidates += $cmd.Source }
    $candidates += 'C:\Program Files\Git\usr\bin\openssl.exe'
    foreach ($c in $candidates) {
        if ($c -and (Test-Path -LiteralPath $c)) { return @{ Name = 'openssl'; Path = $c; Authenticated = $false } }
    }
    throw 'No encryption tool found (gpg or openssl). Install GnuPG or Git for Windows. Nothing was backed up.'
}

function Read-BackupPassphrase {
    param([securestring]$Passphrase, [switch]$Confirm)
    if ($Passphrase) { return $Passphrase }
    $first = Read-Host -AsSecureString -Prompt 'Backup passphrase'
    if ($Confirm) {
        $second = Read-Host -AsSecureString -Prompt 'Repeat the passphrase'
        if ((ConvertTo-PlainText $first) -ne (ConvertTo-PlainText $second)) { throw 'The two passphrases differ.' }
    }
    if ((ConvertTo-PlainText $first).Length -lt 12) { throw 'Use a passphrase of at least 12 characters.' }
    return $first
}

function ConvertTo-PlainText {
    param([securestring]$Secure)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Invoke-WithStdin {
    # Runs an executable, writes $StdinText (plus a newline) to its standard input, returns the exit code.
    param([string]$Exe, [string[]]$ToolArgs, [string]$StdinText)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = ($ToolArgs | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardOutput = $true
    $psi.CreateNoWindow = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.StandardInput.WriteLine($StdinText)
    $p.StandardInput.Close()
    $null = $p.StandardOutput.ReadToEnd()
    $err = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    if ($p.ExitCode -ne 0) { Write-Warning ("encryption tool reported: " + ($err -replace '\s+', ' ').Trim()) }
    return $p.ExitCode
}

function Protect-File {
    param($Tool, [string]$InFile, [string]$OutFile, [securestring]$Passphrase)
    $plain = ConvertTo-PlainText $Passphrase
    if ($Tool.Name -eq 'gpg') {
        $a = @('--batch', '--yes', '--no-tty', '--pinentry-mode', 'loopback', '--passphrase-fd', '0', '--symmetric',
               '--cipher-algo', 'AES256', '--s2k-mode', '3', '--s2k-count', '65011712', '--s2k-digest-algo', 'SHA512', '-o', $OutFile, $InFile)
    } else {
        $a = @('enc', '-aes-256-cbc', '-pbkdf2', '-iter', '600000', '-salt', '-pass', 'stdin', '-in', $InFile, '-out', $OutFile)
    }
    $code = Invoke-WithStdin -Exe $Tool.Path -ToolArgs $a -StdinText $plain
    if ($code -ne 0 -or -not (Test-Path -LiteralPath $OutFile)) { throw "Encryption failed (exit code $code)." }
}

function Unprotect-File {
    param($Tool, [string]$InFile, [string]$OutFile, [securestring]$Passphrase)
    $plain = ConvertTo-PlainText $Passphrase
    if ($Tool.Name -eq 'gpg') {
        $a = @('--batch', '--yes', '--no-tty', '--pinentry-mode', 'loopback', '--passphrase-fd', '0', '--decrypt', '-o', $OutFile, $InFile)
    } else {
        $a = @('enc', '-d', '-aes-256-cbc', '-pbkdf2', '-iter', '600000', '-pass', 'stdin', '-in', $InFile, '-out', $OutFile)
    }
    $code = Invoke-WithStdin -Exe $Tool.Path -ToolArgs $a -StdinText $plain
    if ($code -ne 0 -or -not (Test-Path -LiteralPath $OutFile)) { throw 'Decryption failed (wrong passphrase or damaged file). Nothing was restored.' }
}

function Get-Sha256 {
    param([string]$Path)
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Invoke-CmdRedirect {
    # Runs a native command line through cmd.exe so that its stdout/stdin is redirected BINARY-safely to/from a file.
    param([string]$CommandLine)
    & cmd.exe /d /c $CommandLine
    if ($LASTEXITCODE -ne 0) { throw "command failed with exit code $LASTEXITCODE" }
}

function Wait-ContainerHealthy {
    param([string]$Name, [int]$TimeoutSeconds = 240)
    if ($Name -notmatch '^cvr-[a-z]+$') { throw "Refusing: '$Name' is not a cvr- container." }
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $state = (& docker inspect -f '{{.State.Health.Status}}' $Name) 2>$null
        if ($state -eq 'healthy') { return }
        Start-Sleep -Seconds 3
    }
    throw "Container $Name did not become healthy within $TimeoutSeconds seconds."
}

# Helper container (always --rm, no network, no capabilities, memory limited, no published ports). Mounts only the named volume(s).
function Invoke-VolumeHelper {
    param([string]$Name, [string[]]$Mounts, [string[]]$Command, [string]$StdinFile, [string]$StdoutFile)
    if ($Name -notmatch '^cvr-[a-z0-9-]+$') { throw "Refusing: helper name '$Name' must start with cvr-." }
    foreach ($m in $Mounts) { if ($m -notmatch '^cvr_[a-z]+:/data/[a-z]+(:ro)?$') { throw "Refusing mount '$m'." } }
    $parts = @('docker', 'run', '--rm', '--name', $Name, '--network', 'none', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
               '--memory', '128m', '--pids-limit', '64', '--user', '10001:10001', '--read-only')
    if ($StdinFile) { $parts += '-i' }
    foreach ($m in $Mounts) { $parts += @('-v', $m) }
    $parts += @('--entrypoint', $Command[0], 'cvr-app:dev') + $Command[1..($Command.Length - 1)]
    # An argument with spaces (for example the script text after "sh -c") is wrapped in double quotes for cmd.exe.
    $line = ($parts | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
    if ($StdinFile) { $line += ' < "' + $StdinFile + '"' }
    if ($StdoutFile) { $line += ' > "' + $StdoutFile + '"' }
    Invoke-CmdRedirect $line
}
