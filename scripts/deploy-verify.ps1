<#
.SYNOPSIS
  Verifies the running hardened stack (project casevault-rebuild) and records scrubbed evidence in docs\evidence\deploy\.
  Run it while the stack was started with: scripts\deploy-up.ps1 -FirstRun
  It then finishes the first run (scripts\deploy-up.ps1 -FinishFirstRun) and repeats the login checks WITHOUT the override.
  Passwords, CSRF tokens and session ids are never printed or written; docker commands are scoped to cvr-* names.
#>
. "$PSScriptRoot\deploy-common.ps1"
Assert-Project
$ErrorActionPreference = 'Continue'
Set-StrictMode -Off   # docker inspect objects have optional properties (a bind mount has no volume name)

$evidence = Join-Path $script:RepoRoot 'docs\evidence\deploy'
New-Item -ItemType Directory -Force -Path $evidence | Out-Null
$tmp = Join-Path $script:DeployDataDir 'tmp'
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$base = 'https://localhost:8443'
$openssl = (Get-Command openssl -ErrorAction SilentlyContinue)
if ($openssl) { $opensslPath = $openssl.Source } else { $opensslPath = 'C:\Program Files\Git\usr\bin\openssl.exe' }

function Scrub([string]$text) {
    $text = [regex]::Replace($text, 'JSESSIONID=[^;\s]+', 'JSESSIONID=<id>')
    $text = [regex]::Replace($text, '(name="_csrf"[^>]*value=")[^"]+', '$1<token>')
    $text = [regex]::Replace($text, '(value=")[^"]+("[^>]*name="_csrf")', '$1<token>$2')
    return $text
}
function Save([string]$name, [string[]]$lines) {
    $path = Join-Path $evidence $name
    [System.IO.File]::WriteAllText($path, ((Scrub ($lines -join "`r`n")) + "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "saved $name"
}
function Invoke-Curl([string[]]$CurlArgs) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'curl.exe'
    $quoted = $CurlArgs | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }
    $psi.Arguments = $quoted -join ' '
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $out = $p.StandardOutput.ReadToEnd()
    $err = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    return [pscustomobject]@{ Out = $out; Err = $err; Exit = $p.ExitCode }
}
function Try-Login([string]$user, [string]$pw, [string]$jar, [string]$xff) {
    $hdr = @()
    if ($xff) { $hdr = @('-H', "X-Forwarded-For: $xff") }
    $page = Invoke-Curl (@('-k', '-sS', '--max-time', '30', '-c', $jar, '-b', $jar) + $hdr + @("$base/login"))
    $m = [regex]::Match($page.Out, 'name="_csrf"[^>]*value="([^"]+)"|value="([^"]+)"[^>]*name="_csrf"')
    if (-not $m.Success) { return 'no-csrf-token-in-page' }
    if ($m.Groups[1].Success) { $token = $m.Groups[1].Value } else { $token = $m.Groups[2].Value }
    $body = 'username=' + [uri]::EscapeDataString($user) + '&password=' + [uri]::EscapeDataString($pw) + '&_csrf=' + [uri]::EscapeDataString($token)
    # The body (with the password) lives for a moment in the git-ignored .local-datadeploy	mp folder and is deleted at once.
    $bodyFile = Join-Path $tmp ('body-' + [guid]::NewGuid().ToString('N') + '.txt')
    [System.IO.File]::WriteAllText($bodyFile, $body, (New-Object System.Text.UTF8Encoding($false)))
    try {
        $r = Invoke-Curl (@('-k', '-sS', '--max-time', '30', '-o', 'NUL', '-w', '%{http_code} %{redirect_url}', '-c', $jar, '-b', $jar) + $hdr +
            @('-H', 'Content-Type: application/x-www-form-urlencoded', '--data-binary', ('@' + $bodyFile), "$base/login"))
    } finally {
        Remove-Item -LiteralPath $bodyFile -ErrorAction SilentlyContinue
    }
    return $r.Out.Trim()
}
function Read-Credentials {
    # Read INSIDE the container; the values stay in memory and are never printed or logged.
    $text = (& docker exec cvr-app cat /data/firstrun/initial-credentials.txt 2>$null) -join "`n"
    $result = @{}
    foreach ($line in ($text -split "`n")) {
        if ($line -match '^([a-z_]+)=(.+)$') { $result[$Matches[1]] = $Matches[2].Trim() }
    }
    return $result
}
function Count-InLogs([string]$secret) {
    $count = 0
    foreach ($c in @('cvr-app', 'cvr-db', 'cvr-nginx')) {
        $log = (& docker logs $c 2>&1) -join "`n"
        $count += ([regex]::Matches($log, [regex]::Escape($secret))).Count
    }
    return $count
}

# ---------------------------------------------------------------- 1 containers, inspect, resources
$lines = @("# docker ps (only cvr- containers) $(Get-Date -Format s)")
$lines += (& docker ps --filter 'name=^cvr-' --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}')
$lines += ''
$lines += '# every container on this machine whose name does not start with cvr- is not touched by these scripts'
Save '01-containers.txt' $lines

$lines = @('# docker inspect (hardening settings; no environment values are shown)')
foreach ($name in @('cvr-db', 'cvr-app', 'cvr-nginx')) {
    $i = (& docker container inspect $name | ConvertFrom-Json)[0]
    $lines += ''
    $lines += "## $name"
    $lines += "Image             : $($i.Config.Image)"
    $lines += "User              : $($i.Config.User)"
    $lines += "ReadonlyRootfs    : $($i.HostConfig.ReadonlyRootfs)"
    $lines += "CapDrop           : $($i.HostConfig.CapDrop -join ',')"
    $lines += "CapAdd            : $(if ($i.HostConfig.CapAdd) { $i.HostConfig.CapAdd -join ',' } else { '(none)' })"
    $lines += "SecurityOpt       : $($i.HostConfig.SecurityOpt -join ',')"
    $lines += "Memory (bytes)    : $($i.HostConfig.Memory)  MemorySwap: $($i.HostConfig.MemorySwap)  PidsLimit: $($i.HostConfig.PidsLimit)"
    $lines += "Privileged        : $($i.HostConfig.Privileged)  NetworkMode: $($i.HostConfig.NetworkMode)"
    $ports = $i.HostConfig.PortBindings | ConvertTo-Json -Compress
    $lines += "Published ports   : $ports"
    $lines += "Networks          : $(($i.NetworkSettings.Networks.PSObject.Properties.Name) -join ', ')"
    $lines += "Health            : $($i.State.Health.Status)"
    foreach ($m in $i.Mounts) { $mountName = if ($m.Name) { $m.Name } else { [System.IO.Path]::GetFileName($m.Source) }; $lines += "Mount             : $($m.Type) $mountName -> $($m.Destination) rw=$($m.RW)" }
    $lines += "Tmpfs             : $($i.HostConfig.Tmpfs | ConvertTo-Json -Compress)"
}
$lines += ''
$lines += '## process user inside the containers'
$lines += ('cvr-app : ' + ((& docker exec cvr-app id)))
$lines += ('cvr-nginx : ' + ((& docker exec cvr-nginx id)))
$lines += ('cvr-db : ' + ((& docker exec cvr-db id)))
$lines += ''
$lines += '## docker stats (memory use against the limit)'
$lines += (& docker stats --no-stream --format 'table {{.Name}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.PIDs}}' cvr-db cvr-app cvr-nginx)
$lines += ''
$lines += '## JAVA_TOOL_OPTIONS and profile of cvr-app (the database password is NOT among the environment variables)'
$appEnv = ((& docker container inspect cvr-app | ConvertFrom-Json)[0]).Config.Env
$envNames = $appEnv | Where-Object { $_ -match '^(JAVA_TOOL_OPTIONS|SPRING_PROFILES_ACTIVE|POSTGRES_|CASEVAULT_)' }
$lines += $envNames
$lines += ('database password in the environment of cvr-app: ' + [bool]($appEnv | Where-Object { $_ -match 'PASSWORD' }))
$lines += ''
$lines += '## secret files mounted in cvr-app (names and sizes only)'
$lines += (& docker exec cvr-app ls -l /run/secrets/)
Save '02-inspect.txt' $lines

# ---------------------------------------------------------------- 2 reachability
$lines = @("# reachability from the host $(Get-Date -Format s)")
$login = Invoke-Curl @('-k', '-sS', '--max-time', '20', '-o', 'NUL', '-w', 'https://localhost:8443/login -> HTTP %{http_code} (certificate not verified: self-signed, curl -k)', "$base/login")
$lines += $login.Out
$page = Invoke-Curl @('-k', '-sS', '--max-time', '20', "$base/login")
$title = [regex]::Match($page.Out, '<title>([^<]*)</title>').Groups[1].Value
$lines += "login page title: $title"
$lines += ('login form present: ' + ($page.Out -match 'action="/login"'))
$lines += ''
foreach ($target in @(@('http://localhost:8080/login', 'plain HTTP on the application port 8080'), @('http://localhost:8080/actuator/health', 'application health on port 8080'))) {
    $r = Invoke-Curl @('-sS', '--max-time', '5', '-o', 'NUL', '-w', '%{http_code}', $target[0])
    $lines += "$($target[1]) ($($target[0])): curl exit $($r.Exit), $($r.Err.Trim())"
}
foreach ($port in @(5432, 8080)) {
    $client = New-Object System.Net.Sockets.TcpClient
    $ar = $client.BeginConnect('127.0.0.1', $port, $null, $null)
    $ok = $ar.AsyncWaitHandle.WaitOne(2000) -and $client.Connected
    $lines += "TCP connect 127.0.0.1:$port from the host: " + $(if ($ok) { 'CONNECTED (unexpected)' } else { 'not reachable (expected)' })
    $client.Close()
}
$lines += ('docker port cvr-db  : "' + ((& docker port cvr-db) -join ' ') + '" (empty = nothing published)')
$lines += ('docker port cvr-app : "' + ((& docker port cvr-app) -join ' ') + '" (empty = nothing published)')
$lines += ('docker port cvr-nginx: ' + ((& docker port cvr-nginx) -join ' '))
$lines += ''
$health = Invoke-Curl @('-k', '-sS', '--max-time', '20', "$base/actuator/health")
$info = Invoke-Curl @('-k', '-sS', '--max-time', '20', '-o', 'NUL', '-w', '%{http_code}', "$base/actuator/info")
$lines += "GET /actuator/health through nginx: $($health.Out)"
$lines += "GET /actuator/info through nginx: HTTP $($info.Out) (blocked at the proxy)"
Save '03-reachability.txt' $lines

# ---------------------------------------------------------------- 3 headers (HSTS from the application behind the proxy)
$hdr = Invoke-Curl @('-k', '-sS', '--max-time', '20', '-D', '-', '-o', 'NUL', "$base/login")
$headerLines = @("# response headers of GET $base/login (through nginx)")
$headerLines += ($hdr.Out -split "`r?`n" | Where-Object { $_ -ne '' })
$headerLines += ''
$names = @('Strict-Transport-Security', 'Content-Security-Policy', 'X-Content-Type-Options', 'X-Frame-Options', 'Referrer-Policy', 'Permissions-Policy', 'Cross-Origin-Opener-Policy', 'Cross-Origin-Resource-Policy', 'Cache-Control', 'X-Correlation-ID', 'Server', 'Set-Cookie')
foreach ($n in $names) {
    $count = @($hdr.Out -split "`r?`n" | Where-Object { $_ -match "^$n\s*:" }).Count
    $headerLines += ("{0,-30} present x{1}" -f $n, $count)
}
$cookie = ($hdr.Out -split "`r?`n" | Where-Object { $_ -match '^Set-Cookie' }) -join ' '
$headerLines += ('session cookie flags: Secure=' + ($cookie -match '(?i);\s*secure') + ' HttpOnly=' + ($cookie -match '(?i);\s*httponly') + ' SameSite=Strict=' + ($cookie -match '(?i)samesite=strict'))
$headerLines += ('Server header value contains a version number: ' + [bool](($hdr.Out -split "`r?`n" | Where-Object { $_ -match '^Server\s*:' }) -match '\d'))
$headerLines += ('jsessionid in any header: ' + ($hdr.Out -match '(?i);jsessionid'))
Save '04-headers.txt' $headerLines

# ---------------------------------------------------------------- 4 TLS actually negotiated
$tls = @("# TLS negotiated with $base (openssl s_client, $((& $opensslPath version)))")
foreach ($mode in @(@('default (client offers 1.2 and 1.3)', @()), @('forced TLS 1.3', @('-tls1_3')), @('forced TLS 1.2', @('-tls1_2')))) {
    $tls += ''
    $tls += "## $($mode[0])"
    $out = ('Q' | & $opensslPath s_client -connect localhost:8443 -servername localhost -brief @($mode[1]) 2>&1) | Where-Object { $_ -match 'Protocol version|Ciphersuite|Peer certificate|Verification|Signature type|Hash used|Supported Elliptic' }
    $tls += $out
}
$tls += ''
$tls += '## a weak, non-forward-secret cipher (TLS 1.2, AES128-SHA, no security level restriction) must be refused'
$weak = ('Q' | & $opensslPath s_client -connect localhost:8443 -servername localhost -tls1_2 -cipher 'AES128-SHA@SECLEVEL=0' 2>&1) | Where-Object { $_ -match 'alert|handshake failure|no cipher|Cipher is|error' } | Select-Object -First 4
$tls += $weak
$tls += ''
$tls += '## TLS compression'
$comp = ('Q' | & $opensslPath s_client -connect localhost:8443 -servername localhost 2>&1) | Where-Object { $_ -match 'Compression' } | Select-Object -First 2
$tls += $comp
$tls += ''
$tls += '## HTTP/2 offered by nginx (ALPN, openssl s_client)'
$alpn = ('Q' | & $opensslPath s_client -connect localhost:8443 -servername localhost -alpn 'h2,http/1.1' 2>&1) | Where-Object { $_ -match 'ALPN' }
$tls += $alpn
$tls += ''
$tls += '## the certificate (public part only)'
$tls += (& $opensslPath x509 -in (Join-Path $script:DeployDataDir 'tls\tls.crt') -noout -subject -issuer -dates -ext subjectAltName)
Save '05-tls.txt' $tls

# ---------------------------------------------------------------- 5 login through nginx with the first-run accounts
$creds = Read-Credentials
$out = @("# login through nginx with the first-run accounts $(Get-Date -Format s)")
$out += ('credentials read from the volume file inside cvr-app: ' + $creds.Count + ' accounts (names and passwords are not printed)')
foreach ($user in @('admin_auditor', 'manager_alice', 'analyst_bob', 'client_charlie')) {
    $jar = Join-Path $tmp "jar-$user.txt"
    Remove-Item -LiteralPath $jar -ErrorAction SilentlyContinue
    $res = Try-Login $user $creds[$user] $jar $null
    $dash = Invoke-Curl @('-k', '-sS', '--max-time', '20', '-b', $jar, '-o', 'NUL', '-w', '%{http_code}', "$base/dashboard")
    $out += "$user : POST /login -> $res ; GET /dashboard -> HTTP $($dash.Out)"
    Remove-Item -LiteralPath $jar -ErrorAction SilentlyContinue
}
$wrong = Try-Login 'admin_auditor' 'wrong-password-value' (Join-Path $tmp 'jar-wrong.txt') $null
Remove-Item -LiteralPath (Join-Path $tmp 'jar-wrong.txt') -ErrorAction SilentlyContinue
$out += "admin_auditor with a wrong password -> $wrong"
Save '06-login.txt' $out

# ---------------------------------------------------------------- 6 B7a: the secret file and its trailing newline
$a = @("# B7a: database password through a Docker secret FILE")
$a += 'the file as created by scripts\deploy-init.ps1 on the host (length, last byte only):'
$bytes = [System.IO.File]::ReadAllBytes((Join-Path $script:DeployDataDir 'secrets\db_password.txt'))
$a += "  host file: $($bytes.Length) bytes, last byte = $($bytes[$bytes.Length - 1]) (10 = line feed)"
$a += 'the same file as mounted in cvr-app (/run/secrets/spring.datasource.password):'
$a += ('  size   : ' + ((& docker exec cvr-app wc -c /run/secrets/spring.datasource.password) -replace '\s+/run.*$', ' bytes'))
$a += ('  byte 33 (hex, 0a = line feed): ' + ((& docker exec cvr-app od -An -tx1 -j 32 -N 1 /run/secrets/spring.datasource.password).Trim()))
$a += 'the same file as mounted in cvr-db (/run/secrets/postgres_password):'
$a += ('  size   : ' + ((& docker exec cvr-db wc -c /run/secrets/postgres_password) -replace '\s+/run.*$', ' bytes'))
$a += ''
$a += 'result: the application authenticated to PostgreSQL with that secret (it is healthy and Flyway applied the migrations):'
$a += (& docker logs cvr-app 2>&1 | Select-String -Pattern 'Successfully applied|Schema .* is up to date|Migrating schema|HikariPool-1 - Added connection|Started CaseVaultApplication' | ForEach-Object { ($_.Line -replace '^\S+\s+', '') } | Select-Object -First 5)
$a += ''
$a += 'what the database sees: the password hash method and the connections made by the application role (no secret shown):'
$a += (& docker exec cvr-db psql -U casevault -d casevault -At -c "select 'password_encryption=' || current_setting('password_encryption'), 'connections_by_role_casevault=' || count(*) from pg_stat_activity where usename='casevault'" 2>&1)
Save '07-secret-file.txt' $a

# ---------------------------------------------------------------- 7 rate limit through nginx
Write-Host 'waiting 65 seconds for a clean login rate-limit window ...'
Start-Sleep -Seconds 65
$r = @("# rate limit through nginx: spoofed X-Forwarded-For $(Get-Date -Format s)")
$r += 'the application allows 10 login POSTs per minute per client address; nginx OVERWRITES X-Forwarded-For with the address it saw.'
$r += 'host client, unknown user, a DIFFERENT spoofed X-Forwarded-For on every attempt:'
$results = @()
for ($i = 1; $i -le 12; $i++) {
    $jar = Join-Path $tmp 'jar-rl.txt'
    Remove-Item -LiteralPath $jar -ErrorAction SilentlyContinue
    $res = Try-Login "nobody_$i" 'x' $jar "203.0.113.$i"
    $results += "attempt $i (spoofed 203.0.113.$i): $res"
}
Remove-Item -LiteralPath (Join-Path $tmp 'jar-rl.txt') -ErrorAction SilentlyContinue
$r += $results
$r += ''
$r += 'a second client with a DIFFERENT source address (a throw-away container on the internal edge network, image cvr-app:dev), claiming the same spoofed address as the blocked host client:'
$probeLines = @(
    'J=/tmp/j',
    'B=https://cvr-nginx:8443',
    'curl -ksS -c $J -b $J $B/login -o /tmp/p.html',
    'T=$(grep -o ''name="_csrf"[^>]*value="[^"]*"'' /tmp/p.html | head -1 | sed ''s/.*value="//;s/"$//'')',
    'curl -ksS -o /dev/null -w ''%{http_code} %{redirect_url}\n'' -c $J -b $J -H ''X-Forwarded-For: 203.0.113.1'' -d "username=nobody_x&password=x&_csrf=$T" $B/login'
)
$probeFile = Join-Path $tmp 'probe-client.sh'
[System.IO.File]::WriteAllText($probeFile, (($probeLines -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))
$r += (& docker run --rm --name cvr-probe-client --network casevault-rebuild_cvr_edge --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true --memory 128m -v "$($probeFile):/probe.sh:ro" --entrypoint sh cvr-app:dev /probe.sh)
Remove-Item -LiteralPath $probeFile -ErrorAction SilentlyContinue
$r += ''
$r += 'host client again right after the block (still limited):'
$r += (Try-Login 'nobody_z' 'x' (Join-Path $tmp 'jar-rl2.txt') '198.51.100.7')
Remove-Item -LiteralPath (Join-Path $tmp 'jar-rl2.txt') -ErrorAction SilentlyContinue
Save '08-rate-limit.txt' $r

# ---------------------------------------------------------------- 8 B7c: finish the first run, restart WITHOUT the override
$f = @("# B7c: first-run finish $(Get-Date -Format s)")
$secretsLeak = 0
foreach ($k in $creds.Keys) { $secretsLeak += (Count-InLogs $creds[$k]) }
$f += "occurrences of any first-run password in the logs of cvr-app, cvr-db, cvr-nginx BEFORE the finish: $secretsLeak"
$f += ('files in /data/firstrun before: ' + ((& docker exec cvr-app ls /data/firstrun) -join ','))
$f += ('first-run flag in the environment before: ' + [bool](((& docker container inspect cvr-app | ConvertFrom-Json)[0]).Config.Env | Where-Object { $_ -match 'INITIAL_ACCOUNTS_ENABLED' }))
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'deploy-up.ps1') -FinishFirstRun *> $null
$f += "deploy-up.ps1 -FinishFirstRun exit code: $LASTEXITCODE"
$f += ('cvr-app health after the restart: ' + (& docker container inspect --format '{{.State.Health.Status}}' cvr-app))
$f += ('first-run flag in the environment after: ' + [bool](((& docker container inspect cvr-app | ConvertFrom-Json)[0]).Config.Env | Where-Object { $_ -match 'INITIAL_ACCOUNTS_ENABLED' }))
$f += ('first-run volume mounted in cvr-app after: ' + [bool](((& docker container inspect cvr-app | ConvertFrom-Json)[0]).Mounts | Where-Object { $_.Name -eq 'cvr_firstrun' }))
$leftover = @(& docker run --rm --name cvr-firstrun-check --network none --read-only --cap-drop ALL -v cvr_firstrun:/d --entrypoint ls cvr-app:dev -A /d).Count
$f += "files left in the cvr_firstrun volume after the finish: $leftover"
$f += 'waiting 65 seconds so the login rate-limit window of the host address has passed ...'
Start-Sleep -Seconds 65
foreach ($user in @('admin_auditor', 'client_charlie')) {
    $jar = Join-Path $tmp "jar2-$user.txt"
    Remove-Item -LiteralPath $jar -ErrorAction SilentlyContinue
    $res = Try-Login $user $creds[$user] $jar $null
    $dash = Invoke-Curl @('-k', '-sS', '--max-time', '20', '-b', $jar, '-o', 'NUL', '-w', '%{http_code}', "$base/dashboard")
    $f += "after the restart without the override: $user : POST /login -> $res ; GET /dashboard -> HTTP $($dash.Out)"
    Remove-Item -LiteralPath $jar -ErrorAction SilentlyContinue
}
$secretsLeak2 = 0
foreach ($k in $creds.Keys) { $secretsLeak2 += (Count-InLogs $creds[$k]) }
$f += "occurrences of any first-run password in the logs AFTER the restart: $secretsLeak2"
Save '09-first-run-finish.txt' $f
$creds = $null
Write-Host 'Evidence written to docs\evidence\deploy\'
