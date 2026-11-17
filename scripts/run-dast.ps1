<#
.SYNOPSIS
  Local DAST: OWASP ZAP baseline scan (passive scan plus a short spider) against the local hardened stack ONLY
  (https://localhost:8443, project casevault-rebuild). Writes HTML/JSON/Markdown reports to docs\evidence\dast\.
.DESCRIPTION
  - Refuses any target other than https://localhost:8443 and refuses to run if the stack is not up and healthy.
  - Refuses to start if less than 1.8 GB of physical memory is free (the ZAP container is limited to 1.5 GB).
  - The ZAP image is pinned by digest (below). The digest was read from the registry (docker buildx imagetools inspect),
    the image was pulled BY that digest (Docker verifies content against it) and reports version 2.17.0, which equals the
    latest release listed on GitHub at that time. A signature check (cosign) was NOT done: VERIFY MANUALLY.
  - The ZAP container shares the network namespace of cvr-nginx (--network container:cvr-nginx), so "localhost:8443" inside ZAP is
    exactly the nginx of this stack, nothing else is reachable and no port is published. It runs --rm with all capabilities dropped,
    no-new-privileges, a read-only root file system, a memory and a process limit. It is removed afterwards (also on failure).
  - The self-signed certificate of the local stack is accepted FOR THIS LOCAL TEST ONLY: ZAP does not validate server certificates by
    default and the certificate belongs to localhost on this machine. Nothing here may be used against another host.
  - The scan is NOT authenticated (login page, error pages, static files). See docs\assurance\dast.md.
  - Reports are scrubbed (CSRF token values, session ids) before they stay in the repository.
#>
param([string]$Target = 'https://localhost:8443')

. "$PSScriptRoot\deploy-common.ps1"
Assert-Project
$ErrorActionPreference = 'Continue'

$ZapImage = 'ghcr.io/zaproxy/zaproxy@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af'
if ($Target -ne 'https://localhost:8443') { throw "Refusing: the only allowed target is https://localhost:8443 (got '$Target')." }

foreach ($n in 'cvr-db', 'cvr-app', 'cvr-nginx') {
    $health = (& docker inspect -f '{{.State.Health.Status}}' $n) 2>$null
    if ($health -ne 'healthy') { throw "$n is not healthy. Start the stack first: scripts\deploy-up.ps1" }
}
& docker image inspect $ZapImage *> $null
if ($LASTEXITCODE -ne 0) { throw "The pinned ZAP image is not present. Pull it by digest: docker pull $ZapImage" }

$freeMb = [int]((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1024)
if ($freeMb -lt 1800) { throw "Only $freeMb MB of memory are free (need 1800). Close programs, then run again. Nothing was started." }

$outDir = Join-Path $script:RepoRoot 'docs\evidence\dast'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
foreach ($f in 'zap-baseline.html', 'zap-baseline.json', 'zap-baseline.md', 'zap-console.txt') { Remove-Item -LiteralPath (Join-Path $outDir $f) -ErrorAction SilentlyContinue }

$started = (Get-Date).ToUniversalTime().ToString('o')
Write-Host "Starting ZAP baseline against $Target (free memory $freeMb MB) ..."
$console = Join-Path $outDir 'zap-console.txt'
try {
    # -m 3: spider for at most 3 minutes; -I: do not fail the script on warnings; reports go to /zap/wrk (the evidence folder).
    & docker run --rm --name cvr-zap --network container:cvr-nginx --cap-drop ALL --security-opt no-new-privileges:true `
        --read-only --tmpfs /tmp:rw,size=256m --tmpfs /home/zap:rw,uid=1000,gid=1000,size=512m `
        --memory 1500m --memory-swap 1500m --pids-limit 512 `
        -v "${outDir}:/zap/wrk:rw" `
        $ZapImage zap-baseline.py -t $Target -m 3 -I -r zap-baseline.html -J zap-baseline.json -w zap-baseline.md *> $console
    $zapExit = $LASTEXITCODE
}
finally {
    # The container is --rm; this removes it only if it was left behind (name is exact and ours).
    $left = (& docker ps -a --filter 'name=^cvr-zap$' --format '{{.Names}}')
    if ($left -eq 'cvr-zap') { & docker rm -f cvr-zap | Out-Null }
}
Write-Host "ZAP finished with exit code $zapExit (0 = no alerts, 1 = failures, 2 = warnings; -I makes warnings non-fatal)."

# Scrub: token values and session ids must not stay in the repository.
foreach ($f in 'zap-baseline.html', 'zap-baseline.json', 'zap-baseline.md', 'zap-console.txt') {
    $p = Join-Path $outDir $f
    if (-not (Test-Path -LiteralPath $p)) { continue }
    $t = [IO.File]::ReadAllText($p)
    $t = [regex]::Replace($t, '(?i)(name=\\?"_csrf\\?"[^>]{0,80}?value=\\?")[^"\\]+', '$1[SCRUBBED]')
    $t = [regex]::Replace($t, '(?i)(value=\\?")[^"\\]+(\\?"[^>]{0,80}?name=\\?"_csrf)', '$1[SCRUBBED]$2')
    $t = [regex]::Replace($t, '(?i)JSESSIONID=[A-Za-z0-9._-]+', 'JSESSIONID=[SCRUBBED]')
    [IO.File]::WriteAllText($p, $t)
}
Write-Host "Reports written to docs\evidence\dast\ (started $started). Next: read them, triage every alert, write docs\assurance\dast.md."
