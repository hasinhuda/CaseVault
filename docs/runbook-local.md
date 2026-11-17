# Local runbook (DRAFT)

How to run CaseVault on a developer machine (Windows, PowerShell). Two ways: the fast in-memory way for development and browser tests, and the hardened Docker stack that is closest to a deployment. Everything is synthetic; nothing here is production.

## 1. Requirements

- Java 21 and the Maven wrapper (`.\mvnw.cmd`, no Maven install needed).
- Docker Desktop for the hardened stack and for the PostgreSQL tests (Testcontainers). Without Docker the Postgres tests cannot run.
- `curl.exe` (ships with Windows) for the command-line checks. Git for Windows provides `openssl.exe` and `gpg.exe`, which the backup script uses.

## 2. Fast local run (profile `local`, in-memory H2, plain http)

```powershell
.\mvnw.cmd spring-boot:run "-Dspring-boot.run.profiles=local"
```

Open `http://localhost:8080/login`. The profile creates the four standard accounts plus demo data with random passwords, printed once in the console and written to `.local-data/bootstrap-credentials.txt` (git-ignored). The database is in memory: stopping the application deletes everything. The session cookie is not `Secure` in this profile because it is plain http (the only place this is allowed; the Secure flag is proven by test for the other profiles).

## 3. Hardened Docker stack (project `casevault-rebuild`)

Containers `cvr-db` (PostgreSQL), `cvr-app` (the application), `cvr-nginx` (TLS). Only nginx is published, on `127.0.0.1:8443`. Design and limits: [deployment-hardening.md](assurance/deployment-hardening.md), [ADR 0009](adr/0009-deployment-configuration.md).

```powershell
scripts\deploy-init.ps1                 # once: database password and a self-signed certificate under .local-data\deploy (git-ignored)
scripts\deploy-up.ps1 -Build -FirstRun  # build the image and start; creates the four accounts ONCE
```

The initial passwords are written only to the Docker volume `cvr_firstrun` (file `initial-credentials.txt`). They are never printed by the scripts. Read them only when you need them and only inside a container, for example (prints the file; do it in a private terminal):

```powershell
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true -v cvr_firstrun:/d:ro --entrypoint cat cvr-app:dev /d/initial-credentials.txt
```

Log in at `https://localhost:8443/login` (the browser warns about the self-signed certificate: expected, the certificate belongs to this machine only). Then finish the first run, which restarts the application without the override and deletes the credentials file:

```powershell
scripts\deploy-up.ps1 -FinishFirstRun
```

Check and stop:

```powershell
scripts\deploy-status.ps1               # containers, health, ports, hardening settings
scripts\deploy-verify.ps1               # scripted checks that also write scrubbed evidence (see its header before running)
scripts\deploy-down.ps1                 # remove containers, KEEP data
```

`scripts\deploy-down.ps1 -RemoveData` also deletes the four data volumes. That destroys the database, the evidence files and the keys. Use it only for a deliberate reset (section 4 of [runbook-ops.md](runbook-ops.md) explains how to do it safely).

## 4. Tests and quality gates

```powershell
.\mvnw.cmd -B verify                                              # tests, JaCoCo, SpotBugs/FindSecBugs, Enforcer, SBOM
.\mvnw.cmd -B verify "-Dsurefire.runOrder=reversealphabetical"    # same, other test order (finds order dependence)
```

Use `verify`, not only `test`: the coverage and SpotBugs gates run in `verify`. Postgres tests need Docker running; a skipped count above zero means they did not run.

## 5. Where things are

| What | Where |
|---|---|
| Generated secrets, keys, backups, local credentials | `.local-data/` (git-ignored; never commit) |
| Deployment evidence (scrubbed) | `docs/evidence/deploy/` |
| Operations (backup, restore, rollback, incidents) | [runbook-ops.md](runbook-ops.md) |
| Known limitations and accepted risks | [assurance/known-limitations.md](assurance/known-limitations.md) |
