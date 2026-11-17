# Operations runbook (DRAFT)

For the hardened Docker stack `casevault-rebuild` on one machine. This is a coursework-scale runbook for a single host: it describes what exists and says clearly what does not exist. All commands are PowerShell, run from the repository root. Every script refuses any compose project other than `casevault-rebuild`.

## 1. Start, stop, status, logs

| Task | Command |
|---|---|
| Start (normal) | `scripts\deploy-up.ps1` |
| Start and rebuild the image | `scripts\deploy-up.ps1 -Build` |
| Stop and remove containers, keep data | `scripts\deploy-down.ps1` |
| Status and hardening settings | `scripts\deploy-status.ps1` |
| Application log (last lines) | `docker logs cvr-app --tail 100` |
| Proxy / database log | `docker logs cvr-nginx --tail 100`, `docker logs cvr-db --tail 100` |

Logs carry a correlation id per request (`[cid=...]`). They contain no passwords, tokens or file contents (checked by tests and by the Phase 9 log review).

## 2. First run and accounts

First start only: `scripts\deploy-up.ps1 -Build -FirstRun`, read the one-time credentials inside a container (see [runbook-local.md](runbook-local.md) section 3), then `scripts\deploy-up.ps1 -FinishFirstRun`. After that the stack must never again be started with the first-run override: restoring a backup and normal starts use the base file only. Change the initial passwords after the first login (password policy applies).

## 3. Certificate regeneration

The TLS certificate is self-signed for `localhost` and lives in `.local-data\deploy\tls\`. To replace it: `scripts\deploy-init.ps1 -Force` (this also replaces the database password file, which would no longer match the password inside an existing database, so do NOT use `-Force` on a stack with data; instead delete only `tls.crt` and `tls.key` and run `scripts\deploy-init.ps1`, which creates missing files without touching the others), then `scripts\deploy-down.ps1` and `scripts\deploy-up.ps1`. A real deployment would use a certificate from a trusted authority (not done here).

## 4. Safe reset

A reset deletes all data. Before it: `scripts\backup.ps1` (section 5) unless the data are disposable. Then `scripts\deploy-down.ps1 -RemoveData`, which removes only the containers and the four `cvr_` volumes of this project. Do not use `docker system prune`, `docker volume prune` or `docker compose down -v` by hand: they can touch other projects on the same Docker host.

## 5. Backup

```powershell
scripts\backup.ps1
```

Prompts for a passphrase (at least 12 characters, asked twice, typed hidden). It stops `cvr-app` for a few seconds, dumps PostgreSQL (`pg_dump` inside `cvr-db`), archives the evidence volume and the key volume with throw-away helper containers, packs the three parts and encrypts the pack. Result: `.local-data\backups\<UTC timestamp>\payload.tar.enc` and `manifest.json` (SHA-256 of the encrypted file and of each part; no secret). Encryption is GnuPG symmetric AES-256 with an integrity check when `gpg` is available; otherwise `openssl enc` AES-256-CBC, which is NOT authenticated (the manifest says which was used; only the SHA-256 checks then detect tampering).

What is NOT in the backup: the database password and the TLS key/certificate (`.local-data\deploy\`, back them up separately and keep them off the same disk as the data), and the passphrase. Without the passphrase a backup cannot be read: store it in a password manager, not next to the backup.

Schedule (a recommendation, not an automated job): the application has no scheduler for backups. For a real use run `scripts\backup.ps1` from Windows Task Scheduler daily and before every upgrade, copy the folder to a second device, and test a restore at least monthly. The script currently asks for a passphrase interactively, so an unattended schedule needs a decision about where that secret lives (VERIFY MANUALLY before relying on it).

## 6. Restore

```powershell
scripts\deploy-down.ps1 -RemoveData                       # only if the old data must be discarded (it is destroyed)
scripts\restore.ps1 -BackupFolder <timestamp>             # dry run, explains what it would do
scripts\restore.ps1 -BackupFolder <timestamp> -Confirm    # restore
```

The script verifies the manifest against the encrypted file BEFORE decrypting and each part AFTER decrypting; any mismatch stops it before Docker is touched. It refuses to run while `cvr-` containers or the volumes `cvr_pgdata`, `cvr_evidence`, `cvr_keys` exist, and it starts the stack without the first-run override. Afterwards log in, open a case, download an evidence file and run the audit verification as the auditor. Evidence of the whole sequence: [evidence/deploy/11 to 14](evidence/deploy/).

## 7. Upgrade and rollback of the application image

```powershell
scripts\backup.ps1                                        # always first
docker tag cvr-app:dev cvr-app:prev                       # keep the running image as the rollback target
scripts\deploy-up.ps1 -Build                              # build the new cvr-app:dev and start it
```

Rollback (one command, switches the application container to the kept image; the proxy and the database are untouched):

```powershell
$env:CVR_APP_IMAGE = 'cvr-app:prev'; scripts\deploy-up.ps1
```

`deploy\compose.yaml` reads `image: ${CVR_APP_IMAGE:-cvr-app:dev}`, so without the variable nothing changes. The script accepts only tags of the form `cvr-app:<tag>`. Remove the variable (`Remove-Item Env:CVR_APP_IMAGE`) to return to `cvr-app:dev`.

Limit, stated plainly: **database migrations (Flyway) are forward-only.** If the new image applied a migration, the old image runs against a newer schema and may fail. The image rollback only helps when the new version made no schema change; otherwise the way back is `scripts\restore.ps1` from the backup taken before the upgrade (data written since are lost). The demonstration used two images from the same source (differing by one label) and therefore proves the switch, not a schema rollback ([evidence/deploy/15-rollback.txt](evidence/deploy/15-rollback.txt)).

## 8. Key handling

| Key | Where | Notes |
|---|---|---|
| Evidence keyset (Tink AES-256-GCM) | Docker volume `cvr_keys`, `evidence-keyset.json` | Stored as a cleartext keyset file readable by the application user (a limit in [known-limitations.md](assurance/known-limitations.md)). Loss = every evidence file is unreadable. |
| Audit HMAC key | volume `cvr_keys`, `audit-hmac.key` | Loss or change = the audit chain no longer verifies. |
| Database password | `.local-data\deploy\secrets\db_password.txt` | Mounted as a secret file; not in the environment, not in logs. |
| TLS key | `.local-data\deploy\tls\tls.key` | Self-signed, local only. |
| Backup passphrase | your password manager | Not stored by any script. |

**There is no automated key rotation.** Rotating the evidence keyset or the audit key is not implemented (the keyset format supports adding keys, the application does not do it; rotating the audit key would need a documented re-anchoring of the chain). Rotating the database password means changing it in PostgreSQL and in the secret file together. These are manual, undocumented-by-test procedures: VERIFY MANUALLY before any use.

## 9. Incident steps (first hour, single host)

1. Contain: `scripts\deploy-down.ps1` (keeps data) to stop access, or disable the affected account as the auditor-admin in the application.
2. Preserve: `scripts\backup.ps1` of the current state before changing anything, and copy `docker logs` of the three containers to a file outside the repository.
3. Look: the audit log (login failures, lockouts, disables, downloads, status changes) as `admin_auditor`; run "Verify chain" and note the result and the head. A broken chain is itself an incident.
4. Revoke: disable accounts and revoke sessions in the admin screen; rotate the database password and reset user passwords if credential theft is suspected.
5. Recover: restore from the last good backup (section 6) if data were damaged; accept that events after the backup are lost.
6. Report: write down time, what was seen, what was done. (There is no alerting; nobody is paged.)

## 10. Logs and monitoring: what exists and what does not

Exists: structured application log lines with correlation ids; health endpoint `/actuator/health` (status only; the container health checks use it); the tamper-evident audit log with an on-demand chain verification; rate-limit WARN lines (one per window per limiter); nginx access and error logs in the container; scripted status and verification (`deploy-status.ps1`, `deploy-verify.ps1`).

Does not exist: central log collection or retention policy; metrics and dashboards; alerting or paging; automatic anomaly detection; external copy of the audit chain head (so deletion of the newest audit events is not detected unless you compare the head with a copy you stored yourself); uptime monitoring; log rotation configured beyond the Docker defaults; automated backups; automated restore tests.
