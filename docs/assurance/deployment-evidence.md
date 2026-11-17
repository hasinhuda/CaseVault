# Deployment evidence: backup, restore, rollback (Stage B) - DRAFT

Date of the run: 2026-11-13, local Docker Desktop, project `casevault-rebuild`, `https://localhost:8443`. Image built from the repository state after the Stage A fixes. All data are synthetic; the evidence files are scrubbed (no passwords, passphrase, keys, session ids or CSRF tokens; hashes shortened to 12 hex characters). The backup itself is under `.local-data/backups/` and is git-ignored (checked with `git check-ignore`).

## 1. What was built

| Item | Path | Purpose |
|---|---|---|
| Backup script | [scripts/backup.ps1](../../scripts/backup.ps1) | Consistent encrypted backup of database, evidence volume and key volume with a SHA-256 manifest |
| Restore script | [scripts/restore.ps1](../../scripts/restore.ps1) | Manifest-first, refuses overwriting, needs `-Confirm`, only project `casevault-rebuild` |
| Shared helpers | [scripts/backup-common.ps1](../../scripts/backup-common.ps1) | Encryption tool choice, SecureString handling, helper containers |
| Rollback switch | [deploy/compose.yaml](../../deploy/compose.yaml) (`image: ${CVR_APP_IMAGE:-cvr-app:dev}`), [scripts/deploy-up.ps1](../../scripts/deploy-up.ps1) (tag check) | One-command switch between local `cvr-app:` tags |
| Runbooks | [runbook-local.md](../runbook-local.md), [runbook-ops.md](../runbook-ops.md) | How to run and operate |

Design decisions: the application is stopped for a few seconds during the backup so that the database and the evidence files are from the same moment; `pg_dump` runs inside `cvr-db` over the local socket, so the database password is never read; helper containers run with `--rm`, no network, all capabilities dropped, a memory limit and only one `cvr_` volume each; encryption is GnuPG symmetric AES-256 with integrity protection (the manifest records the tool; with only `openssl enc` the archive would be AES-256-CBC, which is not authenticated, and the script says so); the passphrase is a SecureString handed to the tool through standard input, never an argument or a file; restore never overwrites existing data.

## 2. Steps and results

| # | Step | Result | Evidence |
|---|---|---|---|
| 1 | Stack from scratch: `deploy-down -RemoveData`, `deploy-up -Build -FirstRun`, credentials read only inside a helper container | PASS (all three containers healthy) | [11-backup.txt](../evidence/deploy/11-backup.txt) |
| 2 | Through nginx with `curl.exe` (CSRF token from the page): create case (client), upload a one-line synthetic text file (client), add note (manager) | PASS (302, 302, 302; note visible) | [11-backup.txt](../evidence/deploy/11-backup.txt) |
| 3 | Baseline: four logins, case visible, download SHA-256 equals upload SHA-256 (`7a00d2cf5f54...`), auditor chain verification | PASS (Chain valid, 13 events) | [11-backup.txt](../evidence/deploy/11-backup.txt) |
| 4 | `scripts\backup.ps1` | PASS (gpg, 8582-byte encrypted file, manifest written) | [11-backup.txt](../evidence/deploy/11-backup.txt) |
| 5 | Simulate the failure: `scripts\deploy-down.ps1 -RemoveData` | PASS (no `cvr-` containers, no `cvr_` volumes) | [12-failure-and-refused-restores.txt](../evidence/deploy/12-failure-and-refused-restores.txt) |
| 6 | Restore without `-Confirm` | PASS (dry run only) | same |
| 7 | Restore of a copy with one flipped byte | PASS (refused: manifest hash mismatch, nothing created) | same |
| 8 | Restore with a wrong passphrase | PASS (refused: decryption failed, nothing created) | same |
| 9 | `scripts\restore.ps1 -Confirm`, stack started WITHOUT the first-run override | PASS (healthy; no bootstrap variable; no first-run log line; no `cvr_firstrun` volume) | [13-restore-integrity.txt](../evidence/deploy/13-restore-integrity.txt) |
| 10 | Integrity proof: four users log in, case, note and evidence exist, download SHA-256 identical (`7a00d2cf5f54` = `7a00d2cf5f54`), audit chain valid (22 events) | PASS | same |
| 11 | Negative control: key files missing from the key volume | PASS as a control (evidence download 404, audit chain BROKEN) | [14-negative-control.txt](../evidence/deploy/14-negative-control.txt) |
| 12 | Clean-up of the control by a second full restore of the same backup, integrity script again | PASS (identical hash, Chain valid, 22 events) | same |
| 13 | `docker tag` `cvr-app:prev`, build `cvr-app:next` (one build label differs), upgrade, rollback with one command | PASS | [15-rollback.txt](../evidence/deploy/15-rollback.txt) |

Image ids (first 12 characters): before `50e007d926bf`; after the upgrade `77537536641d` (configured as `cvr-app:next`); after the rollback `50e007d926bf` (configured as `cvr-app:prev`, the same image as before). The default compose configuration still resolves to `cvr-app:dev` when `CVR_APP_IMAGE` is not set (shown in the evidence file). After the rollback the integrity script passed again (Chain valid).

## 3. What the demonstration shows and what it does not

Shows: the backup contains everything needed to rebuild the stack on the same host (database, encrypted evidence, both keys); restore detects a changed or wrong archive before touching Docker; a restore reproduces users, case, note, evidence bytes and a verifiable audit chain; the key volume is essential (control); the application container can be switched to a previous local image with one command.

Does not show / limits:

- Flyway migrations are forward-only. The rollback test used two images from the same source (they differ only by a label), so it proves the image switch but NOT a rollback across a schema change. For that case the documented way back is restore from the pre-upgrade backup, which loses newer data. This was not tested with a real migration.
- The backup was restored on the same machine and the same Docker volumes layout. A restore on a different machine, a different PostgreSQL major version or a different CPU architecture was not tested.
- The backup is encrypted but its passphrase handling is manual. No automated schedule, no off-host copy, no retention policy exist. The database password and TLS files are not part of the backup (stated in the runbook).
- The audit chain was valid after restore because the HMAC key was restored together with the database. A backup of the database alone would not verify. Tail truncation of the audit log is still not detected without an external copy of the chain head (known limitation).
- The backup demo used a passphrase supplied by a local harness (a SecureString object created by a scratch script, kept DPAPI-protected under `.local-data/`); the interactive prompt path is implemented but was not exercised in this run (NOT VERIFIED).
- The helper containers use the application image (`cvr-app:dev`) because it contains `tar`; `pg_dump` and `pg_restore` run inside `cvr-db`.
- Docker Desktop on Windows: file ownership inside the volumes was handled by Docker's initial copy from the image; behaviour on a Linux host was not tested.

## 4. Issues met while doing this (honest log)

- GNU `tar` from Git for Windows reads `C:` as a host name; the script now uses relative paths inside the work folder (works with both `tar` flavours).
- A first demonstration attempt left an extra case and two uploads while I debugged the CSRF token source; the stack was reset with `deploy-down -RemoveData` and the demonstration redone from scratch, so the evidence shows one clean run. The cause was my own scratch script (a PowerShell 5.1 detail: `"$id?x"` reads `?` as part of the variable name), not the application.
- The negative control wrote new audit events signed with a new key, so moving the old keys back would not repair the chain; the state was discarded and restored again from the backup (which also proves that a backup restores more than once).
