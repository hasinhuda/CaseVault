# ADR 0009: Deployment configuration - secrets via files, proxy trust, initial accounts opt-in

## Status
Accepted (Phase 12A, DRAFT). The reverse proxy and compose file are Phase 12B and are not built yet.

## Context
The prod-like profile had a default database password, a comment that claimed TLS the application does not provide, no way to create a first administrator, and no awareness of a reverse proxy (all clients would share one rate-limit bucket).

## Decision
1. **Database credentials.** No default password. The profile reads `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_DB`, `POSTGRES_USER` and `POSTGRES_PASSWORD` (or Spring's `SPRING_DATASOURCE_PASSWORD`). A Docker/Compose secret is read through Spring Boot's configtree import (`spring.config.import=optional:configtree:/run/secrets/`): a file `/run/secrets/spring.datasource.password` supplies `spring.datasource.password`. A start-up check (`ProdLikeConfigurationCheck`) fails the start before any bean exists if no password is provided. An explicitly empty password is not rejected (the existing guard tests use H2 with an empty one); PostgreSQL decides whether that is acceptable.
2. **Proxy trust.** The application listens on plain HTTP on internal port 8080 and does not terminate TLS. `server.forward-headers-strategy=native` makes Tomcat believe `X-Forwarded-For`, `-Proto`, `-Host` and `-Port` only from internal proxy addresses (private and loopback ranges by default; narrow with `server.tomcat.remoteip.internal-proxies`). The client address is the right-most address that is not an internal proxy. The existing limiter flag `casevault.ratelimit.trust-forwarded-for` stays false in prod-like and the application refuses to start if it is combined with `native` or `framework`.
3. **Initial accounts.** `casevault.bootstrap.initial-accounts-enabled` (default false, prod-like only) with `casevault.bootstrap.initial-credentials-file` (no default). Runs only when no user exists, through the existing bootstrap path: the four standard accounts, no demo data, `generateSecurePassword`, Argon2id hashes, passwords only in the file with owner-only permissions where supported, nothing printed or logged. Missing path: the application refuses to start. File write failure: the transaction rolls back, no accounts remain.
4. **Health.** `GET /actuator/health` without authentication answers `200 {"status":"UP"}` and `GET /actuator/info` answers `200 {}` (no components, details, paths or versions; test PROXY-05). The container healthcheck can use the health URL; whether the runtime image contains `curl` or `wget` is UNCONFIRMED (checked in Phase 12B).

## Threats considered
| Threat | Control | Residual risk |
|---|---|---|
| Spoofed `X-Forwarded-For` to choose the limiter key or evade lockout of an address | Native strategy: only internal proxies are believed; right-most non-proxy address; spoofed prefixes ignored (PROXY-03); flag/strategy combination refused (DEPLOY-PROXY-01) | If the proxy APPENDS instead of overwriting and the real client has a private address, the left-most entry is believed (PROXY-04 documents the overwrite case; an experiment showed the append case). The proxy must overwrite and the app port must not be published. Direct internet clients are not believed because their address is not an internal proxy |
| Spoofed `X-Forwarded-Proto` / `-Host` | Same trust rule | A published app port inside a private network would trust private-range callers |
| Credential file exposure (initial accounts) | Owner-only permissions where supported; never logged; one-time; delete after first login; path must be given explicitly | Windows hosts do not get POSIX permissions (best effort); no password change feature exists, so the initial passwords remain valid until one is built |
| Opt-in left enabled in production | Default false; only acts when no user exists; prod-like only; a documented step: unset the flag after the first start | An operator can still forget the flag; it does nothing once users exist |
| Default or guessable database password | No default; fail-fast check; secret files via configtree | Password is in an environment variable or a file on the host; no rotation; no secret manager |

## Consequences
- Compose (Phase 12B) must publish only the proxy, mount the secret as `spring.datasource.password`, set `SPRING_PROFILES_ACTIVE=prod-like`, and the proxy must set the headers and overwrite `X-Forwarded-For` with `$remote_addr`.
- Environment variable names proven by `DeploymentEnvironmentNamesTest`: `CASEVAULT_BOOTSTRAP_INITIAL_ACCOUNTS_ENABLED`, `CASEVAULT_BOOTSTRAP_INITIAL_CREDENTIALS_FILE`, `POSTGRES_PASSWORD`, `SPRING_DATASOURCE_PASSWORD`, `SPRING_PROFILES_ACTIVE`.
- Related findings: F-014, F-015, F-016 (`docs/assurance/findings-log.md`).
