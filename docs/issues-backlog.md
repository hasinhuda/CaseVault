# Issues & Technical Debt Backlog

This backlog tracks identified technical debt, deferred security enhancements, and upcoming architectural milestones.

## Phase 2 Authentication & Performance Notes

1. **Argon2id Memory Cost (64 MiB) vs. Constrained JVM Heap (384 MB)**:
   - **Current Configuration**: Argon2id password hashing enforces `memory = 65,536 KiB` (64 MiB) per verification operation (matching OWASP Cryptographic Storage recommendations and Hard Rule 10).
   - **Risk Analysis**: In environments where JVM maximum heap is constrained to 384 MB (e.g. small container instances), concurrent login attempts can place significant pressure on heap memory:
     - 4 concurrent Argon2id computations allocate `4 * 64 MB = 256 MB` off-heap / native memory buffer.
     - Under a burst of simultaneous login requests or automated brute-force attacks, memory pressure could lead to `OutOfMemoryError` or heavy GC pauses if JVM heap + native memory exceeds container cgroup limits.
   - **Mitigation & Architectural Roadmap**:
     - *Immediate*: Account lockout after 5 failures and IP rate limiting at reverse proxy ingress mitigate automated concurrent flood attacks.
     - *Container Sizing*: Production container specifications must provision at least 1 GB RAM (e.g., `-Xmx512m` plus native off-heap buffer margin) to support concurrent legitimate authentications safely.
     - *Alternative/Scale*: If deployed in severely constrained environments (< 512 MB total RAM), parameter tuning to `memory = 32,768 KiB` (32 MiB) with 4 iterations should be evaluated and documented via an ADR amendment.

## Phase 3 Authorisation Technical Debt

2. **Spring Security Deprecated AntPathRequestMatcher in SecurityConfig**:
   - **Current Configuration**: `SecurityConfig` employs `AntPathRequestMatcher.antMatcher("/api/**")` within `DelegatingAuthenticationEntryPoint` to route unauthenticated API requests to `HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)`.
   - **Status**: In Spring Security 6.5.x, `AntPathRequestMatcher` is marked `@Deprecated(forRemoval = true)`. The emerging replacement is `PathPatternRequestMatcher` (`org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher.withDefaults().matcher("/api/**")`).
   - **Deferred Action**: To avoid regressions or behavioral mismatches during Phase 3 authorisation baseline stabilization, `AntPathRequestMatcher` is intentionally retained. Migration to `PathPatternRequestMatcher` is scheduled for refactoring alongside Spring Boot 3.5.x patch upgrades before Phase 6 production hardening.

## Phase 4 Case Workflow & UI Technical Debt

3. **`remediation_actions` Schema Missing `title` and `target_date` Columns (FR-07)**:
   - **Current State**: FR-07 specifies "title, target date, and completion status" for remediation actions. The V4 migration only has `description`, `status`, and `created_at`. The `title` and `target_date` columns are absent.
   - **Impact**: Minimal for the current workflow phase; `description` serves as a combined title/description field. A future migration should add `title VARCHAR(200)` and `target_date TIMESTAMP NULL` if the full FR-07 specification is required.
   - **Deferred Action**: Add columns via a new Flyway migration (V5 or later) when the full remediation tracking UI is implemented.

4. **CLIENT Read Access to Notes and Remediation Actions (FR-07 Clarification)**:
   - **Current State**: FR-07 states notes and actions are authored by ANALYST and MANAGER. Whether CLIENTs may _read_ notes and actions on their own cases is not explicitly stated. The current implementation blocks CLIENT from reading notes and actions (they can only see the case overview).
   - **Deferred Action**: VERIFY MANUALLY with product owner whether CLIENT should have read-only access to case notes and remediation actions. If yes, update `CaseWebController` to show read-only tabs.
# Evidence backlog (DRAFT)

- Antivirus scanning is a deterministic synthetic-only stub; integrate an approved scanner before production use.
- AES-GCM processing holds evidence in memory and is limited to 10 MB; use streaming encryption for larger files.
- Storage is local single-node filesystem storage; production needs resilient managed storage.
- Retention and deletion workflows are not yet implemented.
- The cryptographic audit chain remains pending for Phase 6; the current recorder logs minimal metadata only.
