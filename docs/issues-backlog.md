# Issues & Technical Debt Backlog

This backlog tracks identified technical debt, deferred security enhancements, and upcoming architectural milestones.

## Phase 2 Authentication & Performance Notes

5. **Argon2id Memory Cost (64 MiB) vs. Constrained JVM Heap (384 MB)**:
   - **Current Configuration**: Argon2id password hashing enforces `memory = 65,536 KiB` (64 MiB) per verification operation (matching OWASP Cryptographic Storage recommendations and Hard Rule 10).
   - **Risk Analysis**: In environments where JVM maximum heap is constrained to 384 MB (e.g. small container instances), concurrent login attempts can place significant pressure on heap memory:
     - 4 concurrent Argon2id computations allocate `4 * 64 MB = 256 MB` off-heap / native memory buffer.
     - Under a burst of simultaneous login requests or automated brute-force attacks, memory pressure could lead to `OutOfMemoryError` or heavy GC pauses if JVM heap + native memory exceeds container cgroup limits.
   - **Mitigation & Architectural Roadmap**:
     - *Immediate*: Account lockout after 5 failures and IP rate limiting at reverse proxy ingress mitigate automated concurrent flood attacks.
     - *Container Sizing*: Production container specifications must provision at least 1 GB RAM (e.g., `-Xmx512m` plus native off-heap buffer margin) to support concurrent legitimate authentications safely.
     - *Alternative/Scale*: If deployed in severely constrained environments (< 512 MB total RAM), parameter tuning to `memory = 32,768 KiB` (32 MiB) with 4 iterations should be evaluated and documented via an ADR amendment.
