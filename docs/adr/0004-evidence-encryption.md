# ADR 0004: Digital Evidence Storage & Envelope Encryption at Rest

## Status
Accepted

## Context
CaseVault accepts and stores sensitive digital evidence artifacts (disk images, network captures, memory dumps, forensic logs) uploaded by clients and incident response analysts. Exposure of these artifacts—whether via physical disk theft, unencrypted backup snapshots, directory traversal vulnerabilities, or cloud storage misconfiguration—constitutes a critical data breach and compromises ongoing forensic investigations and legal proceedings.
Under Hard Rule 1 and Hard Rule 7, no custom cryptographic algorithms may be used, no real malware is permitted, and encryption keys must never be stored in source code or Git history.

## Decision
1. **Google Tink Envelope Encryption**:
   - Digital evidence binaries are encrypted at rest using **Google Tink**.
   - Algorithm: **AES-256-GCM** authenticated encryption with associated data (AEAD).
   - Envelope encryption model: Each uploaded evidence artifact is encrypted before being written to persistent storage.
2. **Storage Location Outside Web Root**:
   - Encrypted artifacts are stored in a dedicated local or mounted volume directory (configured via `casevault.storage.evidence-dir`) located strictly outside the web application document root and classpath.
   - Files on disk are stored with UUID-derived filenames containing solely ciphertext; no original file extensions or cleartext filenames exist on the filesystem.
3. **Key Management & Storage**:
   - Keyset files are stored in git-ignored directories (`.local-data/keyset.json` or `secrets/keyset.json`).
   - If keyset files do not exist at application startup, the application bootstrap routine dynamically generates a new secure keyset using Tink's `AeadKeyTemplates.AES256_GCM` and persists it with restricted file permissions (`600` / owner-only).
   - Keys are never logged, printed, or transmitted to clients.
4. **Pre-Encryption Validation (MIME & Antivirus Stub)**:
   - Before encryption, the upload stream is inspected using **Apache Tika** for magic-byte verification.
   - Files disguised with fraudulent extensions (e.g., `.exe` renamed to `.png`) are rejected immediately.
   - SVG files and executable formats (`.exe`, `.sh`, `.bat`, `.ps1`, `.jar`, `.php`, `.jsp`) are strictly prohibited.
   - An antivirus scanning stub performs synthetic-only signature checks.
5. **Decryption and Streaming Download**:
   - Decryption occurs exclusively in-memory upon authorized request.
   - Files are served via `StreamingResponseBody` with defensive HTTP headers:
     - `Content-Disposition: attachment; filename="<sanitized-filename>"`
     - `X-Content-Type-Options: nosniff`
     - `Content-Security-Policy: default-src 'none'`
   - Plaintext evidence is never cached or written to temporary unencrypted disk locations.

## Implementation note (Phase 5 DRAFT)

The current implementation uses Tink AES-256-GCM with associated data formed from the case ID and evidence ID. It stores a randomly generated stored name only, verifies a JDK SHA-256 value after decryption, and uses download headers for attachment, `nosniff`, and `no-store`.

Residual risk: this prototype stores the Tink keyset beside (but outside) the encrypted evidence directory under `.local-data/keys/`. Owner-only POSIX permissions are requested where supported. A production deployment needs a KMS or externally supplied master key; local keyset storage alone does not provide that separation.

## Consequences
- **Positive**:
   - Strong authenticated encryption (AES-256-GCM) ensures confidentiality and detects disk tampering.
   - Decoupled key management ensures physical disk compromise or backup exposure yields only unreadable ciphertext.
   - Use of audited, standard Google Tink libraries adheres to the zero-custom-crypto mandate.
- **Negative / Trade-offs**:
   - In-memory AEAD encryption requires buffer management for large evidence files (chunked streaming or Tink Streaming AEAD should be adopted if file sizes exceed single-buffer limits).
   - Backup workflows must preserve both the encrypted evidence volume and the corresponding keyset securely.

## Compliance & Standards Mapping
- **OWASP Top 10**:
  - OWASP Top 10:2025 [VERIFY MANUALLY]: A02 (Cryptographic Failures), A04 (Insecure Design)
  - OWASP Top 10:2021: A02:2021 (Cryptographic Failures), A04:2021 (Insecure Design)
- **CWE**:
  - CWE-311: Missing Encryption of Sensitive Data
  - CWE-327: Use of a Broken or Risky Cryptographic Algorithm (mitigated: AES-256-GCM via Tink)
  - CWE-434: Unrestricted Upload of File with Dangerous Type (mitigated: Apache Tika magic-byte check)
- **ASVS 5.0**:
  - V6 Cryptographic Verification (V6.2.1, V6.2.2 [VERIFY MANUALLY])
  - V12 File and Resource Verification (V12.1.1, V12.1.2 [VERIFY MANUALLY])
