# Data Flow Specification: CaseVault

## 1. Overview
This document models data movement across CaseVault's trust boundaries during key operations: authentication, case management, evidence upload/encryption, evidence download/decryption, and audit logging.

---

## 2. Global Data Flow Diagram (DFD)

> **As built vs target.** The "TLS Ingress or Reverse Proxy" node (Trust Boundary 1) is a **TARGET (not built in this submission)**: the application is reached over plain HTTP. All other nodes exist in the code. The key store is a file next to the data, not a separate service. See [known-limitations.md](assurance/known-limitations.md).

```mermaid
flowchart TD
    subgraph External["Untrusted External Zone"]
        User["User Browser"]
    end

    subgraph Boundary1["Trust Boundary 1: Transport and Network"]
        TLS["TLS Ingress or Reverse Proxy - TARGET (not built)"]
    end

    subgraph Boundary2["Trust Boundary 2: Application Context"]
        SecFilter["Security Filter and CSRF Validator"]
        Controller["Web and REST Controllers"]
        CaseService["Case Management Service"]
        EvidenceService["Evidence Service"]
        AuditService["Audit Chaining Service"]
        CryptoService["Tink and Argon2id Crypto Engine"]
    end

    subgraph Boundary3["Trust Boundary 3: Persistent Storage"]
        DB[("PostgreSQL Database")]
        Storage[("Encrypted File Storage")]
        KeyDir[("Local Key Store in .local-data/")]
    end

    User -->|1. HTTP Request with Session or Credentials| TLS
    TLS -->|2. Clear Request Internal| SecFilter
    SecFilter -->|3. Validated Principal| Controller
    Controller -->|4. DTO Command| CaseService
    Controller -->|4b. Multipart Upload| EvidenceService

    CaseService -->|5. Record State Change| DB
    CaseService -->|6. Trigger Audit Event| AuditService

    EvidenceService -->|7. Send Binary for Encryption| CryptoService
    CryptoService -->|8. Read Keyset| KeyDir
    CryptoService -->|9. Write AES-256-GCM Ciphertext| Storage
    EvidenceService -->|10. Store File Metadata and SHA-256| DB

    AuditService -->|11. Fetch Previous HMAC and Compute New Hash| DB
```

---

## 3. Sequence Flows Across Boundaries

### 3.1 Authentication & Session Issuance Flow

```mermaid
sequenceDiagram
    autonumber
    actor User as User Browser
    participant Sec as Security Filter
    participant Auth as AuthService
    participant Hash as Argon2id Engine
    participant DB as PostgreSQL DB
    participant Audit as AuditService

    User->>Sec: POST /login (username, password, CSRF)
    Sec->>Auth: authenticate(username, password)
    Auth->>DB: findByUsername(username)
    DB-->>Auth: UserRecord (hash, salt, attempts, lockedUntil)
    Auth->>Hash: verify(rawPassword, storedHash)
    Hash-->>Auth: boolean isValid
    alt Valid Credentials & Account Not Locked
        Auth->>DB: resetFailedAttempts(userId)
        Auth->>Audit: logEvent("AUTH_LOGIN_SUCCESS", userId)
        Auth-->>Sec: AuthenticationSuccess
        Sec-->>User: Set-Cookie (JSESSIONID; HttpOnly; SameSite=Strict; Secure)
    else Invalid Credentials or Locked
        Auth->>DB: incrementFailedAttempts(userId)
        Auth->>Audit: logEvent("AUTH_LOGIN_FAILURE", username)
        Auth-->>Sec: AuthenticationException
        Sec-->>User: HTTP 401 (Generic error message; uniform timing)
    end
```

---

### 3.2 Evidence Upload & Encryption Flow (Tink AES-256-GCM AEAD)

```mermaid
sequenceDiagram
    autonumber
    actor Client as Authenticated Client/Analyst
    participant Ctrl as EvidenceController
    participant Tika as Apache Tika Validator
    participant Svc as EvidenceService
    participant Tink as Google Tink (AES-256-GCM)
    participant Disk as File System Storage
    participant DB as PostgreSQL DB
    participant Audit as AuditService

    Client->>Ctrl: POST /cases/{id}/evidence (file binary, description)
    Ctrl->>Svc: uploadEvidence(caseId, file)
    Svc->>Svc: verifyCallerTenant(caseId)
    Svc->>Tika: inspectMagicBytes(inputStream)
    alt Invalid MIME or Executable
        Tika-->>Svc: Disallowed File Type
        Svc-->>Ctrl: ValidationException
        Ctrl-->>Client: HTTP 400 (Invalid file format)
    else Valid Binary (Document/Data)
        Tika-->>Svc: Verified MIME
        Svc->>Tink: encrypt(rawBytes)
        Tink-->>Svc: ciphertextBytes
        Svc->>Disk: writeCiphertext(storagePath, ciphertextBytes)
        Svc->>DB: insertEvidenceRecord(id, caseId, sha256, storagePath, size)
        Svc->>Audit: logEvent("EVIDENCE_UPLOAD", evidenceId)
        Svc-->>Ctrl: EvidenceResponseDTO
        Ctrl-->>Client: HTTP 201 Created
    end
```

---

### 3.3 Evidence Secure Streaming Download Flow

```mermaid
sequenceDiagram
    autonumber
    actor User as Authorized User
    participant Ctrl as EvidenceController
    participant Svc as EvidenceService
    participant DB as PostgreSQL DB
    participant Disk as File System Storage
    participant Tink as Google Tink (AES-256-GCM)
    participant Audit as AuditService

    User->>Ctrl: GET /cases/{caseId}/evidence/{evidenceId}/download
    Ctrl->>Svc: getEvidence(caseId, evidenceId)
    Svc->>DB: findEvidenceByIdAndTenant(evidenceId, callerOrgId)
    alt Record Not Found or Foreign Tenant
        DB-->>Svc: empty()
        Svc-->>Ctrl: ResourceNotFoundException
        Ctrl-->>User: HTTP 404 Not Found
    else Record Found
        DB-->>Svc: EvidenceMetadata
        Svc->>Disk: readCiphertext(storagePath)
        Disk-->>Svc: ciphertextBytes
        Svc->>Tink: decrypt(ciphertextBytes)
        Tink-->>Svc: plaintextBytes
        Svc->>Audit: logEvent("EVIDENCE_DOWNLOAD", evidenceId)
        Svc-->>Ctrl: StreamingResponseBody (plaintextBytes)
        Ctrl-->>User: HTTP 200 (Content-Disposition: attachment; filename=safe)
    end
```

---

### 3.4 Cryptographic Audit Log Chaining Flow

```mermaid
sequenceDiagram
    autonumber
    participant App as Application Service
    participant Audit as AuditService
    participant DB as PostgreSQL DB

    App->>Audit: appendEvent(eventType, actorId, payload)
    activate Audit
    Audit->>DB: BEGIN TRANSACTION with EXCLUSIVE LOCK on audit_log
    Audit->>DB: selectLastAuditEntry()
    DB-->>Audit: LastRow (sequenceNum, currentHash)
    Audit->>Audit: truncateToMilliseconds(now())
    Audit->>Audit: newHash = HMAC_SHA256(secretKey, lastHash + eventType + payload + actorId + timestamp)
    Audit->>DB: insertAuditRow(sequenceNum+1, newHash, lastHash, eventType, payload, actorId, timestamp)
    Audit->>DB: COMMIT TRANSACTION (Releases lock)
    deactivate Audit
```

---

## 4. Compliance & Standards Mapping
- **OWASP Top 10**:
  - OWASP Top 10:2025 [VERIFY MANUALLY]: A01 (Broken Access Control), A02 (Cryptographic Failures), A04 (Insecure Design), A08 (Integrity Failures)
  - OWASP Top 10:2021: A01:2021, A02:2021, A04:2021, A08:2021
- **CWE**: CWE-284, CWE-311, CWE-353, CWE-434
- **ASVS 5.0**: V2 Authentication, V4 Access Control, V6 Cryptography, V7 Logging, V12 File Handling [VERIFY MANUALLY]
