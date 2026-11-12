package com.casevault.audit;

import com.casevault.model.AuditEvent;
import com.casevault.repository.AuditEventRepository;
import com.casevault.service.AuditEventType;
import com.casevault.service.AuditKeyProvider;
import com.casevault.service.AuditLogService;
import com.casevault.service.AuditLogService.ChainHead;
import com.casevault.service.ChainVerificationResult;
import com.casevault.service.ChainVerificationResult.BreakKind;
import com.casevault.service.ChainedAuditEventRecorder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
class AuditChainTest {

    @TempDir
    static Path sharedTempDir;

    @DynamicPropertySource
    static void configureAudit(DynamicPropertyRegistry registry) {
        registry.add("casevault.audit.key-path", () -> sharedTempDir.resolve("keys").resolve("audit.key").toString());
        registry.add("casevault.storage.evidence-dir", () -> sharedTempDir.resolve("evidence").toString());
        registry.add("casevault.storage.keyset-path", () -> sharedTempDir.resolve("keyset.json").toString());
    }

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private AuditEventRepository auditEventRepository;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Autowired
    private JdbcTemplate jdbc;

    @BeforeEach
    void cleanChain() {
        jdbc.update("DELETE FROM audit_events");
    }

    private void appendFive() {
        UUID user = UUID.randomUUID();
        UUID caseId = UUID.randomUUID();
        auditLogService.append(AuditEventType.LOGIN_SUCCESS, user, null, "SUCCESS");
        auditLogService.append(AuditEventType.CASE_CREATED, user, caseId, "CREATED");
        auditLogService.append(AuditEventType.CASE_ASSIGNED, user, caseId, "ASSIGNED");
        auditLogService.append(AuditEventType.ACCESS_DENIED, user, caseId, "NOT_PERMITTED");
        auditLogService.append(AuditEventType.LOGOUT, user, null, "SUCCESS");
    }

    @Test
    @DisplayName("SEC-AUDIT-01: five appended events form a valid chain with genesis link and sequence 1..5")
    void fiveEventsVerify() {
        appendFive();

        ChainVerificationResult result = auditLogService.verifyChain();
        assertTrue(result.valid());
        assertEquals(5, result.eventsVerified());
        assertNull(result.firstBrokenSequenceNo());
        assertNull(result.breakKind());

        List<AuditEvent> events = auditEventRepository
                .findBySequenceNoGreaterThanOrderBySequenceNoAsc(0, org.springframework.data.domain.PageRequest.of(0, 10));
        assertEquals(5, events.size());
        assertEquals(AuditLogService.GENESIS_PREV_HASH, events.get(0).getPrevHash());
        for (int i = 1; i < events.size(); i++) {
            assertEquals(i + 1, events.get(i).getSequenceNo());
            assertEquals(events.get(i - 1).getHmac(), events.get(i).getPrevHash());
        }
        assertEquals(64, events.get(0).getHmac().length());
    }

    @Test
    @DisplayName("SEC-AUDIT-02: verification pages through the chain (page size 2) and an empty chain is valid")
    void pagingAndEmptyChain() {
        ChainVerificationResult empty = auditLogService.verifyChain();
        assertTrue(empty.valid());
        assertEquals(0, empty.eventsVerified());

        appendFive();
        ChainVerificationResult paged = auditLogService.verifyChain(2);
        assertTrue(paged.valid());
        assertEquals(5, paged.eventsVerified());
        assertThrows(IllegalArgumentException.class, () -> auditLogService.verifyChain(0));
    }

    @Test
    @DisplayName("SEC-AUDIT-03: changing reason_code of one row reports that exact sequence as HMAC mismatch")
    void tamperReasonCode() {
        appendFive();
        jdbc.update("UPDATE audit_events SET reason_code = 'SUCCESS' WHERE sequence_no = 4");

        ChainVerificationResult result = auditLogService.verifyChain();
        assertFalse(result.valid());
        assertEquals(4L, result.firstBrokenSequenceNo());
        assertEquals(BreakKind.HMAC_MISMATCH, result.breakKind());
        assertEquals(3, result.eventsVerified());
    }

    @Test
    @DisplayName("SEC-AUDIT-04: changing prev_hash of one row reports a link mismatch at that sequence")
    void tamperPrevHash() {
        appendFive();
        jdbc.update("UPDATE audit_events SET prev_hash = ? WHERE sequence_no = 3", "f".repeat(64));

        ChainVerificationResult result = auditLogService.verifyChain();
        assertFalse(result.valid());
        assertEquals(3L, result.firstBrokenSequenceNo());
        assertEquals(BreakKind.LINK_MISMATCH, result.breakKind());
    }

    @Test
    @DisplayName("SEC-AUDIT-05: deleting a middle row reports the missing sequence number as a gap")
    void deleteMiddleRow() {
        appendFive();
        jdbc.update("DELETE FROM audit_events WHERE sequence_no = 3");

        ChainVerificationResult result = auditLogService.verifyChain();
        assertFalse(result.valid());
        assertEquals(3L, result.firstBrokenSequenceNo());
        assertEquals(BreakKind.SEQUENCE_GAP, result.breakKind());
    }

    @Test
    @DisplayName("SEC-AUDIT-06: swapping the sequence numbers of two rows is detected at the first swapped position")
    void swapSequenceNumbers() {
        appendFive();
        jdbc.update("UPDATE audit_events SET sequence_no = 9000 WHERE sequence_no = 2");
        jdbc.update("UPDATE audit_events SET sequence_no = 2 WHERE sequence_no = 3");
        jdbc.update("UPDATE audit_events SET sequence_no = 3 WHERE sequence_no = 9000");

        ChainVerificationResult result = auditLogService.verifyChain();
        assertFalse(result.valid());
        assertEquals(2L, result.firstBrokenSequenceNo());
    }

    @Test
    @DisplayName("SEC-AUDIT-07: a row forged without the key (random hmac) is detected")
    void forgedRowWithoutKey() {
        appendFive();
        AuditEvent last = auditEventRepository.findFirstByOrderBySequenceNoDesc().orElseThrow();
        jdbc.update("INSERT INTO audit_events (id, sequence_no, event_type, user_id, case_id, reason_code, "
                        + "occurred_at, prev_hash, hmac) VALUES (?, ?, 'LOGOUT', NULL, NULL, 'SUCCESS', ?, ?, ?)",
                UUID.randomUUID(), 6L, Timestamp.from(Instant.now()), last.getHmac(), "a".repeat(64));

        ChainVerificationResult result = auditLogService.verifyChain();
        assertFalse(result.valid());
        assertEquals(6L, result.firstBrokenSequenceNo());
        assertEquals(BreakKind.HMAC_MISMATCH, result.breakKind());
    }

    @Test
    @DisplayName("SEC-AUDIT-08: tail truncation and truncate-then-append stay undetectable by verifyChain alone; "
            + "an externally anchored head detects both")
    void tailTruncationNeedsExternalAnchor() {
        appendFive();
        ChainHead anchor = auditLogService.currentHead().orElseThrow();

        // Deleting the newest row: the remaining chain is internally consistent (honest limitation).
        jdbc.update("DELETE FROM audit_events WHERE sequence_no = 5");
        assertTrue(auditLogService.verifyChain().valid(), "verifyChain alone cannot see a missing tail");
        assertNotEquals(anchor, auditLogService.currentHead().orElseThrow(), "the anchored head exposes the loss");

        // Truncate then append: the chain is again internally valid, but the head differs from the anchor.
        auditLogService.append(AuditEventType.LOGOUT, null, null, "SUCCESS");
        assertTrue(auditLogService.verifyChain().valid(), "verifyChain alone cannot see a replaced tail");
        ChainHead after = auditLogService.currentHead().orElseThrow();
        assertEquals(anchor.sequenceNo(), after.sequenceNo());
        assertNotEquals(anchor.hmac(), after.hmac(), "the anchored head exposes the replaced tail");
    }

    @Test
    @DisplayName("SEC-AUDIT-09: a chain verified with a different key is invalid (key isolation)")
    void differentKeyInvalid(@TempDir Path otherKeyDir) {
        appendFive();
        AuditLogService otherKeyService = new AuditLogService(auditEventRepository, transactionManager,
                new AuditKeyProvider(otherKeyDir.resolve("other.key").toString()));

        ChainVerificationResult result = otherKeyService.verifyChain();
        assertFalse(result.valid());
        assertEquals(1L, result.firstBrokenSequenceNo());
        assertEquals(BreakKind.HMAC_MISMATCH, result.breakKind());
    }

    @Test
    @DisplayName("SEC-AUDIT-10: reason codes outside the whitelist are stored as UNSPECIFIED, nothing else is stored")
    void whitelistAndNoSecrets() {
        auditLogService.append(AuditEventType.LOGIN_FAILURE, null, null, "password=hunter2");
        auditLogService.append(AuditEventType.LOGIN_FAILURE, null, null, null);
        auditLogService.append(AuditEventType.LOGIN_FAILURE, null, null, "bad_credentials");
        auditLogService.append(AuditEventType.LOGIN_FAILURE, null, null, "BAD_CREDENTIALS");

        List<String> reasons = jdbc.queryForList(
                "SELECT reason_code FROM audit_events ORDER BY sequence_no", String.class);
        assertEquals(List.of("UNSPECIFIED", "UNSPECIFIED", "UNSPECIFIED", "BAD_CREDENTIALS"), reasons);

        List<String> columns = jdbc.queryForList(
                "SELECT LOWER(column_name) FROM information_schema.columns WHERE LOWER(table_name) = 'audit_events'",
                String.class);
        assertEquals(Set.of("id", "sequence_no", "event_type", "user_id", "case_id", "reason_code",
                "occurred_at", "prev_hash", "hmac"), Set.copyOf(columns));
        assertTrue(auditLogService.verifyChain().valid());
        assertThrows(IllegalArgumentException.class, () -> auditLogService.append(null, null, null, "ACCEPTED"));
    }

    @Test
    @DisplayName("SEC-AUDIT-11: occurred_at has millisecond precision and the chain verifies after a database round trip")
    void millisecondPrecisionRoundTrip() {
        AuditEvent saved = auditLogService.append(AuditEventType.CASE_CREATED, UUID.randomUUID(), UUID.randomUUID(),
                "CREATED");
        assertEquals(0, saved.getOccurredAt().getNano() % 1_000_000);

        AuditEvent reloaded = auditEventRepository.findFirstByOrderBySequenceNoDesc().orElseThrow();
        assertEquals(saved.getOccurredAt(), reloaded.getOccurredAt());
        assertEquals(0, reloaded.getOccurredAt().getNano() % 1_000_000);
        assertTrue(auditLogService.verifyChain().valid());
    }

    @Test
    @DisplayName("SEC-AUDIT-12: the recorder stores only well-formed UUIDs and maps unknown reasons to UNSPECIFIED")
    void recorderStoresOnlyUuids() {
        ChainedAuditEventRecorder recorder = new ChainedAuditEventRecorder(auditLogService);
        String user = UUID.randomUUID().toString();
        recorder.record(AuditEventType.EVIDENCE_UPLOADED, user, "not-a-uuid <script>", "ACCEPTED");
        recorder.record(AuditEventType.LOGIN_FAILURE, "alice@example.test", null, "wrong password");

        AuditEvent first = auditEventRepository
                .findBySequenceNoGreaterThanOrderBySequenceNoAsc(0, org.springframework.data.domain.PageRequest.of(0, 5))
                .get(0);
        assertEquals(UUID.fromString(user), first.getUserId());
        assertNull(first.getCaseId());
        assertEquals("ACCEPTED", first.getReasonCode());

        assertEquals(Long.valueOf(2L), jdbc.queryForObject("SELECT COUNT(*) FROM audit_events", Long.class));
        assertEquals(1L, jdbc.queryForObject(
                "SELECT COUNT(*) FROM audit_events WHERE user_id IS NULL AND reason_code = 'UNSPECIFIED'", Long.class));
        assertTrue(auditLogService.verifyChain().valid());
    }

    @Test
    @DisplayName("SEC-AUDIT-13: the recorder is fail-closed: an append failure reaches the caller")
    void recorderFailsClosed() {
        AuditLogService failing = org.mockito.Mockito.mock(AuditLogService.class);
        org.mockito.Mockito.doThrow(new IllegalStateException("db down")).when(failing)
                .recordEvent(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
        ChainedAuditEventRecorder recorder = new ChainedAuditEventRecorder(failing);

        assertThrows(IllegalStateException.class,
                () -> recorder.record(AuditEventType.LOGOUT, null, null, "SUCCESS"));
    }

    @Test
    @DisplayName("SEC-AUDIT-14: the key file is created lazily, reused, restricted where the OS allows and invalid keys are rejected")
    void keyLifecycle(@TempDir Path dir) throws IOException {
        Path keyFile = dir.resolve("nested").resolve("audit.key");
        AuditKeyProvider provider = new AuditKeyProvider(keyFile.toString());
        assertFalse(Files.exists(keyFile), "no key file before first use");

        byte[] first = provider.key().getEncoded();
        assertTrue(Files.exists(keyFile));
        assertEquals(32, first.length);
        assertEquals(first.length, new AuditKeyProvider(keyFile.toString()).key().getEncoded().length);
        assertTrue(java.security.MessageDigest.isEqual(first, new AuditKeyProvider(keyFile.toString()).key().getEncoded()));

        if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            assertEquals(Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
                    Files.getPosixFilePermissions(keyFile));
        }
        // On non-POSIX systems (Windows) permissions are best effort only: VERIFY MANUALLY (see ADR 0005).

        Path broken = dir.resolve("broken.key");
        Files.writeString(broken, "AAAA");
        assertThrows(IllegalStateException.class, () -> new AuditKeyProvider(broken.toString()).key());
        Path notBase64 = dir.resolve("notbase64.key");
        Files.writeString(notBase64, "%%%not base64%%%");
        assertThrows(IllegalStateException.class, () -> new AuditKeyProvider(notBase64.toString()).key());
    }
}
