package com.casevault.evidence;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.casevault.exception.BadRequestException;
import com.casevault.exception.ResourceNotFoundException;
import com.casevault.model.Case;
import com.casevault.model.Organisation;
import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.CaseRepository;
import com.casevault.repository.EvidenceRepository;
import com.casevault.repository.OrganisationRepository;
import com.casevault.repository.UserRepository;
import com.casevault.security.CaseVaultUserPrincipal;
import com.casevault.dto.EvidenceResponseDto;
import com.casevault.service.CaseAccessService;
import com.casevault.service.LoggingAuditEventRecorder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
@org.springframework.test.context.TestPropertySource(properties = "casevault.audit.recorder=logging")
@org.junit.jupiter.api.extension.ExtendWith(com.casevault.support.RestoreBootstrapDataAfterAll.class)
public class EvidenceLogSecurityTest {

    private static final Pattern AUDIT_LINE_PATTERN = Pattern.compile(
            "^audit-placeholder eventType=(EVIDENCE_UPLOADED|EVIDENCE_DOWNLOADED|EVIDENCE_REJECTED) " +
            "userId=[0-9a-fA-F-]{36} caseId=[0-9a-fA-F-]{36} " +
            "reasonCode=(ACCEPTED|VALIDATION_REJECTED|INTEGRITY_VERIFIED|INTEGRITY_FAILED|FILE_NOT_FOUND)$"
    );

    @TempDir
    static Path sharedTempDir;

    @DynamicPropertySource
    static void configureStorage(DynamicPropertyRegistry registry) {
        registry.add("casevault.storage.evidence-dir", () -> sharedTempDir.resolve("evidence").toString());
        registry.add("casevault.storage.keyset-path", () -> sharedTempDir.resolve("keyset.json").toString());
    }

    @Autowired
    private CaseAccessService caseAccessService;

    @Autowired
    private OrganisationRepository organisationRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CaseRepository caseRepository;

    @Autowired
    private EvidenceRepository evidenceRepository;

    private ListAppender<ILoggingEvent> listAppender;
    private Logger auditLogger;

    private User clientUser;
    private Case aCase;
    private CaseVaultUserPrincipal principal;

    @org.springframework.beans.factory.annotation.Autowired
    private org.springframework.jdbc.core.JdbcTemplate cleanupJdbc;

    @BeforeEach
    void setUp() {
        auditLogger = (Logger) LoggerFactory.getLogger(LoggingAuditEventRecorder.class);
        listAppender = new ListAppender<>();
        listAppender.start();
        auditLogger.addAppender(listAppender);

        // F-008: FK-safe cleanup (reports, actions, notes, evidence, cases); other classes may have committed rows
        com.casevault.support.TestDatabaseCleaner.deleteCasesAndDependents(cleanupJdbc);
        evidenceRepository.deleteAll();
        caseRepository.deleteAll();
        userRepository.deleteAll();
        organisationRepository.deleteAll();

        Instant now = Instant.now();
        Organisation org = organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "Log Test Org", "ORG_LOG", now));
        clientUser = userRepository.save(new User(UUID.randomUUID().toString(), org, "log_client_user", "hash", Role.CLIENT, "log_client@test.local", true, now));
        aCase = caseRepository.save(new Case(UUID.randomUUID().toString(), org, "Log Case", "RANSOMWARE", "HIGH", "OPEN", clientUser, null, now));

        principal = new CaseVaultUserPrincipal(clientUser, now);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities()));
    }

    @AfterEach
    void tearDown() {
        if (auditLogger != null && listAppender != null) {
            auditLogger.detachAppender(listAppender);
            listAppender.stop();
        }
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("SEC-EVID-LOG-01: Upload accepted audit log contains only metadata and no secrets or filenames")
    void uploadAcceptedAuditLogContainsOnlyMetadata() {
        MockMultipartFile file = new MockMultipartFile(
                "file", "sensitive_audit_report.txt", "text/plain", "Top Secret Plaintext 98765".getBytes(StandardCharsets.UTF_8));

        caseAccessService.uploadEvidence(aCase.getId(), file, principal);

        List<ILoggingEvent> events = listAppender.list;
        assertEquals(1, events.size(), "Exactly 1 audit event must be logged on successful upload");

        String formatted = events.get(0).getFormattedMessage();
        assertTrue(AUDIT_LINE_PATTERN.matcher(formatted).matches(), "Log line must conform strictly to audit format: " + formatted);
        assertTrue(formatted.contains("eventType=EVIDENCE_UPLOADED"));
        assertTrue(formatted.contains("reasonCode=ACCEPTED"));
        assertTrue(formatted.contains("userId=" + clientUser.getId()));
        assertTrue(formatted.contains("caseId=" + aCase.getId()));

        assertFalse(formatted.contains("sensitive_audit_report.txt"), "Audit line must not contain file name");
        assertFalse(formatted.contains("Top Secret Plaintext"), "Audit line must not contain file content");
        assertFalse(formatted.contains("\r"), "Audit line must not contain CR");
        assertFalse(formatted.contains("\n"), "Audit line must not contain LF");
    }

    @Test
    @DisplayName("SEC-EVID-LOG-02: Upload rejected with CRLF filename prevents log injection and does not create second line")
    void uploadRejectedAuditLogPreventsCrlfInjection() {
        MockMultipartFile maliciousFile = new MockMultipartFile(
                "file", "report\r\nFAKE-EVENT: evil\r\n.exe", "application/octet-stream", "dummy bytes".getBytes(StandardCharsets.UTF_8));

        assertThrows(BadRequestException.class, () ->
                caseAccessService.uploadEvidence(aCase.getId(), maliciousFile, principal));

        List<ILoggingEvent> events = listAppender.list;
        assertEquals(1, events.size(), "Exactly 1 audit event must be logged on rejection");

        String formatted = events.get(0).getFormattedMessage();
        assertTrue(AUDIT_LINE_PATTERN.matcher(formatted).matches(), "Log line must match strict pattern: " + formatted);
        assertTrue(formatted.contains("eventType=EVIDENCE_REJECTED"));
        assertTrue(formatted.contains("reasonCode=VALIDATION_REJECTED"));

        assertFalse(formatted.contains("FAKE-EVENT"), "Injected header/event must not appear in log message");
        assertFalse(formatted.contains("\r"), "Log message must not contain CR");
        assertFalse(formatted.contains("\n"), "Log message must not contain LF");
    }

    @Test
    @DisplayName("SEC-EVID-LOG-03: Download verified audit log contains only metadata and no keys or filenames")
    void downloadVerifiedAuditLogContainsOnlyMetadata() {
        MockMultipartFile file = new MockMultipartFile(
                "file", "download_log.txt", "text/plain", "Downloaded Plaintext 111".getBytes(StandardCharsets.UTF_8));

        EvidenceResponseDto uploaded = caseAccessService.uploadEvidence(aCase.getId(), file, principal);
        listAppender.list.clear();

        caseAccessService.openEvidence(aCase.getId(), uploaded.getId(), principal);

        List<ILoggingEvent> events = listAppender.list;
        assertEquals(1, events.size(), "Exactly 1 audit event must be logged on download");

        String formatted = events.get(0).getFormattedMessage();
        assertTrue(AUDIT_LINE_PATTERN.matcher(formatted).matches(), "Log line must match strict pattern: " + formatted);
        assertTrue(formatted.contains("eventType=EVIDENCE_DOWNLOADED"));
        assertTrue(formatted.contains("reasonCode=INTEGRITY_VERIFIED"));

        assertFalse(formatted.contains("download_log.txt"), "Must not leak filename");
        assertFalse(formatted.contains("Downloaded Plaintext"), "Must not leak content");
    }

    @Test
    @DisplayName("SEC-EVID-LOG-04: Integrity failure audit log records INTEGRITY_FAILED with zero plaintext leakage")
    void integrityFailureAuditLogRecordsIntegrityFailedWithoutLeakage() throws IOException {
        MockMultipartFile file = new MockMultipartFile(
                "file", "tamper_log.txt", "text/plain", "Tamper Plaintext 222".getBytes(StandardCharsets.UTF_8));

        EvidenceResponseDto uploaded = caseAccessService.uploadEvidence(aCase.getId(), file, principal);
        listAppender.list.clear();

        // Tamper ciphertext
        var evEntity = evidenceRepository.findById(uploaded.getId()).orElseThrow();
        Path cipherPath = sharedTempDir.resolve("evidence").resolve(evEntity.getStoredName());
        byte[] bytes = Files.readAllBytes(cipherPath);
        bytes[bytes.length - 1] ^= 1;
        Files.write(cipherPath, bytes);

        assertThrows(ResourceNotFoundException.class, () ->
                caseAccessService.openEvidence(aCase.getId(), uploaded.getId(), principal));

        List<ILoggingEvent> events = listAppender.list;
        assertEquals(1, events.size(), "Exactly 1 audit event must be logged on integrity failure");

        String formatted = events.get(0).getFormattedMessage();
        assertTrue(AUDIT_LINE_PATTERN.matcher(formatted).matches(), "Log line must match strict pattern: " + formatted);
        assertTrue(formatted.contains("eventType=EVIDENCE_REJECTED"));
        assertTrue(formatted.contains("reasonCode=INTEGRITY_FAILED"));

        assertFalse(formatted.contains("Tamper Plaintext"), "Must not leak plaintext");
        assertFalse(formatted.contains("keyset"), "Must not leak keyset");
    }

    @Test
    @DisplayName("SEC-EVID-LOG-05: Missing file audit log records FILE_NOT_FOUND without leaking path")
    void missingFileAuditLogRecordsFileNotFoundWithoutLeakingPath() throws IOException {
        MockMultipartFile file = new MockMultipartFile(
                "file", "missing_log.txt", "text/plain", "Missing Plaintext 333".getBytes(StandardCharsets.UTF_8));

        EvidenceResponseDto uploaded = caseAccessService.uploadEvidence(aCase.getId(), file, principal);
        listAppender.list.clear();

        // Delete file
        var evEntity = evidenceRepository.findById(uploaded.getId()).orElseThrow();
        Path cipherPath = sharedTempDir.resolve("evidence").resolve(evEntity.getStoredName());
        Files.deleteIfExists(cipherPath);

        assertThrows(ResourceNotFoundException.class, () ->
                caseAccessService.openEvidence(aCase.getId(), uploaded.getId(), principal));

        List<ILoggingEvent> events = listAppender.list;
        assertEquals(1, events.size(), "Exactly 1 audit event must be logged on missing file");

        String formatted = events.get(0).getFormattedMessage();
        assertTrue(AUDIT_LINE_PATTERN.matcher(formatted).matches(), "Log line must match strict pattern: " + formatted);
        assertTrue(formatted.contains("eventType=EVIDENCE_REJECTED"));
        assertTrue(formatted.contains("reasonCode=FILE_NOT_FOUND"));

        assertFalse(formatted.contains(cipherPath.toString()), "Must not leak physical path");
    }
}
