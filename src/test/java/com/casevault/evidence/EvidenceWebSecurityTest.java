package com.casevault.evidence;

import com.casevault.model.Case;
import com.casevault.model.Evidence;
import com.casevault.model.Organisation;
import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.CaseRepository;
import com.casevault.repository.EvidenceRepository;
import com.casevault.repository.OrganisationRepository;
import com.casevault.repository.UserRepository;
import com.casevault.security.CaseVaultUserPrincipal;
import com.casevault.service.AuditEventRecorder;
import com.casevault.service.AuditEventType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class EvidenceWebSecurityTest {

    @TempDir
    static Path sharedTempDir;

    @DynamicPropertySource
    static void configureStorage(DynamicPropertyRegistry registry) {
        if (sharedTempDir == null) {
            try {
                sharedTempDir = Files.createTempDirectory("casevault-evidence-web-test");
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        registry.add("casevault.storage.evidence-dir", () -> sharedTempDir.resolve("evidence").toString());
        registry.add("casevault.storage.keyset-path", () -> sharedTempDir.resolve("keys/evidence-keyset.json").toString());
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private OrganisationRepository organisationRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CaseRepository caseRepository;

    @Autowired
    private EvidenceRepository evidenceRepository;

    @Autowired
    private com.casevault.service.CaseAccessService caseAccessService;

    @MockitoSpyBean
    private AuditEventRecorder auditEventRecorder;

    private Organisation orgInternal;
    private Organisation orgA;
    private Organisation orgB;

    private User clientUserA;
    private User clientUserB;
    private User analystBob;
    private User managerAlice;
    private User clientManagerA;
    private User auditorAdmin;

    private Case caseA;
    private Case caseB;
    private Evidence evidenceA;

    private static final byte[] VALID_PDF_BYTES = "%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Count 0>>endobj\nxref\n0 3\n0000000000 65535 f\n0000000009 00000 n\n0000000052 00000 n\ntrailer<</Size 3/Root 1 0 R>>\nstartxref\n99\n%%EOF".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] VALID_PNG_BYTES = new byte[]{
            (byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
            0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x08, 0x02, 0x00, 0x00, 0x00, (byte) 0x90, 0x77, 0x53, (byte) 0xDE
    };
    private static final byte[] VALID_TXT_BYTES = "2026-11-10 14:00:00 Incident Report Case #49281".getBytes(StandardCharsets.UTF_8);

    @BeforeEach
    void setUp() {
        evidenceRepository.deleteAll();
        caseRepository.deleteAll();
        clearInvocations(auditEventRecorder);

        Instant now = Instant.now();
        orgInternal = organisationRepository.findByCode("ORG_INTERNAL")
                .orElseGet(() -> organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "Internal Consultancy", "ORG_INTERNAL", now)));
        orgA = organisationRepository.findByCode("ORG_EVID_A")
                .orElseGet(() -> organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "Evidence Client A", "ORG_EVID_A", now)));
        orgB = organisationRepository.findByCode("ORG_EVID_B")
                .orElseGet(() -> organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "Evidence Client B", "ORG_EVID_B", now)));

        clientUserA = createUser("client_user_a_" + UUID.randomUUID().toString().substring(0, 8), orgA, Role.CLIENT, now);
        clientUserB = createUser("client_user_b_" + UUID.randomUUID().toString().substring(0, 8), orgB, Role.CLIENT, now);
        analystBob = createUser("analyst_bob_" + UUID.randomUUID().toString().substring(0, 8), orgInternal, Role.ANALYST, now);
        managerAlice = createUser("mgr_alice_" + UUID.randomUUID().toString().substring(0, 8), orgInternal, Role.MANAGER, now);
        clientManagerA = createUser("client_mgr_a_" + UUID.randomUUID().toString().substring(0, 8), orgA, Role.MANAGER, now);
        auditorAdmin = createUser("auditor_adm_" + UUID.randomUUID().toString().substring(0, 8), null, Role.AUDITOR_ADMIN, now);

        caseA = caseRepository.save(new Case(
                UUID.randomUUID().toString(), orgA, "Case A Primary Incident", "RANSOMWARE", "HIGH", "OPEN", clientUserA, analystBob, now
        ));
        caseB = caseRepository.save(new Case(
                UUID.randomUUID().toString(), orgB, "Case B Foreign Incident", "PHISHING", "MEDIUM", "OPEN", clientUserB, null, now
        ));

        evidenceA = evidenceRepository.save(new Evidence(
                UUID.randomUUID().toString(),
                caseA,
                "initial_report.pdf",
                UUID.randomUUID().toString(),
                "application/pdf",
                (long) VALID_PDF_BYTES.length,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                1,
                clientUserA,
                now
        ));
    }

    private User createUser(String username, Organisation org, Role role, Instant now) {
        return userRepository.save(new User(
                UUID.randomUUID().toString(),
                org,
                username,
                "$argon2id$v=19$m=65536,t=3,p=1$fakeHashForEvidenceTests",
                role,
                username + "@test.local",
                true,
                now
        ));
    }

    private Authentication authFor(User user) {
        CaseVaultUserPrincipal principal = new CaseVaultUserPrincipal(user, Instant.now());
        return new UsernamePasswordAuthenticationToken(principal, "N/A", principal.getAuthorities());
    }

    @Test
    @DisplayName("SEC-EVID-WEB-01: Upload without CSRF token is rejected with HTTP 403 Forbidden")
    void uploadWithoutCsrfTokenRejectedWith403() throws Exception {
        MockMultipartFile file = new MockMultipartFile("file", "valid.txt", "text/plain", VALID_TXT_BYTES);

        mockMvc.perform(multipart("/cases/{id}/evidence", caseA.getId())
                        .file(file)
                        .with(authentication(authFor(clientUserA))))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("SEC-EVID-WEB-02: Unauthenticated upload is rejected with HTTP 401 Unauthorized (existing security filter chain)")
    void unauthenticatedUploadRedirectedToLogin() throws Exception {
        MockMultipartFile file = new MockMultipartFile("file", "valid.txt", "text/plain", VALID_TXT_BYTES);

        mockMvc.perform(multipart("/cases/{id}/evidence", caseA.getId())
                        .file(file)
                        .with(csrf()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("SEC-EVID-WEB-03: Upload by MANAGER and AUDITOR_ADMIN returns HTTP 404 (never 403) and leaks nothing")
    void uploadByManagerAndAuditorAdminReturns404() throws Exception {
        MockMultipartFile file = new MockMultipartFile("file", "valid.txt", "text/plain", VALID_TXT_BYTES);

        // 1. Internal consultancy MANAGER attempting upload -> HTTP 404
        mockMvc.perform(multipart("/cases/{id}/evidence", caseA.getId())
                        .file(file)
                        .with(authentication(authFor(managerAlice)))
                        .with(csrf()))
                .andExpect(status().isNotFound())
                .andExpect(content().string(containsString("Incident Correlation ID")))
                .andExpect(content().string(not(containsString("Exception"))))
                .andExpect(content().string(not(containsString("caseA"))));

        // 2. Client MANAGER attempting upload -> HTTP 404
        mockMvc.perform(multipart("/cases/{id}/evidence", caseA.getId())
                        .file(file)
                        .with(authentication(authFor(clientManagerA)))
                        .with(csrf()))
                .andExpect(status().isNotFound())
                .andExpect(content().string(containsString("Incident Correlation ID")));

        // 3. AUDITOR_ADMIN attempting upload -> HTTP 404
        mockMvc.perform(multipart("/cases/{id}/evidence", caseA.getId())
                        .file(file)
                        .with(authentication(authFor(auditorAdmin)))
                        .with(csrf()))
                .andExpect(status().isNotFound())
                .andExpect(content().string(containsString("Incident Correlation ID")))
                .andExpect(content().string(not(containsString("Case A Primary Incident"))));
    }

    @Test
    @DisplayName("SEC-EVID-WEB-04: Cross-tenant: CLIENT of Org B returns HTTP 404 for upload, list, download on Case of Org A")
    void crossTenantEvidenceAccessReturns404OverHttp() throws Exception {
        MockMultipartFile file = new MockMultipartFile("file", "cross_tenant.txt", "text/plain", VALID_TXT_BYTES);

        // 1. Cross-tenant upload -> HTTP 404
        mockMvc.perform(multipart("/cases/{id}/evidence", caseA.getId())
                        .file(file)
                        .with(authentication(authFor(clientUserB)))
                        .with(csrf()))
                .andExpect(status().isNotFound())
                .andExpect(content().string(containsString("Incident Correlation ID")));

        // 2. Cross-tenant list (via case detail view) -> HTTP 404
        mockMvc.perform(get("/cases/{id}", caseA.getId())
                        .param("tab", "evidence")
                        .with(authentication(authFor(clientUserB))))
                .andExpect(status().isNotFound());

        // 3. Cross-tenant download -> HTTP 404
        mockMvc.perform(get("/cases/{caseId}/evidence/{evidenceId}", caseA.getId(), evidenceA.getId())
                        .with(authentication(authFor(clientUserB))))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("SEC-EVID-WEB-05: Oversize file upload returns safe HTTP 400 error page with correlation ID and no stack trace")
    void oversizeFileUploadReturnsSafe400ErrorPage() throws Exception {
        byte[] oversized = new byte[10 * 1024 * 1024 + 1024]; // 10MB + 1KB
        MockMultipartFile file = new MockMultipartFile("file", "oversized.txt", "text/plain", oversized);

        mockMvc.perform(multipart("/cases/{id}/evidence", caseA.getId())
                        .file(file)
                        .with(authentication(authFor(clientUserA)))
                        .with(csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("Incident Correlation ID")))
                .andExpect(content().string(containsString("10MB")))
                .andExpect(content().string(not(containsString("MaxUploadSizeExceededException"))))
                .andExpect(content().string(not(containsString("StackTrace"))))
                .andExpect(content().string(not(containsString("at com.casevault"))));
    }

    @Test
    @DisplayName("SEC-EVID-WEB-06: Disallowed uploads return specific safe error and trigger EVIDENCE_REJECTED audit event")
    void disallowedUploadsReturnSafeErrorAndTriggerAuditRejected() throws Exception {
        // (a) fake.png containing plain text bytes
        clearInvocations(auditEventRecorder);
        MockMultipartFile fakePng = new MockMultipartFile("file", "fake.png", "image/png", "Just plain text, not a PNG image".getBytes(StandardCharsets.UTF_8));
        mockMvc.perform(multipart("/cases/{id}/evidence", caseA.getId())
                        .file(fakePng)
                        .with(authentication(authFor(clientUserA)))
                        .with(csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("MIME type mismatch")));
        verify(auditEventRecorder, atLeastOnce()).record(eq(AuditEventType.EVIDENCE_REJECTED), eq(clientUserA.getId()), eq(caseA.getId()), eq("VALIDATION_REJECTED"));

        // (b) MZ bytes in .pdf
        clearInvocations(auditEventRecorder);
        MockMultipartFile mzPdf = new MockMultipartFile("file", "malicious.pdf", "application/pdf", new byte[]{'M', 'Z', 0x00, 0x00, 0x01, 0x02});
        mockMvc.perform(multipart("/cases/{id}/evidence", caseA.getId())
                        .file(mzPdf)
                        .with(authentication(authFor(clientUserA)))
                        .with(csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("Executable binary or script header detected")));
        verify(auditEventRecorder, atLeastOnce()).record(eq(AuditEventType.EVIDENCE_REJECTED), eq(clientUserA.getId()), eq(caseA.getId()), eq("VALIDATION_REJECTED"));

        // (c) ELF bytes in .txt
        clearInvocations(auditEventRecorder);
        MockMultipartFile elfTxt = new MockMultipartFile("file", "linux_tool.txt", "text/plain", new byte[]{0x7F, 'E', 'L', 'F', 0x01, 0x01, 0x01, 0x00});
        mockMvc.perform(multipart("/cases/{id}/evidence", caseA.getId())
                        .file(elfTxt)
                        .with(authentication(authFor(clientUserA)))
                        .with(csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("Executable binary or script header detected")));
        verify(auditEventRecorder, atLeastOnce()).record(eq(AuditEventType.EVIDENCE_REJECTED), eq(clientUserA.getId()), eq(caseA.getId()), eq("VALIDATION_REJECTED"));

        // (d) report.pdf.exe
        clearInvocations(auditEventRecorder);
        MockMultipartFile pdfExe = new MockMultipartFile("file", "report.pdf.exe", "application/octet-stream", VALID_TXT_BYTES);
        mockMvc.perform(multipart("/cases/{id}/evidence", caseA.getId())
                        .file(pdfExe)
                        .with(authentication(authFor(clientUserA)))
                        .with(csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("is not permitted")));
        verify(auditEventRecorder, atLeastOnce()).record(eq(AuditEventType.EVIDENCE_REJECTED), eq(clientUserA.getId()), eq(caseA.getId()), eq("VALIDATION_REJECTED"));

        // (e) report.exe.pdf
        clearInvocations(auditEventRecorder);
        MockMultipartFile exePdf = new MockMultipartFile("file", "report.exe.pdf", "application/pdf", VALID_PDF_BYTES);
        mockMvc.perform(multipart("/cases/{id}/evidence", caseA.getId())
                        .file(exePdf)
                        .with(authentication(authFor(clientUserA)))
                        .with(csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("Double extension detected")));
        verify(auditEventRecorder, atLeastOnce()).record(eq(AuditEventType.EVIDENCE_REJECTED), eq(clientUserA.getId()), eq(caseA.getId()), eq("VALIDATION_REJECTED"));

        // (f) empty file
        clearInvocations(auditEventRecorder);
        MockMultipartFile emptyFile = new MockMultipartFile("file", "empty.txt", "text/plain", new byte[0]);
        mockMvc.perform(multipart("/cases/{id}/evidence", caseA.getId())
                        .file(emptyFile)
                        .with(authentication(authFor(clientUserA)))
                        .with(csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("empty")));
        verify(auditEventRecorder, atLeastOnce()).record(eq(AuditEventType.EVIDENCE_REJECTED), eq(clientUserA.getId()), eq(caseA.getId()), eq("VALIDATION_REJECTED"));
    }

    @Test
    @DisplayName("SEC-EVID-WEB-07: Valid PDF, PNG and TXT uploads are accepted and trigger EVIDENCE_UPLOADED audit event")
    void validUploadsAcceptedAndTriggerAuditUploaded() throws Exception {
        // 1. Valid PDF
        clearInvocations(auditEventRecorder);
        MockMultipartFile pdfFile = new MockMultipartFile("file", "forensic_report.pdf", "application/pdf", VALID_PDF_BYTES);
        mockMvc.perform(multipart("/cases/{id}/evidence", caseA.getId())
                        .file(pdfFile)
                        .with(authentication(authFor(clientUserA)))
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/cases/" + caseA.getId() + "?tab=evidence"));
        verify(auditEventRecorder, atLeastOnce()).record(eq(AuditEventType.EVIDENCE_UPLOADED), eq(clientUserA.getId()), eq(caseA.getId()), eq("ACCEPTED"));

        // 2. Valid PNG
        clearInvocations(auditEventRecorder);
        MockMultipartFile pngFile = new MockMultipartFile("file", "screenshot.png", "image/png", VALID_PNG_BYTES);
        mockMvc.perform(multipart("/cases/{id}/evidence", caseA.getId())
                        .file(pngFile)
                        .with(authentication(authFor(clientUserA)))
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/cases/" + caseA.getId() + "?tab=evidence"));
        verify(auditEventRecorder, atLeastOnce()).record(eq(AuditEventType.EVIDENCE_UPLOADED), eq(clientUserA.getId()), eq(caseA.getId()), eq("ACCEPTED"));

        // 3. Valid TXT
        clearInvocations(auditEventRecorder);
        MockMultipartFile txtFile = new MockMultipartFile("file", "incident_log.txt", "text/plain", VALID_TXT_BYTES);
        mockMvc.perform(multipart("/cases/{id}/evidence", caseA.getId())
                        .file(txtFile)
                        .with(authentication(authFor(clientUserA)))
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/cases/" + caseA.getId() + "?tab=evidence"));
        verify(auditEventRecorder, atLeastOnce()).record(eq(AuditEventType.EVIDENCE_UPLOADED), eq(clientUserA.getId()), eq(caseA.getId()), eq("ACCEPTED"));
    }

    @Test
    @DisplayName("SEC-EVID-WEB-08: Form fields organisationId, uploader, caseId sent over HTTP are ignored")
    void formParametersIgnoredOverHttp() throws Exception {
        MockMultipartFile file = new MockMultipartFile("file", "params_probe.txt", "text/plain", VALID_TXT_BYTES);

        mockMvc.perform(multipart("/cases/{id}/evidence", caseA.getId())
                        .file(file)
                        .param("organisationId", orgB.getId())
                        .param("uploader", clientUserB.getId())
                        .param("uploadedBy", clientUserB.getId())
                        .param("caseId", caseB.getId())
                        .with(authentication(authFor(clientUserA)))
                        .with(csrf()))
                .andExpect(status().is3xxRedirection());

        List<Evidence> list = evidenceRepository.findByACaseId(caseA.getId());
        Evidence saved = list.stream()
                .filter(e -> "params_probe.txt".equals(e.getOriginalName()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Uploaded evidence must exist"));

        assertEquals(caseA.getId(), saved.getCase().getId(), "Case ID must match path variable");
        assertEquals(orgA.getId(), saved.getCase().getOrganisation().getId(), "Organisation must remain Org A");
        assertEquals(clientUserA.getId(), saved.getUploadedBy().getId(), "UploadedBy must be Client A");
        assertNotEquals(clientUserB.getId(), saved.getUploadedBy().getId(), "Injected uploader must be ignored");
        assertNotEquals(orgB.getId(), saved.getCase().getOrganisation().getId(), "Injected org must be ignored");
    }

    private Evidence uploadViaMockMvc(String caseId, User uploader, String filename, String contentType, byte[] content) throws Exception {
        MockMultipartFile file = new MockMultipartFile("file", filename, contentType, content);
        mockMvc.perform(multipart("/cases/{id}/evidence", caseId)
                        .file(file)
                        .with(authentication(authFor(uploader)))
                        .with(csrf()))
                .andExpect(status().is3xxRedirection());

        return evidenceRepository.findByACaseId(caseId).stream()
                .filter(e -> filename.equals(e.getOriginalName()))
                .reduce((first, second) -> second)
                .orElseThrow(() -> new AssertionError("Uploaded evidence not found"));
    }

    @Test
    @DisplayName("SEC-EVID-DL-01: Download responses include required defensive headers (Content-Disposition, octet-stream, nosniff, no-store)")
    void downloadIncludesDefensiveHeadersAndPayload() throws Exception {
        Evidence ev = uploadViaMockMvc(caseA.getId(), clientUserA, "download_sample.txt", "text/plain", VALID_TXT_BYTES);

        mockMvc.perform(get("/cases/{caseId}/evidence/{evidenceId}", caseA.getId(), ev.getId())
                        .with(authentication(authFor(clientUserA))))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_OCTET_STREAM))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.header().string("Cache-Control", "no-store"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.header().string("Content-Disposition", containsString("attachment")))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.header().string("Content-Disposition", containsString("download_sample.txt")))
                .andExpect(content().bytes(VALID_TXT_BYTES));
    }

    @Test
    @DisplayName("SEC-EVID-DL-02: Stored display name containing CR, LF or quotes cannot inject headers or split response")
    void storedNameWithCrLfOrQuotesCannotInjectHeaderOrSplitResponse() throws Exception {
        Evidence ev = uploadViaMockMvc(caseA.getId(), clientUserA, "crlf_target.txt", "text/plain", VALID_TXT_BYTES);

        ev.setOriginalName("report\r\nInjected-Header: evil\r\n\"quote_test\".txt");
        evidenceRepository.save(ev);

        var mvcResult = mockMvc.perform(get("/cases/{caseId}/evidence/{evidenceId}", caseA.getId(), ev.getId())
                        .with(authentication(authFor(clientUserA))))
                .andExpect(status().isOk())
                .andReturn();

        String cd = mvcResult.getResponse().getHeader("Content-Disposition");
        org.junit.jupiter.api.Assertions.assertNotNull(cd);
        org.junit.jupiter.api.Assertions.assertFalse(cd.contains("\r"), "Content-Disposition must not contain raw CR");
        org.junit.jupiter.api.Assertions.assertFalse(cd.contains("\n"), "Content-Disposition must not contain raw LF");
        // Verify no injected header exists on the HTTP response
        org.junit.jupiter.api.Assertions.assertNull(mvcResult.getResponse().getHeader("Injected-Header"), "No injected header on response");
        // Verify no unescaped quote in Content-Disposition: quotes only exist as delimiter quotes for filename="..."
        long quoteCount = cd.chars().filter(ch -> ch == '"').count();
        org.junit.jupiter.api.Assertions.assertEquals(2, quoteCount, "Content-Disposition should only contain matching delimiter quotes");
    }

    @Test
    @DisplayName("SEC-EVID-DL-03: Tampered stored ciphertext returns safe 404 error page, releases no plaintext, and records INTEGRITY_FAILED audit event")
    void tamperedStoredCiphertextReturnsSafe404AndIntegrityFailedAudit() throws Exception {
        Evidence ev = uploadViaMockMvc(caseA.getId(), clientUserA, "tamper_test.txt", "text/plain", VALID_TXT_BYTES);

        Path ciphertextPath = sharedTempDir.resolve("evidence").resolve(ev.getStoredName());
        byte[] ciphertext = Files.readAllBytes(ciphertextPath);
        ciphertext[ciphertext.length - 1] ^= 1; // Flip one bit/byte to invalidate AEAD authentication tag
        Files.write(ciphertextPath, ciphertext);

        clearInvocations(auditEventRecorder);
        mockMvc.perform(get("/cases/{caseId}/evidence/{evidenceId}", caseA.getId(), ev.getId())
                        .with(authentication(authFor(clientUserA))))
                .andExpect(status().isNotFound())
                .andExpect(content().string(containsString("Incident Correlation ID")))
                .andExpect(content().string(not(containsString("GeneralSecurityException"))))
                .andExpect(content().string(not(containsString("StackTrace"))))
                .andExpect(content().string(not(containsString("keyset"))))
                .andExpect(content().string(not(containsString(ciphertextPath.toString()))))
                .andExpect(content().string(not(containsString("Incident Report Case #49281"))));

        verify(auditEventRecorder, times(1)).record(eq(AuditEventType.EVIDENCE_REJECTED), eq(clientUserA.getId()), eq(caseA.getId()), eq("INTEGRITY_FAILED"));
        verifyNoMoreInteractions(auditEventRecorder);
    }

    @Test
    @DisplayName("SEC-EVID-DL-04: Deleted or missing stored file returns safe 404 error page, releases no plaintext, and records FILE_NOT_FOUND audit event")
    void missingStoredFileReturnsSafe404AndFileNotFoundAudit() throws Exception {
        Evidence ev = uploadViaMockMvc(caseA.getId(), clientUserA, "missing_test.txt", "text/plain", VALID_TXT_BYTES);

        Path ciphertextPath = sharedTempDir.resolve("evidence").resolve(ev.getStoredName());
        Files.deleteIfExists(ciphertextPath); // Delete the physical ciphertext file

        clearInvocations(auditEventRecorder);
        mockMvc.perform(get("/cases/{caseId}/evidence/{evidenceId}", caseA.getId(), ev.getId())
                        .with(authentication(authFor(clientUserA))))
                .andExpect(status().isNotFound())
                .andExpect(content().string(containsString("Incident Correlation ID")))
                .andExpect(content().string(not(containsString("NoSuchFileException"))))
                .andExpect(content().string(not(containsString("StackTrace"))))
                .andExpect(content().string(not(containsString(ciphertextPath.toString()))));

        verify(auditEventRecorder, times(1)).record(eq(AuditEventType.EVIDENCE_REJECTED), eq(clientUserA.getId()), eq(caseA.getId()), eq("FILE_NOT_FOUND"));
        verifyNoMoreInteractions(auditEventRecorder);
    }

    @Test
    @DisplayName("SEC-EVID-DL-05: Hash mismatch between plaintext and DB sha256 records exactly ONE INTEGRITY_FAILED audit event")
    void hashMismatchRecordsExactlyOneAuditIntegrityFailedEvent() throws Exception {
        Evidence ev = uploadViaMockMvc(caseA.getId(), clientUserA, "hash_mismatch.txt", "text/plain", VALID_TXT_BYTES);

        // Corrupt the DB record's sha256Hex so it mismatches decrypted plaintext
        ev.setSha256Hex("0000000000000000000000000000000000000000000000000000000000000000");
        evidenceRepository.save(ev);

        clearInvocations(auditEventRecorder);
        mockMvc.perform(get("/cases/{caseId}/evidence/{evidenceId}", caseA.getId(), ev.getId())
                        .with(authentication(authFor(clientUserA))))
                .andExpect(status().isNotFound())
                .andExpect(content().string(containsString("Incident Correlation ID")));

        // Must record exactly ONE INTEGRITY_FAILED audit event, not duplicate
        verify(auditEventRecorder, times(1)).record(eq(AuditEventType.EVIDENCE_REJECTED), eq(clientUserA.getId()), eq(caseA.getId()), eq("INTEGRITY_FAILED"));
        verifyNoMoreInteractions(auditEventRecorder);
    }
}
