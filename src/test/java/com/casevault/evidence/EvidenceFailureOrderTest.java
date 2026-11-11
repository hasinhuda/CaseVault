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
import com.casevault.service.CaseAccessService;
import com.casevault.service.EvidenceStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.reset;

@SpringBootTest
public class EvidenceFailureOrderTest {

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

    @MockitoSpyBean
    private EvidenceRepository evidenceRepository;

    @MockitoSpyBean
    private EvidenceStore evidenceStorageService;

    private Case testCase;
    private CaseVaultUserPrincipal clientPrincipal;

    @BeforeEach
    void setUp() throws IOException {
        reset(evidenceRepository);
        reset(evidenceStorageService);

        evidenceRepository.deleteAll();
        caseRepository.deleteAll();
        userRepository.deleteAll();
        organisationRepository.deleteAll();

        Path evidenceDir = sharedTempDir.resolve("evidence");
        if (Files.exists(evidenceDir)) {
            try (Stream<Path> s = Files.list(evidenceDir)) {
                for (Path p : s.toList()) {
                    Files.deleteIfExists(p);
                }
            }
        } else {
            Files.createDirectories(evidenceDir);
        }

        Organisation org = organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "Failure Test Org", "ORG_FAIL", Instant.now()));
        User user = userRepository.save(new User(UUID.randomUUID().toString(), org, "client_user", "hash", Role.CLIENT, "client@test.local", true, Instant.now()));
        testCase = caseRepository.save(new Case(UUID.randomUUID().toString(), org, "Test Case", "RANSOMWARE", "HIGH", "OPEN", user, null, Instant.now()));
        clientPrincipal = new CaseVaultUserPrincipal(user, Instant.now());
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(clientPrincipal, null, clientPrincipal.getAuthorities()));
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("SEC-EVID-FAIL-01: When DB save fails, the written encrypted file is deleted (no orphan file on disk)")
    void whenDatabaseSaveFailsWrittenEncryptedFileIsDeleted() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
                "file", "valid_report.txt", "text/plain", "Forensic evidence content 12345".getBytes(StandardCharsets.UTF_8));

        Path evidenceDir = sharedTempDir.resolve("evidence");

        // Simulate database failure during repository save
        doThrow(new DataIntegrityViolationException("Simulated DB failure"))
                .when(evidenceRepository).save(any(Evidence.class));

        assertThrows(DataIntegrityViolationException.class, () ->
                caseAccessService.uploadEvidence(testCase.getId(), file, clientPrincipal));

        // Assert real directory state: no orphan file remains on disk
        try (Stream<Path> stream = Files.list(evidenceDir)) {
            List<Path> filesOnDisk = stream.toList();
            assertTrue(filesOnDisk.isEmpty(), "Storage directory must have no orphan files after DB failure: " + filesOnDisk);
        }

        // Assert real DB state: no record in evidence table
        assertEquals(0, evidenceRepository.count(), "Evidence table must contain 0 rows after failed save");
    }

    @Test
    @DisplayName("SEC-EVID-FAIL-02: When encrypted file write fails, no database row remains")
    void whenFileStorageWriteFailsNoDatabaseRowRemains() {
        MockMultipartFile file = new MockMultipartFile(
                "file", "valid_report.txt", "text/plain", "Forensic evidence content 12345".getBytes(StandardCharsets.UTF_8));

        Path evidenceDir = sharedTempDir.resolve("evidence");

        // Simulate storage write failure
        doThrow(new RuntimeException("Simulated disk write failure"))
                .when(evidenceStorageService).encryptAndStore(any(), any(), any());

        assertThrows(RuntimeException.class, () ->
                caseAccessService.uploadEvidence(testCase.getId(), file, clientPrincipal));

        // Assert real DB state: no row saved
        assertEquals(0, evidenceRepository.count(), "Evidence table must contain 0 rows after storage write failure");

        // Assert real directory state: no files on disk
        try (Stream<Path> stream = Files.list(evidenceDir)) {
            List<Path> filesOnDisk = stream.toList();
            assertTrue(filesOnDisk.isEmpty(), "Storage directory must contain no files after storage write failure");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
