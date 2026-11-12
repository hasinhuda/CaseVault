package com.casevault.db;

import com.casevault.model.Case;
import com.casevault.model.Evidence;
import com.casevault.model.Organisation;
import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.CaseRepository;
import com.casevault.repository.EvidenceRepository;
import com.casevault.repository.OrganisationRepository;
import com.casevault.repository.UserRepository;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationInfo;
import org.flywaydb.core.api.MigrationState;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Testcontainers
@SpringBootTest
public class PostgresFlywayMigrationTest {

    @Container
    static final PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driverClassName", () -> "org.postgresql.Driver");
        registry.add("spring.jpa.database-platform", () -> "org.hibernate.dialect.PostgreSQLDialect");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
        registry.add("spring.jpa.open-in-view", () -> "false");
    }

    @Autowired
    private Flyway flyway;

    @Autowired
    private OrganisationRepository organisationRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CaseRepository caseRepository;

    @Autowired
    private EvidenceRepository evidenceRepository;

    @Test
    @DisplayName("SEC-DB-001: Flyway V1, V2, V3, V4, and V5 migrations execute successfully on real PostgreSQL container")
    void testFlywayMigrationsOnRealPostgreSql() {
        assertNotNull(flyway, "Flyway bean must be configured");

        MigrationInfo[] applied = flyway.info().applied();
        assertEquals(10, applied.length, "V1-V6, the PostgreSQL-only V7, V8 (reports), V9 (user status trace) and V10 (report version) must be applied to PostgreSQL");

        assertEquals("1", applied[0].getVersion().getVersion());
        assertEquals("baseline", applied[0].getDescription());
        assertEquals(MigrationState.SUCCESS, applied[0].getState());

        assertEquals("2", applied[1].getVersion().getVersion());
        assertEquals("auth schema", applied[1].getDescription());
        assertEquals(MigrationState.SUCCESS, applied[1].getState());

        assertEquals("3", applied[2].getVersion().getVersion());
        assertEquals("cases and evidence schema", applied[2].getDescription());
        assertEquals(MigrationState.SUCCESS, applied[2].getState());

        assertEquals("4", applied[3].getVersion().getVersion());
        assertEquals("case workflow schema", applied[3].getDescription());
        assertEquals(MigrationState.SUCCESS, applied[3].getState());

        assertEquals("5", applied[4].getVersion().getVersion());
        assertEquals("evidence storage schema", applied[4].getDescription());
        assertEquals(MigrationState.SUCCESS, applied[4].getState());

        // Phase 6A: V6 (all databases) and V7 (PostgreSQL-only immutability trigger, vendor location).
        assertEquals("6", applied[5].getVersion().getVersion());
        assertEquals("audit events", applied[5].getDescription());
        assertEquals(MigrationState.SUCCESS, applied[5].getState());

        assertEquals("7", applied[6].getVersion().getVersion());
        assertEquals("audit events immutable", applied[6].getDescription());
        assertEquals(MigrationState.SUCCESS, applied[6].getState());

        // Phase 7A: V8 reports (all databases).
        assertEquals("8", applied[7].getVersion().getVersion());
        assertEquals("reports", applied[7].getDescription());
        assertEquals(MigrationState.SUCCESS, applied[7].getState());

        // Phase 7B: V9 user status trace (all databases).
        assertEquals("9", applied[8].getVersion().getVersion());
        assertEquals("user status trace", applied[8].getDescription());
        assertEquals(MigrationState.SUCCESS, applied[8].getState());

        // Phase 7C: V10 report version (all databases).
        assertEquals("10", applied[9].getVersion().getVersion());
        assertEquals("report version", applied[9].getDescription());
        assertEquals(MigrationState.SUCCESS, applied[9].getState());
    }

    @Test
    @DisplayName("SEC-DB-002: Real PostgreSQL schema enforces foreign keys, unique constraints, and schema operations")
    void testPostgresSchemaIntegrityAndCrud() {
        Instant now = Instant.now();
        String orgId = UUID.randomUUID().toString();
        Organisation org = new Organisation(orgId, "PostgreSQL Security Testing Corp", "ORG_PG_TEST", now);
        organisationRepository.save(org);

        String userId = UUID.randomUUID().toString();
        User user = new User(
                userId,
                org,
                "pg_test_analyst",
                "$argon2id$v=19$m=65536,t=3,p=1$fakeHashForPgContainerTest",
                Role.ANALYST,
                "pg.analyst@casevault.local",
                true,
                now
        );
        userRepository.save(user);

        User retrieved = userRepository.findById(userId).orElseThrow();
        assertEquals("pg_test_analyst", retrieved.getUsername());
        assertNotNull(retrieved.getOrganisation());
        assertEquals("ORG_PG_TEST", retrieved.getOrganisation().getCode());
        assertTrue(retrieved.isEnabled());

        // Verify Evidence V5 schema integrity on real PostgreSQL
        Case testCase = caseRepository.save(new Case(
                UUID.randomUUID().toString(), org, "PG Evidence Test Case", "SECURITY_INCIDENT",
                "HIGH", "OPEN", user, null, now
        ));

        String evidenceId = UUID.randomUUID().toString();
        String storedName = UUID.randomUUID().toString();
        Evidence ev = evidenceRepository.save(new Evidence(
                evidenceId,
                testCase,
                "forensic_image.raw",
                storedName,
                "application/octet-stream",
                4096L,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                1,
                user,
                now
        ));

        Evidence retrievedEv = evidenceRepository.findById(evidenceId).orElseThrow();
        assertEquals("forensic_image.raw", retrievedEv.getOriginalName());
        assertEquals(storedName, retrievedEv.getStoredName());
        assertEquals("application/octet-stream", retrievedEv.getContentType());
        assertEquals(4096L, retrievedEv.getSizeBytes());
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", retrievedEv.getSha256Hex());
        assertEquals(1, retrievedEv.getEncryptionVersion());
    }
}
