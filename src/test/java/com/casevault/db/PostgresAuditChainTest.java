package com.casevault.db;

import com.casevault.model.AuditEvent;
import com.casevault.service.AuditEventType;
import com.casevault.service.AuditLogService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.file.Path;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Real PostgreSQL (Docker required): millisecond round trip, chain verification and DB-level immutability. */
@Testcontainers
@SpringBootTest
class PostgresAuditChainTest {

    @TempDir
    static Path sharedTempDir;

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
        registry.add("casevault.audit.key-path", () -> sharedTempDir.resolve("keys").resolve("audit.key").toString());
        registry.add("casevault.storage.evidence-dir", () -> sharedTempDir.resolve("evidence").toString());
        registry.add("casevault.storage.keyset-path", () -> sharedTempDir.resolve("keyset.json").toString());
    }

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    @DisplayName("SEC-AUDIT-16: on PostgreSQL the timestamp keeps millisecond precision and the chain verifies after a round trip")
    void millisecondsRoundTripOnPostgres() {
        UUID user = UUID.randomUUID();
        AuditEvent saved = null;
        for (int i = 0; i < 5; i++) {
            saved = auditLogService.append(AuditEventType.CASE_CREATED, user, UUID.randomUUID(), "CREATED");
            assertEquals(0, saved.getOccurredAt().getNano() % 1_000_000);
        }
        assertTrue(auditLogService.verifyChain().valid());
        assertTrue(auditLogService.verifyChain(2).valid());
        assertEquals(0, auditLogService.currentHead().orElseThrow().sequenceNo() - saved.getSequenceNo());
    }

    @Test
    @DisplayName("SEC-AUDIT-17: on PostgreSQL the immutability trigger rejects UPDATE, DELETE and TRUNCATE on audit_events")
    void postgresRejectsMutation() {
        auditLogService.append(AuditEventType.LOGIN_SUCCESS, UUID.randomUUID(), null, "SUCCESS");

        assertThrows(DataAccessException.class, () -> jdbc.update("UPDATE audit_events SET reason_code = 'SUCCESS'"));
        assertThrows(DataAccessException.class, () -> jdbc.update("DELETE FROM audit_events"));
        assertThrows(DataAccessException.class, () -> jdbc.execute("TRUNCATE TABLE audit_events"));
        assertTrue(auditLogService.verifyChain().valid());
    }
}
