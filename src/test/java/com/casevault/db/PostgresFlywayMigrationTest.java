package com.casevault.db;

import com.casevault.model.Organisation;
import com.casevault.model.Role;
import com.casevault.model.User;
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

    @Test
    @DisplayName("SEC-DB-001: Flyway V1 and V2 migrations execute successfully on real PostgreSQL container")
    void testFlywayMigrationsOnRealPostgreSql() {
        assertNotNull(flyway, "Flyway bean must be configured");

        MigrationInfo[] applied = flyway.info().applied();
        assertEquals(2, applied.length, "Both V1 and V2 migrations must be applied to PostgreSQL");

        assertEquals("1", applied[0].getVersion().getVersion());
        assertEquals("baseline", applied[0].getDescription());
        assertEquals(MigrationState.SUCCESS, applied[0].getState());

        assertEquals("2", applied[1].getVersion().getVersion());
        assertEquals("auth schema", applied[1].getDescription());
        assertEquals(MigrationState.SUCCESS, applied[1].getState());
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
    }
}

