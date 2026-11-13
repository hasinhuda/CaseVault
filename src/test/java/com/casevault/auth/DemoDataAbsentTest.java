package com.casevault.auth;

import com.casevault.bootstrap.DataBootstrapService;
import com.casevault.repository.CaseRepository;
import com.casevault.repository.OrganisationRepository;
import com.casevault.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase 9E: the demo data exists ONLY in the local profile. Each nested class has its own in-memory database, so the
 * bootstrap really runs there (default profile) or is refused (prod-like).
 */
class DemoDataAbsentTest {

    private static final String[] DEMO_USERS = {"demo_client_b", "demo_admin_2"};

    @Nested
    @SpringBootTest
    @TestPropertySource(properties = "spring.datasource.url=jdbc:h2:mem:casevault_demo_absent_default;DB_CLOSE_DELAY=-1")
    class DefaultProfile {
        @DynamicPropertySource
        static void configure(DynamicPropertyRegistry registry) {
            registry.add("casevault.audit.key-path", () -> java.nio.file.Paths.get("target", "demo-absent-default", "audit.key").toString());
            registry.add("casevault.storage.evidence-dir", () -> java.nio.file.Paths.get("target", "demo-absent-default", "evidence").toString());
            registry.add("casevault.storage.keyset-path", () -> java.nio.file.Paths.get("target", "demo-absent-default", "keyset.json").toString());
        }

        @Autowired
        UserRepository users;
        @Autowired
        OrganisationRepository organisations;
        @Autowired
        CaseRepository cases;

        @Test
        @DisplayName("DEMO-ABSENT-01: default (test) profile: the four normal accounts exist, no demo organisation, user, administrator or case")
        void noDemoDataInDefaultProfile() {
            assertTrue(users.findByUsername("admin_auditor").isPresent(), "the normal bootstrap still runs");
            assertEquals(4, users.count());
            for (String name : DEMO_USERS) {
                assertTrue(users.findByUsername(name).isEmpty(), name);
            }
            assertTrue(organisations.findByCode("ORG_DEMO_B").isEmpty());
            assertTrue(cases.findAll().stream().noneMatch(c -> c.getTitle().startsWith("DEMO")));
        }
    }

    @Nested
    @SpringBootTest
    @ActiveProfiles("prod-like")
    @TestPropertySource(properties = {
            "spring.datasource.url=jdbc:h2:mem:casevault_demo_absent_prod;DB_CLOSE_DELAY=-1",
            "spring.datasource.driverClassName=org.h2.Driver",
            "spring.datasource.username=sa",
            "spring.datasource.password=",
            "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect"
    })
    class ProdLikeProfile {
        @DynamicPropertySource
        static void configure(DynamicPropertyRegistry registry) {
            registry.add("casevault.audit.key-path", () -> java.nio.file.Paths.get("target", "demo-absent-prod", "audit.key").toString());
            registry.add("casevault.storage.evidence-dir", () -> java.nio.file.Paths.get("target", "demo-absent-prod", "evidence").toString());
            registry.add("casevault.storage.keyset-path", () -> java.nio.file.Paths.get("target", "demo-absent-prod", "keyset.json").toString());
        }

        @Autowired
        DataBootstrapService bootstrap;
        @Autowired
        UserRepository users;
        @Autowired
        OrganisationRepository organisations;
        @Autowired
        CaseRepository cases;

        @Test
        @DisplayName("DEMO-ABSENT-02: prod-like profile: no users, no demo organisation or case, and nothing printed when the bootstrap runs")
        void noDemoDataInProdLikeProfile() {
            PrintStream original = System.out;
            ByteArrayOutputStream captured = new ByteArrayOutputStream();
            try {
                System.setOut(new PrintStream(captured, true, StandardCharsets.UTF_8));
                bootstrap.run(new DefaultApplicationArguments(new String[0]));
            } finally {
                System.setOut(original);
            }
            String console = captured.toString(StandardCharsets.UTF_8);
            assertFalse(console.contains("DEMO DATA") || console.contains("Password:") || console.contains("demo_"));
            assertEquals(0, users.count());
            assertTrue(organisations.findByCode("ORG_DEMO_B").isEmpty());
            assertEquals(0, cases.count());
        }
    }
}
