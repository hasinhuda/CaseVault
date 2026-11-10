package com.casevault.auth;

import com.casevault.bootstrap.DataBootstrapService;
import com.casevault.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
@ActiveProfiles("prod-like")
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:h2:mem:casevault_prod_test;DB_CLOSE_DELAY=-1",
        "spring.datasource.driverClassName=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect"
})
public class BootstrapProdProfileSecurityTest {

    @Autowired
    private DataBootstrapService bootstrapService;

    @Autowired
    private UserRepository userRepository;

    @Test
    @DisplayName("SEC-AUTH-15: Prod-like profile strictly disables bootstrap generation and prints no credentials")
    void testProdLikeProfileDisablesBootstrap() {
        // Capture stdout
        PrintStream originalOut = System.out;
        ByteArrayOutputStream capturedOut = new ByteArrayOutputStream();

        try {
            System.setOut(new PrintStream(capturedOut, true, StandardCharsets.UTF_8));

            // Execute bootstrap runner explicitly in prod-like profile context
            bootstrapService.run(new DefaultApplicationArguments(new String[0]));

            String consoleOutput = capturedOut.toString(StandardCharsets.UTF_8);

            // Verify nothing was printed to console
            assertFalse(consoleOutput.contains("CASEVAULT FIRST-RUN BOOTSTRAP"),
                    "Prod-like profile must never print bootstrap credentials to stdout");
            assertFalse(consoleOutput.contains("Password:"),
                    "Console output must never contain password strings");

            // Verify no bootstrap users were created
            assertTrue(userRepository.findByUsername("admin_auditor").isEmpty(),
                    "admin_auditor must not be generated under prod-like profile");
            assertTrue(userRepository.findByUsername("manager_alice").isEmpty(),
                    "manager_alice must not be generated under prod-like profile");
            assertTrue(userRepository.findByUsername("analyst_bob").isEmpty(),
                    "analyst_bob must not be generated under prod-like profile");
            assertTrue(userRepository.findByUsername("client_charlie").isEmpty(),
                    "client_charlie must not be generated under prod-like profile");
        } finally {
            System.setOut(originalOut);
        }
    }
}

