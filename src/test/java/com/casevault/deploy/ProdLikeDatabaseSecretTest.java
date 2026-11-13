package com.casevault.deploy;

import com.casevault.support.TestAppStarter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.context.ConfigurableApplicationContext;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase 12A: the prod-like profile has no default database password. A password must come from the environment
 * (POSTGRES_PASSWORD or SPRING_DATASOURCE_PASSWORD) or from a Docker/Compose secret file read through Spring Boot's
 * configtree import. The application is started for real (private H2 database instead of PostgreSQL, OS environment
 * variables hidden so the developer's machine cannot change the result).
 */
class ProdLikeDatabaseSecretTest {

    @TempDir
    Path tempDir;

    @Test
    @DisplayName("DEPLOY-SECRET-01: prod-like without any database password fails fast at start-up with a message naming POSTGRES_PASSWORD (no default password)")
    void failsFastWithoutPassword() {
        List<String> args = TestAppStarter.baseArgs(tempDir, false);
        Throwable failure = assertThrows(Throwable.class, () -> TestAppStarter.start("prod-like", true, args).close());
        String messages = TestAppStarter.messages(failure);
        assertTrue(messages.contains("POSTGRES_PASSWORD"), messages);
    }

    @Test
    @DisplayName("DEPLOY-SECRET-02: a secret file named spring.datasource.password in a configtree directory supplies the password")
    void configtreeSuppliesThePassword() throws IOException {
        Path secrets = Files.createDirectory(tempDir.resolve("run-secrets"));
        Files.writeString(secrets.resolve("spring.datasource.password"), "test-only-secret-value");
        List<String> args = TestAppStarter.baseArgs(tempDir, false);
        args.add("--spring.config.import=optional:configtree:" + secrets.toAbsolutePath().toString().replace('\\', '/') + "/");
        try (ConfigurableApplicationContext context = TestAppStarter.start("prod-like", true, args)) {
            assertEquals("test-only-secret-value", context.getEnvironment().getProperty("spring.datasource.password"));
            assertTrue(context.isActive());
        }
    }

    @Test
    @DisplayName("DEPLOY-SECRET-03: an environment-style POSTGRES_PASSWORD still works without any secret file")
    void environmentPasswordStillWorks() {
        List<String> args = TestAppStarter.baseArgs(tempDir, false);
        args.add("--POSTGRES_PASSWORD=test-only-env-value");
        try (ConfigurableApplicationContext context = TestAppStarter.start("prod-like", true, args)) {
            assertEquals("test-only-env-value", context.getEnvironment().getProperty("spring.datasource.password"));
        }
    }

    @Test
    @DisplayName("DEPLOY-SECRET-05: the prod-like profile names the PostgreSQL driver (the base file sets the H2 driver; without this override the real stack cannot start)")
    void profileNamesThePostgresqlDriver() throws IOException {
        String file = Files.readString(Path.of("src/main/resources/application-prod-like.properties"));
        assertTrue(file.contains("spring.datasource.driverClassName=org.postgresql.Driver"));
        assertTrue(file.indexOf("spring.datasource.driverClassName=org.postgresql.Driver") < file.indexOf("spring.datasource.url="));
    }

    @Test
    @DisplayName("DEPLOY-SECRET-04: the profile file contains no default password and states that TLS is not terminated by the application")
    void profileFileHasNoDefaultPassword() throws IOException {
        String file = Files.readString(Path.of("src/main/resources/application-prod-like.properties"));
        assertFalse(file.contains("POSTGRES_PASSWORD:"), "no ${POSTGRES_PASSWORD:default}");
        assertTrue(file.contains("spring.datasource.password=${POSTGRES_PASSWORD}"));
        assertTrue(file.contains("optional:configtree:/run/secrets/"));
        assertTrue(file.contains("does NOT terminate TLS"));
        assertFalse(file.contains("Strict HTTPS"));
        assertFalse(file.contains("server.port=8443"));
    }
}
