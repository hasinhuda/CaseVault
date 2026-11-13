package com.casevault.deploy;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.casevault.model.User;
import com.casevault.repository.CaseRepository;
import com.casevault.repository.OrganisationRepository;
import com.casevault.repository.UserRepository;
import com.casevault.security.PasswordPolicyValidator;
import com.casevault.support.TestAppStarter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;
import org.springframework.context.ConfigurableApplicationContext;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase 12A: the opt-in that creates the four standard accounts in a deployed (prod-like) stack. Default off; when on
 * it needs a credentials file path, writes the random passwords only there, and creates no demo data. Each test starts
 * the real application with a private H2 database (the "existing users" test starts it twice on the same database).
 */
class InitialAccountsOptInTest {

    private static final List<String> NAMES = List.of("admin_auditor", "manager_alice", "analyst_bob", "client_charlie");

    @TempDir
    Path tempDir;

    private static List<String> optIn(Path tempDir, Path credentialsFile) {
        List<String> args = TestAppStarter.baseArgs(tempDir, true);
        args.add("--casevault.bootstrap.initial-accounts-enabled=true");
        if (credentialsFile != null) {
            args.add("--casevault.bootstrap.initial-credentials-file=" + credentialsFile.toAbsolutePath().toString().replace('\\', '/'));
        }
        return args;
    }

    private static Map<String, String> readCredentials(Path file) throws IOException {
        Map<String, String> result = new HashMap<>();
        for (String line : Files.readAllLines(file)) {
            if (!line.startsWith("#") && line.contains("=")) {
                result.put(line.substring(0, line.indexOf('=')), line.substring(line.indexOf('=') + 1));
            }
        }
        return result;
    }

    @Test
    @DisplayName("DEPLOY-BOOT-01: default prod-like creates no users, no organisations and no cases, and writes no credentials")
    void defaultCreatesNothing() {
        List<String> args = TestAppStarter.baseArgs(tempDir, true);
        try (ConfigurableApplicationContext context = TestAppStarter.start("prod-like", true, args)) {
            assertEquals(0, context.getBean(UserRepository.class).count());
            assertEquals(0, context.getBean(CaseRepository.class).count());
            assertTrue(context.getBean(OrganisationRepository.class).findByCode("ORG_DEMO_B").isEmpty());
        }
    }

    @Test
    @DisplayName("DEPLOY-BOOT-02: with the opt-in and a file path the four standard accounts exist (no demo data); passwords are random, distinct, policy-valid, only Argon2id hashes in the database, in the owner-only file, and in no log line or console output")
    void optInCreatesTheStandardAccountsOnly() throws IOException {
        Path file = tempDir.resolve("secure").resolve("initial-credentials.txt");
        ListAppender<ILoggingEvent> logs = new ListAppender<>();
        logs.start();
        Logger root = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        root.addAppender(logs);
        PrintStream originalOut = System.out;
        ByteArrayOutputStream console = new ByteArrayOutputStream();
        try {
            System.setOut(new PrintStream(console, true, StandardCharsets.UTF_8));
            try (ConfigurableApplicationContext context = TestAppStarter.start("prod-like", true, optIn(tempDir, file))) {
                UserRepository users = context.getBean(UserRepository.class);
                assertEquals(4, users.count());
                assertEquals(0, context.getBean(CaseRepository.class).count(), "no demo case");
                assertTrue(context.getBean(OrganisationRepository.class).findByCode("ORG_DEMO_B").isEmpty(), "no demo organisation");
                assertTrue(users.findByUsername("demo_client_b").isEmpty() && users.findByUsername("demo_admin_2").isEmpty());

                assertTrue(Files.exists(file), "credentials file");
                Map<String, String> credentials = readCredentials(file);
                assertEquals(new HashSet<>(NAMES), credentials.keySet());
                assertEquals(4, new HashSet<>(credentials.values()).size(), "distinct passwords");
                for (String name : NAMES) {
                    String pw = credentials.get(name);
                    assertEquals(18, pw.length());
                    assertTrue(PasswordPolicyValidator.isValid(pw));
                    User user = users.findByUsername(name).orElseThrow();
                    assertTrue(user.getPasswordHash().startsWith("$argon2id$"));
                    assertFalse(user.getPasswordHash().contains(pw));
                    for (ILoggingEvent event : logs.list) {
                        assertFalse(event.getFormattedMessage().contains(pw), "a log line contains a password");
                    }
                    assertFalse(console.toString(StandardCharsets.UTF_8).contains(pw), "console output contains a password");
                }
                assertFalse(console.toString(StandardCharsets.UTF_8).contains("FIRST-RUN BOOTSTRAP"));
                if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
                    assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(file));
                }
            }
        } finally {
            System.setOut(originalOut);
            root.detachAppender(logs);
            logs.stop();
        }
    }

    @Test
    @DisplayName("DEPLOY-BOOT-03: the opt-in without a credentials file path refuses to start with a clear message and creates nothing")
    void optInWithoutPathFailsToStart() {
        Throwable failure = assertThrows(Throwable.class,
                () -> TestAppStarter.start("prod-like", true, optIn(tempDir, null)).close());
        String messages = TestAppStarter.messages(failure);
        assertTrue(messages.contains("casevault.bootstrap.initial-credentials-file"), messages);
        assertFalse(Files.exists(tempDir.resolve("initial-credentials.txt")));
    }

    @Test
    @DisplayName("DEPLOY-BOOT-04: with existing users the opt-in does nothing (no new accounts, no new file)")
    void existingUsersAreLeftAlone() {
        Path first = tempDir.resolve("first.txt");
        Path second = tempDir.resolve("second.txt");
        List<String> firstArgs = optIn(tempDir, first);
        // the second start uses the SAME in-memory database
        String database = firstArgs.stream().filter(a -> a.startsWith("--spring.datasource.url=")).findFirst().orElseThrow();
        List<String> secondArgs = optIn(tempDir, second);
        secondArgs.removeIf(a -> a.startsWith("--spring.datasource.url="));
        secondArgs.add(database);
        try (ConfigurableApplicationContext one = TestAppStarter.start("prod-like", true, firstArgs)) {
            assertEquals(4, one.getBean(UserRepository.class).count());
            try (ConfigurableApplicationContext two = TestAppStarter.start("prod-like", true, secondArgs)) {
                assertEquals(4, two.getBean(UserRepository.class).count(), "no additional accounts");
            }
        }
        assertTrue(Files.exists(first));
        assertFalse(Files.exists(second), "no second credentials file");
    }

    @Test
    @DisplayName("DEPLOY-BOOT-05: the opt-in property has no effect outside prod-like (the default profile bootstrap is unchanged: no credentials file is written)")
    void flagIsIgnoredInTheDefaultProfile() {
        Path file = tempDir.resolve("ignored.txt");
        try (ConfigurableApplicationContext context = TestAppStarter.start("default", true, optIn(tempDir, file))) {
            assertEquals(4, context.getBean(UserRepository.class).count(), "the existing silent bootstrap of the default profile");
        }
        assertFalse(Files.exists(file), "the default profile never writes this file");
    }
}
