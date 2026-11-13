package com.casevault.bootstrap;

import com.casevault.model.Case;
import com.casevault.model.Organisation;
import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.CaseRepository;
import com.casevault.repository.OrganisationRepository;
import com.casevault.repository.UserRepository;
import com.casevault.security.PasswordPolicyValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

@Component
public class DataBootstrapService implements ApplicationRunner {

    private static final Logger logger = LoggerFactory.getLogger(DataBootstrapService.class);
    private static final String CHAR_LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String CHAR_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String NUMBER = "0123456789";
    private static final String OTHER_CHAR = "!@#$%&*()_+-=[]?";
    private static final String PASSWORD_ALLOW = CHAR_LOWER + CHAR_UPPER + NUMBER + OTHER_CHAR;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final OrganisationRepository organisationRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final org.springframework.core.env.Environment environment;
    private final CaseRepository caseRepository;

    @Value("${casevault.bootstrap.credentials-dir:.local-data}")
    private Path credentialsDir;

    /** Phase 12A opt-in (default false), honoured only in the prod-like profile. */
    @Value("${casevault.bootstrap.initial-accounts-enabled:false}")
    private boolean initialAccountsEnabled;

    /** Where the one-time credentials of the opt-in are written; no default. */
    @Value("${casevault.bootstrap.initial-credentials-file:#{null}}")
    private Path initialCredentialsFile;

    public DataBootstrapService(OrganisationRepository organisationRepository,
                                UserRepository userRepository,
                                PasswordEncoder passwordEncoder,
                                org.springframework.core.env.Environment environment,
                                CaseRepository caseRepository) {
        this.organisationRepository = organisationRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.environment = environment;
        this.caseRepository = caseRepository;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        boolean prodLike = environment.matchesProfiles("prod-like");
        if (prodLike && !initialAccountsEnabled) {
            logger.info("Prod-like profile active: bootstrap is disabled in production environments.");
            return;
        }
        if (prodLike && initialCredentialsFile == null) {
            // Phase 12A: the opt-in must say where the one-time credentials go. Nothing is created and nothing is printed.
            throw new IllegalStateException("casevault.bootstrap.initial-accounts-enabled=true requires "
                    + "casevault.bootstrap.initial-credentials-file (a path for the one-time credentials file); "
                    + "refusing to start without it.");
        }

        if (userRepository.count() > 0) {
            logger.info("Database already initialized with existing users. Skipping first-run bootstrap.");
            return;
        }

        logger.info("Initializing first-run CaseVault bootstrap data...");

        Instant now = Instant.now();

        // 1. Create baseline organisations
        Organisation internalOrg = organisationRepository.findByCode("ORG_INTERNAL")
                .orElseGet(() -> organisationRepository.save(new Organisation(
                        UUID.randomUUID().toString(),
                        "CyberConsulting IR Consultancy",
                        "ORG_INTERNAL",
                        now
                )));

        Organisation clientOrg = organisationRepository.findByCode("ORG_ACME")
                .orElseGet(() -> organisationRepository.save(new Organisation(
                        UUID.randomUUID().toString(),
                        "Acme Corporation Client",
                        "ORG_ACME",
                        now
                )));

        // 2. Generate secure credentials for each role
        String adminPassword = generateSecurePassword(18);
        String managerPassword = generateSecurePassword(18);
        String analystPassword = generateSecurePassword(18);
        String clientPassword = generateSecurePassword(18);

        // 3. Create synthetic users
        User admin = new User(
                UUID.randomUUID().toString(),
                null,
                "admin_auditor",
                passwordEncoder.encode(adminPassword),
                Role.AUDITOR_ADMIN,
                "admin.auditor@casevault.local",
                true,
                now
        );

        User manager = new User(
                UUID.randomUUID().toString(),
                internalOrg,
                "manager_alice",
                passwordEncoder.encode(managerPassword),
                Role.MANAGER,
                "alice.manager@casevault.local",
                true,
                now
        );

        User analyst = new User(
                UUID.randomUUID().toString(),
                internalOrg,
                "analyst_bob",
                passwordEncoder.encode(analystPassword),
                Role.ANALYST,
                "bob.analyst@casevault.local",
                true,
                now
        );

        User client = new User(
                UUID.randomUUID().toString(),
                clientOrg,
                "client_charlie",
                passwordEncoder.encode(clientPassword),
                Role.CLIENT,
                "charlie.client@acme.local",
                true,
                now
        );

        userRepository.save(admin);
        userRepository.save(manager);
        userRepository.save(analyst);
        userRepository.save(client);

        // 4. Save and print credentials ONLY in the "local" profile; silent in test and disabled in prod-like
        if (environment.matchesProfiles("local")) {
            // Phase 9E: demo data for browser tests (tenant isolation, two administrators). Created in the same
            // first-run pass, under the same guards (not prod-like, no users yet), only in the local profile, and
            // with random passwords handled exactly like the four accounts above.
            Map<String, String> demoCredentials = createLocalDemoData(now);
            saveCredentialsToLocalFile(adminPassword, managerPassword, analystPassword, clientPassword, demoCredentials);
            printBootstrapConsoleBanner(adminPassword, managerPassword, analystPassword, clientPassword, demoCredentials);
        } else if (prodLike) {
            // Phase 12A: explicit opt-in for a deployed stack. The four standard accounts only (no demo data), the
            // credentials go ONLY to the configured file; nothing is printed or logged. If the file cannot be
            // written the transaction rolls back, so no account exists whose password nobody knows.
            Map<String, String> initial = new LinkedHashMap<>();
            initial.put("admin_auditor", adminPassword);
            initial.put("manager_alice", managerPassword);
            initial.put("analyst_bob", analystPassword);
            initial.put("client_charlie", clientPassword);
            writeInitialCredentialsFile(initial);
            logger.info("Initial accounts created; the credentials were written to the configured file.");
        }
    }

    /** One-time credentials file for a deployed stack: owner-only permissions where the platform supports them. */
    private void writeInitialCredentialsFile(Map<String, String> credentials) {
        Path file = initialCredentialsFile.toAbsolutePath().normalize();
        StringBuilder content = new StringBuilder("# CaseVault initial credentials (one time; delete this file after the first login)\n");
        credentials.forEach((name, pw) -> content.append(name).append('=').append(pw).append('\n'));
        try {
            Path parent = file.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.deleteIfExists(file);
            if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
                Files.createFile(file, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            } else {
                Files.createFile(file);
            }
            Files.writeString(file, content.toString(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("The initial credentials file could not be written; no accounts were created.", e);
        }
    }

    /** DEMO data (synthetic): a second client organisation with a user and a case, and a second administrator. */
    private Map<String, String> createLocalDemoData(Instant now) {
        Organisation demoOrg = organisationRepository.findByCode("ORG_DEMO_B")
                .orElseGet(() -> organisationRepository.save(new Organisation(
                        UUID.randomUUID().toString(), "Demo Client Org B", "ORG_DEMO_B", now)));
        String demoClientPassword = generateSecurePassword(18);
        String demoAdminPassword = generateSecurePassword(18);
        User demoClient = userRepository.save(new User(UUID.randomUUID().toString(), demoOrg, "demo_client_b",
                passwordEncoder.encode(demoClientPassword), Role.CLIENT, "demo.client.b@demo.local", true, now));
        userRepository.save(new User(UUID.randomUUID().toString(), null, "demo_admin_2",
                passwordEncoder.encode(demoAdminPassword), Role.AUDITOR_ADMIN, "demo.admin.2@demo.local", true, now));
        caseRepository.save(new Case(UUID.randomUUID().toString(), demoOrg,
                "DEMO case of Demo Client Org B (synthetic demo data)", "OTHER", "LOW", "OPEN", demoClient, null, now));
        Map<String, String> credentials = new LinkedHashMap<>();
        credentials.put("demo_client_b", demoClientPassword);
        credentials.put("demo_admin_2", demoAdminPassword);
        return credentials;
    }

    public static String generateSecurePassword(int length) {
        StringBuilder sb;
        String password;
        do {
            sb = new StringBuilder(length);
            // Guarantee at least one of each required character category
            sb.append(CHAR_LOWER.charAt(RANDOM.nextInt(CHAR_LOWER.length())));
            sb.append(CHAR_UPPER.charAt(RANDOM.nextInt(CHAR_UPPER.length())));
            sb.append(NUMBER.charAt(RANDOM.nextInt(NUMBER.length())));
            sb.append(OTHER_CHAR.charAt(RANDOM.nextInt(OTHER_CHAR.length())));

            for (int i = 4; i < length; i++) {
                sb.append(PASSWORD_ALLOW.charAt(RANDOM.nextInt(PASSWORD_ALLOW.length())));
            }

            // Shuffle characters
            char[] chars = sb.toString().toCharArray();
            for (int i = chars.length - 1; i > 0; i--) {
                int j = RANDOM.nextInt(i + 1);
                char temp = chars[i];
                chars[i] = chars[j];
                chars[j] = temp;
            }
            password = new String(chars);
        } while (!PasswordPolicyValidator.isValid(password));

        return password;
    }

    private void saveCredentialsToLocalFile(String adminPw, String managerPw, String analystPw, String clientPw,
                                            Map<String, String> demoCredentials) {
        try {
            // Phase 9E: honour casevault.bootstrap.credentials-dir (default .local-data, so nothing changes for the
            // normal local start). Before this, the property was read but ignored, and tests overwrote the real file.
            Path dir = credentialsDir.toAbsolutePath().normalize();
            if (!Files.exists(dir)) {
                Files.createDirectories(dir);
            }
            Path credFile = dir.resolve("bootstrap-credentials.txt").normalize();
            if (!credFile.startsWith(dir)) {
                throw new SecurityException("Invalid target file path outside local-data directory");
            }
            StringBuilder sb = new StringBuilder();
            sb.append("# CaseVault First-Run Synthetic Credentials (Git-Ignored)\n");
            sb.append("# Generated At: ").append(Instant.now()).append("\n\n");
            sb.append("admin_auditor=").append(adminPw).append("\n");
            sb.append("manager_alice=").append(managerPw).append("\n");
            sb.append("analyst_bob=").append(analystPw).append("\n");
            sb.append("client_charlie=").append(clientPw).append("\n");
            sb.append("\n# DEMO accounts (local profile only)\n");
            demoCredentials.forEach((name, pw) -> sb.append(name).append('=').append(pw).append("\n"));

            Files.writeString(credFile, sb.toString(), StandardCharsets.UTF_8);
            logger.info("Saved first-run synthetic credentials to secure local storage");
        } catch (IOException e) {
            logger.error("Failed to write bootstrap credentials to local storage", e);
        }
    }

    private void printBootstrapConsoleBanner(String adminPw, String managerPw, String analystPw, String clientPw,
                                             Map<String, String> demoCredentials) {
        System.out.println("\n================================================================================");
        System.out.println("  [CASEVAULT FIRST-RUN BOOTSTRAP] Initial Credentials Generated");
        System.out.println("--------------------------------------------------------------------------------");
        System.out.println("  Role: AUDITOR_ADMIN | Username: admin_auditor  | Password: " + adminPw);
        System.out.println("  Role: MANAGER       | Username: manager_alice  | Password: " + managerPw);
        System.out.println("  Role: ANALYST       | Username: analyst_bob    | Password: " + analystPw);
        System.out.println("  Role: CLIENT        | Username: client_charlie | Password: " + clientPw);
        System.out.println("--------------------------------------------------------------------------------");
        System.out.println("  DEMO DATA (local profile only)");
        System.out.println("  Role: CLIENT (Demo Client Org B) | Username: demo_client_b | Password: " + demoCredentials.get("demo_client_b"));
        System.out.println("  Role: AUDITOR_ADMIN (second)     | Username: demo_admin_2  | Password: " + demoCredentials.get("demo_admin_2"));
        System.out.println("================================================================================\n");
    }
}

