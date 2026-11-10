package com.casevault.bootstrap;

import com.casevault.model.Organisation;
import com.casevault.model.Role;
import com.casevault.model.User;
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.time.Instant;
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

    @Value("${casevault.bootstrap.credentials-dir:.local-data}")
    private String credentialsDir;

    public DataBootstrapService(OrganisationRepository organisationRepository,
                                UserRepository userRepository,
                                PasswordEncoder passwordEncoder,
                                org.springframework.core.env.Environment environment) {
        this.organisationRepository = organisationRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.environment = environment;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (environment.matchesProfiles("prod-like")) {
            logger.info("Prod-like profile active: bootstrap is disabled in production environments.");
            return;
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
            saveCredentialsToLocalFile(adminPassword, managerPassword, analystPassword, clientPassword);
            printBootstrapConsoleBanner(adminPassword, managerPassword, analystPassword, clientPassword);
        }
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

    private void saveCredentialsToLocalFile(String adminPw, String managerPw, String analystPw, String clientPw) {
        try {
            Path baseDir = Paths.get(".").toAbsolutePath().normalize();
            Path dir = baseDir.resolve(".local-data").normalize();
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

            Files.writeString(credFile, sb.toString(), StandardCharsets.UTF_8);
            logger.info("Saved first-run synthetic credentials to secure local storage");
        } catch (IOException e) {
            logger.error("Failed to write bootstrap credentials to local storage", e);
        }
    }

    private void printBootstrapConsoleBanner(String adminPw, String managerPw, String analystPw, String clientPw) {
        System.out.println("\n================================================================================");
        System.out.println("  [CASEVAULT FIRST-RUN BOOTSTRAP] Initial Credentials Generated");
        System.out.println("--------------------------------------------------------------------------------");
        System.out.println("  Role: AUDITOR_ADMIN | Username: admin_auditor  | Password: " + adminPw);
        System.out.println("  Role: MANAGER       | Username: manager_alice  | Password: " + managerPw);
        System.out.println("  Role: ANALYST       | Username: analyst_bob    | Password: " + analystPw);
        System.out.println("  Role: CLIENT        | Username: client_charlie | Password: " + clientPw);
        System.out.println("================================================================================\n");
    }
}

