package com.casevault.support;

import com.casevault.CaseVaultApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.StandardEnvironment;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Starts the real application (servlet web server on a random port) with explicit command-line style arguments, for
 * tests of start-up behaviour (profiles, secrets, opt-ins). The environment can be created WITHOUT the operating
 * system's environment variables and system properties, so a variable such as POSTGRES_PASSWORD on the developer's
 * machine cannot change the result. PostgreSQL is replaced by a private in-memory H2 database.
 */
public final class TestAppStarter {

    private TestAppStarter() {
    }

    /** Base arguments: private H2 database, temp directories for keys and evidence, random port. */
    public static List<String> baseArgs(Path tempDir, boolean withPassword) {
        List<String> args = new ArrayList<>(List.of(
                "--server.port=0",
                "--spring.main.banner-mode=off",
                "--spring.datasource.url=jdbc:h2:mem:casevault_start_" + UUID.randomUUID().toString().replace("-", "") + ";DB_CLOSE_DELAY=-1",
                "--spring.datasource.driverClassName=org.h2.Driver",
                "--spring.datasource.username=sa",
                "--spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
                "--casevault.audit.key-path=" + tempDir.resolve("keys").resolve("audit.key").toString().replace('\\', '/'),
                "--casevault.storage.evidence-dir=" + tempDir.resolve("evidence").toString().replace('\\', '/'),
                "--casevault.storage.keyset-path=" + tempDir.resolve("keyset.json").toString().replace('\\', '/')));
        if (withPassword) {
            args.add("--spring.datasource.password=");
        }
        return args;
    }

    /** Starts the application. {@code isolatedEnvironment} drops OS environment variables and system properties. */
    public static ConfigurableApplicationContext start(String profile, boolean isolatedEnvironment, List<String> args) {
        SpringApplicationBuilder builder = new SpringApplicationBuilder(CaseVaultApplication.class).profiles(profile);
        if (isolatedEnvironment) {
            StandardEnvironment environment = new StandardEnvironment();
            environment.getPropertySources().remove(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
            environment.getPropertySources().remove(StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
            builder.environment(environment);
        }
        return builder.run(args.toArray(new String[0]));
    }

    /** The messages of the exception and all its causes, joined (for "fails with a clear message" assertions). */
    public static String messages(Throwable t) {
        StringBuilder sb = new StringBuilder();
        for (Throwable c = t; c != null; c = c.getCause()) {
            sb.append(c.getMessage()).append(" | ");
        }
        return sb.toString();
    }
}
