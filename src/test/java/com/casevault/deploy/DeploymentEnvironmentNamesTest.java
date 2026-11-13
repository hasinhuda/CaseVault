package com.casevault.deploy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.PropertySourcesPropertyResolver;
import org.springframework.core.env.SystemEnvironmentPropertySource;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Phase 12A: the environment variable names a compose file must use. They are checked with the same mechanisms
 * Spring uses at start-up (resolver for @Value placeholders, binder for configuration properties).
 */
class DeploymentEnvironmentNamesTest {

    private static SystemEnvironmentPropertySource env(Map<String, Object> values) {
        return new SystemEnvironmentPropertySource("systemEnvironment", values);
    }

    @Test
    @DisplayName("DEPLOY-ENV-01: the opt-in and database variables map to the property names (@Value placeholders)")
    void valuePlaceholdersFromEnvironment() {
        MutablePropertySources sources = new MutablePropertySources();
        sources.addFirst(env(Map.of(
                "CASEVAULT_BOOTSTRAP_INITIAL_ACCOUNTS_ENABLED", "true",
                "CASEVAULT_BOOTSTRAP_INITIAL_CREDENTIALS_FILE", "/run/casevault/initial-credentials.txt",
                "POSTGRES_PASSWORD", "x")));
        PropertySourcesPropertyResolver resolver = new PropertySourcesPropertyResolver(sources);
        assertEquals("true", resolver.getProperty("casevault.bootstrap.initial-accounts-enabled"));
        assertEquals("/run/casevault/initial-credentials.txt", resolver.getProperty("casevault.bootstrap.initial-credentials-file"));
        assertEquals("x", resolver.getProperty("POSTGRES_PASSWORD"));
    }

    @Test
    @DisplayName("DEPLOY-ENV-02: SPRING_DATASOURCE_PASSWORD binds to spring.datasource.password and SPRING_PROFILES_ACTIVE to spring.profiles.active")
    void springEnvironmentVariablesBind() {
        Binder binder = new Binder(ConfigurationPropertySources.from(env(Map.of(
                "SPRING_DATASOURCE_PASSWORD", "y",
                "SPRING_PROFILES_ACTIVE", "prod-like"))));
        assertEquals("y", binder.bind("spring.datasource.password", String.class).get());
        assertEquals("prod-like", binder.bind("spring.profiles.active", String.class).get());
    }
}
