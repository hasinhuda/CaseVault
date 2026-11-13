package com.casevault.deploy;

import com.casevault.support.TestAppStarter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.context.ConfigurableApplicationContext;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase 12A: the two ways of reading a proxy address must not be combined, and the prod-like profile uses Tomcat's
 * remote address handling with the limiter flag off. Environment-variable names for a compose file are checked too.
 */
class ForwardedForStrategyGuardTest {

    @TempDir
    Path tempDir;

    @Test
    @DisplayName("DEPLOY-PROXY-01: trust-forwarded-for=true together with server.forward-headers-strategy=native refuses to start (a left-over spoofed entry could become the limiter key)")
    void bothMechanismsAreRefused() {
        List<String> args = TestAppStarter.baseArgs(tempDir, true);
        args.add("--casevault.ratelimit.trust-forwarded-for=true");
        args.add("--server.forward-headers-strategy=native");
        Throwable failure = assertThrows(Throwable.class, () -> TestAppStarter.start("default", true, args).close());
        String messages = TestAppStarter.messages(failure);
        assertTrue(messages.contains("must not be combined"), messages);
    }

    @Test
    @DisplayName("DEPLOY-PROXY-02: prod-like starts with strategy native and the limiter flag off (as shipped); the flag alone (strategy none) is still allowed as before")
    void prodLikeDefaultsAndFlagAloneAllowed() {
        List<String> prodLike = TestAppStarter.baseArgs(tempDir, true);
        try (ConfigurableApplicationContext context = TestAppStarter.start("prod-like", true, prodLike)) {
            assertEquals("native", context.getEnvironment().getProperty("server.forward-headers-strategy"));
            assertEquals("false", context.getEnvironment().getProperty("casevault.ratelimit.trust-forwarded-for"));
        }
        List<String> flagOnly = TestAppStarter.baseArgs(tempDir, true);
        flagOnly.add("--casevault.ratelimit.trust-forwarded-for=true");
        try (ConfigurableApplicationContext context = TestAppStarter.start("default", true, flagOnly)) {
            assertTrue(context.isActive());
        }
    }
}
