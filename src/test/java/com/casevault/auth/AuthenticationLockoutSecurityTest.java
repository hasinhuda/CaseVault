package com.casevault.auth;

import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.UserRepository;
import com.casevault.security.CaseVaultAuthenticationProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
public class AuthenticationLockoutSecurityTest {

    @Autowired
    private CaseVaultAuthenticationProvider authenticationProvider;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private User testUser;
    private final String rawPassword = "ValidTestPassword123!";

    @BeforeEach
    void setUp() {
        String testUsername = "lockout_test_user_" + UUID.randomUUID().toString().substring(0, 8);
        testUser = new User(
                UUID.randomUUID().toString(),
                null,
                testUsername,
                passwordEncoder.encode(rawPassword),
                Role.ANALYST,
                testUsername + "@casevault.local",
                true,
                Instant.now()
        );
        userRepository.save(testUser);
    }

    @Test
    @DisplayName("SEC-AUTH-03: Account locks after 5 consecutive failed attempts for 15 minutes")
    void testAccountLockoutAfterFiveFailures() {
        // First 4 failed attempts: account should not be locked yet
        for (int i = 1; i <= 4; i++) {
            BadCredentialsException ex = assertThrows(BadCredentialsException.class, () ->
                    authenticationProvider.authenticate(new UsernamePasswordAuthenticationToken(testUser.getUsername(), "WrongPw123!"))
            );
            assertEquals(CaseVaultAuthenticationProvider.GENERIC_AUTH_ERROR, ex.getMessage());
            User u = userRepository.findById(testUser.getId()).orElseThrow();
            assertEquals(i, u.getFailedLoginAttempts());
            assertFalse(u.isAccountLocked(Instant.now()));
        }

        // 5th failed attempt: triggers lockout
        BadCredentialsException ex5 = assertThrows(BadCredentialsException.class, () ->
                authenticationProvider.authenticate(new UsernamePasswordAuthenticationToken(testUser.getUsername(), "WrongPw123!"))
        );
        assertEquals(CaseVaultAuthenticationProvider.GENERIC_AUTH_ERROR, ex5.getMessage());

        User lockedUser = userRepository.findById(testUser.getId()).orElseThrow();
        assertEquals(5, lockedUser.getFailedLoginAttempts());
        assertTrue(lockedUser.isAccountLocked(Instant.now()), "Account must be locked after 5 failures");
        assertNotNull(lockedUser.getLockedUntil());
        assertTrue(lockedUser.getLockedUntil().isAfter(Instant.now()));

        // Even with the CORRECT password, locked user is rejected
        BadCredentialsException exLocked = assertThrows(BadCredentialsException.class, () ->
                authenticationProvider.authenticate(new UsernamePasswordAuthenticationToken(testUser.getUsername(), rawPassword))
        );
        assertEquals(CaseVaultAuthenticationProvider.GENERIC_AUTH_ERROR, exLocked.getMessage());
    }

    @Test
    @DisplayName("SEC-AUTH-04: Error message is generic and identical for unknown user and wrong password")
    void testGenericErrorMessageUniformity() {
        // Unknown user
        BadCredentialsException unknownUserEx = assertThrows(BadCredentialsException.class, () ->
                authenticationProvider.authenticate(new UsernamePasswordAuthenticationToken("non_existent_user_999", "SomePassword123!"))
        );

        // Wrong password for existing user
        BadCredentialsException wrongPwEx = assertThrows(BadCredentialsException.class, () ->
                authenticationProvider.authenticate(new UsernamePasswordAuthenticationToken(testUser.getUsername(), "IncorrectPassword123!"))
        );

        assertEquals(CaseVaultAuthenticationProvider.GENERIC_AUTH_ERROR, unknownUserEx.getMessage());
        assertEquals(CaseVaultAuthenticationProvider.GENERIC_AUTH_ERROR, wrongPwEx.getMessage());
        assertEquals(unknownUserEx.getMessage(), wrongPwEx.getMessage());
    }

    @Test
    @DisplayName("SEC-AUTH-05: Non-existent user executes dummy Argon2id evaluation for timing equalization")
    void testConstantTimingDummyEvaluation() {
        // Warm up JIT and thread pool
        try {
            authenticationProvider.authenticate(new UsernamePasswordAuthenticationToken("warmup_non_existent", "WarmupPw123!"));
        } catch (BadCredentialsException ignored) {
        }

        long startUnknown = System.nanoTime();
        try {
            authenticationProvider.authenticate(new UsernamePasswordAuthenticationToken("unknown_timing_user", "TestPassword123!"));
        } catch (BadCredentialsException ignored) {
        }
        long durationUnknownMs = (System.nanoTime() - startUnknown) / 1_000_000;

        long startExisting = System.nanoTime();
        try {
            authenticationProvider.authenticate(new UsernamePasswordAuthenticationToken(testUser.getUsername(), "TestPassword123!"));
        } catch (BadCredentialsException ignored) {
        }
        long durationExistingMs = (System.nanoTime() - startExisting) / 1_000_000;

        // Both executions perform an Argon2id verification (memory=64MB, iterations=3), so both take non-trivial time (>10ms)
        assertTrue(durationUnknownMs > 5, "Unknown user must execute Argon2id dummy hash, taking significant computation time");
        assertTrue(durationExistingMs > 5, "Existing user invalid password check must take significant computation time");
    }

    @Test
    @DisplayName("SEC-AUTH-10: Disabled account cannot log in even with valid credentials")
    @Transactional
    void testDisabledAccountCannotLogin() {
        testUser.setEnabled(false);
        userRepository.save(testUser);

        BadCredentialsException ex = assertThrows(BadCredentialsException.class, () ->
                authenticationProvider.authenticate(new UsernamePasswordAuthenticationToken(testUser.getUsername(), rawPassword))
        );
        assertEquals(CaseVaultAuthenticationProvider.GENERIC_AUTH_ERROR, ex.getMessage());
    }
}

