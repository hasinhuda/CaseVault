package com.casevault.auth;

import com.casevault.security.PasswordEncoderConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
public class Argon2idSecurityTest {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    @DisplayName("SEC-AUTH-01: Argon2id password hashing matches expected parameters and verifies correctly")
    void testArgon2idParametersAndVerification() {
        assertNotNull(passwordEncoder, "PasswordEncoder must be configured");
        assertTrue(passwordEncoder instanceof Argon2PasswordEncoder, "PasswordEncoder must be Argon2PasswordEncoder");

        String rawPassword = "CorrectHorseBatteryStaple123!";
        String encoded = passwordEncoder.encode(rawPassword);

        assertNotNull(encoded);
        // Argon2 format starts with $argon2id$v=19$m=65536,t=3,p=1$
        assertTrue(encoded.startsWith("$argon2id$"), "Hash must use Argon2id variant");
        assertTrue(encoded.contains("m=" + PasswordEncoderConfig.MEMORY_KIB), "Memory cost must be 65536 KiB (64 MiB)");
        assertTrue(encoded.contains("t=" + PasswordEncoderConfig.ITERATIONS), "Iterations must be 3");
        assertTrue(encoded.contains("p=" + PasswordEncoderConfig.PARALLELISM), "Parallelism must be 1");

        assertTrue(passwordEncoder.matches(rawPassword, encoded), "Correct password must match hash");
        assertFalse(passwordEncoder.matches("WrongPassword123!", encoded), "Incorrect password must not match hash");
    }
}

