package com.casevault.auth;

import com.casevault.security.PasswordPolicyValidator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PasswordPolicySecurityTest {

    @Test
    @DisplayName("SEC-AUTH-02: Password policy accepts valid passwords meeting length, complexity, and rarity rules")
    void testValidPasswordAccepted() {
        assertTrue(PasswordPolicyValidator.isValid("SecureP@ssw0rd2026!"));
        assertTrue(PasswordPolicyValidator.isValid("Vault#Crypt99Alpha"));
        assertTrue(PasswordPolicyValidator.isValid("VeryStrongAndLongP@ss1"));
    }

    @Test
    @DisplayName("SEC-AUTH-02a: Password policy rejects passwords shorter than 12 characters")
    void testShortPasswordRejected() {
        assertFalse(PasswordPolicyValidator.isValid("Short1!"));
        assertFalse(PasswordPolicyValidator.isValid("Abc1234567!")); // 11 chars
        assertThrows(PasswordPolicyValidator.PasswordPolicyException.class, () ->
                PasswordPolicyValidator.validate("Abc1234567!"));
    }

    @Test
    @DisplayName("SEC-AUTH-02b: Password policy rejects common and dictionary passwords")
    void testCommonPasswordRejected() {
        assertFalse(PasswordPolicyValidator.isValid("password12345"));
        assertFalse(PasswordPolicyValidator.isValid("123456789012"));
        assertFalse(PasswordPolicyValidator.isValid("casevault123!"));
        assertFalse(PasswordPolicyValidator.isValid("administrator1"));
        assertThrows(PasswordPolicyValidator.PasswordPolicyException.class, () ->
                PasswordPolicyValidator.validate("password12345"));
    }

    @Test
    @DisplayName("SEC-AUTH-02c: Password policy requires uppercase, lowercase, digit, and special character")
    void testComplexityRequirements() {
        // Missing uppercase
        assertFalse(PasswordPolicyValidator.isValid("securep@ssw0rd2026!"));
        // Missing lowercase
        assertFalse(PasswordPolicyValidator.isValid("SECUREP@SSW0RD2026!"));
        // Missing digit
        assertFalse(PasswordPolicyValidator.isValid("SecureP@sswordLong!"));
        // Missing special character
        assertFalse(PasswordPolicyValidator.isValid("SecurePassword2026Long"));
    }
}

