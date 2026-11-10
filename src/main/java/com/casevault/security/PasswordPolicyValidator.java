package com.casevault.security;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

public class PasswordPolicyValidator {

    public static final int MIN_PASSWORD_LENGTH = 12;
    private static final Pattern UPPERCASE_PATTERN = Pattern.compile("[A-Z]");
    private static final Pattern LOWERCASE_PATTERN = Pattern.compile("[a-z]");
    private static final Pattern DIGIT_PATTERN = Pattern.compile("[0-9]");
    private static final Pattern SPECIAL_PATTERN = Pattern.compile("[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?`~]");

    private static final Set<String> COMMON_PASSWORDS;

    static {
        Set<String> common = new HashSet<>();
        common.add("password12345");
        common.add("password1234");
        common.add("123456789012");
        common.add("1234567890123");
        common.add("administrator1");
        common.add("administrator");
        common.add("qwertyuiop12");
        common.add("admin12345678");
        common.add("welcome123456");
        common.add("casevault1234");
        common.add("casevault123!");
        common.add("letmein123456");
        common.add("changeme12345");
        common.add("iloveyou12345");
        common.add("trustnoone123");
        common.add("springsecurity");
        COMMON_PASSWORDS = Collections.unmodifiableSet(common);
    }

    public static void validate(String password) {
        if (password == null || password.length() < MIN_PASSWORD_LENGTH) {
            throw new PasswordPolicyException("Password must be at least " + MIN_PASSWORD_LENGTH + " characters long");
        }

        String lower = password.toLowerCase(java.util.Locale.ROOT);
        if (COMMON_PASSWORDS.contains(lower)) {
            throw new PasswordPolicyException("Password is too common and easily guessable");
        }

        if (!UPPERCASE_PATTERN.matcher(password).find()) {
            throw new PasswordPolicyException("Password must contain at least one uppercase letter");
        }

        if (!LOWERCASE_PATTERN.matcher(password).find()) {
            throw new PasswordPolicyException("Password must contain at least one lowercase letter");
        }

        if (!DIGIT_PATTERN.matcher(password).find()) {
            throw new PasswordPolicyException("Password must contain at least one numerical digit");
        }

        if (!SPECIAL_PATTERN.matcher(password).find()) {
            throw new PasswordPolicyException("Password must contain at least one special character");
        }
    }

    public static boolean isValid(String password) {
        try {
            validate(password);
            return true;
        } catch (PasswordPolicyException ex) {
            return false;
        }
    }

    public static class PasswordPolicyException extends IllegalArgumentException {
        public PasswordPolicyException(String message) {
            super(message);
        }
    }
}

