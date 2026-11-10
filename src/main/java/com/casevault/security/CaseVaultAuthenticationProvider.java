package com.casevault.security;

import com.casevault.model.User;
import com.casevault.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

@Component
public class CaseVaultAuthenticationProvider implements AuthenticationProvider {

    private static final Logger logger = LoggerFactory.getLogger(CaseVaultAuthenticationProvider.class);
    public static final String GENERIC_AUTH_ERROR = "Invalid username or password";
    public static final int MAX_FAILED_ATTEMPTS = 5;
    public static final Duration LOCK_DURATION = Duration.ofMinutes(15);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final String dummyPasswordHash;

    public CaseVaultAuthenticationProvider(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        // Pre-compute dummy Argon2id hash for constant-ish timing defense on unknown users
        this.dummyPasswordHash = passwordEncoder.encode("CaseVaultDummySaltTimingHash123!");
    }

    @Override
    @Transactional(noRollbackFor = {BadCredentialsException.class, AuthenticationException.class})
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String rawPassword = authentication.getCredentials() != null ? authentication.getCredentials().toString() : "";
        Instant now = Instant.now();

        Optional<User> userOptional = userRepository.findByUsername(username);

        if (userOptional.isEmpty()) {
            // Constant-ish timing: evaluate dummy hash so execution time mirrors an existing user evaluation
            passwordEncoder.matches(rawPassword, dummyPasswordHash);
            logger.warn("Authentication failed: unknown username");
            throw new BadCredentialsException(GENERIC_AUTH_ERROR);
        }

        User user = userOptional.get();

        // Check if account is disabled
        if (!user.isEnabled()) {
            // Equalize timing
            passwordEncoder.matches(rawPassword, user.getPasswordHash());
            logger.warn("Authentication rejected: user account is disabled");
            throw new BadCredentialsException(GENERIC_AUTH_ERROR);
        }

        // Check if account is locked
        if (user.isAccountLocked(now)) {
            // Equalize timing
            passwordEncoder.matches(rawPassword, user.getPasswordHash());
            logger.warn("Authentication rejected: user account is locked");
            throw new BadCredentialsException(GENERIC_AUTH_ERROR);
        }

        // Verify password
        boolean matches = passwordEncoder.matches(rawPassword, user.getPasswordHash());

        if (!matches) {
            int newAttempts = user.getFailedLoginAttempts() + 1;
            if (newAttempts >= MAX_FAILED_ATTEMPTS) {
                Instant lockUntil = now.plus(LOCK_DURATION);
                userRepository.lockUserAccount(user.getId(), newAttempts, lockUntil, now);
                logger.warn("User account locked after excessive failed attempts");
            } else {
                userRepository.incrementFailedAttempts(user.getId(), now);
                logger.warn("Incremented failed login count for user");
            }
            throw new BadCredentialsException(GENERIC_AUTH_ERROR);
        }

        // Password matches: reset failed login attempts
        if (user.getFailedLoginAttempts() > 0 || user.getLockedUntil() != null) {
            userRepository.resetFailedAttempts(user.getId(), now);
        }

        CaseVaultUserPrincipal principal = new CaseVaultUserPrincipal(user, now);
        logger.info("User successfully authenticated");
        return new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

