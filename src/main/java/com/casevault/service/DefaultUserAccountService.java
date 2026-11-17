package com.casevault.service;

import com.casevault.dto.ChangePasswordRequestDto;
import com.casevault.exception.ResourceNotFoundException;
import com.casevault.model.User;
import com.casevault.repository.UserRepository;
import com.casevault.security.CaseVaultUserPrincipal;
import com.casevault.security.PasswordPolicyValidator;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Objects;

@Service
public class DefaultUserAccountService implements UserAccountService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditEventRecorder auditEventRecorder;

    public DefaultUserAccountService(UserRepository userRepository,
                                     PasswordEncoder passwordEncoder,
                                     AuditEventRecorder auditEventRecorder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.auditEventRecorder = auditEventRecorder;
    }

    @Override
    @Transactional
    public void changePassword(CaseVaultUserPrincipal principal, ChangePasswordRequestDto request) {
        Objects.requireNonNull(principal, "principal required");
        Objects.requireNonNull(request, "request required");

        if (request.getCurrentPassword() == null || request.getCurrentPassword().isBlank()) {
            throw new IllegalArgumentException("Current password is required.");
        }
        if (request.getNewPassword() == null || request.getNewPassword().isBlank()) {
            throw new IllegalArgumentException("New password is required.");
        }
        if (!Objects.equals(request.getNewPassword(), request.getConfirmPassword())) {
            throw new IllegalArgumentException("New password and confirmation do not match.");
        }

        User user = userRepository.findById(principal.getUserId())
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + principal.getUserId()));

        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPasswordHash())) {
            auditEventRecorder.record(AuditEventType.ACCESS_DENIED, principal.getUserId(), null, "BAD_CREDENTIALS");
            throw new IllegalArgumentException("Current password is incorrect.");
        }

        if (passwordEncoder.matches(request.getNewPassword(), user.getPasswordHash())) {
            throw new IllegalArgumentException("New password must be different from current password.");
        }

        PasswordPolicyValidator.validate(request.getNewPassword());

        Instant now = Instant.now();
        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        user.setPasswordResetRequired(false);
        user.setPasswordUpdatedAt(now);
        user.setUpdatedAt(now);
        User updated = userRepository.save(user);

        // Update SecurityContext so that in-memory principal immediately has passwordResetRequired == false
        CaseVaultUserPrincipal newPrincipal = new CaseVaultUserPrincipal(updated, now);
        Authentication newAuth = new UsernamePasswordAuthenticationToken(
                newPrincipal,
                newPrincipal.getPassword(),
                newPrincipal.getAuthorities()
        );
        SecurityContextHolder.getContext().setAuthentication(newAuth);

        auditEventRecorder.record(AuditEventType.USER_PASSWORD_CHANGED, principal.getUserId(), null,
                AuditReasonCode.PASSWORD_CHANGED.name());
    }
}
