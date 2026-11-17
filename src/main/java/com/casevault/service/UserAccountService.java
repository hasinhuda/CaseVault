package com.casevault.service;

import com.casevault.dto.ChangePasswordRequestDto;
import com.casevault.security.CaseVaultUserPrincipal;

/**
 * Service for authenticated user account operations such as changing passwords.
 */
public interface UserAccountService {

    /**
     * Changes the authenticated user's password after validating the current password,
     * confirming the new password matches confirmation, verifying difference from old password,
     * and enforcing password policy requirements.
     */
    void changePassword(CaseVaultUserPrincipal principal, ChangePasswordRequestDto request);
}
