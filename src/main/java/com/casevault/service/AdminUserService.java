package com.casevault.service;

import com.casevault.security.CaseVaultUserPrincipal;

import java.time.Instant;
import java.util.List;

/**
 * Account administration and health for AUDITOR_ADMIN only (FR-14, FR-15, SR-07). Every other role gets
 * ResourceNotFoundException (HTTP 404). Safety refusals throw AdminActionRefusedException.
 */
public interface AdminUserService {

    /** One listed account. Never carries a password hash, failed-login counter, token or session id. */
    record UserRow(String id, String username, String role, String organisationCode, boolean enabled,
                   boolean locked, Instant statusChangedAt) {
    }

    record UserPage(List<UserRow> rows, int page, int size, int totalPages, long totalElements,
                    boolean hasPrevious, boolean hasNext) {
        public UserPage {
            rows = List.copyOf(rows);
        }

        @Override
        public List<UserRow> rows() {
            return List.copyOf(rows);
        }
    }

    enum ActionResult { DONE, NO_CHANGE }

    /** Health summary without paths, versions, host names, secrets or exception text. */
    record HealthView(boolean databaseReachable, boolean evidenceStorageWritable, String chainState,
                      Long headSequence) {
    }

    UserPage listUsers(CaseVaultUserPrincipal admin, String pageRaw, String sizeRaw);

    UserRow getUser(CaseVaultUserPrincipal admin, String userId);

    ActionResult disable(CaseVaultUserPrincipal admin, String userId);

    ActionResult enable(CaseVaultUserPrincipal admin, String userId);

    void revokeSessions(CaseVaultUserPrincipal admin, String userId);

    HealthView health(CaseVaultUserPrincipal admin);
}
