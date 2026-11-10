package com.casevault.security;

import com.casevault.model.Case;
import com.casevault.model.Evidence;
import com.casevault.model.Role;
import org.springframework.stereotype.Component;

import java.util.Objects;

/**
 * Pure authorization rule evaluator for CaseVault access control.
 * Implements tenant isolation and role boundaries defined in ADR 0003 and requirements SR-01, SR-02, SR-07.
 */
@Component
public class AccessPolicy {

    /**
     * Well-known organisation code for the internal consultancy staff organisation.
     * Verified against DataBootstrapService baseline.
     */
    public static final String INTERNAL_ORG_CODE = "ORG_INTERNAL";

    /**
     * Determines whether the given principal has read access to the specified case.
     *
     * @param principal the authenticated caller principal
     * @param aCase     the candidate case
     * @return true if access is permitted; false otherwise
     */
    public boolean canReadCase(CaseVaultUserPrincipal principal, Case aCase) {
        if (principal == null || aCase == null) {
            return false;
        }

        Role role = principal.getRole();
        if (role == null) {
            return false;
        }

        // SR-07: AUDITOR_ADMIN has strict zero-access to case content
        if (role == Role.AUDITOR_ADMIN) {
            return false;
        }

        String principalOrgId = principal.getOrganisationId();
        String caseOrgId = aCase.getOrganisation() != null ? aCase.getOrganisation().getId() : null;

        switch (role) {
            case CLIENT:
                // CLIENT: only cases of own organisation
                return principalOrgId != null && Objects.equals(principalOrgId, caseOrgId);

            case ANALYST:
                // ANALYST: only cases whose assigned_analyst_id equals caller user id (regardless of case org)
                if (aCase.getAssignedAnalyst() == null) {
                    return false;
                }
                return Objects.equals(principal.getUserId(), aCase.getAssignedAnalyst().getId());

            case MANAGER:
                // MANAGER: if caller belongs to internal staff org (ORG_INTERNAL), all cases; otherwise only own organisation
                if (INTERNAL_ORG_CODE.equals(principal.getOrganisationCode())) {
                    return true;
                }
                return principalOrgId != null && Objects.equals(principalOrgId, caseOrgId);

            default:
                return false;
        }
    }

    /**
     * Determines whether the given principal has read access to the specified evidence artifact.
     * Evidence access derives strictly from case access.
     *
     * @param principal the authenticated caller principal
     * @param evidence  the candidate evidence
     * @return true if access is permitted; false otherwise
     */
    public boolean canReadEvidence(CaseVaultUserPrincipal principal, Evidence evidence) {
        if (principal == null || evidence == null || evidence.getCase() == null) {
            return false;
        }
        return canReadCase(principal, evidence.getCase());
    }
}
