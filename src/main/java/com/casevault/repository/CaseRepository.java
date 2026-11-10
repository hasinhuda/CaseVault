package com.casevault.repository;

import com.casevault.model.Case;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface CaseRepository extends JpaRepository<Case, String>, JpaSpecificationExecutor<Case> {

    List<Case> findByOrganisationId(String organisationId);

    List<Case> findByAssignedAnalystId(String analystId);

    @Query("SELECT c FROM Case c WHERE c.organisation.id = :orgId AND c.assignedAnalyst.id = :analystId")
    List<Case> findByOrganisationIdAndAssignedAnalystId(@Param("orgId") String orgId, @Param("analystId") String analystId);
}

