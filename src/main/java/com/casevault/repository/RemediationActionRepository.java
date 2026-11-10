package com.casevault.repository;

import com.casevault.model.RemediationAction;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface RemediationActionRepository extends JpaRepository<RemediationAction, String> {

    List<RemediationAction> findByCaseEntityIdOrderByCreatedAtAsc(String caseId);
}

