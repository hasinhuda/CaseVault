package com.casevault.repository;

import com.casevault.model.Evidence;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface EvidenceRepository extends JpaRepository<Evidence, String> {

    List<Evidence> findByACaseId(String caseId);
}

