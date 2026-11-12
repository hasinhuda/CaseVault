package com.casevault.repository;

import com.casevault.model.Report;
import com.casevault.model.ReportStatus;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ReportRepository extends JpaRepository<Report, String> {

    /** The report id must belong to the case id of the path (IDOR protection). */
    Optional<Report> findByIdAndCaseEntityId(String id, String caseId);

    List<Report> findByCaseEntityIdOrderByCreatedAtAsc(String caseId);

    List<Report> findByCaseEntityIdAndStatusOrderByCreatedAtAsc(String caseId, ReportStatus status);
}
