package com.casevault.repository;

import com.casevault.model.CaseNote;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface CaseNoteRepository extends JpaRepository<CaseNote, String> {

    List<CaseNote> findByCaseEntityIdOrderByCreatedAtAsc(String caseId);
}

