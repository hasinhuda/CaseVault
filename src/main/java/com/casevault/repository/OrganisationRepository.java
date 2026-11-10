package com.casevault.repository;

import com.casevault.model.Organisation;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OrganisationRepository extends JpaRepository<Organisation, String> {
    Optional<Organisation> findByCode(String code);
    Optional<Organisation> findByName(String name);
}

