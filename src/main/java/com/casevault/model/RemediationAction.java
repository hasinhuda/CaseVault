package com.casevault.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

@Entity
@Table(name = "remediation_actions")
public class RemediationAction {

    @Id
    @Column(name = "id", length = 36, nullable = false, updatable = false)
    private String id;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "case_id", nullable = false)
    private Case caseEntity;

    @Column(name = "description", length = 500, nullable = false)
    private String description;

    @Column(name = "status", length = 50, nullable = false)
    private String status;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "created_by", nullable = false)
    private User createdBy;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    public RemediationAction() {
    }

    public RemediationAction(String id, Case caseEntity, String description, String status, User createdBy, Instant createdAt) {
        this.id = id != null ? id : UUID.randomUUID().toString();
        this.caseEntity = caseEntity != null
                ? new Case(caseEntity.getId(), caseEntity.getOrganisation(), caseEntity.getTitle(),
                caseEntity.getCategory(), caseEntity.getSeverity(), caseEntity.getStatus(),
                caseEntity.getOwner(), caseEntity.getAssignedAnalyst(), caseEntity.getCreatedAt())
                : null;
        this.description = description;
        this.status = status;
        this.createdBy = createdBy != null
                ? new User(createdBy.getId(), createdBy.getOrganisation(), createdBy.getUsername(),
                createdBy.getPasswordHash(), createdBy.getRole(), createdBy.getEmail(),
                createdBy.isEnabled(), createdBy.getCreatedAt())
                : null;
        this.createdAt = createdAt != null ? createdAt : Instant.now();
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public Case getCaseEntity() {
        return caseEntity != null
                ? new Case(caseEntity.getId(), caseEntity.getOrganisation(), caseEntity.getTitle(),
                caseEntity.getCategory(), caseEntity.getSeverity(), caseEntity.getStatus(),
                caseEntity.getOwner(), caseEntity.getAssignedAnalyst(), caseEntity.getCreatedAt())
                : null;
    }

    public void setCaseEntity(Case caseEntity) {
        this.caseEntity = caseEntity != null
                ? new Case(caseEntity.getId(), caseEntity.getOrganisation(), caseEntity.getTitle(),
                caseEntity.getCategory(), caseEntity.getSeverity(), caseEntity.getStatus(),
                caseEntity.getOwner(), caseEntity.getAssignedAnalyst(), caseEntity.getCreatedAt())
                : null;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public User getCreatedBy() {
        return createdBy != null
                ? new User(createdBy.getId(), createdBy.getOrganisation(), createdBy.getUsername(),
                createdBy.getPasswordHash(), createdBy.getRole(), createdBy.getEmail(),
                createdBy.isEnabled(), createdBy.getCreatedAt())
                : null;
    }

    public void setCreatedBy(User createdBy) {
        this.createdBy = createdBy != null
                ? new User(createdBy.getId(), createdBy.getOrganisation(), createdBy.getUsername(),
                createdBy.getPasswordHash(), createdBy.getRole(), createdBy.getEmail(),
                createdBy.isEnabled(), createdBy.getCreatedAt())
                : null;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RemediationAction that = (RemediationAction) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}

