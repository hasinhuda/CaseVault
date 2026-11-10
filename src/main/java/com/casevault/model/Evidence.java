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
@Table(name = "evidence")
public class Evidence {

    @Id
    @Column(name = "id", length = 36, nullable = false, updatable = false)
    private String id;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "case_id", nullable = false)
    private Case aCase;

    @Column(name = "original_name", length = 255, nullable = false)
    private String originalName;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "uploaded_by", nullable = false)
    private User uploadedBy;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    public Evidence() {
    }

    public Evidence(String id, Case aCase, String originalName, User uploadedBy, Instant createdAt) {
        this.id = id != null ? id : UUID.randomUUID().toString();
        this.aCase = aCase != null
                ? new Case(aCase.getId(), aCase.getOrganisation(), aCase.getTitle(), aCase.getCategory(),
                aCase.getSeverity(), aCase.getStatus(), aCase.getOwner(), aCase.getAssignedAnalyst(), aCase.getCreatedAt())
                : null;
        this.originalName = originalName;
        this.uploadedBy = uploadedBy != null
                ? new User(uploadedBy.getId(), uploadedBy.getOrganisation(), uploadedBy.getUsername(),
                uploadedBy.getPasswordHash(), uploadedBy.getRole(), uploadedBy.getEmail(),
                uploadedBy.isEnabled(), uploadedBy.getCreatedAt())
                : null;
        this.createdAt = createdAt != null ? createdAt : Instant.now();
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public Case getCase() {
        return aCase != null
                ? new Case(aCase.getId(), aCase.getOrganisation(), aCase.getTitle(), aCase.getCategory(),
                aCase.getSeverity(), aCase.getStatus(), aCase.getOwner(), aCase.getAssignedAnalyst(), aCase.getCreatedAt())
                : null;
    }

    public void setCase(Case aCase) {
        this.aCase = aCase != null
                ? new Case(aCase.getId(), aCase.getOrganisation(), aCase.getTitle(), aCase.getCategory(),
                aCase.getSeverity(), aCase.getStatus(), aCase.getOwner(), aCase.getAssignedAnalyst(), aCase.getCreatedAt())
                : null;
    }

    public String getOriginalName() {
        return originalName;
    }

    public void setOriginalName(String originalName) {
        this.originalName = originalName;
    }

    public User getUploadedBy() {
        return uploadedBy != null
                ? new User(uploadedBy.getId(), uploadedBy.getOrganisation(), uploadedBy.getUsername(),
                uploadedBy.getPasswordHash(), uploadedBy.getRole(), uploadedBy.getEmail(),
                uploadedBy.isEnabled(), uploadedBy.getCreatedAt())
                : null;
    }

    public void setUploadedBy(User uploadedBy) {
        this.uploadedBy = uploadedBy != null
                ? new User(uploadedBy.getId(), uploadedBy.getOrganisation(), uploadedBy.getUsername(),
                uploadedBy.getPasswordHash(), uploadedBy.getRole(), uploadedBy.getEmail(),
                uploadedBy.isEnabled(), uploadedBy.getCreatedAt())
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
        Evidence evidence = (Evidence) o;
        return Objects.equals(id, evidence.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
