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
@Table(name = "cases")
public class Case {

    @Id
    @Column(name = "id", length = 36, nullable = false, updatable = false)
    private String id;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "organisation_id", nullable = false)
    private Organisation organisation;

    @Column(name = "title", length = 200, nullable = false)
    private String title;

    @Column(name = "category", length = 50, nullable = false)
    private String category;

    @Column(name = "severity", length = 20, nullable = false)
    private String severity;

    @Column(name = "status", length = 50, nullable = false)
    private String status;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "owner_user_id", nullable = false)
    private User owner;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "assigned_analyst_id")
    private User assignedAnalyst;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    public Case() {
    }

    public Case(String id, Organisation organisation, String title, String category,
                String severity, String status, User owner, User assignedAnalyst, Instant createdAt) {
        this.id = id != null ? id : UUID.randomUUID().toString();
        this.organisation = organisation != null
                ? new Organisation(organisation.getId(), organisation.getName(), organisation.getCode(), organisation.getCreatedAt())
                : null;
        this.title = title;
        this.category = category;
        this.severity = severity;
        this.status = status;
        this.owner = owner != null
                ? new User(owner.getId(), owner.getOrganisation(), owner.getUsername(), owner.getPasswordHash(),
                owner.getRole(), owner.getEmail(), owner.isEnabled(), owner.getCreatedAt())
                : null;
        this.assignedAnalyst = assignedAnalyst != null
                ? new User(assignedAnalyst.getId(), assignedAnalyst.getOrganisation(), assignedAnalyst.getUsername(),
                assignedAnalyst.getPasswordHash(), assignedAnalyst.getRole(), assignedAnalyst.getEmail(),
                assignedAnalyst.isEnabled(), assignedAnalyst.getCreatedAt())
                : null;
        this.createdAt = createdAt != null ? createdAt : Instant.now();
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public Organisation getOrganisation() {
        return organisation != null
                ? new Organisation(organisation.getId(), organisation.getName(), organisation.getCode(), organisation.getCreatedAt())
                : null;
    }

    public void setOrganisation(Organisation organisation) {
        this.organisation = organisation != null
                ? new Organisation(organisation.getId(), organisation.getName(), organisation.getCode(), organisation.getCreatedAt())
                : null;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public User getOwner() {
        return owner != null
                ? new User(owner.getId(), owner.getOrganisation(), owner.getUsername(), owner.getPasswordHash(),
                owner.getRole(), owner.getEmail(), owner.isEnabled(), owner.getCreatedAt())
                : null;
    }

    public void setOwner(User owner) {
        this.owner = owner != null
                ? new User(owner.getId(), owner.getOrganisation(), owner.getUsername(), owner.getPasswordHash(),
                owner.getRole(), owner.getEmail(), owner.isEnabled(), owner.getCreatedAt())
                : null;
    }

    public User getAssignedAnalyst() {
        return assignedAnalyst != null
                ? new User(assignedAnalyst.getId(), assignedAnalyst.getOrganisation(), assignedAnalyst.getUsername(),
                assignedAnalyst.getPasswordHash(), assignedAnalyst.getRole(), assignedAnalyst.getEmail(),
                assignedAnalyst.isEnabled(), assignedAnalyst.getCreatedAt())
                : null;
    }

    public void setAssignedAnalyst(User assignedAnalyst) {
        this.assignedAnalyst = assignedAnalyst != null
                ? new User(assignedAnalyst.getId(), assignedAnalyst.getOrganisation(), assignedAnalyst.getUsername(),
                assignedAnalyst.getPasswordHash(), assignedAnalyst.getRole(), assignedAnalyst.getEmail(),
                assignedAnalyst.isEnabled(), assignedAnalyst.getCreatedAt())
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
        Case aCase = (Case) o;
        return Objects.equals(id, aCase.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
