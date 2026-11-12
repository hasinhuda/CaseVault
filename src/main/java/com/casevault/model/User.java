package com.casevault.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

@Entity
@Table(name = "users")
public class User {

    @Id
    @Column(name = "id", length = 36, nullable = false, updatable = false)
    private String id;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "organisation_id")
    private Organisation organisation;

    @Column(name = "username", length = 50, nullable = false, unique = true)
    private String username;

    @Column(name = "password_hash", length = 255, nullable = false)
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    @Column(name = "role", length = 50, nullable = false)
    private Role role;

    @Column(name = "email", length = 100, nullable = false, unique = true)
    private String email;

    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    @Column(name = "failed_login_attempts", nullable = false)
    private int failedLoginAttempts = 0;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    @Column(name = "password_updated_at", nullable = false)
    private Instant passwordUpdatedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Column(name = "status_changed_at")
    private Instant statusChangedAt;

    @Column(name = "status_changed_by", length = 36)
    private String statusChangedBy;

    public User() {
    }

    public User(String id, Organisation organisation, String username, String passwordHash,
                Role role, String email, boolean enabled, Instant now) {
        this.id = id != null ? id : UUID.randomUUID().toString();
        this.organisation = organisation != null ? new Organisation(organisation.getId(), organisation.getName(), organisation.getCode(), organisation.getCreatedAt()) : null;
        this.username = username;
        this.passwordHash = passwordHash;
        this.role = role;
        this.email = email;
        this.enabled = enabled;
        this.failedLoginAttempts = 0;
        this.lockedUntil = null;
        Instant timestamp = now != null ? now : Instant.now();
        this.passwordUpdatedAt = timestamp;
        this.createdAt = timestamp;
        this.updatedAt = timestamp;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public Organisation getOrganisation() {
        return organisation != null ? new Organisation(organisation.getId(), organisation.getName(), organisation.getCode(), organisation.getCreatedAt()) : null;
    }

    public void setOrganisation(Organisation organisation) {
        this.organisation = organisation != null ? new Organisation(organisation.getId(), organisation.getName(), organisation.getCode(), organisation.getCreatedAt()) : null;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public int getFailedLoginAttempts() {
        return failedLoginAttempts;
    }

    public void setFailedLoginAttempts(int failedLoginAttempts) {
        this.failedLoginAttempts = failedLoginAttempts;
    }

    public Instant getLockedUntil() {
        return lockedUntil;
    }

    public void setLockedUntil(Instant lockedUntil) {
        this.lockedUntil = lockedUntil;
    }

    public Instant getPasswordUpdatedAt() {
        return passwordUpdatedAt;
    }

    public void setPasswordUpdatedAt(Instant passwordUpdatedAt) {
        this.passwordUpdatedAt = passwordUpdatedAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }

    public Instant getStatusChangedAt() {
        return statusChangedAt;
    }

    public String getStatusChangedBy() {
        return statusChangedBy;
    }

    /** Records who enabled or disabled the account and when (target traceability; the audit row stores the actor only). */
    public void recordStatusChange(String actorUserId, Instant now) {
        this.statusChangedBy = actorUserId;
        this.statusChangedAt = now;
        this.updatedAt = now;
    }

    public boolean isAccountLocked(Instant now) {
        return lockedUntil != null && lockedUntil.isAfter(now);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        User user = (User) o;
        return Objects.equals(id, user.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}

