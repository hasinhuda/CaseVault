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
@Table(name = "case_notes")
public class CaseNote {

    @Id
    @Column(name = "id", length = 36, nullable = false, updatable = false)
    private String id;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "case_id", nullable = false)
    private Case caseEntity;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "author_id", nullable = false)
    private User author;

    @Column(name = "body", nullable = false, columnDefinition = "TEXT")
    private String body;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    public CaseNote() {
    }

    public CaseNote(String id, Case caseEntity, User author, String body, Instant createdAt) {
        this.id = id != null ? id : UUID.randomUUID().toString();
        this.caseEntity = caseEntity != null
                ? new Case(caseEntity.getId(), caseEntity.getOrganisation(), caseEntity.getTitle(),
                caseEntity.getCategory(), caseEntity.getSeverity(), caseEntity.getStatus(),
                caseEntity.getOwner(), caseEntity.getAssignedAnalyst(), caseEntity.getCreatedAt())
                : null;
        this.author = author != null
                ? new User(author.getId(), author.getOrganisation(), author.getUsername(),
                author.getPasswordHash(), author.getRole(), author.getEmail(),
                author.isEnabled(), author.getCreatedAt())
                : null;
        this.body = body;
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

    public User getAuthor() {
        return author != null
                ? new User(author.getId(), author.getOrganisation(), author.getUsername(),
                author.getPasswordHash(), author.getRole(), author.getEmail(),
                author.isEnabled(), author.getCreatedAt())
                : null;
    }

    public void setAuthor(User author) {
        this.author = author != null
                ? new User(author.getId(), author.getOrganisation(), author.getUsername(),
                author.getPasswordHash(), author.getRole(), author.getEmail(),
                author.isEnabled(), author.getCreatedAt())
                : null;
    }

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
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
        CaseNote caseNote = (CaseNote) o;
        return Objects.equals(id, caseNote.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}

