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

/**
 * Incident report. The body is plain text. Fields change only through the transition methods below; there are no
 * generic setters, so request data can never be bound onto status, author, approver or case.
 */
@Entity
@Table(name = "reports")
public class Report {

    public static final int MAX_BODY_LENGTH = 10000;

    @Id
    @Column(name = "id", length = 36, nullable = false, updatable = false)
    private String id;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "case_id", nullable = false, updatable = false)
    private Case caseEntity;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "author_id", nullable = false, updatable = false)
    private User author;

    @Column(name = "body", length = MAX_BODY_LENGTH, nullable = false)
    private String body;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", length = 20, nullable = false)
    private ReportStatus status;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "approved_by")
    private User approvedBy;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Column(name = "submitted_at")
    private Instant submittedAt;

    @Column(name = "approved_at")
    private Instant approvedAt;

    protected Report() {
    }

    public Report(String id, Case caseEntity, User author, String body, Instant now) {
        this.id = id;
        this.caseEntity = copyOf(caseEntity);
        this.author = copyOf(author);
        this.body = body;
        this.status = ReportStatus.DRAFT;
        this.createdAt = now;
        this.updatedAt = now;
    }

    public void replaceBody(String newBody, Instant now) {
        this.body = newBody;
        this.updatedAt = now;
    }

    public void markSubmitted(Instant now) {
        this.status = ReportStatus.SUBMITTED;
        this.submittedAt = now;
        this.updatedAt = now;
    }

    public void markApproved(User approver, Instant now) {
        this.status = ReportStatus.APPROVED;
        this.approvedBy = copyOf(approver);
        this.approvedAt = now;
        this.updatedAt = now;
    }

    public String getId() {
        return id;
    }

    public String getCaseId() {
        return caseEntity.getId();
    }

    public String getAuthorId() {
        return author.getId();
    }

    public String getAuthorUsername() {
        return author.getUsername();
    }

    public String getBody() {
        return body;
    }

    public ReportStatus getStatus() {
        return status;
    }

    public String getApprovedById() {
        return approvedBy == null ? null : approvedBy.getId();
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public Instant getSubmittedAt() {
        return submittedAt;
    }

    public Instant getApprovedAt() {
        return approvedAt;
    }

    // Defensive copies (same approach as CaseNote): the entity never keeps or hands out the caller's mutable objects.
    private static Case copyOf(Case c) {
        return c == null ? null : new Case(c.getId(), c.getOrganisation(), c.getTitle(), c.getCategory(),
                c.getSeverity(), c.getStatus(), c.getOwner(), c.getAssignedAnalyst(), c.getCreatedAt());
    }

    private static User copyOf(User u) {
        return u == null ? null : new User(u.getId(), u.getOrganisation(), u.getUsername(), u.getPasswordHash(),
                u.getRole(), u.getEmail(), u.isEnabled(), u.getCreatedAt());
    }
}
