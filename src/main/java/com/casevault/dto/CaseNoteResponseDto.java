package com.casevault.dto;

import com.casevault.model.CaseNote;

import java.time.Instant;

public class CaseNoteResponseDto {

    private String id;
    private String caseId;
    private String authorId;
    private String authorUsername;
    private String authorRole;
    private String body;
    private Instant createdAt;

    public CaseNoteResponseDto() {
    }

    public CaseNoteResponseDto(String id, String caseId, String authorId, String authorUsername,
                               String authorRole, String body, Instant createdAt) {
        this.id = id;
        this.caseId = caseId;
        this.authorId = authorId;
        this.authorUsername = authorUsername;
        this.authorRole = authorRole;
        this.body = body;
        this.createdAt = createdAt;
    }

    public static CaseNoteResponseDto fromEntity(CaseNote note) {
        if (note == null) {
            return null;
        }
        return new CaseNoteResponseDto(
                note.getId(),
                note.getCaseEntity() != null ? note.getCaseEntity().getId() : null,
                note.getAuthor() != null ? note.getAuthor().getId() : null,
                note.getAuthor() != null ? note.getAuthor().getUsername() : null,
                note.getAuthor() != null && note.getAuthor().getRole() != null ? note.getAuthor().getRole().name() : null,
                note.getBody(),
                note.getCreatedAt()
        );
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getCaseId() {
        return caseId;
    }

    public void setCaseId(String caseId) {
        this.caseId = caseId;
    }

    public String getAuthorId() {
        return authorId;
    }

    public void setAuthorId(String authorId) {
        this.authorId = authorId;
    }

    public String getAuthorUsername() {
        return authorUsername;
    }

    public void setAuthorUsername(String authorUsername) {
        this.authorUsername = authorUsername;
    }

    public String getAuthorRole() {
        return authorRole;
    }

    public void setAuthorRole(String authorRole) {
        this.authorRole = authorRole;
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
}

