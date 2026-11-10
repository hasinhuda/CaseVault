package com.casevault.dto;

import com.casevault.model.RemediationAction;

import java.time.Instant;

public class RemediationActionResponseDto {

    private String id;
    private String caseId;
    private String description;
    private String status;
    private String createdById;
    private String createdByName;
    private Instant createdAt;

    public RemediationActionResponseDto() {
    }

    public RemediationActionResponseDto(String id, String caseId, String description, String status,
                                        String createdById, String createdByName, Instant createdAt) {
        this.id = id;
        this.caseId = caseId;
        this.description = description;
        this.status = status;
        this.createdById = createdById;
        this.createdByName = createdByName;
        this.createdAt = createdAt;
    }

    public static RemediationActionResponseDto fromEntity(RemediationAction action) {
        if (action == null) {
            return null;
        }
        return new RemediationActionResponseDto(
                action.getId(),
                action.getCaseEntity() != null ? action.getCaseEntity().getId() : null,
                action.getDescription(),
                action.getStatus(),
                action.getCreatedBy() != null ? action.getCreatedBy().getId() : null,
                action.getCreatedBy() != null ? action.getCreatedBy().getUsername() : null,
                action.getCreatedAt()
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

    public String getCreatedById() {
        return createdById;
    }

    public void setCreatedById(String createdById) {
        this.createdById = createdById;
    }

    public String getCreatedByName() {
        return createdByName;
    }

    public void setCreatedByName(String createdByName) {
        this.createdByName = createdByName;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
}

