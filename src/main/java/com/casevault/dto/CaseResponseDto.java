package com.casevault.dto;

import com.casevault.model.Case;

import java.time.Instant;

public class CaseResponseDto {

    private String id;
    private String organisationId;
    private String organisationName;
    private String title;
    private String category;
    private String severity;
    private String status;
    private String ownerUserId;
    private String ownerUsername;
    private String assignedAnalystId;
    private String assignedAnalystUsername;
    private Instant createdAt;

    public CaseResponseDto() {
    }

    public static CaseResponseDto fromEntity(Case c) {
        CaseResponseDto dto = new CaseResponseDto();
        dto.id = c.getId();
        if (c.getOrganisation() != null) {
            dto.organisationId = c.getOrganisation().getId();
            dto.organisationName = c.getOrganisation().getName();
        }
        dto.title = c.getTitle();
        dto.category = c.getCategory();
        dto.severity = c.getSeverity();
        dto.status = c.getStatus();
        if (c.getOwner() != null) {
            dto.ownerUserId = c.getOwner().getId();
            dto.ownerUsername = c.getOwner().getUsername();
        }
        if (c.getAssignedAnalyst() != null) {
            dto.assignedAnalystId = c.getAssignedAnalyst().getId();
            dto.assignedAnalystUsername = c.getAssignedAnalyst().getUsername();
        }
        dto.createdAt = c.getCreatedAt();
        return dto;
    }

    public String getId() {
        return id;
    }

    public String getOrganisationId() {
        return organisationId;
    }

    public String getOrganisationName() {
        return organisationName;
    }

    public String getTitle() {
        return title;
    }

    public String getCategory() {
        return category;
    }

    public String getSeverity() {
        return severity;
    }

    public String getStatus() {
        return status;
    }

    public String getOwnerUserId() {
        return ownerUserId;
    }

    public String getOwnerUsername() {
        return ownerUsername;
    }

    public String getAssignedAnalystId() {
        return assignedAnalystId;
    }

    public String getAssignedAnalystUsername() {
        return assignedAnalystUsername;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}

