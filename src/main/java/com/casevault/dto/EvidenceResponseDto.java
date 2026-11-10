package com.casevault.dto;

import com.casevault.model.Evidence;

import java.time.Instant;

public class EvidenceResponseDto {

    private String id;
    private String caseId;
    private String originalName;
    private String uploadedByUserId;
    private String uploadedByUsername;
    private Instant createdAt;

    public EvidenceResponseDto() {
    }

    public static EvidenceResponseDto fromEntity(Evidence e) {
        EvidenceResponseDto dto = new EvidenceResponseDto();
        dto.id = e.getId();
        if (e.getCase() != null) {
            dto.caseId = e.getCase().getId();
        }
        dto.originalName = e.getOriginalName();
        if (e.getUploadedBy() != null) {
            dto.uploadedByUserId = e.getUploadedBy().getId();
            dto.uploadedByUsername = e.getUploadedBy().getUsername();
        }
        dto.createdAt = e.getCreatedAt();
        return dto;
    }

    public String getId() {
        return id;
    }

    public String getCaseId() {
        return caseId;
    }

    public String getOriginalName() {
        return originalName;
    }

    public String getUploadedByUserId() {
        return uploadedByUserId;
    }

    public String getUploadedByUsername() {
        return uploadedByUsername;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}

