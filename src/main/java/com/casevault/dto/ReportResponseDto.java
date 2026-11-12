package com.casevault.dto;

import com.casevault.model.Report;

import java.time.Instant;

/** Read model of a report. The body is plain text and must be rendered with th:text only. */
public record ReportResponseDto(String id, String caseId, String authorId, String authorUsername, String body,
                                String status, String approvedById, Instant createdAt, Instant updatedAt,
                                Instant submittedAt, Instant approvedAt) {

    public static ReportResponseDto fromEntity(Report r) {
        return new ReportResponseDto(r.getId(), r.getCaseId(), r.getAuthorId(),
                r.getAuthorUsername(), r.getBody(), r.getStatus().name(), r.getApprovedById(),
                r.getCreatedAt(), r.getUpdatedAt(), r.getSubmittedAt(), r.getApprovedAt());
    }
}
