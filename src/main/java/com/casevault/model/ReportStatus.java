package com.casevault.model;

/** Report workflow: DRAFT -> SUBMITTED -> APPROVED (no reject or return-to-draft step yet). */
public enum ReportStatus {
    DRAFT,
    SUBMITTED,
    APPROVED
}
