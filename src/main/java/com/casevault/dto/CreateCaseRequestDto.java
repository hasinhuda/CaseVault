package com.casevault.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Request DTO for creating a case.
 * Security Note (SR-01, Mass Assignment Prevention, Input Validation):
 * This DTO binds ONLY client-controllable input fields (title, category, severity).
 * It strictly ignores any client-supplied organisationId, role, status, owner, or assignedAnalyst.
 * Category and severity are strictly constrained by regex allow-lists matching domain specifications.
 * Furthermore, unknown properties are ignored to prevent prototype pollution / mass-assignment attacks.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class CreateCaseRequestDto {

    @NotBlank(message = "Title is required")
    @Size(max = 200, message = "Title must not exceed 200 characters")
    private String title;

    @NotBlank(message = "Category is required")
    @Pattern(
            regexp = "RANSOMWARE|DATA_EXFILTRATION|DATA_LEAK|PHISHING|INSIDER_THREAT|MALWARE|UNAUTHORIZED_ACCESS|DENIAL_OF_SERVICE|OTHER",
            message = "Category must be one of the allowed incident categories"
    )
    @Size(max = 50, message = "Category must not exceed 50 characters")
    private String category;

    @NotBlank(message = "Severity is required")
    @Pattern(
            regexp = "LOW|MEDIUM|HIGH|CRITICAL",
            message = "Severity must be LOW, MEDIUM, HIGH, or CRITICAL"
    )
    @Size(max = 20, message = "Severity must not exceed 20 characters")
    private String severity;

    public CreateCaseRequestDto() {
    }

    public CreateCaseRequestDto(String title, String category, String severity) {
        this.title = title;
        this.category = category;
        this.severity = severity;
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
}

