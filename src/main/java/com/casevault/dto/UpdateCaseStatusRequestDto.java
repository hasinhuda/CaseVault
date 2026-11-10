package com.casevault.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public class UpdateCaseStatusRequestDto {

    @NotBlank(message = "Status cannot be blank")
    @Pattern(regexp = "^(OPEN|ASSIGNED|IN_PROGRESS|PENDING_REVIEW|CLOSED)$", message = "Invalid case status")
    private String status;

    public UpdateCaseStatusRequestDto() {
    }

    public UpdateCaseStatusRequestDto(String status) {
        this.status = status;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}

