package com.casevault.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public class UpdateRemediationActionStatusRequestDto {

    @NotBlank(message = "Status cannot be blank")
    @Pattern(regexp = "^(OPEN|IN_PROGRESS|COMPLETED)$", message = "Invalid remediation action status")
    private String status;

    public UpdateRemediationActionStatusRequestDto() {
    }

    public UpdateRemediationActionStatusRequestDto(String status) {
        this.status = status;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}

