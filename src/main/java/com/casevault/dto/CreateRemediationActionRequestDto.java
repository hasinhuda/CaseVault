package com.casevault.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class CreateRemediationActionRequestDto {

    @NotBlank(message = "Description cannot be blank")
    @Size(min = 1, max = 500, message = "Description must not exceed 500 characters")
    private String description;

    public CreateRemediationActionRequestDto() {
    }

    public CreateRemediationActionRequestDto(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}

