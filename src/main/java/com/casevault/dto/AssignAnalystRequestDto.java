package com.casevault.dto;

import jakarta.validation.constraints.NotBlank;

public class AssignAnalystRequestDto {

    @NotBlank(message = "Analyst ID cannot be blank")
    private String analystId;

    public AssignAnalystRequestDto() {
    }

    public AssignAnalystRequestDto(String analystId) {
        this.analystId = analystId;
    }

    public String getAnalystId() {
        return analystId;
    }

    public void setAnalystId(String analystId) {
        this.analystId = analystId;
    }
}

