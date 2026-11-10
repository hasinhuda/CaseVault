package com.casevault.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class CreateCaseNoteRequestDto {

    @NotBlank(message = "Note body cannot be blank")
    @Size(min = 1, max = 4000, message = "Note body must not exceed 4000 characters")
    private String body;

    public CreateCaseNoteRequestDto() {
    }

    public CreateCaseNoteRequestDto(String body) {
        this.body = body;
    }

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
    }
}

