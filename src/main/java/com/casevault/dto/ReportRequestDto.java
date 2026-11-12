package com.casevault.dto;

/**
 * The only client input for creating or editing a report: the plain-text body. Status, author, approver, case and
 * organisation are deliberately not fields, so they can never be bound from a request.
 */
public class ReportRequestDto {

    private String body;

    public ReportRequestDto() {
    }

    public ReportRequestDto(String body) {
        this.body = body;
    }

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
    }
}
