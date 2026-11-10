package com.casevault.dto;

import java.util.Set;

public class SearchCasesRequestDto {

    private static final Set<String> ALLOWED_SORT_FIELDS = Set.of(
            "createdAt", "title", "severity", "status", "category"
    );

    private String q;
    private String status;
    private String severity;
    private String category;
    private int page = 0;
    private int size = 10;
    private String sort = "createdAt";
    private String direction = "desc";

    public SearchCasesRequestDto() {
    }

    public String getQ() {
        return q;
    }

    public void setQ(String q) {
        this.q = q;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public int getPage() {
        return Math.max(0, page);
    }

    public void setPage(int page) {
        this.page = Math.max(0, page);
    }

    public int getSize() {
        if (size <= 0) {
            return 10;
        }
        return Math.min(size, 50); // Capped at max 50 per requirements
    }

    public void setSize(int size) {
        if (size <= 0) {
            this.size = 10;
        } else {
            this.size = Math.min(size, 50);
        }
    }

    public String getSort() {
        if (sort == null || !ALLOWED_SORT_FIELDS.contains(sort)) {
            return "createdAt"; // Safe allow-listed default
        }
        return sort;
    }

    public void setSort(String sort) {
        if (sort != null && ALLOWED_SORT_FIELDS.contains(sort)) {
            this.sort = sort;
        } else {
            this.sort = "createdAt";
        }
    }

    public String getDirection() {
        if ("asc".equals(direction) || "ASC".equals(direction)) {
            return "asc";
        }
        return "desc";
    }

    public void setDirection(String direction) {
        if ("asc".equals(direction) || "ASC".equals(direction)) {
            this.direction = "asc";
        } else {
            this.direction = "desc";
        }
    }
}

