package com.casevault.dto;

import com.casevault.model.User;

public class UserSummaryDto {

    private String id;
    private String username;
    private String role;

    public UserSummaryDto() {
    }

    public UserSummaryDto(String id, String username, String role) {
        this.id = id;
        this.username = username;
        this.role = role;
    }

    public static UserSummaryDto fromEntity(User user) {
        if (user == null) {
            return null;
        }
        return new UserSummaryDto(
                user.getId(),
                user.getUsername(),
                user.getRole() != null ? user.getRole().name() : null
        );
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
}

