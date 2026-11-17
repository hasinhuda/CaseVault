package com.casevault.dto;

import com.casevault.model.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class CreateUserRequestDto {

    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    @Pattern(regexp = "^[a-zA-Z0-9_.-]+$", message = "Username may only contain letters, numbers, underscores, dots, and hyphens")
    private String username;

    @NotBlank(message = "Email is required")
    @Email(message = "Valid email address is required")
    @Size(max = 100, message = "Email cannot exceed 100 characters")
    private String email;

    @NotNull(message = "Role is required")
    private Role role;

    private String organisationId;

    @NotBlank(message = "Password is required")
    private String password;

    public CreateUserRequestDto() {
    }

    public CreateUserRequestDto(String username, String email, Role role, String organisationId, String password) {
        this.username = username;
        this.email = email;
        this.role = role;
        this.organisationId = organisationId;
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public String getOrganisationId() {
        return organisationId;
    }

    public void setOrganisationId(String organisationId) {
        this.organisationId = organisationId;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}

