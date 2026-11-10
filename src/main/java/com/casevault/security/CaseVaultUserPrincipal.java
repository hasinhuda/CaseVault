package com.casevault.security;

import com.casevault.model.Role;
import com.casevault.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.util.Collection;
import java.util.List;

public class CaseVaultUserPrincipal implements UserDetails {

    private static final long serialVersionUID = 1L;

    private final String userId;
    private final String username;
    private final String passwordHash;
    private final Role role;
    private final String organisationId;
    private final String organisationCode;
    private final boolean enabled;
    private final boolean accountNonLocked;

    public CaseVaultUserPrincipal(User user, Instant now) {
        this.userId = user.getId();
        this.username = user.getUsername();
        this.passwordHash = user.getPasswordHash();
        this.role = user.getRole();
        this.organisationId = user.getOrganisation() != null ? user.getOrganisation().getId() : null;
        this.organisationCode = user.getOrganisation() != null ? user.getOrganisation().getCode() : null;
        this.enabled = user.isEnabled();
        this.accountNonLocked = !user.isAccountLocked(now != null ? now : Instant.now());
    }

    public String getUserId() {
        return userId;
    }

    public String getOrganisationId() {
        return organisationId;
    }

    public String getOrganisationCode() {
        return organisationCode;
    }

    public Role getRole() {
        return role;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    @Override
    public String getPassword() {
        return passwordHash;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}

