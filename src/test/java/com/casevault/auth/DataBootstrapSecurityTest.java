package com.casevault.auth;

import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
public class DataBootstrapSecurityTest {

    @Autowired
    private UserRepository userRepository;

    @Test
    @DisplayName("SEC-AUTH-14: First-run bootstrap generates synthetic accounts for all required roles silently in non-local profiles")
    @org.springframework.transaction.annotation.Transactional(readOnly = true)
    void testBootstrapSyntheticAccountsCreated() {
        Optional<User> admin = userRepository.findByUsername("admin_auditor");
        Optional<User> manager = userRepository.findByUsername("manager_alice");
        Optional<User> analyst = userRepository.findByUsername("analyst_bob");
        Optional<User> client = userRepository.findByUsername("client_charlie");

        assertTrue(admin.isPresent(), "admin_auditor must exist");
        assertEquals(Role.AUDITOR_ADMIN, admin.get().getRole());
        assertTrue(admin.get().isEnabled());

        assertTrue(manager.isPresent(), "manager_alice must exist");
        assertEquals(Role.MANAGER, manager.get().getRole());
        assertNotNull(manager.get().getOrganisation(), "Manager must belong to an organisation");

        assertTrue(analyst.isPresent(), "analyst_bob must exist");
        assertEquals(Role.ANALYST, analyst.get().getRole());
        assertNotNull(analyst.get().getOrganisation(), "Analyst must belong to an organisation");

        assertTrue(client.isPresent(), "client_charlie must exist");
        assertEquals(Role.CLIENT, client.get().getRole());
        assertNotNull(client.get().getOrganisation(), "Client must belong to an organisation");

        // Passwords must be hashed with Argon2id, not cleartext
        for (User u : new User[]{admin.get(), manager.get(), analyst.get(), client.get()}) {
            assertTrue(u.getPasswordHash().startsWith("$argon2id$"), "User password must be an Argon2id hash");
            assertFalse(u.getPasswordHash().contains("password"), "Password hash must not contain cleartext");
        }
    }

    private void assertEquals(Object expected, Object actual) {
        org.junit.jupiter.api.Assertions.assertEquals(expected, actual);
    }
}

