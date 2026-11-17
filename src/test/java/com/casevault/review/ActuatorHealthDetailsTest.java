package com.casevault.review;

import com.casevault.model.Organisation;
import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.OrganisationRepository;
import com.casevault.repository.UserRepository;
import com.casevault.security.CaseVaultUserPrincipal;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.Locale;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/** Stage A code review (CR-03): /actuator/health must not show component details, not even to a signed-in CLIENT. */
@SpringBootTest
@AutoConfigureMockMvc
class ActuatorHealthDetailsTest {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private OrganisationRepository organisationRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    @DisplayName("CR-03: a signed-in CLIENT calling /actuator/health gets only the status, never components, details, database product or disk figures")
    void signedInUserSeesNoHealthDetails() throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        Organisation org = organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "CR " + suffix, "CR_" + suffix, Instant.now()));
        User client = userRepository.save(new User(UUID.randomUUID().toString(), org, "cr_" + suffix,
                passwordEncoder.encode("Review-Password-1234!"), Role.CLIENT, "cr_" + suffix + "@test.local", true, Instant.now()));
        CaseVaultUserPrincipal principal = new CaseVaultUserPrincipal(client, Instant.now());
        String body = mockMvc.perform(get("/actuator/health").accept("application/json")
                        .with(authentication(new UsernamePasswordAuthenticationToken(principal, "N/A", principal.getAuthorities()))))
                .andReturn().getResponse().getContentAsString();
        assertEquals("{\"status\":\"UP\"}", body);
        for (String leak : new String[]{"components", "details", "database", "diskspace", "total", "free", "path", "validationquery"}) {
            assertFalse(body.toLowerCase(Locale.ROOT).contains(leak), leak + " in " + body);
        }
    }
}
