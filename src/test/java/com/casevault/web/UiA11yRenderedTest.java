package com.casevault.web;

import com.casevault.model.Case;
import com.casevault.model.Organisation;
import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.CaseRepository;
import com.casevault.repository.OrganisationRepository;
import com.casevault.repository.UserRepository;
import com.casevault.security.CaseVaultUserPrincipal;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/** Phase 9C: accessibility attributes on rendered pages (real templates, real filter chain, H2). */
@SpringBootTest
@AutoConfigureMockMvc
class UiA11yRenderedTest {

    @TempDir
    static Path sharedTempDir;

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        registry.add("casevault.audit.key-path", () -> sharedTempDir.resolve("keys").resolve("audit.key").toString());
        registry.add("casevault.storage.evidence-dir", () -> sharedTempDir.resolve("evidence").toString());
        registry.add("casevault.storage.keyset-path", () -> sharedTempDir.resolve("keyset.json").toString());
    }

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private OrganisationRepository organisationRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private CaseRepository caseRepository;

    private User user(Organisation org, Role role, boolean enabled) {
        String name = "a11y_" + UUID.randomUUID().toString().substring(0, 8);
        return userRepository.save(new User(UUID.randomUUID().toString(), org, name, passwordEncoder.encode("A11y-Password-1234!"),
                role, name + "@test.local", enabled, Instant.now()));
    }

    private Organisation org() {
        String s = UUID.randomUUID().toString().substring(0, 8);
        return organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "A11Y " + s, "A11Y_" + s, Instant.now()));
    }

    private static RequestPostProcessor as(User u) {
        CaseVaultUserPrincipal principal = new CaseVaultUserPrincipal(u, Instant.now());
        return authentication(new UsernamePasswordAuthenticationToken(principal, "N/A", principal.getAuthorities()));
    }

    private String page(String path, User u) throws Exception {
        MvcResult r = mockMvc.perform(get(path).with(as(u))).andReturn();
        assertEquals(200, r.getResponse().getStatus(), path);
        return r.getResponse().getContentAsString();
    }

    private static String text(String html) {
        return html.replaceAll("(?s)<[^>]*>", "").replaceAll("\\s+", " ").trim();
    }

    /** Texts of all links that carry aria-current="page". */
    private static List<String> currentLinks(String html) {
        List<String> found = new ArrayList<>();
        Matcher m = Pattern.compile("(?s)<a\\b([^>]*)>(.*?)</a>").matcher(html);
        while (m.find()) {
            if (m.group(1).contains("aria-current=\"page\"")) {
                found.add(text(m.group(2)));
            }
        }
        return found;
    }

    @Test
    @DisplayName("UI-A11Y-NAV-01: the active link has aria-current=\"page\" on dashboard and cases for CLIENT, ANALYST and MANAGER, and on dashboard, audit, users and health for AUDITOR_ADMIN; exactly one per navigation")
    void ariaCurrentPerRole() throws Exception {
        Organisation org = org();
        for (Role role : List.of(Role.CLIENT, Role.ANALYST, Role.MANAGER)) {
            User u = user(org, role, true);
            assertEquals(List.of("Dashboard"), currentLinks(page("/dashboard", u)), role + " dashboard");
            assertEquals(List.of("Cases"), currentLinks(page("/cases", u)), role + " cases");
        }
        User client = user(org, Role.CLIENT, true);
        assertEquals(List.of("Report Incident"), currentLinks(page("/cases/new", client)));
        User auditor = user(null, Role.AUDITOR_ADMIN, true);
        assertEquals(List.of("Dashboard"), currentLinks(page("/dashboard", auditor)));
        assertEquals(List.of("Audit log"), currentLinks(page("/audit", auditor)));
        assertEquals(List.of("Users"), currentLinks(page("/admin/users", auditor)));
        assertEquals(List.of("Health"), currentLinks(page("/admin/health", auditor)));
    }

    @Test
    @DisplayName("UI-A11Y-NAV-02: case detail tabs mark the open tab with aria-current=\"page\" (overview by default, notes when selected)")
    void caseTabsAriaCurrent() throws Exception {
        Organisation org = org();
        User client = user(org, Role.CLIENT, true);
        Case c = caseRepository.save(new Case(UUID.randomUUID().toString(), org, "A11Y tabs " + UUID.randomUUID(), "OTHER", "LOW", "OPEN",
                client, null, Instant.now()));
        List<String> overview = currentLinks(page("/cases/" + c.getId(), client));
        assertTrue(overview.contains("Overview"), overview.toString());
        List<String> notes = currentLinks(page("/cases/" + c.getId() + "?tab=notes", client));
        assertTrue(notes.stream().anyMatch(t -> t.startsWith("Investigation Notes")), notes.toString());
        assertTrue(notes.stream().noneMatch(t -> t.equals("Overview")), notes.toString());
    }

    @Test
    @DisplayName("UI-A11Y-ACTIONS-01: repeated row actions in the cases list and the users list each have a distinct accessible name that includes the target")
    void rowActionsHaveDistinctNames() throws Exception {
        Organisation org = org();
        User client = user(org, Role.CLIENT, true);
        List<String> titles = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            String title = "A11Y action case " + i + " " + UUID.randomUUID().toString().substring(0, 6);
            titles.add(title);
            caseRepository.save(new Case(UUID.randomUUID().toString(), org, title, "PHISHING", "HIGH", "OPEN", client, null, Instant.now()));
        }
        String cases = page("/cases", client);
        Set<String> views = namesOf(cases, "View");
        assertEquals(3, views.size(), "three View links with three distinct names: " + views);
        for (String title : titles) {
            assertTrue(views.contains("View case " + title), title);
        }

        user(null, Role.ANALYST, true);
        user(null, Role.ANALYST, false);
        user(null, Role.ANALYST, false);
        User auditor = user(null, Role.AUDITOR_ADMIN, true);
        String users = page("/admin/users?size=100", auditor);
        for (String action : List.of("Disable", "Enable", "Revoke sessions")) {
            List<String> all = allNamesOf(users, action);
            assertTrue(all.size() >= 2, action + " rows: " + all.size());
            assertEquals(all.size(), new HashSet<>(all).size(), action + " names are distinct: " + all);
            for (String n : all) {
                assertTrue(n.startsWith(action) && n.contains("a11y_") || n.startsWith(action) && n.length() > action.length() + 6, n);
            }
        }
    }

    private static List<String> allNamesOf(String html, String visibleText) {
        List<String> names = new ArrayList<>();
        Matcher m = Pattern.compile("(?s)<(a|button)\\b([^>]*)>(.*?)</\\1>").matcher(html);
        while (m.find()) {
            if (text(m.group(3)).equals(visibleText)) {
                Matcher label = Pattern.compile("aria-label=\"([^\"]*)\"").matcher(m.group(2));
                assertTrue(label.find(), visibleText + " control without aria-label: " + m.group(2));
                names.add(label.group(1));
            }
        }
        return names;
    }

    private static Set<String> namesOf(String html, String visibleText) {
        return new HashSet<>(allNamesOf(html, visibleText));
    }
}
