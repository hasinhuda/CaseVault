package com.casevault.web;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.casevault.model.Organisation;
import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.OrganisationRepository;
import com.casevault.repository.UserRepository;
import com.casevault.security.CaseVaultUserPrincipal;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/** Phase 8B: the correlation id (SR-15): strict client UUID only, injection-proof, on every response, in the log context. */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = "casevault.ratelimit.login-limit=100000")
class CorrelationIdTest {

    private static final Pattern UUID_TEXT = Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private OrganisationRepository organisationRepository;
    @Autowired
    private UserRepository userRepository;

    private Authentication auth;
    private Logger rootLogger;
    private ListAppender<ILoggingEvent> logs;

    @BeforeEach
    void setUp() {
        rootLogger = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        logs = new ListAppender<>();
        logs.start();
        rootLogger.addAppender(logs);
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        Organisation org = organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "CID " + suffix, "CID_" + suffix, Instant.now()));
        User user = userRepository.save(new User(UUID.randomUUID().toString(), org, "cid_" + suffix, "{noop}x", Role.CLIENT,
                "cid_" + suffix + "@test.local", true, Instant.now()));
        CaseVaultUserPrincipal principal = new CaseVaultUserPrincipal(user, Instant.now());
        auth = new UsernamePasswordAuthenticationToken(principal, "N/A", principal.getAuthorities());
    }

    @AfterEach
    void tearDown() {
        rootLogger.detachAppender(logs);
        logs.stop();
    }

    private MvcResult notFoundWith(String headerValue) throws Exception {
        var request = get("/no-such-page-" + UUID.randomUUID()).with(authentication(auth));
        if (headerValue != null) {
            request.header("X-Correlation-ID", headerValue);
        }
        return mockMvc.perform(request).andReturn();
    }

    @Test
    @DisplayName("SEC-ERR-10: a valid client UUID is echoed (canonical lower case); CR/LF, long junk, script text, wrong shapes and an empty value are replaced by a fresh UUID")
    void clientValueRules() throws Exception {
        String valid = UUID.randomUUID().toString();
        assertEquals(valid, notFoundWith(valid).getResponse().getHeader("X-Correlation-ID"));
        assertEquals(valid, notFoundWith(valid.toUpperCase()).getResponse().getHeader("X-Correlation-ID"));

        List<String> bad = List.of(
                valid + "\r\nInjected-Header: yes",
                "abc\r\nSet-Cookie: x=1",
                "x".repeat(5000),
                "<script>alert(1)</script>",
                valid + " ",
                valid.substring(1),
                valid + "0",
                "00000000-0000-0000-0000-00000000000g",
                "%0d%0aInjected",
                "");
        for (String value : bad) {
            MvcResult r = notFoundWith(value);
            String id = r.getResponse().getHeader("X-Correlation-ID");
            assertTrue(id != null && UUID_TEXT.matcher(id).matches(), "replaced by a UUID for: " + value.length() + " chars");
            assertNotEquals(valid, id);
            assertEquals(1, r.getResponse().getHeaders("X-Correlation-ID").size(), "exactly one header value");
            assertEquals(null, r.getResponse().getHeader("Injected-Header"));
            assertEquals(null, r.getResponse().getHeader("Set-Cookie"));
            assertFalse(r.getResponse().getContentAsString().contains("Injected"));
        }
        for (ILoggingEvent event : logs.list) {
            assertFalse(event.getFormattedMessage().contains("Injected"), "client text must not reach the log");
            String cid = event.getMDCPropertyMap().get("correlationId");
            assertTrue(cid == null || UUID_TEXT.matcher(cid).matches(), "MDC value is always a UUID");
        }
    }

    @Test
    @DisplayName("SEC-ERR-11: every response carries X-Correlation-ID (page, redirect, error, POST, static file); a new id per request; the error page shows the same id as the header and the log line (MDC)")
    void everyResponseHasAnId() throws Exception {
        String first = mockMvc.perform(get("/login")).andReturn().getResponse().getHeader("X-Correlation-ID");
        String second = mockMvc.perform(get("/login")).andReturn().getResponse().getHeader("X-Correlation-ID");
        assertTrue(UUID_TEXT.matcher(first).matches() && UUID_TEXT.matcher(second).matches());
        assertNotEquals(first, second, "one id per request");
        assertTrue(UUID_TEXT.matcher(mockMvc.perform(get("/css/app.css")).andReturn().getResponse().getHeader("X-Correlation-ID")).matches());
        MvcResult redirect = mockMvc.perform(post("/login").with(csrf()).param("username", "nobody_" + UUID.randomUUID()).param("password", "x")).andReturn();
        assertEquals(302, redirect.getResponse().getStatus());
        assertTrue(UUID_TEXT.matcher(redirect.getResponse().getHeader("X-Correlation-ID")).matches());
        assertTrue(UUID_TEXT.matcher(mockMvc.perform(get("/dashboard").with(authentication(auth))).andReturn().getResponse().getHeader("X-Correlation-ID")).matches());

        MvcResult notFound = notFoundWith(null);
        String id = notFound.getResponse().getHeader("X-Correlation-ID");
        assertEquals(404, notFound.getResponse().getStatus());
        assertTrue(notFound.getResponse().getContentAsString().contains(id), "the page shows the id of the header");
        assertTrue(logs.list.stream().anyMatch(e -> id.equals(e.getMDCPropertyMap().get("correlationId"))),
                "a log line was written with this id in its context");
    }
}
