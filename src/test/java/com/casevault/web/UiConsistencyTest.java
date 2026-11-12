package com.casevault.web;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Phase 9B: small static guards on the stylesheet and on the wording of the auditor's "Cases" entry. */
class UiConsistencyTest {

    private static final Path TEMPLATES = Paths.get("src/main/resources/templates");

    @Test
    @DisplayName("UI-CSS-01: app.css defines .text-muted with the existing muted colour variable (it is used by several templates)")
    void textMutedIsDefined() throws IOException {
        String css = Files.readString(Paths.get("src/main/resources/static/css/app.css"));
        Matcher m = Pattern.compile("(?m)^\\.text-muted\\s*\\{([^}]*)\\}").matcher(css);
        assertTrue(m.find(), ".text-muted rule");
        assertTrue(m.group(1).contains("color: var(--text-muted)"), m.group(1));
        assertTrue(css.contains("--text-muted: #64748B;"), "the muted colour itself is unchanged");
        assertFalse(css.toLowerCase().contains("outline: none"));
    }

    @Test
    @DisplayName("UI-NAV-01: every template that names the auditor's restricted Cases entry uses the same label, Cases (Restricted)")
    void auditorCasesLabelIsConsistent() throws IOException {
        Pattern label = Pattern.compile("Cases \\((\\w+)\\)");
        Set<String> wordings = new TreeSet<>();
        List<String> files = new ArrayList<>();
        try (Stream<Path> all = Files.walk(TEMPLATES)) {
            for (Path file : all.filter(p -> p.toString().endsWith(".html")).toList()) {
                Matcher m = label.matcher(Files.readString(file));
                while (m.find()) {
                    wordings.add(m.group(1));
                    files.add(file.getFileName().toString());
                }
            }
        }
        assertEquals(Set.of("Restricted"), wordings, "one wording only, found in " + files);
        assertTrue(files.contains("layout.html") && files.contains("dashboard.html"), "both places that render it: " + files);
    }

    @Test
    @DisplayName("UI-NAV-02: error.html and rate-limited.html choose their link from the signedIn flag and still use th:text only")
    void errorTemplatesUseTheFlag() throws IOException {
        for (String name : List.of("error.html", "rate-limited.html")) {
            String html = Files.readString(TEMPLATES.resolve(name));
            assertTrue(html.contains("th:if=\"${signedIn}\""), name);
            assertTrue(html.contains("th:unless=\"${signedIn}\""), name);
            assertTrue(html.contains("Back to login") && html.contains("Return to Dashboard"), name);
            assertFalse(html.contains("th:utext"), name);
        }
    }
}
