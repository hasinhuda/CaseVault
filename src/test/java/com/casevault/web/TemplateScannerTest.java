package com.casevault.web;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase 8C: a stricter static scanner for templates and static files. It ADDS to the older scanners (SEC-CASE-13,
 * SEC-EVID-UI-04 and the per-area template tests); nothing was relaxed. Every rule is proven by a small in-memory
 * sample (no bad file is added to the repository).
 */
class TemplateScannerTest {

    /** Rule name to pattern. Patterns run against the WHOLE file text so tags that span several lines are covered. */
    private static final Map<String, Pattern> RULES = new LinkedHashMap<>();

    static {
        int ci = Pattern.CASE_INSENSITIVE;
        RULES.put("th:utext", Pattern.compile("th:utext", ci));
        RULES.put("innerHTML", Pattern.compile("innerHTML", ci));
        RULES.put("outerHTML", Pattern.compile("outerHTML", ci));
        RULES.put("insertAdjacentHTML", Pattern.compile("insertAdjacentHTML", ci));
        RULES.put("document.write", Pattern.compile("document\\s*\\.\\s*write", ci));
        RULES.put("eval(", Pattern.compile("\\beval\\s*\\(", ci));
        RULES.put("new Function", Pattern.compile("new\\s+Function\\b"));
        RULES.put("localStorage", Pattern.compile("localStorage", ci));
        RULES.put("sessionStorage", Pattern.compile("sessionStorage", ci));
        RULES.put("inline event handler", Pattern.compile("<[a-zA-Z][^>]*\\s(?:th:)?on[a-z]+\\s*=", ci));
        RULES.put("javascript: URL", Pattern.compile("javascript\\s*:", ci));
        RULES.put("script without src", Pattern.compile("<script(?![^>]*\\ssrc\\s*=)(?![^>]*\\sth:src\\s*=)[^>]*>", ci));
        RULES.put("th:inline javascript", Pattern.compile("th:inline\\s*=\\s*[\"'](?:javascript|js)[\"']", ci));
        RULES.put("style attribute", Pattern.compile("<[a-zA-Z][^>]*\\s(?:th:)?style\\s*=", ci));
        RULES.put("style block", Pattern.compile("<style[\\s>]", ci));
        RULES.put("external http(s) resource", Pattern.compile(
                "(?:\\s(?:th:)?(?:src|href|action|data|poster|srcset)\\s*=\\s*[\"']\\s*[\"']?\\s*(?:https?:)?//)"
                        + "|(?:url\\(\\s*[\"']?\\s*(?:https?:)?//)|(?:@import\\s+[\"']?\\s*(?:https?:)?//)", ci));
    }

    static List<String> violations(String content) {
        List<String> found = new ArrayList<>();
        for (Map.Entry<String, Pattern> rule : RULES.entrySet()) {
            if (rule.getValue().matcher(content).find()) {
                found.add(rule.getKey());
            }
        }
        return found;
    }

    @Test
    @DisplayName("SEC-TPL-01: no template and no static file (src/main/resources/templates and static) breaks any scanner rule")
    void repositoryFilesAreClean() throws IOException {
        List<String> problems = new ArrayList<>();
        int scanned = 0;
        for (String dir : List.of("src/main/resources/templates", "src/main/resources/static")) {
            Path root = Paths.get(dir);
            assertTrue(Files.isDirectory(root), dir + " must exist");
            try (Stream<Path> files = Files.walk(root)) {
                for (Path file : files.filter(Files::isRegularFile).toList()) {
                    String name = file.getFileName().toString().toLowerCase();
                    if (!(name.endsWith(".html") || name.endsWith(".css") || name.endsWith(".js") || name.endsWith(".svg"))) {
                        continue;
                    }
                    scanned++;
                    for (String rule : violations(Files.readString(file))) {
                        problems.add(file.toString().replace('\\', '/') + " -> " + rule);
                    }
                }
            }
        }
        assertTrue(scanned >= 15, "the scanner must have looked at the templates and static files, scanned " + scanned);
        assertEquals(List.of(), problems);
    }

    @Test
    @DisplayName("SEC-TPL-02: every scanner rule fires on a small bad sample (in memory); the rule name is reported")
    void everyRuleFires() {
        Map<String, String> bad = new LinkedHashMap<>();
        bad.put("th:utext", "<p th:utext=\"${x}\">a</p>");
        bad.put("innerHTML", "<script src=\"/js/a.js\"></script> el.innerHTML = x;");
        bad.put("outerHTML", "el.outerHTML = x;");
        bad.put("insertAdjacentHTML", "el.insertAdjacentHTML('beforeend', x);");
        bad.put("document.write", "document.write('<b>x</b>');");
        bad.put("eval(", "var a = eval ('1+1');");
        bad.put("new Function", "var f = new Function('return 1');");
        bad.put("localStorage", "localStorage.setItem('k', 'v');");
        bad.put("sessionStorage", "sessionStorage.getItem('k');");
        bad.put("inline event handler", "<button type=\"button\" onclick=\"go()\">x</button>");
        bad.put("javascript: URL", "<a href=\"javascript:void(0)\">x</a>");
        bad.put("script without src", "<script>var a = 1;</script>");
        bad.put("th:inline javascript", "<script th:src=\"@{/js/a.js}\" th:inline=\"javascript\"></script>");
        bad.put("style attribute", "<div style=\"color:red\">x</div>");
        bad.put("style block", "<style>body { color: red }</style>");
        bad.put("external http(s) resource", "<script src=\"https://cdn.example.test/lib.js\"></script>");
        assertEquals(RULES.keySet(), bad.keySet(), "a sample for every rule");
        for (Map.Entry<String, String> sample : bad.entrySet()) {
            assertTrue(violations(sample.getValue()).contains(sample.getKey()),
                    "rule must fire: " + sample.getKey() + " on " + sample.getValue());
        }
    }

    @Test
    @DisplayName("SEC-TPL-03: variants are caught (multi-line tag, upper case, th:-prefixed handler and style, CDN link and CSS import) and a clean sample passes")
    void variantsAndCleanSample() {
        assertTrue(violations("<input\n   type=\"text\"\n   ONFOCUS=\"x()\"/>").contains("inline event handler"));
        assertTrue(violations("<a th:onclick=\"|go('${id}')|\">x</a>").contains("inline event handler"));
        assertTrue(violations("<p\n  th:style=\"${s}\">x</p>").contains("style attribute"));
        assertTrue(violations("<link rel=\"stylesheet\" href=\"//cdn.example.test/a.css\"/>").contains("external http(s) resource"));
        assertTrue(violations("<img th:src=\"'http://img.example.test/a.png'\"/>").contains("external http(s) resource"));
        assertTrue(violations("body { background: url(https://img.example.test/a.png); }").contains("external http(s) resource"));
        assertTrue(violations("@import \"https://fonts.example.test/a.css\";").contains("external http(s) resource"));
        assertTrue(violations("<SCRIPT>alert(1)</SCRIPT>").contains("script without src"));
        assertTrue(violations("<a HREF=\"JavaScript:alert(1)\">x</a>").contains("javascript: URL"));

        String clean = "<!DOCTYPE html>\n<html xmlns:th=\"http://www.thymeleaf.org\" lang=\"en\">\n<head>\n"
                + "<link rel=\"stylesheet\" th:href=\"@{/css/app.css}\"/>\n<script th:src=\"@{/js/app.js}\"></script>\n"
                + "<script src=\"/js/other.js\"></script>\n</head>\n<body>\n<a th:href=\"@{/cases}\" class=\"btn\">Cases</a>\n"
                + "<form th:action=\"@{/login}\" method=\"post\"><button type=\"submit\">Go</button></form>\n"
                + "<p th:text=\"${message}\">text with the words once, button and online</p>\n</body></html>";
        assertEquals(List.of(), violations(clean));
        assertFalse(violations("<p>nothing special</p>").iterator().hasNext());
    }
}
