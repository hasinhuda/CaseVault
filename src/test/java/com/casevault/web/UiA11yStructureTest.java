package com.casevault.web;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase 9C: static structure checks on every page template (source level, like TemplateScannerTest). Fragments in
 * layout.html are checked for the parts they own. Rendered checks are in UiA11yRenderedTest.
 */
class UiA11yStructureTest {

    private static final Path TEMPLATES = Paths.get("src/main/resources/templates");

    private static List<Path> pages() throws IOException {
        try (Stream<Path> all = Files.walk(TEMPLATES)) {
            return all.filter(p -> p.toString().endsWith(".html") && !p.getFileName().toString().equals("layout.html")).toList();
        }
    }

    private static String name(Path p) {
        return TEMPLATES.relativize(p).toString().replace('\\', '/');
    }

    @Test
    @DisplayName("UI-A11Y-STRUCT-01: every page has lang, a title (own or from the htmlhead fragment), exactly one h1 and a main landmark; every skip link points to an existing id")
    void pageBasics() throws IOException {
        List<String> problems = new ArrayList<>();
        List<Path> pages = pages();
        assertEquals(13, pages.size(), "all 13 page templates are scanned");
        for (Path page : pages) {
            String html = Files.readString(page);
            String n = name(page);
            if (!Pattern.compile("<html[^>]*\\slang=\"en\"").matcher(html).find()) problems.add(n + ": lang");
            if (!(html.contains("<title") || html.contains("layout :: htmlhead("))) problems.add(n + ": title");
            long h1 = Pattern.compile("<h1[\\s>]").matcher(html).results().count();
            if (h1 != 1) problems.add(n + ": h1 count " + h1);
            if (!Pattern.compile("<main[\\s>]").matcher(html).find()) problems.add(n + ": main");
            Matcher skip = Pattern.compile("<a href=\"#([\\w-]+)\" class=\"skip-link\"").matcher(html);
            while (skip.find()) {
                if (!html.contains("id=\"" + skip.group(1) + "\"")) problems.add(n + ": skip link target " + skip.group(1));
            }
            if (Pattern.compile("<label[^>]*class=\"skip-link\"").matcher(html).find()) problems.add(n + ": label uses skip-link class");
        }
        String layout = Files.readString(TEMPLATES.resolve("layout.html"));
        assertTrue(layout.contains("lang=\"en\"") && layout.contains("<title"), "layout htmlhead fragment has lang and title");
        assertEquals(List.of(), problems);
    }

    @Test
    @DisplayName("UI-A11Y-STRUCT-02: heading levels never skip downwards (h1 then h2 then h3 ...) in any page")
    void noSkippedHeadingLevels() throws IOException {
        List<String> problems = new ArrayList<>();
        for (Path page : pages()) {
            Matcher m = Pattern.compile("<h([1-6])[\\s>]").matcher(Files.readString(page));
            int previous = 0;
            while (m.find()) {
                int level = Integer.parseInt(m.group(1));
                if (level > previous + 1) problems.add(name(page) + ": h" + previous + " then h" + level);
                previous = level;
            }
        }
        assertEquals(List.of(), problems);
    }

    @Test
    @DisplayName("UI-A11Y-STRUCT-03: every data table has a caption and every th has a scope")
    void tablesHaveCaptionAndScope() throws IOException {
        List<String> problems = new ArrayList<>();
        int tables = 0;
        for (Path page : pages()) {
            String html = Files.readString(page);
            Matcher t = Pattern.compile("(?s)<table[\\s>].*?</table>").matcher(html);
            while (t.find()) {
                tables++;
                if (!t.group().contains("<caption")) problems.add(name(page) + ": table without caption");
                Matcher th = Pattern.compile("<th(\\s[^>]*)?>").matcher(t.group());
                while (th.find()) {
                    if (th.group().contains("scope=\"") == false) problems.add(name(page) + ": th without scope");
                }
            }
        }
        assertTrue(tables >= 5, "tables scanned: " + tables);
        assertEquals(List.of(), problems);
    }

    @Test
    @DisplayName("UI-A11Y-STRUCT-04: every visible input, select and textarea has a label for it or an aria-label")
    void controlsHaveLabels() throws IOException {
        List<String> problems = new ArrayList<>();
        int controls = 0;
        for (Path page : pages()) {
            String html = Files.readString(page);
            Set<String> labelFor = new HashSet<>();
            boolean dynamicLabel = false;
            Matcher l = Pattern.compile("<label[^>]*\\s(th:for|for)=\"([^\"]*)\"").matcher(html);
            while (l.find()) {
                labelFor.add(l.group(2));
                dynamicLabel |= l.group(1).equals("th:for");
            }
            Matcher c = Pattern.compile("<(input|select|textarea)\\b([^>]*)>").matcher(html);
            while (c.find()) {
                String attrs = c.group(2);
                if (c.group(1).equals("input") && Pattern.compile("type=\"(hidden|submit|button)\"").matcher(attrs).find()) continue;
                if (attrs.contains("th:name=\"${_csrf")) continue;
                controls++;
                if (attrs.contains("aria-label=")) continue;
                Matcher id = Pattern.compile("\\s(id|th:id)=\"([^\"]*)\"").matcher(attrs);
                boolean labelled = false;
                if (id.find()) {
                    labelled = id.group(1).equals("th:id") ? dynamicLabel : labelFor.contains(id.group(2));
                }
                if (!labelled) problems.add(name(page) + ": control without label: " + c.group().replaceAll("\\s+", " "));
            }
        }
        assertTrue(controls >= 20, "controls scanned: " + controls);
        assertEquals(List.of(), problems);
    }
}
