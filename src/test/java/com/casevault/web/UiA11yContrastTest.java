package com.casevault.web;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase 9C: WCAG 2.1 AA contrast of the colour pairs declared in app.css, and the focus rules. The pairs are read
 * from the stylesheet itself (custom properties resolved), so a colour change that breaks a pair fails here.
 * Relative luminance L = 0.2126 R + 0.7152 G + 0.0722 B with each channel c/255 linearised
 * (c <= 0.03928 ? c/12.92 : ((c+0.055)/1.055)^2.4); ratio = (L1 + 0.05) / (L2 + 0.05), L1 the lighter colour.
 */
class UiA11yContrastTest {

    private static final double TEXT = 4.5;
    private static final double LARGE_OR_UI = 3.0;

    private static final Map<String, String> VARS = new HashMap<>();
    private static final Map<String, Map<String, String>> RULES = new HashMap<>();
    private static final String CSS;

    static {
        try {
            CSS = Files.readString(Paths.get("src/main/resources/static/css/app.css"));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        String css = CSS.replaceAll("(?s)/\\*.*?\\*/", "");
        Matcher root = Pattern.compile("(?s):root\\s*\\{([^}]*)\\}").matcher(css);
        assertTrue(root.find(), ":root block");
        for (String decl : root.group(1).split(";")) {
            int i = decl.indexOf(':');
            if (i > 0) {
                VARS.put(decl.substring(0, i).trim(), decl.substring(i + 1).trim());
            }
        }
        Matcher rule = Pattern.compile("([^{}]+)\\{([^{}]*)\\}").matcher(css);
        while (rule.find()) {
            String selectors = rule.group(1).trim();
            if (selectors.startsWith("@") || selectors.startsWith(":root")) {
                continue;
            }
            for (String selector : selectors.split(",")) {
                Map<String, String> props = RULES.computeIfAbsent(selector.trim().replaceAll("\\s+", " "), k -> new HashMap<>());
                for (String decl : rule.group(2).split(";")) {
                    int i = decl.indexOf(':');
                    if (i > 0) {
                        props.put(decl.substring(0, i).trim(), decl.substring(i + 1).trim());
                    }
                }
            }
        }
    }

    private static String resolve(String value) {
        Matcher m = Pattern.compile("var\\((--[\\w-]+)\\)").matcher(value);
        return m.matches() ? VARS.get(m.group(1)) : value;
    }

    /** Colour of a property; shorthands (border, outline, background) give their colour token. */
    private static String colour(String selector, String prop) {
        Map<String, String> props = RULES.get(selector);
        assertTrue(props != null, "selector in app.css: " + selector);
        String value = props.get(prop);
        if (value == null) {
            String shorthand = prop.equals("border-color") ? "border" : prop.equals("background-color") ? "background" : prop;
            value = props.get(shorthand);
            if (value != null) {
                String[] tokens = value.split("\\s+");
                value = tokens[tokens.length - 1];
            }
        }
        assertTrue(value != null, selector + " declares " + prop);
        if (prop.equals("outline") || prop.equals("border")) {
            String[] tokens = value.split("\\s+");
            value = tokens[tokens.length - 1];
        }
        String resolved = resolve(value);
        assertTrue(resolved != null && resolved.matches("#[0-9A-Fa-f]{6}"), selector + " " + prop + " is a hex colour: " + resolved);
        return resolved;
    }

    private static double luminance(String hex) {
        double[] c = new double[3];
        for (int i = 0; i < 3; i++) {
            double v = Integer.parseInt(hex.substring(1 + 2 * i, 3 + 2 * i), 16) / 255.0;
            c[i] = v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
        }
        return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
    }

    static double ratio(String a, String b) {
        double x = luminance(a);
        double y = luminance(b);
        return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
    }

    private record Pair(String element, String fgSel, String fgProp, String bgSel, String bgProp, double min) {
    }

    private static Pair text(String element, String fgSel, String bgSel) {
        return new Pair(element, fgSel, "color", bgSel, "background-color", TEXT);
    }

    private static Pair own(String element, String sel) {
        return text(element, sel, sel);
    }

    @Test
    @DisplayName("UI-A11Y-CONTRAST-01: every declared text, badge, alert, button and control-boundary colour pair meets WCAG AA (4.5:1 text, 3:1 large text and UI boundaries)")
    void declaredPairsMeetAa() {
        List<Pair> pairs = new ArrayList<>(List.of(
                // body and card text
                text("body text on page", "body", "body"),
                text("text on cards", "body", ".card"),
                text("page subtitle on card", ".page-subtitle", ".card"),
                text("muted text (.text-muted) on card", ".text-muted", ".card"),
                text("metadata label on card", ".metadata-label", ".card"),
                text("timeline meta on card", ".timeline-meta", ".card"),
                text("timeline body text", "body", ".timeline-body"),
                text("table header text", "table.data-table th", "table.data-table th"),
                text("metric label on metric card", ".metric-label", ".metric-card"),
                new Pair("metric value (2rem bold, large text)", ".metric-value", "color", ".metric-card", "background-color", LARGE_OR_UI),
                // links
                text("table link", ".table-link", ".card"),
                text("tab link", ".tabs-nav a", "body"),
                text("tab link active/hover", ".tabs-nav a.active", "body"),
                // buttons
                own("primary button", ".btn-primary"),
                text("primary button hover (text from the base rule)", ".btn-primary", ".btn-primary:hover"),
                own("secondary button", ".btn-secondary"),
                text("secondary button hover (text from the base rule)", ".btn-secondary", ".btn-secondary:hover"),
                own("danger button", ".btn-danger"),
                text("danger button hover (text from the base rule)", ".btn-danger", ".btn-danger:hover"),
                // dark header, sidebar, footer
                text("brand link in header", ".brand a", "header.app-header"),
                text("header nav link", "nav.nav-links a", "header.app-header"),
                text("header text", "header.app-header", "header.app-header"),
                own("role badge in header", ".user-profile .badge-role"),
                own("environment tag", ".brand .env-tag"),
                text("organisation tag in header", ".layout-header-org", "header.app-header"),
                text("footer text", "footer.app-footer", "footer.app-footer"),
                text("sidebar link", ".sidebar-link", ".app-sidebar"),
                own("sidebar link active", ".sidebar-link.active"),
                text("sidebar heading", ".sidebar-heading", ".app-sidebar"),
                text("restricted entry in sidebar", ".sidebar-restricted-tag", ".app-sidebar"),
                text("skip link", ".skip-link", ".skip-link"),
                // alerts
                own("alert danger", ".alert-danger"),
                own("alert success", ".alert-success"),
                own("alert info", ".alert-info"),
                // report/audit/user status badges: dark text on a tint
                text("status badge ok", ".status-badge", ".status-ok"),
                text("status badge bad", ".status-badge", ".status-bad"),
                text("status badge warn", ".status-badge", ".status-warn"),
                text("status badge neutral", ".status-badge", ".status-neutral"),
                text("report step done", ".stepper .step", ".stepper .step-done"),
                text("report step current", ".stepper .step", ".stepper .step-current"),
                // UI component boundaries (3:1)
                new Pair("text input border", ".form-control", "border-color", ".form-control", "background-color", LARGE_OR_UI),
                new Pair("filter input border", ".filter-item input", "border-color", ".form-control", "background-color", LARGE_OR_UI),
                new Pair("secondary button border", ".btn-secondary", "border-color", ".card", "background-color", LARGE_OR_UI),
                new Pair("secondary button border (hover)", ".btn-secondary:hover", "border-color", ".btn-secondary:hover", "background-color", LARGE_OR_UI),
                new Pair("focus ring on page", "a:focus-visible", "outline", "body", "background-color", LARGE_OR_UI),
                new Pair("focus ring on the dark header", "a:focus-visible", "outline", "header.app-header", "background-color", LARGE_OR_UI),
                new Pair("focus ring on the dark sidebar", "a:focus-visible", "outline", ".app-sidebar", "background-color", LARGE_OR_UI)));
        // every case severity and status badge (text and colour), plus the older badge set that shares the variables
        for (String name : List.of("low", "medium", "high", "critical")) {
            pairs.add(own("severity badge " + name, ".badge-severity-" + name));
            pairs.add(own("legacy badge " + name, ".badge-" + name));
        }
        for (String name : List.of("open", "assigned", "in_progress", "pending_review", "closed")) {
            pairs.add(own("status badge " + name, ".badge-status-" + name));
        }
        for (String name : List.of("open", "assigned", "in_progress", "pending_review", "closed")) {
            pairs.add(own("legacy status badge " + name, ".badge-" + name));
        }

        List<String> failures = new ArrayList<>();
        for (Pair p : pairs) {
            String fg = colour(p.fgSel(), p.fgProp());
            String bg = colour(p.bgSel(), p.bgProp());
            double r = ratio(fg, bg);
            if (r < p.min()) {
                failures.add(String.format(Locale.ROOT, "%s: %s on %s = %.2f (needs %.1f)", p.element(), fg, bg, r, p.min()));
            }
        }
        assertEquals(List.of(), failures);
        assertTrue(pairs.size() >= 60, "the pair list covers the stylesheet, size " + pairs.size());
    }

    @Test
    @DisplayName("UI-A11Y-CONTRAST-02: the ratio function reproduces known values (black on white 21:1, the former failing pairs fail)")
    void formulaSelfCheck() {
        assertEquals(21.0, ratio("#000000", "#FFFFFF"), 0.01);
        assertTrue(ratio("#D68910", "#FEF9E7") < 3.0, "the former HIGH badge pair");
        assertTrue(ratio("#1E8449", "#EAFAF1") < TEXT, "the former success pair");
        assertTrue(ratio("#E2E8F0", "#FFFFFF") < LARGE_OR_UI, "the former control border");
    }

    @Test
    @DisplayName("UI-A11Y-FOCUS-01: app.css has :focus-visible rules for links, buttons, inputs, selects, textareas and the skip link, and never removes the outline")
    void focusRules() {
        String css = CSS.replaceAll("(?s)/\\*.*?\\*/", "");
        assertFalse(Pattern.compile("outline\\s*:\\s*(none|0)\\b", Pattern.CASE_INSENSITIVE).matcher(css).find(), "outline removed");
        assertFalse(Pattern.compile("outline-style\\s*:\\s*none", Pattern.CASE_INSENSITIVE).matcher(css).find());
        Matcher m = Pattern.compile("([^{}]*:focus-visible[^{}]*)\\{([^}]*)\\}").matcher(css);
        assertTrue(m.find(), ":focus-visible rule");
        String selectors = m.group(1);
        for (String element : List.of("a:focus-visible", "button:focus-visible", "input:focus-visible", "select:focus-visible",
                "textarea:focus-visible", ".skip-link:focus-visible")) {
            assertTrue(selectors.contains(element), element);
        }
        Matcher width = Pattern.compile("outline\\s*:\\s*(\\d+)px\\s+solid").matcher(m.group(2));
        assertTrue(width.find() && Integer.parseInt(width.group(1)) >= 2, "outline of at least 2px: " + m.group(2));
        // the older :focus rule is still there (no focus style was removed)
        assertTrue(css.contains("a:focus, button:focus, input:focus, select:focus, textarea:focus"));
    }
}
