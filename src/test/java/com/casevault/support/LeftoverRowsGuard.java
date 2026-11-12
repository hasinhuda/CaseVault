package com.casevault.support;

import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Regression guard for test-order-dependent failures (finding F-008). Many test classes share one cached Spring
 * context and one in-memory H2 database ("casevault"). Tests that run outside a rolled-back transaction (real HTTP,
 * MockMvc with real logins) COMMIT rows. A later class that deletes cases without first deleting their dependents
 * then fails on a foreign key, but only in some run orders.
 *
 * After every test class this extension counts the rows in the case dependents. It prints the counts (so a leak is
 * attributable to the class that left it) and FAILS the class that leaves report rows behind. It is registered
 * through the JUnit service loader (src/test/resources/META-INF/services). It only reads; it never changes data.
 * Classes that use another database (Testcontainers PostgreSQL, the prod-like H2 databases) are not seen by it.
 */
public class LeftoverRowsGuard implements BeforeAllCallback, AfterAllCallback {

    private static final String URL = "jdbc:h2:mem:casevault;IFEXISTS=TRUE;DB_CLOSE_DELAY=-1";
    private static final String[] TABLES = {"reports", "remediation_actions", "case_notes", "evidence", "cases", "users"};

    private static final ExtensionContext.Namespace NS = ExtensionContext.Namespace.create(LeftoverRowsGuard.class);

    @Override
    public void beforeAll(ExtensionContext context) {
        context.getStore(NS).put("before", counts());
    }

    @Override
    @SuppressWarnings("unchecked")
    public void afterAll(ExtensionContext context) {
        Map<String, Long> after = counts();
        if (after.isEmpty()) {
            return;
        }
        Map<String, Long> before = context.getStore(NS).get("before", Map.class);
        System.out.println("[ROWS] " + context.getRequiredTestClass().getSimpleName() + " before=" + before + " after=" + after);
        long reports = after.getOrDefault("reports", 0L);
        if (reports > 0 && !"false".equals(System.getProperty("casevault.guard.strict"))) {
            throw new IllegalStateException(context.getRequiredTestClass().getSimpleName() + " left " + reports
                    + " committed row(s) in the reports table. Delete them in @AfterAll/@AfterEach (children before parents, see"
                    + " TestDatabaseCleaner); otherwise a later class that deletes cases fails on FK_REPORTS_CASE in some run orders.");
        }
    }

    private static Map<String, Long> counts() {
        Map<String, Long> result = new LinkedHashMap<>();
        try (Connection c = DriverManager.getConnection(URL, "sa", ""); Statement s = c.createStatement()) {
            for (String table : TABLES) {
                try (ResultSet rs = s.executeQuery("SELECT COUNT(*) FROM " + table)) {
                    rs.next();
                    result.put(table, rs.getLong(1));
                }
            }
        } catch (SQLException e) {
            // no such database yet (class without a Spring context) or tables not created: nothing to report
            return new LinkedHashMap<>();
        }
        return result;
    }
}
