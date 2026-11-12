package com.casevault.support;

import org.springframework.jdbc.core.JdbcTemplate;

/**
 * FK-safe cleanup for test classes that share the cached Spring context and the in-memory H2 database (F-008).
 * Children are deleted before parents. Tests that commit data (real HTTP, real logins) leave rows behind; a class
 * that wants a clean case table must not rely on other classes having cleaned up.
 */
public final class TestDatabaseCleaner {

    private TestDatabaseCleaner() {
    }

    /** Removes only reports. Used by classes that create reports so they leave none behind. */
    public static void deleteReports(JdbcTemplate jdbc) {
        jdbc.update("DELETE FROM reports");
    }

    /** Removes every case and everything that references a case, children first (reports, actions, notes, evidence, cases). */
    public static void deleteCasesAndDependents(JdbcTemplate jdbc) {
        jdbc.update("DELETE FROM reports");
        jdbc.update("DELETE FROM remediation_actions");
        jdbc.update("DELETE FROM case_notes");
        jdbc.update("DELETE FROM evidence");
        jdbc.update("DELETE FROM cases");
    }
}
