package com.casevault.support;

import com.casevault.bootstrap.DataBootstrapService;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.context.ApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.junit.jupiter.SpringExtension;

/**
 * Put the database back into the first-run state (F-008). A few test classes delete ALL users and organisations in
 * their setup, which also removes the synthetic accounts that the first-run bootstrap created in the shared cached
 * context. A later class that expects those accounts (DataBootstrapSecurityTest) then fails, but only in run orders
 * where it comes after them. The bootstrap skips itself when any user exists, so this extension first removes the
 * remaining case data, users and organisations (children before parents, the same wipe those classes do in their
 * setup) and then runs the bootstrap again. It does not change any assertion.
 */
public class RestoreBootstrapDataAfterAll implements AfterAllCallback {

    @Override
    public void afterAll(ExtensionContext context) {
        ApplicationContext spring = SpringExtension.getApplicationContext(context);
        JdbcTemplate jdbc = spring.getBean(JdbcTemplate.class);
        TestDatabaseCleaner.deleteCasesAndDependents(jdbc);
        jdbc.update("DELETE FROM users");
        jdbc.update("DELETE FROM organisations");
        spring.getBean(DataBootstrapService.class).run(new DefaultApplicationArguments());
    }
}
