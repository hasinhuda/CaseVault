package com.casevault.config;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * Phase 12A: fail fast, before any bean (and so any database connection) is created, when the prod-like profile has
 * no database password. The profile file has no default password; Spring Boot's binder would otherwise keep the
 * unresolved text {@code ${POSTGRES_PASSWORD}} and pass it on as if it were the password. A password can come from
 * POSTGRES_PASSWORD, SPRING_DATASOURCE_PASSWORD or a configtree secret file named spring.datasource.password. The
 * message names the sources and never contains a value.
 */
@Component
@Profile("prod-like")
public class ProdLikeConfigurationCheck implements BeanFactoryPostProcessor {

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
        // A bean factory post-processor is created before autowiring works, so the environment is taken from the factory.
        Environment environment = beanFactory.getBean(Environment.class);
        try {
            environment.getProperty("spring.datasource.password");
        } catch (IllegalArgumentException unresolved) {
            throw new IllegalStateException("The prod-like profile has no database password. Provide it with the "
                    + "environment variable POSTGRES_PASSWORD (or SPRING_DATASOURCE_PASSWORD) or with a secret file "
                    + "named spring.datasource.password in /run/secrets/. There is no default password.");
        }
    }
}
