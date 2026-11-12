package com.casevault.ratelimit;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.ViewResolver;

import java.time.Clock;

/** Wires the filter. It is added to the security chain only; the container registration is switched off. */
@Configuration
public class RateLimitConfig {

    @Bean
    public Clock rateLimitClock() {
        return Clock.systemUTC();
    }

    @Bean
    public RateLimitFilter rateLimitFilter(RateLimiter limiter, RateLimitSettings settings, Clock clock,
                                           org.thymeleaf.spring6.view.ThymeleafViewResolver thymeleafViewResolver) {
        ViewResolver resolver = thymeleafViewResolver;
        return new RateLimitFilter(limiter, settings, clock, new ThymeleafBlockedPageRenderer(resolver));
    }

    /** Without this Boot would also register the filter in the servlet container, before Spring Security. */
    @Bean
    public FilterRegistrationBean<RateLimitFilter> rateLimitFilterRegistration(RateLimitFilter filter) {
        FilterRegistrationBean<RateLimitFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }
}
