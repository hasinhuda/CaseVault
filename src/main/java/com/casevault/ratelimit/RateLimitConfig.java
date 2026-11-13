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
                                           org.thymeleaf.spring6.view.ThymeleafViewResolver thymeleafViewResolver,
                                           org.springframework.boot.autoconfigure.web.ServerProperties serverProperties) {
        // Phase 12A: with Tomcat's remote address handling ("native") or Spring's ForwardedHeaderFilter ("framework")
        // the request already carries the client address, and an X-Forwarded-For left over from a spoofed prefix could
        // still be read here. The two mechanisms must not be combined.
        org.springframework.boot.autoconfigure.web.ServerProperties.ForwardHeadersStrategy strategy =
                serverProperties.getForwardHeadersStrategy();
        if (settings.trustForwardedFor() && strategy != null
                && strategy != org.springframework.boot.autoconfigure.web.ServerProperties.ForwardHeadersStrategy.NONE) {
            throw new IllegalStateException("casevault.ratelimit.trust-forwarded-for=true must not be combined with "
                    + "server.forward-headers-strategy=" + strategy
                    + ": the client address is already resolved from the proxy header; use only one mechanism.");
        }
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
