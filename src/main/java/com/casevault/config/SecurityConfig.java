package com.casevault.config;

import com.casevault.repository.UserRepository;
import com.casevault.security.CaseVaultAuthenticationProvider;
import com.casevault.security.CaseVaultUserPrincipal;
import com.casevault.security.SessionAbsoluteTimeoutFilter;
import com.casevault.service.AuditEventRecorder;
import com.casevault.service.AuditEventType;
import com.casevault.security.UserStatusEnforcementFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.LinkedHashMap;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final CaseVaultAuthenticationProvider authenticationProvider;
    private final UserRepository userRepository;
    private final AuditEventRecorder auditEventRecorder;

    public SecurityConfig(CaseVaultAuthenticationProvider authenticationProvider, UserRepository userRepository,
                          AuditEventRecorder auditEventRecorder) {
        this.authenticationProvider = authenticationProvider;
        this.userRepository = userRepository;
        this.auditEventRecorder = auditEventRecorder;
    }

    /** In-memory registry of active sessions (per node, lost on restart). */
    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    /** Publishes session destruction so the registry forgets ended sessions. */
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, SessionRegistry sessionRegistry,
                                                   com.casevault.ratelimit.RateLimitFilter rateLimitFilter,
                                                   @org.springframework.beans.factory.annotation.Value("${casevault.security.hsts-enabled:false}") boolean hstsEnabled,
                                                   @org.springframework.beans.factory.annotation.Value("${casevault.session.max-per-user:3}") int maxSessionsPerUser) throws Exception {
        LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints = new LinkedHashMap<>();
        entryPoints.put(PathPatternRequestMatcher.withDefaults().matcher("/api/**"), new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));
        entryPoints.put(new MediaTypeRequestMatcher(MediaType.APPLICATION_JSON), new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));

        DelegatingAuthenticationEntryPoint delegatingEntryPoint = new DelegatingAuthenticationEntryPoint(entryPoints);
        delegatingEntryPoint.setDefaultEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"));

        http
            // A parent-less ProviderManager: registering the provider with HttpSecurity AND letting Spring Boot add
            // it to the global manager made every failed login run the provider twice (double lockout counting and
            // double audit events). One manager, one invocation.
            .authenticationManager(new ProviderManager(authenticationProvider))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                .requestMatchers("/login", "/error", "/css/**", "/js/**", "/images/**").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/dashboard", true)
                .failureUrl("/login?error=true")
                .permitAll()
            )
            .httpBasic(Customizer.withDefaults())
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessHandler((request, response, authentication) -> {
                    if (authentication != null && authentication.getPrincipal() instanceof CaseVaultUserPrincipal principal) {
                        auditEventRecorder.record(AuditEventType.LOGOUT, principal.getUserId(), null, "SUCCESS");
                    }
                    new org.springframework.security.web.DefaultRedirectStrategy()
                        .sendRedirect(request, response, "/login?logout=true");
                })
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            )
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(delegatingEntryPoint)
            )
            .headers(headers -> headers
                .contentTypeOptions(Customizer.withDefaults())
                .frameOptions(frameOptions -> frameOptions.deny())
                .referrerPolicy(referrer -> referrer.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                .permissionsPolicyHeader(permissions -> permissions.policy("camera=(), microphone=(), geolocation=()"))
                .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'; frame-ancestors 'none'; object-src 'none'"))
                // Phase 8B: a second CSP header with the remaining directives. Several CSP headers are all enforced
                // (the browser applies the intersection), so the first, long-standing policy value stays byte for
                // byte unchanged (TEST-BASE-002) while base-uri, form-action, script-src and style-src are added.
                // No 'unsafe-inline' and no 'unsafe-eval' anywhere.
                .addHeaderWriter((request, response) -> response.addHeader("Content-Security-Policy",
                        "base-uri 'self'; form-action 'self'; script-src 'self'; style-src 'self'"))
                .crossOriginOpenerPolicy(coop -> coop.policy(
                        org.springframework.security.web.header.writers.CrossOriginOpenerPolicyHeaderWriter.CrossOriginOpenerPolicy.SAME_ORIGIN))
                .crossOriginResourcePolicy(corp -> corp.policy(
                        org.springframework.security.web.header.writers.CrossOriginResourcePolicyHeaderWriter.CrossOriginResourcePolicy.SAME_ORIGIN))
                // HSTS only where the profile says so (prod-like). Browsers honour it over https only; Spring
                // Security additionally writes it only on secure requests.
                .httpStrictTransportSecurity(hsts -> {
                    if (hstsEnabled) {
                        hsts.includeSubDomains(true).maxAgeInSeconds(31_536_000L);
                    } else {
                        hsts.disable();
                    }
                })
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .sessionFixation(fixation -> fixation.changeSessionId())
                // Phase 8C: at most casevault.session.max-per-user (default 3) concurrent sessions per user. The
                // OLDEST session is expired when the cap is exceeded (the new login wins). Every session is also
                // registered so an admin can expire them (Phase 7B revoke-sessions). An expired session is refused
                // on its next request.
                .sessionConcurrency(concurrency -> concurrency
                    .maximumSessions(maxSessionsPerUser)
                    .sessionRegistry(sessionRegistry)
                    .expiredSessionStrategy(event -> {
                        jakarta.servlet.http.HttpServletRequest request = event.getRequest();
                        jakarta.servlet.http.HttpServletResponse response = event.getResponse();
                        String uri = request.getRequestURI();
                        if (uri != null && uri.startsWith("/api/")) {
                            response.setStatus(HttpStatus.UNAUTHORIZED.value());
                        } else {
                            new org.springframework.security.web.DefaultRedirectStrategy()
                                .sendRedirect(request, response, "/login?expired=true");
                        }
                    }))
            )
            .addFilterBefore(new SessionAbsoluteTimeoutFilter(), UsernamePasswordAuthenticationFilter.class)
            // Phase 8A: in-process rate limiting; before the login filter so every attempt is counted.
            .addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterAfter(new UserStatusEnforcementFilter(userRepository), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
