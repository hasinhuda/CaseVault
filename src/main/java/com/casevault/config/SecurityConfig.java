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
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
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
                                                   com.casevault.ratelimit.RateLimitFilter rateLimitFilter) throws Exception {
        LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints = new LinkedHashMap<>();
        entryPoints.put(AntPathRequestMatcher.antMatcher("/api/**"), new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));
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
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .sessionFixation(fixation -> fixation.changeSessionId())
                // Unlimited sessions per user, but every session is registered so an admin can expire them
                // (Phase 7B revoke-sessions). The expired session is refused on its next request.
                .sessionConcurrency(concurrency -> concurrency
                    .maximumSessions(-1)
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
