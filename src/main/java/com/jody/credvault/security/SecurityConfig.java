package com.jody.credvault.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

import com.jody.credvault.model.AuditAction;
import com.jody.credvault.service.AuditService;
import com.jody.credvault.service.VaultSession;

/**
 * The web security rules. Everything is locked down by default; only the
 * login and registration pages (and their CSS/JS) are public.
 */
@Configuration
public class SecurityConfig {

    /**
     * Content Security Policy: the browser may only load scripts, styles and
     * images from this site, and no inline scripts. Even if an attacker
     * managed to inject HTML, the browser would refuse to run their script.
     */
    static final String CONTENT_SECURITY_POLICY =
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            + "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuditService audit) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/register", "/css/**", "/js/**", "/error").permitAll()
                .anyRequest().authenticated())

            .formLogin(form -> form
                .loginPage("/login")
                .defaultSuccessUrl("/vault", true)
                .failureUrl("/login?error")
                .permitAll())

            // Logout must be a POST with a CSRF token, so a malicious link can't log you out
            .logout(logout -> logout
                .logoutUrl("/logout")
                .addLogoutHandler((request, response, authentication) -> {
                    if (authentication != null && authentication.getPrincipal() instanceof VaultSession s) {
                        audit.record(s.username(), AuditAction.LOGOUT, true, null, null);
                    }
                })
                .invalidateHttpSession(true)   // destroys the session, and the data key with it
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID")
                .logoutSuccessUrl("/login?logout"))

            // A new session ID is issued at login, defeating session fixation attacks
            .sessionManagement(session -> session
                .sessionFixation(fixation -> fixation.changeSessionId()))

            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp.policyDirectives(CONTENT_SECURITY_POLICY))
                .frameOptions(frame -> frame.deny())
                .referrerPolicy(referrer -> referrer
                    .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER)));

        // CSRF protection is on by default; we deliberately don't disable it.
        return http.build();
    }
}
