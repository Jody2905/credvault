package com.jody.credvault.security;

import java.util.Arrays;
import java.util.List;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import com.jody.credvault.model.AuditAction;
import com.jody.credvault.service.AuditService;
import com.jody.credvault.service.InvalidCredentialsException;
import com.jody.credvault.service.VaultService;
import com.jody.credvault.service.VaultSession;

/**
 * Connects Spring Security's login form to the vault.
 *
 * Instead of comparing a password hash, logging in IS unlocking the vault:
 * if the master password can unwrap the data key, the user is who they say
 * they are, and the unlocked key goes into their session.
 */
@Component
public class VaultAuthenticationProvider implements AuthenticationProvider {

    static final String LOCKED_MESSAGE = "Too many failed attempts. Try again in 15 minutes.";

    private final VaultService vault;
    private final LoginAttemptService attempts;
    private final AuditService audit;

    public VaultAuthenticationProvider(VaultService vault, LoginAttemptService attempts, AuditService audit) {
        this.vault = vault;
        this.attempts = attempts;
        this.audit = audit;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        Object credentials = authentication.getCredentials();
        char[] password = credentials == null ? new char[0] : credentials.toString().toCharArray();

        try {
            // Checked BEFORE the password: a locked account doesn't even get a guess
            if (attempts.isBlocked(username)) {
                audit.record(username, AuditAction.LOGIN_BLOCKED, false, null, "account temporarily locked");
                throw new LockedException(LOCKED_MESSAGE);
            }
            VaultSession session = vault.unlock(username, password);
            attempts.loginSucceeded(username);
            return UsernamePasswordAuthenticationToken.authenticated(
                    session, null, List.of(new SimpleGrantedAuthority("ROLE_" + session.role())));
        } catch (InvalidCredentialsException e) {
            attempts.loginFailed(username);
            throw new BadCredentialsException(e.getMessage());
        } finally {
            Arrays.fill(password, '\0');   // wipe our copy of the password
        }
    }

    @Override
    public boolean supports(Class<?> authenticationType) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authenticationType);
    }
}
