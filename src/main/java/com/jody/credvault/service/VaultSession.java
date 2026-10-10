package com.jody.credvault.service;

import java.io.Serializable;
import java.security.Principal;
import java.util.UUID;

import javax.crypto.SecretKey;

import com.jody.credvault.model.Role;

/**
 * An unlocked vault: who the user is, plus their decrypted data key.
 *
 * After login, Spring Security keeps this as the logged-in "principal" in the
 * server-side HTTP session. The browser only ever holds a random session ID
 * cookie; the key itself never leaves server memory and is never written to
 * the database or to disk. When the session ends, the key is gone.
 */
public record VaultSession(UUID userId, String username, Role role, SecretKey dataKey)
        implements Serializable, Principal {

    /** Lets Spring Security show the username wherever it needs a name. */
    @Override
    public String getName() {
        return username;
    }

    /** Never print the key, even by accident in a log message. */
    @Override
    public String toString() {
        return "VaultSession[username=" + username + ", role=" + role + ", dataKey=***]";
    }
}
