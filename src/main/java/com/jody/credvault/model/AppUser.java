package com.jody.credvault.model;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * A vault owner.
 *
 * Notice what is NOT here: no master password and no password hash.
 * We only store the salt and iteration count needed to re-derive the key, and
 * the user's data key in wrapped (encrypted) form. Logging in means proving
 * you can unwrap it. Someone who steals the database gets nothing they can
 * use without guessing each master password, at 600,000 iterations per guess.
 *
 * Table is "app_users" because "user" is a reserved word in PostgreSQL.
 */
@Entity
@Table(name = "app_users")
public class AppUser {

    /** Random UUIDs, not 1, 2, 3...: IDs that can't be guessed or counted. */
    @Id
    private UUID id;

    @Column(nullable = false, unique = true, length = 50)
    private String username;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 10)
    private Role role;

    @Column(name = "kdf_salt", nullable = false, length = 64)
    private String kdfSalt;

    @Column(name = "kdf_iterations", nullable = false)
    private int kdfIterations;

    @Column(name = "wrapped_data_key", nullable = false, length = 200)
    private String wrappedDataKey;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    /** Required by JPA. */
    protected AppUser() {
    }

    public AppUser(UUID id, String username, Role role,
                   String kdfSalt, int kdfIterations, String wrappedDataKey) {
        this.id = id;
        this.username = username;
        this.role = role;
        this.kdfSalt = kdfSalt;
        this.kdfIterations = kdfIterations;
        this.wrappedDataKey = wrappedDataKey;
        this.createdAt = Instant.now();
    }

    /** Used when the master password changes: new salt, same data key re-wrapped. */
    public void replaceKeyMaterial(String kdfSalt, int kdfIterations, String wrappedDataKey) {
        this.kdfSalt = kdfSalt;
        this.kdfIterations = kdfIterations;
        this.wrappedDataKey = wrappedDataKey;
    }

    public UUID getId() { return id; }
    public String getUsername() { return username; }
    public Role getRole() { return role; }
    public String getKdfSalt() { return kdfSalt; }
    public int getKdfIterations() { return kdfIterations; }
    public String getWrappedDataKey() { return wrappedDataKey; }
    public Instant getCreatedAt() { return createdAt; }
}
