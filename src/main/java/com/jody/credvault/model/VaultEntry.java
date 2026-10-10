package com.jody.credvault.model;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

/**
 * One saved credential.
 *
 * The title and URL are stored as plain text so the vault list can be shown
 * without decrypting anything. The login username, password and notes are
 * always encrypted, each with its own random IV and bound to this entry, its
 * owner and the field name. Notes are encrypted even when empty, so the
 * database doesn't reveal which entries have notes.
 */
@Entity
@Table(name = "vault_entries",
       indexes = @Index(name = "idx_entries_owner", columnList = "owner_id"))
public class VaultEntry {

    @Id
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "owner_id", nullable = false, updatable = false)
    private AppUser owner;

    @Column(nullable = false, length = 100)
    private String title;

    @Column(length = 255)
    private String url;

    @Column(name = "enc_username", nullable = false, length = 1500)
    private String encryptedUsername;

    @Column(name = "enc_password", nullable = false, length = 3000)
    private String encryptedPassword;

    @Column(name = "enc_notes", nullable = false, length = 12000)
    private String encryptedNotes;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected VaultEntry() {
    }

    public VaultEntry(UUID id, AppUser owner) {
        this.id = id;
        this.owner = owner;
        this.createdAt = Instant.now();
        this.updatedAt = this.createdAt;
    }

    public void update(String title, String url, String encryptedUsername,
                       String encryptedPassword, String encryptedNotes) {
        this.title = title;
        this.url = url;
        this.encryptedUsername = encryptedUsername;
        this.encryptedPassword = encryptedPassword;
        this.encryptedNotes = encryptedNotes;
        this.updatedAt = Instant.now();
    }

    public UUID getId() { return id; }
    public AppUser getOwner() { return owner; }
    public String getTitle() { return title; }
    public String getUrl() { return url; }
    public String getEncryptedUsername() { return encryptedUsername; }
    public String getEncryptedPassword() { return encryptedPassword; }
    public String getEncryptedNotes() { return encryptedNotes; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
}
