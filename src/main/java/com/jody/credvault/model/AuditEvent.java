package com.jody.credvault.model;

import java.time.Instant;
import java.util.UUID;

import org.hibernate.annotations.Immutable;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

/**
 * One line in the audit trail.
 *
 * Append-only: @Immutable and updatable = false mean the application can add
 * audit records but never edit them. There are no setters at all.
 *
 * Rule: an audit record NEVER contains a secret, only who did what, to which
 * entry, and whether it worked.
 */
@Entity
@Immutable
@Table(name = "audit_events", indexes = {
        @Index(name = "idx_audit_username", columnList = "username"),
        @Index(name = "idx_audit_time", columnList = "occurred_at")
})
public class AuditEvent {

    private static final int MAX_USERNAME = 50;
    private static final int MAX_DETAIL = 255;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "occurred_at", nullable = false, updatable = false)
    private Instant occurredAt;

    @Column(nullable = false, updatable = false, length = MAX_USERNAME)
    private String username;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, updatable = false, length = 30)
    private AuditAction action;

    @Column(nullable = false, updatable = false)
    private boolean success;

    @Column(name = "entry_id", updatable = false)
    private UUID entryId;

    @Column(updatable = false, length = MAX_DETAIL)
    private String detail;

    protected AuditEvent() {
    }

    public AuditEvent(String username, AuditAction action, boolean success,
                      UUID entryId, String detail) {
        this.occurredAt = Instant.now();
        // Usernames in failed logins come from outside, so cap their length
        this.username = truncate(username == null ? "" : username, MAX_USERNAME);
        this.action = action;
        this.success = success;
        this.entryId = entryId;
        this.detail = detail == null ? null : truncate(detail, MAX_DETAIL);
    }

    private static String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max);
    }

    public Long getId() { return id; }
    public Instant getOccurredAt() { return occurredAt; }
    public String getUsername() { return username; }
    public AuditAction getAction() { return action; }
    public boolean isSuccess() { return success; }
    public UUID getEntryId() { return entryId; }
    public String getDetail() { return detail; }
}
