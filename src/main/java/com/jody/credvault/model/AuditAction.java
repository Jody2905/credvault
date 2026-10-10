package com.jody.credvault.model;

public enum AuditAction {
    ACCOUNT_CREATED,
    UNLOCK_SUCCESS,
    UNLOCK_FAILED,
    /** Login refused because the account is temporarily locked after repeated failures. */
    LOGIN_BLOCKED,
    LOGOUT,
    ENTRY_CREATED,
    ENTRY_VIEWED,
    ENTRY_UPDATED,
    ENTRY_DELETED,
    MASTER_PASSWORD_CHANGED,
    /** Someone tried to touch an entry that belongs to another user. */
    ACCESS_DENIED,
    /** An entry failed to decrypt: its stored data was altered. */
    INTEGRITY_FAILURE
}
