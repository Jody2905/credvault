package com.jody.credvault.service;

import java.time.Instant;
import java.util.UUID;

/** What the vault list shows. It contains nothing secret, so nothing is decrypted to build it. */
public record EntrySummary(UUID id, String title, String url, Instant updatedAt) {
}
