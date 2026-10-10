package com.jody.credvault.service;

import java.time.Instant;
import java.util.UUID;

/** A fully decrypted entry, created only when its owner asks to see it. */
public record RevealedEntry(UUID id, String title, String url, String username,
                            String password, String notes, Instant updatedAt) {

    @Override
    public String toString() {
        return "RevealedEntry[id=" + id + ", title=" + title + ", username=***, password=***, notes=***]";
    }
}
