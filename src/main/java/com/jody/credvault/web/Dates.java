package com.jody.credvault.web;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/** Formats timestamps for display in the server's local time zone. */
final class Dates {

    private static final DateTimeFormatter FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(ZoneId.systemDefault());

    private Dates() {
    }

    static String format(Instant instant) {
        return instant == null ? "" : FORMAT.format(instant);
    }
}
