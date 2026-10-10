package com.jody.credvault.security;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import org.springframework.stereotype.Component;

/**
 * Brute-force protection: after 5 failed logins for a username within
 * 15 minutes, that username is locked for 15 minutes.
 *
 * Failures are counted for ANY username, including ones that don't exist.
 * Otherwise an attacker could tell real accounts apart, because only real
 * ones would ever get locked.
 *
 * Kept in memory: simple, and it resets if the app restarts. A system with
 * several servers would keep this in a shared store such as Redis instead.
 */
@Component
public class LoginAttemptService {

    static final int MAX_FAILURES = 5;
    static final Duration WINDOW = Duration.ofMinutes(15);
    static final Duration LOCK_DURATION = Duration.ofMinutes(15);
    private static final int MAX_TRACKED = 10_000;

    private final Clock clock;
    private final Map<String, Attempts> attempts = new HashMap<>();

    private static final class Attempts {
        final Instant firstFailure;
        int failures;
        Instant lockedUntil;

        Attempts(Instant firstFailure) {
            this.firstFailure = firstFailure;
        }
    }

    public LoginAttemptService() {
        this(Clock.systemUTC());
    }

    /** Tests pass in a clock they control, so they don't have to wait 15 minutes. */
    LoginAttemptService(Clock clock) {
        this.clock = clock;
    }

    public synchronized boolean isBlocked(String username) {
        Attempts a = attempts.get(key(username));
        return a != null && a.lockedUntil != null && clock.instant().isBefore(a.lockedUntil);
    }

    public synchronized void loginFailed(String username) {
        Instant now = clock.instant();
        if (attempts.size() >= MAX_TRACKED) {
            removeExpired(now);
        }
        Attempts a = attempts.get(key(username));
        if (a == null || isExpired(a, now)) {
            a = new Attempts(now);
            attempts.put(key(username), a);
        }
        a.failures++;
        if (a.failures >= MAX_FAILURES) {
            a.lockedUntil = now.plus(LOCK_DURATION);
        }
    }

    public synchronized void loginSucceeded(String username) {
        attempts.remove(key(username));
    }

    private static boolean isExpired(Attempts a, Instant now) {
        if (a.lockedUntil != null) {
            return !now.isBefore(a.lockedUntil);
        }
        return now.isAfter(a.firstFailure.plus(WINDOW));
    }

    /** Stops an attacker filling memory by trying millions of random usernames. */
    private void removeExpired(Instant now) {
        attempts.values().removeIf(a -> isExpired(a, now));
    }

    private static String key(String username) {
        return username == null ? "" : username.strip().toLowerCase(Locale.ROOT);
    }
}
