package com.jody.credvault.security;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

import org.junit.jupiter.api.Test;

/** Plain unit tests: a fake clock lets us "wait" 15 minutes instantly. */
class LoginAttemptServiceTest {

    /** A clock the test can move forward. */
    static final class TestClock extends Clock {
        private Instant now = Instant.parse("2026-10-10T12:00:00Z");

        void advance(Duration d) { now = now.plus(d); }
        @Override public Instant instant() { return now; }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
    }

    private final TestClock clock = new TestClock();
    private final LoginAttemptService attempts = new LoginAttemptService(clock);

    private void fail(String user, int times) {
        for (int i = 0; i < times; i++) {
            attempts.loginFailed(user);
        }
    }

    @Test
    void fourFailuresDoNotLock() {
        fail("alice", LoginAttemptService.MAX_FAILURES - 1);
        assertFalse(attempts.isBlocked("alice"));
    }

    @Test
    void fifthFailureLocks() {
        fail("alice", LoginAttemptService.MAX_FAILURES);
        assertTrue(attempts.isBlocked("alice"));
    }

    @Test
    void lockExpiresAfterFifteenMinutes() {
        fail("alice", LoginAttemptService.MAX_FAILURES);
        clock.advance(Duration.ofMinutes(14));
        assertTrue(attempts.isBlocked("alice"));
        clock.advance(Duration.ofMinutes(2));
        assertFalse(attempts.isBlocked("alice"));
    }

    @Test
    void successResetsTheCount() {
        fail("alice", LoginAttemptService.MAX_FAILURES - 1);
        attempts.loginSucceeded("alice");
        fail("alice", LoginAttemptService.MAX_FAILURES - 1);
        assertFalse(attempts.isBlocked("alice"));
    }

    @Test
    void oldFailuresOutsideTheWindowDontCount() {
        fail("alice", LoginAttemptService.MAX_FAILURES - 1);
        clock.advance(Duration.ofMinutes(16));
        fail("alice", 1);
        assertFalse(attempts.isBlocked("alice"));
    }

    @Test
    void usernamesAreMatchedCaseInsensitively() {
        fail("Alice", 2);
        fail(" ALICE ", 3);
        assertTrue(attempts.isBlocked("alice"));
    }

    @Test
    void lockingOneUserDoesNotAffectAnother() {
        fail("alice", LoginAttemptService.MAX_FAILURES);
        assertFalse(attempts.isBlocked("bob"));
    }

    @Test
    void nonExistentUsernamesAreLockedToo() {
        // So locking behaviour can't be used to discover which usernames are real
        fail("no-such-user", LoginAttemptService.MAX_FAILURES);
        assertTrue(attempts.isBlocked("no-such-user"));
    }
}
