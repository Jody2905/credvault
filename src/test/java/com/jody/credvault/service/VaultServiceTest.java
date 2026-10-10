package com.jody.credvault.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

import com.jody.credvault.model.AuditAction;
import com.jody.credvault.model.AuditEvent;
import com.jody.credvault.repository.AppUserRepository;
import com.jody.credvault.repository.AuditEventRepository;
import com.jody.credvault.repository.VaultEntryRepository;

/**
 * Runs the real service against a real (in-memory) database.
 * Tests read the raw tables with plain SQL to prove what's actually stored.
 */
@SpringBootTest
class VaultServiceTest {

    private static final String ALICE_PW = "correct-horse-battery-staple";
    private static final String BOB_PW = "purple-lantern-river-stone";
    private static final String SECRET = "Treasury-Admin-Pa55!";

    @Autowired private VaultService vault;
    @Autowired private AppUserRepository users;
    @Autowired private VaultEntryRepository entries;
    @Autowired private AuditEventRepository auditEvents;
    @Autowired private JdbcTemplate jdbc;

    @BeforeEach
    void cleanDatabase() {
        // Plain SQL: the application itself is never allowed to delete audit records
        jdbc.update("DELETE FROM audit_events");
        jdbc.update("DELETE FROM vault_entries");
        jdbc.update("DELETE FROM app_users");
    }

    private VaultSession alice() {
        return vault.register("alice", ALICE_PW.toCharArray());
    }

    private VaultSession bob() {
        return vault.register("bob", BOB_PW.toCharArray());
    }

    private EntryInput entry(String title, String password) {
        return new EntryInput(title, "https://example.com", "alice@example.com", password, "some notes");
    }

    private long auditCount(String username, AuditAction action) {
        return auditEvents.countByUsernameAndAction(username, action);
    }

    // ---- Accounts -------------------------------------------------------

    @Test
    void registerThenUnlockWithCorrectPassword() {
        alice();
        VaultSession session = vault.unlock("alice", ALICE_PW.toCharArray());
        assertEquals("alice", session.username());
        assertNotNull(session.dataKey());
        assertEquals(1, auditCount("alice", AuditAction.UNLOCK_SUCCESS));
    }

    @Test
    void usernameIsCaseInsensitive() {
        vault.register("  Alice ", ALICE_PW.toCharArray());
        assertEquals("alice", vault.unlock("ALICE", ALICE_PW.toCharArray()).username());
    }

    @Test
    void wrongPasswordIsRejectedAndTheFailureIsAudited() {
        alice();
        assertThrows(InvalidCredentialsException.class,
                () -> vault.unlock("alice", "wrong-password-123".toCharArray()));
        // Recorded even though the unlock threw an exception (REQUIRES_NEW)
        assertEquals(1, auditCount("alice", AuditAction.UNLOCK_FAILED));
    }

    @Test
    void unknownUserGetsExactlyTheSameErrorAsWrongPassword() {
        alice();
        InvalidCredentialsException unknown = assertThrows(InvalidCredentialsException.class,
                () -> vault.unlock("mallory", "anything-at-all-123".toCharArray()));
        InvalidCredentialsException wrong = assertThrows(InvalidCredentialsException.class,
                () -> vault.unlock("alice", "anything-at-all-123".toCharArray()));
        assertEquals(wrong.getMessage(), unknown.getMessage());
    }

    @Test
    void weakMasterPasswordsAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> vault.register("alice", "short".toCharArray()));
        assertThrows(IllegalArgumentException.class,
                () -> vault.register("alice", "my-name-is-ALICE-ok".toCharArray()));
        assertEquals(0, users.count());
    }

    @Test
    void invalidAndDuplicateUsernamesAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> vault.register("a", ALICE_PW.toCharArray()));
        assertThrows(IllegalArgumentException.class,
                () -> vault.register("alice'; DROP TABLE app_users;--", ALICE_PW.toCharArray()));
        alice();
        assertThrows(UsernameTakenException.class, () -> vault.register("ALICE", BOB_PW.toCharArray()));
    }

    @Test
    void noPasswordOrPasswordHashIsStoredForUsers() {
        alice();
        String row = jdbc.queryForList("SELECT * FROM app_users").get(0).toString();
        assertFalse(row.contains(ALICE_PW));
        assertTrue(row.contains("v1:"));   // only the wrapped data key
    }

    // ---- Entries --------------------------------------------------------

    @Test
    void addListAndRevealEntry() {
        VaultSession alice = alice();
        UUID id = vault.addEntry(alice, entry("Treasury Portal", SECRET));

        List<EntrySummary> list = vault.listEntries(alice);
        assertEquals(1, list.size());
        assertEquals("Treasury Portal", list.get(0).title());

        RevealedEntry revealed = vault.reveal(alice, id);
        assertEquals(SECRET, revealed.password());
        assertEquals("alice@example.com", revealed.username());
        assertEquals("some notes", revealed.notes());
        assertEquals(1, auditCount("alice", AuditAction.ENTRY_VIEWED));
    }

    @Test
    void secretsAreNeverStoredInPlainText() {
        VaultSession alice = alice();
        vault.addEntry(alice, entry("Bank", SECRET));

        var row = jdbc.queryForMap("SELECT enc_username, enc_password, enc_notes FROM vault_entries");
        for (Object value : row.values()) {
            String stored = value.toString();
            assertTrue(stored.startsWith("v1:"));
            assertFalse(stored.contains(SECRET));
            assertFalse(stored.contains("alice@example.com"));
            assertFalse(stored.contains("some notes"));
        }
    }

    @Test
    void anotherUserCannotReadUpdateOrDeleteMyEntry() {
        VaultSession alice = alice();
        VaultSession bob = bob();
        UUID aliceEntry = vault.addEntry(alice, entry("Payroll", SECRET));

        assertThrows(EntryNotFoundException.class, () -> vault.reveal(bob, aliceEntry));
        assertThrows(EntryNotFoundException.class,
                () -> vault.updateEntry(bob, aliceEntry, entry("Hacked", "x")));
        assertThrows(EntryNotFoundException.class, () -> vault.deleteEntry(bob, aliceEntry));

        assertEquals(3, auditCount("bob", AuditAction.ACCESS_DENIED));
        assertEquals(SECRET, vault.reveal(alice, aliceEntry).password());   // untouched
        assertTrue(vault.listEntries(bob).isEmpty());
    }

    @Test
    void entryThatDoesNotExistLooksTheSameAsSomeoneElsesEntry() {
        VaultSession alice = alice();
        VaultSession bob = bob();
        UUID aliceEntry = vault.addEntry(alice, entry("Payroll", SECRET));

        String other = assertThrows(EntryNotFoundException.class,
                () -> vault.reveal(bob, aliceEntry)).getMessage();
        String missing = assertThrows(EntryNotFoundException.class,
                () -> vault.reveal(bob, UUID.randomUUID())).getMessage();
        assertEquals(other, missing);
    }

    @Test
    void ciphertextCopiedBetweenEntriesIsDetected() {
        VaultSession alice = alice();
        UUID first = vault.addEntry(alice, entry("First", "password-one"));
        UUID second = vault.addEntry(alice, entry("Second", "password-two"));

        // An attacker with database access copies one encrypted password over another
        String stolen = jdbc.queryForObject(
                "SELECT enc_password FROM vault_entries WHERE id = ?", String.class, first);
        jdbc.update("UPDATE vault_entries SET enc_password = ? WHERE id = ?", stolen, second);

        assertThrows(VaultIntegrityException.class, () -> vault.reveal(alice, second));
        assertEquals(1, auditCount("alice", AuditAction.INTEGRITY_FAILURE));
        assertEquals("password-one", vault.reveal(alice, first).password());
    }

    @Test
    void updateAndDeleteEntry() {
        VaultSession alice = alice();
        UUID id = vault.addEntry(alice, entry("Old title", "old-password"));

        vault.updateEntry(alice, id, entry("New title", "new-password"));
        RevealedEntry updated = vault.reveal(alice, id);
        assertEquals("New title", updated.title());
        assertEquals("new-password", updated.password());

        vault.deleteEntry(alice, id);
        assertTrue(vault.listEntries(alice).isEmpty());
        assertThrows(EntryNotFoundException.class, () -> vault.reveal(alice, id));
    }

    @Test
    void invalidEntriesAreRejected() {
        VaultSession alice = alice();
        assertThrows(IllegalArgumentException.class,
                () -> vault.addEntry(alice, entry("", SECRET)));
        assertThrows(IllegalArgumentException.class,
                () -> vault.addEntry(alice, entry("No password", "")));
        assertThrows(IllegalArgumentException.class,
                () -> vault.addEntry(alice, entry("x".repeat(101), SECRET)));
        assertThrows(IllegalArgumentException.class,
                () -> vault.addEntry(alice, new EntryInput("Evil link", "javascript:alert(1)", "", SECRET, "")));
        assertEquals(0, entries.count());
    }

    // ---- Master password ------------------------------------------------

    @Test
    void changingMasterPasswordKeepsEntriesAndRetiresOldPassword() {
        VaultSession alice = alice();
        UUID id = vault.addEntry(alice, entry("Bank", SECRET));
        String newPassword = "a-brand-new-master-password";

        vault.changeMasterPassword(alice, ALICE_PW.toCharArray(), newPassword.toCharArray());

        assertThrows(InvalidCredentialsException.class,
                () -> vault.unlock("alice", ALICE_PW.toCharArray()));
        VaultSession again = vault.unlock("alice", newPassword.toCharArray());
        assertEquals(SECRET, vault.reveal(again, id).password());
    }

    @Test
    void changingMasterPasswordRequiresTheCurrentOne() {
        VaultSession alice = alice();
        assertThrows(InvalidCredentialsException.class,
                () -> vault.changeMasterPassword(alice, "not-my-password".toCharArray(),
                        "a-brand-new-master-password".toCharArray()));
        assertEquals("alice", vault.unlock("alice", ALICE_PW.toCharArray()).username());
    }

    // ---- Audit trail ----------------------------------------------------

    @Test
    void auditTrailNeverContainsSecrets() {
        VaultSession alice = alice();
        UUID id = vault.addEntry(alice, entry("Bank", SECRET));
        vault.reveal(alice, id);
        assertThrows(InvalidCredentialsException.class,
                () -> vault.unlock("alice", "guessing-the-password".toCharArray()));

        String everything = jdbc.queryForList("SELECT * FROM audit_events").toString();
        assertFalse(everything.contains(SECRET));
        assertFalse(everything.contains(ALICE_PW));
        assertFalse(everything.contains("guessing-the-password"));
    }

    @Test
    void auditTrailShowsAUsersOwnHistoryNewestFirst() {
        VaultSession alice = alice();
        UUID id = vault.addEntry(alice, entry("Bank", SECRET));
        vault.reveal(alice, id);

        List<AuditEvent> trail = vault.auditTrail(alice);
        assertEquals(AuditAction.ENTRY_VIEWED, trail.get(0).getAction());
        assertEquals(AuditAction.ACCOUNT_CREATED, trail.get(trail.size() - 1).getAction());
    }

    @Test
    void sessionNeverPrintsTheKey() {
        assertFalse(alice().toString().contains("SecretKeySpec"));
        assertTrue(entry("x", SECRET).toString().contains("password=***"));
    }
}
