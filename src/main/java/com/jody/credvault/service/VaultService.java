package com.jody.credvault.service;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.jody.credvault.crypto.CryptoException;
import com.jody.credvault.crypto.CryptoService;
import com.jody.credvault.crypto.EncryptedData;
import com.jody.credvault.model.AppUser;
import com.jody.credvault.model.AuditAction;
import com.jody.credvault.model.AuditEvent;
import com.jody.credvault.model.Role;
import com.jody.credvault.model.VaultEntry;
import com.jody.credvault.repository.AppUserRepository;
import com.jody.credvault.repository.VaultEntryRepository;

/**
 * The vault's business rules. Every security decision about accounts and
 * entries is made here, not in the web layer, so the rules hold no matter
 * how the service is called, and they can be tested directly.
 */
@Service
public class VaultService {

    public static final int MIN_MASTER_PASSWORD = 12;
    public static final int MAX_MASTER_PASSWORD = 128;
    static final int MAX_TITLE = 100;
    static final int MAX_URL = 255;
    static final int MAX_LOGIN_USERNAME = 200;
    static final int MAX_SECRET = 500;
    static final int MAX_NOTES = 2000;

    private static final Pattern USERNAME = Pattern.compile("^[a-z0-9._-]{3,50}$");

    private final AppUserRepository users;
    private final VaultEntryRepository entries;
    private final AuditService audit;
    private final CryptoService crypto;
    private final byte[] dummySalt;

    public VaultService(AppUserRepository users, VaultEntryRepository entries,
                        AuditService audit, CryptoService crypto) {
        this.users = users;
        this.entries = entries;
        this.audit = audit;
        this.crypto = crypto;
        this.dummySalt = crypto.newSalt();
    }

    // ==================================================================
    // Accounts
    // ==================================================================

    @Transactional
    public VaultSession register(String rawUsername, char[] masterPassword) {
        String username = normalize(rawUsername);
        validateUsername(username);
        validateMasterPassword(masterPassword, username);

        if (users.existsByUsername(username)) {
            audit.record(username, AuditAction.ACCOUNT_CREATED, false, null, "username already taken");
            throw new UsernameTakenException();
        }

        UUID id = UUID.randomUUID();
        byte[] salt = crypto.newSalt();
        SecretKey kek = crypto.deriveKey(masterPassword, salt);
        SecretKey dataKey = crypto.newDataKey();
        String wrapped = crypto.wrapKey(kek, dataKey, dataKeyContext(id)).encode();

        users.save(new AppUser(id, username, Role.USER, b64(salt), crypto.iterations(), wrapped));
        audit.record(username, AuditAction.ACCOUNT_CREATED, true, null, null);
        return new VaultSession(id, username, Role.USER, dataKey);
    }

    /**
     * Logs in by proving the master password can unwrap the data key.
     * Wrong password and unknown username give the same error, after the
     * same amount of work, so neither the message nor the response time
     * reveals whether a username exists.
     */
    @Transactional(readOnly = true)
    public VaultSession unlock(String rawUsername, char[] masterPassword) {
        String username = normalize(rawUsername);
        if (masterPassword == null || masterPassword.length == 0) {
            audit.record(username, AuditAction.UNLOCK_FAILED, false, null, "empty password");
            throw new InvalidCredentialsException();
        }

        Optional<AppUser> found = users.findByUsername(username);
        if (found.isEmpty()) {
            crypto.deriveKey(masterPassword, dummySalt);   // equal-time work, result discarded
            audit.record(username, AuditAction.UNLOCK_FAILED, false, null, "unknown username");
            throw new InvalidCredentialsException();
        }

        AppUser user = found.get();
        try {
            SecretKey dataKey = unwrapDataKey(user, masterPassword);
            audit.record(username, AuditAction.UNLOCK_SUCCESS, true, null, null);
            return new VaultSession(user.getId(), username, user.getRole(), dataKey);
        } catch (CryptoException e) {
            audit.record(username, AuditAction.UNLOCK_FAILED, false, null, "wrong master password");
            throw new InvalidCredentialsException();
        }
    }

    /**
     * Re-wraps the same data key under a new password. Entries don't need
     * re-encrypting: that's the point of envelope encryption.
     */
    @Transactional
    public void changeMasterPassword(VaultSession session, char[] currentPassword, char[] newPassword) {
        AppUser user = users.findById(session.userId()).orElseThrow(InvalidCredentialsException::new);

        SecretKey dataKey;
        try {
            dataKey = unwrapDataKey(user, currentPassword);
        } catch (CryptoException e) {
            audit.record(user.getUsername(), AuditAction.MASTER_PASSWORD_CHANGED, false, null,
                    "current password incorrect");
            throw new InvalidCredentialsException();
        }
        validateMasterPassword(newPassword, user.getUsername());

        byte[] newSalt = crypto.newSalt();
        SecretKey newKek = crypto.deriveKey(newPassword, newSalt);
        String rewrapped = crypto.wrapKey(newKek, dataKey, dataKeyContext(user.getId())).encode();
        user.replaceKeyMaterial(b64(newSalt), crypto.iterations(), rewrapped);

        audit.record(user.getUsername(), AuditAction.MASTER_PASSWORD_CHANGED, true, null, null);
    }

    // ==================================================================
    // Entries
    // ==================================================================

    @Transactional
    public UUID addEntry(VaultSession session, EntryInput input) {
        validate(input);
        UUID id = UUID.randomUUID();
        AppUser owner = users.getReferenceById(session.userId());
        VaultEntry entry = new VaultEntry(id, owner);
        applyInput(session, entry, input);
        entries.save(entry);
        audit.record(session.username(), AuditAction.ENTRY_CREATED, true, id, null);
        return id;
    }

    @Transactional(readOnly = true)
    public List<EntrySummary> listEntries(VaultSession session) {
        return entries.findByOwner_IdOrderByTitleAsc(session.userId()).stream()
                .map(e -> new EntrySummary(e.getId(), e.getTitle(), e.getUrl(), e.getUpdatedAt()))
                .toList();
    }

    @Transactional(readOnly = true)
    public RevealedEntry reveal(VaultSession session, UUID entryId) {
        VaultEntry e = findOwned(session, entryId, AuditAction.ENTRY_VIEWED);
        try {
            RevealedEntry revealed = new RevealedEntry(
                    e.getId(), e.getTitle(), e.getUrl(),
                    decryptField(session, e, "username", e.getEncryptedUsername()),
                    decryptField(session, e, "password", e.getEncryptedPassword()),
                    decryptField(session, e, "notes", e.getEncryptedNotes()),
                    e.getUpdatedAt());
            audit.record(session.username(), AuditAction.ENTRY_VIEWED, true, entryId, null);
            return revealed;
        } catch (CryptoException ex) {
            audit.record(session.username(), AuditAction.INTEGRITY_FAILURE, false, entryId,
                    "stored data failed authentication");
            throw new VaultIntegrityException();
        }
    }

    @Transactional
    public void updateEntry(VaultSession session, UUID entryId, EntryInput input) {
        VaultEntry e = findOwned(session, entryId, AuditAction.ENTRY_UPDATED);
        validate(input);
        applyInput(session, e, input);   // a managed entity: JPA saves the change on commit
        audit.record(session.username(), AuditAction.ENTRY_UPDATED, true, entryId, null);
    }

    @Transactional
    public void deleteEntry(VaultSession session, UUID entryId) {
        VaultEntry e = findOwned(session, entryId, AuditAction.ENTRY_DELETED);
        entries.delete(e);
        audit.record(session.username(), AuditAction.ENTRY_DELETED, true, entryId, null);
    }

    @Transactional(readOnly = true)
    public List<AuditEvent> auditTrail(VaultSession session) {
        return audit.historyFor(session.username());
    }

    // ==================================================================
    // Helpers
    // ==================================================================

    /**
     * Loads an entry only if this user owns it. If the entry exists but
     * belongs to someone else, that's recorded as ACCESS_DENIED, a strong
     * signal that someone is probing, but the caller gets the same
     * "not found" as for an entry that doesn't exist.
     */
    private VaultEntry findOwned(VaultSession session, UUID entryId, AuditAction attempted) {
        if (entryId == null) {
            throw new EntryNotFoundException();
        }
        Optional<VaultEntry> owned = entries.findByIdAndOwner_Id(entryId, session.userId());
        if (owned.isPresent()) {
            return owned.get();
        }
        if (entries.existsById(entryId)) {
            audit.record(session.username(), AuditAction.ACCESS_DENIED, false, entryId,
                    "attempted " + attempted + " on another user's entry");
        } else {
            audit.record(session.username(), attempted, false, entryId, "entry not found");
        }
        throw new EntryNotFoundException();
    }

    private SecretKey unwrapDataKey(AppUser user, char[] password) {
        SecretKey kek = crypto.deriveKey(password, b64d(user.getKdfSalt()), user.getKdfIterations());
        return crypto.unwrapKey(kek, EncryptedData.decode(user.getWrappedDataKey()),
                dataKeyContext(user.getId()));
    }

    private void applyInput(VaultSession session, VaultEntry entry, EntryInput in) {
        entry.update(
                in.title().strip(),
                blankToNull(in.url()),
                encryptField(session, entry, "username", nullToEmpty(in.username())),
                encryptField(session, entry, "password", in.password()),
                encryptField(session, entry, "notes", nullToEmpty(in.notes())));
    }

    private String encryptField(VaultSession s, VaultEntry e, String field, String value) {
        return crypto.encrypt(s.dataKey(), value.getBytes(UTF_8), fieldContext(e.getId(), s.userId(), field))
                .encode();
    }

    private String decryptField(VaultSession s, VaultEntry e, String field, String stored) {
        byte[] plain = crypto.decrypt(s.dataKey(), EncryptedData.decode(stored),
                fieldContext(e.getId(), s.userId(), field));
        return new String(plain, UTF_8);
    }

    /** Binds the wrapped data key to its owner. */
    private static byte[] dataKeyContext(UUID userId) {
        return ("credvault|user:" + userId + "|datakey").getBytes(UTF_8);
    }

    /** Binds each encrypted field to its entry, its owner and its field name. */
    private static byte[] fieldContext(UUID entryId, UUID ownerId, String field) {
        return ("credvault|entry:" + entryId + "|owner:" + ownerId + "|field:" + field).getBytes(UTF_8);
    }

    // ---- Validation --------------------------------------------------

    private static String normalize(String username) {
        return username == null ? "" : username.strip().toLowerCase(Locale.ROOT);
    }

    private static void validateUsername(String username) {
        if (!USERNAME.matcher(username).matches()) {
            throw new IllegalArgumentException(
                    "Username must be 3-50 characters: letters, numbers, dots, dashes or underscores");
        }
    }

    private static void validateMasterPassword(char[] password, String username) {
        if (password == null || password.length < MIN_MASTER_PASSWORD) {
            throw new IllegalArgumentException(
                    "Master password must be at least " + MIN_MASTER_PASSWORD + " characters");
        }
        if (password.length > MAX_MASTER_PASSWORD) {
            throw new IllegalArgumentException(
                    "Master password must be at most " + MAX_MASTER_PASSWORD + " characters");
        }
        if (containsIgnoreCase(password, username)) {
            throw new IllegalArgumentException("Master password must not contain your username");
        }
    }

    private static void validate(EntryInput in) {
        if (in == null) {
            throw new IllegalArgumentException("Entry details are required");
        }
        requireLength("Title", in.title(), 1, MAX_TITLE);
        requireLength("Password", in.password(), 1, MAX_SECRET);
        requireLength("URL", nullToEmpty(in.url()), 0, MAX_URL);
        requireLength("Username", nullToEmpty(in.username()), 0, MAX_LOGIN_USERNAME);
        requireLength("Notes", nullToEmpty(in.notes()), 0, MAX_NOTES);
        String url = nullToEmpty(in.url()).strip().toLowerCase(Locale.ROOT);
        if (!url.isEmpty() && !(url.startsWith("https://") || url.startsWith("http://"))) {
            // Blocks links like javascript:... from ever being stored
            throw new IllegalArgumentException("URL must start with http:// or https://");
        }
    }

    private static void requireLength(String name, String value, int min, int max) {
        int length = value == null ? 0 : value.strip().length();
        if (length < min) {
            throw new IllegalArgumentException(name + " is required");
        }
        if (value != null && value.length() > max) {
            throw new IllegalArgumentException(name + " must be at most " + max + " characters");
        }
    }

    /** Checks the password without turning it into a String, which couldn't be wiped. */
    private static boolean containsIgnoreCase(char[] haystack, String needle) {
        if (needle.isEmpty() || needle.length() > haystack.length) {
            return false;
        }
        for (int i = 0; i <= haystack.length - needle.length(); i++) {
            int j = 0;
            while (j < needle.length()
                    && Character.toLowerCase(haystack[i + j]) == Character.toLowerCase(needle.charAt(j))) {
                j++;
            }
            if (j == needle.length()) {
                return true;
            }
        }
        return false;
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    private static String blankToNull(String s) {
        return s == null || s.isBlank() ? null : s.strip();
    }

    private static String b64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static byte[] b64d(String s) {
        return Base64.getDecoder().decode(s);
    }
}
