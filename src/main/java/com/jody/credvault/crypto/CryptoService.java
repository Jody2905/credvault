package com.jody.credvault.crypto;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * All of the vault's cryptography lives in this one class, so it can be
 * reviewed and tested in isolation. It uses only the Java standard library.
 *
 * DESIGN: envelope encryption
 *
 *   master password --PBKDF2--> key-encryption key (KEK)
 *                                     | unwraps
 *                                     v
 *                               data key (random AES-256)
 *                                     | encrypts
 *                                     v
 *                               each vault entry's secret
 *
 * - The master password is never stored, and neither is the KEK.
 * - Each user has one random data key, stored only in wrapped (encrypted) form.
 * - Changing the master password only re-wraps the data key; the entries
 *   themselves don't need re-encrypting.
 *
 * ALGORITHMS
 * - PBKDF2-HMAC-SHA256, 600,000 iterations (OWASP's current recommendation),
 *   to turn a human password into a 256-bit key. The high iteration count
 *   makes each password guess slow for an attacker.
 * - AES-256-GCM for encryption. GCM is "authenticated encryption": it detects
 *   any tampering with the ciphertext, not just hides it.
 * Both are NIST-approved and built into Java, so no third-party crypto library.
 */
public class CryptoService {

    public static final int PBKDF2_ITERATIONS = 600_000;
    private static final int KEY_BITS = 256;
    private static final int SALT_BYTES = 16;
    private static final int IV_BYTES = 12;       // the standard nonce size for GCM
    private static final int TAG_BITS = 128;      // GCM authentication tag size

    private static final String KDF = "PBKDF2WithHmacSHA256";
    private static final String CIPHER = "AES/GCM/NoPadding";

    private final SecureRandom random = new SecureRandom();
    private final int iterations;

    public CryptoService() {
        this(PBKDF2_ITERATIONS);
    }

    /** Lets tests use fewer iterations so they run quickly. Never lower it in real use. */
    public CryptoService(int iterations) {
        if (iterations < 1) {
            throw new IllegalArgumentException("iterations must be positive");
        }
        this.iterations = iterations;
    }

    /** The iteration count used for new accounts. */
    public int iterations() {
        return iterations;
    }

    // ------------------------------------------------------------------
    // Keys
    // ------------------------------------------------------------------

    /** A fresh random salt. Every user gets their own, so identical passwords give different keys. */
    public byte[] newSalt() {
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        return salt;
    }

    /** A brand-new random AES-256 data key. */
    public SecretKey newDataKey() {
        try {
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(KEY_BITS, random);
            return generator.generateKey();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Could not generate a key", e);
        }
    }

    /**
     * Turns the master password into the key-encryption key.
     * The password is a char[] rather than a String so it can be wiped from
     * memory afterwards; Java Strings can't be erased once created.
     */
    public SecretKey deriveKey(char[] password, byte[] salt) {
        return deriveKey(password, salt, iterations);
    }

    /**
     * Same, with an explicit iteration count. Each user's count is stored with
     * their account, so raising the default later doesn't lock out older accounts.
     */
    public SecretKey deriveKey(char[] password, byte[] salt, int iterations) {
        if (password == null || password.length == 0) {
            throw new CryptoException("Password is required");
        }
        if (iterations < 1) {
            throw new CryptoException("Invalid iteration count");
        }
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);
        try {
            byte[] keyBytes = SecretKeyFactory.getInstance(KDF).generateSecret(spec).getEncoded();
            try {
                return new SecretKeySpec(keyBytes, "AES");
            } finally {
                Arrays.fill(keyBytes, (byte) 0);
            }
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Key derivation failed", e);
        } finally {
            spec.clearPassword();
        }
    }

    /** Encrypts the data key with the KEK so it can be stored safely. */
    public EncryptedData wrapKey(SecretKey kek, SecretKey dataKey, byte[] context) {
        return encrypt(kek, dataKey.getEncoded(), context);
    }

    /** Decrypts a stored data key. Fails if the master password (so the KEK) is wrong. */
    public SecretKey unwrapKey(SecretKey kek, EncryptedData wrapped, byte[] context) {
        byte[] keyBytes = decrypt(kek, wrapped, context);
        try {
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }

    // ------------------------------------------------------------------
    // Encryption
    // ------------------------------------------------------------------

    /**
     * Encrypts plaintext with AES-256-GCM.
     *
     * @param context "additional authenticated data": not secret, not encrypted,
     *                but bound to the ciphertext. We pass the owner's and entry's
     *                IDs, so an attacker with database access can't swap one
     *                user's encrypted password into another user's row; it
     *                would fail to decrypt.
     */
    public EncryptedData encrypt(SecretKey key, byte[] plaintext, byte[] context) {
        // A NEW random IV every time. Reusing an IV with the same key breaks GCM completely.
        byte[] iv = new byte[IV_BYTES];
        random.nextBytes(iv);
        try {
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            if (context != null) {
                cipher.updateAAD(context);
            }
            return new EncryptedData(iv, cipher.doFinal(plaintext));
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Encryption failed", e);
        }
    }

    /** Decrypts and verifies. Throws if the key is wrong or the data or context was altered. */
    public byte[] decrypt(SecretKey key, EncryptedData data, byte[] context) {
        if (data.iv() == null || data.iv().length != IV_BYTES) {
            throw new CryptoException("Decryption failed");
        }
        try {
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, data.iv()));
            if (context != null) {
                cipher.updateAAD(context);
            }
            return cipher.doFinal(data.ciphertext());
        } catch (AEADBadTagException e) {
            // Wrong key, tampered ciphertext or wrong context: GCM can't tell which, and neither do we
            throw new CryptoException("Decryption failed");
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Decryption failed", e);
        }
    }
}
