package com.jody.credvault.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

class CryptoServiceTest {

    // Few iterations so tests are fast; real use has 600,000
    private final CryptoService crypto = new CryptoService(1_000);

    private static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void encryptThenDecryptReturnsOriginal() {
        SecretKey key = crypto.newDataKey();
        EncryptedData enc = crypto.encrypt(key, bytes("hunter2"), bytes("user:1|entry:7"));
        assertArrayEquals(bytes("hunter2"), crypto.decrypt(key, enc, bytes("user:1|entry:7")));
    }

    @Test
    void ciphertextDoesNotContainPlaintext() {
        SecretKey key = crypto.newDataKey();
        EncryptedData enc = crypto.encrypt(key, bytes("SuperSecretPassword"), null);
        String asText = new String(enc.ciphertext(), StandardCharsets.ISO_8859_1);
        assertFalse(asText.contains("SuperSecretPassword"));
    }

    @Test
    void sameInputEncryptsDifferentlyEachTime() {
        // A fresh random IV every time, so two identical passwords look unrelated in the database
        SecretKey key = crypto.newDataKey();
        EncryptedData a = crypto.encrypt(key, bytes("same"), null);
        EncryptedData b = crypto.encrypt(key, bytes("same"), null);
        assertFalse(Arrays.equals(a.iv(), b.iv()));
        assertFalse(Arrays.equals(a.ciphertext(), b.ciphertext()));
    }

    @Test
    void wrongKeyFails() {
        EncryptedData enc = crypto.encrypt(crypto.newDataKey(), bytes("secret"), null);
        assertThrows(CryptoException.class, () -> crypto.decrypt(crypto.newDataKey(), enc, null));
    }

    @Test
    void tamperedCiphertextIsDetected() {
        SecretKey key = crypto.newDataKey();
        EncryptedData enc = crypto.encrypt(key, bytes("transfer $100"), null);
        byte[] tampered = enc.ciphertext().clone();
        tampered[0] ^= 1;   // flip a single bit
        EncryptedData bad = new EncryptedData(enc.iv(), tampered);
        assertThrows(CryptoException.class, () -> crypto.decrypt(key, bad, null));
    }

    @Test
    void ciphertextMovedToAnotherRowFails() {
        // Simulates an attacker copying user 1's encrypted password into user 2's row
        SecretKey key = crypto.newDataKey();
        EncryptedData enc = crypto.encrypt(key, bytes("secret"), bytes("user:1|entry:7"));
        assertThrows(CryptoException.class,
                () -> crypto.decrypt(key, enc, bytes("user:2|entry:9")));
    }

    @Test
    void samePasswordAndSaltGiveSameKey() {
        byte[] salt = crypto.newSalt();
        SecretKey a = crypto.deriveKey("correct horse".toCharArray(), salt);
        SecretKey b = crypto.deriveKey("correct horse".toCharArray(), salt);
        assertArrayEquals(a.getEncoded(), b.getEncoded());
        assertEquals(32, a.getEncoded().length);   // 256-bit key
    }

    @Test
    void differentSaltGivesDifferentKey() {
        SecretKey a = crypto.deriveKey("correct horse".toCharArray(), crypto.newSalt());
        SecretKey b = crypto.deriveKey("correct horse".toCharArray(), crypto.newSalt());
        assertFalse(Arrays.equals(a.getEncoded(), b.getEncoded()));
    }

    @Test
    void callerIsResponsibleForWipingThePasswordArray() {
        char[] password = "correct horse".toCharArray();
        crypto.deriveKey(password, crypto.newSalt());
        // PBEKeySpec copies the password; our own array is untouched by design,
        // so the caller is responsible for wiping it. This test documents that.
        assertEquals('c', password[0]);
        Arrays.fill(password, '\0');
        assertEquals('\0', password[0]);
    }

    @Test
    void emptyPasswordIsRejected() {
        assertThrows(CryptoException.class, () -> crypto.deriveKey(new char[0], crypto.newSalt()));
    }

    @Test
    void fullEnvelopeFlowWorksAndWrongMasterPasswordFails() {
        byte[] salt = crypto.newSalt();
        byte[] context = bytes("user:1|datakey");

        // Account creation
        SecretKey kek = crypto.deriveKey("my master password".toCharArray(), salt);
        SecretKey dataKey = crypto.newDataKey();
        EncryptedData wrapped = crypto.wrapKey(kek, dataKey, context);
        EncryptedData entry = crypto.encrypt(dataKey, bytes("bank-pin-4821"), bytes("user:1|entry:1"));

        // Later login with the right password
        SecretKey kekAgain = crypto.deriveKey("my master password".toCharArray(), salt);
        SecretKey unwrapped = crypto.unwrapKey(kekAgain, wrapped, context);
        assertArrayEquals(bytes("bank-pin-4821"), crypto.decrypt(unwrapped, entry, bytes("user:1|entry:1")));

        // Login with the wrong password
        SecretKey wrongKek = crypto.deriveKey("wrong password".toCharArray(), salt);
        assertThrows(CryptoException.class, () -> crypto.unwrapKey(wrongKek, wrapped, context));
    }

    @Test
    void changingMasterPasswordKeepsEntriesReadable() {
        byte[] context = bytes("user:1|datakey");
        SecretKey dataKey = crypto.newDataKey();
        EncryptedData entry = crypto.encrypt(dataKey, bytes("secret"), null);

        byte[] newSalt = crypto.newSalt();
        SecretKey newKek = crypto.deriveKey("new password".toCharArray(), newSalt);
        EncryptedData rewrapped = crypto.wrapKey(newKek, dataKey, context);

        SecretKey recovered = crypto.unwrapKey(
                crypto.deriveKey("new password".toCharArray(), newSalt), rewrapped, context);
        assertArrayEquals(bytes("secret"), crypto.decrypt(recovered, entry, null));
    }

    @Test
    void encodeDecodeRoundTrip() {
        EncryptedData enc = crypto.encrypt(crypto.newDataKey(), bytes("x"), null);
        String stored = enc.encode();
        EncryptedData back = EncryptedData.decode(stored);
        assertArrayEquals(enc.iv(), back.iv());
        assertArrayEquals(enc.ciphertext(), back.ciphertext());
        assertEquals("v1", stored.split(":")[0]);
    }

    @Test
    void malformedStoredValuesAreRejected() {
        assertThrows(CryptoException.class, () -> EncryptedData.decode("garbage"));
        assertThrows(CryptoException.class, () -> EncryptedData.decode("v2:AAAA:BBBB"));
        assertThrows(CryptoException.class, () -> EncryptedData.decode("v1:!!!:###"));
        assertThrows(CryptoException.class, () -> EncryptedData.decode(null));
    }

    @Test
    void decryptWithBadIvLengthFailsCleanly() {
        SecretKey key = crypto.newDataKey();
        EncryptedData enc = crypto.encrypt(key, bytes("x"), null);
        EncryptedData bad = new EncryptedData(new byte[5], enc.ciphertext());
        assertThrows(CryptoException.class, () -> crypto.decrypt(key, bad, null));
    }

    @Test
    void differentDataKeysAreDifferent() {
        assertNotEquals(
                Arrays.toString(crypto.newDataKey().getEncoded()),
                Arrays.toString(crypto.newDataKey().getEncoded()));
    }
}
