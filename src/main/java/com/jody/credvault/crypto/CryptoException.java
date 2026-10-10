package com.jody.credvault.crypto;

/**
 * Thrown when encryption or decryption fails. Messages are deliberately vague:
 * telling an attacker exactly WHY decryption failed (wrong key? tampered data?)
 * can leak information, so callers just learn that it failed.
 */
public class CryptoException extends RuntimeException {

    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
