package com.jody.credvault.crypto;

import java.util.Base64;

/**
 * The result of an encryption: the random IV (nonce) plus the ciphertext.
 * The ciphertext also contains GCM's 16-byte authentication tag at the end.
 *
 * Stored in the database as one text value: "v1:<iv base64>:<ciphertext base64>".
 * The "v1" prefix is a format version. If the algorithm ever has to change,
 * old values can still be recognised and re-encrypted ("crypto agility").
 */
public record EncryptedData(byte[] iv, byte[] ciphertext) {

    private static final String VERSION = "v1";

    public String encode() {
        Base64.Encoder b64 = Base64.getEncoder();
        return VERSION + ":" + b64.encodeToString(iv) + ":" + b64.encodeToString(ciphertext);
    }

    public static EncryptedData decode(String encoded) {
        if (encoded == null) {
            throw new CryptoException("No encrypted value");
        }
        String[] parts = encoded.split(":");
        if (parts.length != 3 || !VERSION.equals(parts[0])) {
            throw new CryptoException("Unrecognised encrypted value format");
        }
        try {
            Base64.Decoder b64 = Base64.getDecoder();
            return new EncryptedData(b64.decode(parts[1]), b64.decode(parts[2]));
        } catch (IllegalArgumentException e) {
            throw new CryptoException("Encrypted value is not valid Base64", e);
        }
    }
}
