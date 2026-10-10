package com.jody.credvault.service;

/** An entry's encrypted data failed its authenticity check: it was altered in the database. */
public class VaultIntegrityException extends RuntimeException {

    public VaultIntegrityException() {
        super("This entry failed an integrity check and may have been tampered with");
    }
}
