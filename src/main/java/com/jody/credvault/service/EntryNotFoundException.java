package com.jody.credvault.service;

/**
 * Thrown both when an entry doesn't exist and when it belongs to someone else,
 * so the response never confirms that another user's entry exists.
 */
public class EntryNotFoundException extends RuntimeException {

    public EntryNotFoundException() {
        super("Entry not found");
    }
}
