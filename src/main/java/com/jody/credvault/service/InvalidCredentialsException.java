package com.jody.credvault.service;

/**
 * One message for both "no such user" and "wrong password", so an attacker
 * can't use the login form to find out which usernames exist.
 */
public class InvalidCredentialsException extends RuntimeException {

    public InvalidCredentialsException() {
        super("Invalid username or master password");
    }
}
