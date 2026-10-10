package com.jody.credvault.service;

public class UsernameTakenException extends RuntimeException {

    public UsernameTakenException() {
        super("That username is not available");
    }
}
