package com.jody.credvault.service;

/** What a user types in when adding or editing an entry. */
public record EntryInput(String title, String url, String username, String password, String notes) {

    @Override
    public String toString() {
        return "EntryInput[title=" + title + ", url=" + url + ", username=***, password=***, notes=***]";
    }
}
