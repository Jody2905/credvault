package com.jody.credvault.web;

import com.jody.credvault.service.EntryInput;
import com.jody.credvault.service.RevealedEntry;

/** Holds what's typed into the add/edit form. */
public class EntryForm {

    private String title = "";
    private String url = "";
    private String username = "";
    private String password = "";
    private String notes = "";

    public static EntryForm from(RevealedEntry e) {
        EntryForm f = new EntryForm();
        f.title = e.title();
        f.url = e.url() == null ? "" : e.url();
        f.username = e.username();
        f.password = e.password();
        f.notes = e.notes();
        return f;
    }

    public EntryInput toInput() {
        return new EntryInput(title, url, username, password, notes);
    }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    public String getNotes() { return notes; }
    public void setNotes(String notes) { this.notes = notes; }

    @Override
    public String toString() {
        return "EntryForm[title=" + title + ", password=***]";
    }
}
