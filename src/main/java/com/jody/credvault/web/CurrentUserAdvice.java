package com.jody.credvault.web;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

import com.jody.credvault.service.VaultSession;

/** Makes the logged-in username available to every page, for the top bar. */
@ControllerAdvice
public class CurrentUserAdvice {

    @ModelAttribute("currentUser")
    public String currentUser(@AuthenticationPrincipal VaultSession session) {
        return session == null ? null : session.username();
    }
}
