package com.jody.credvault.web;

import java.util.List;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.jody.credvault.service.InvalidCredentialsException;
import com.jody.credvault.service.VaultService;
import com.jody.credvault.service.VaultSession;

/** Changing the master password, and the user's own activity log. */
@Controller
public class AccountController {

    private final VaultService vault;

    public AccountController(VaultService vault) {
        this.vault = vault;
    }

    public record ActivityRow(String time, String action, boolean success, String detail) {
    }

    @GetMapping("/account")
    public String account() {
        return "account";
    }

    @PostMapping("/account/password")
    public String changePassword(@AuthenticationPrincipal VaultSession session,
                                 @RequestParam(name = "currentPassword", defaultValue = "") String current,
                                 @RequestParam(name = "newPassword", defaultValue = "") String newPassword,
                                 @RequestParam(name = "confirm", defaultValue = "") String confirm,
                                 Model model, RedirectAttributes redirect) {
        if (!newPassword.equals(confirm)) {
            model.addAttribute("error", "The two new passwords don't match.");
            return "account";
        }
        try {
            vault.changeMasterPassword(session, current.toCharArray(), newPassword.toCharArray());
        } catch (InvalidCredentialsException e) {
            model.addAttribute("error", "Your current master password is incorrect.");
            return "account";
        } catch (IllegalArgumentException e) {
            model.addAttribute("error", e.getMessage());
            return "account";
        }
        redirect.addFlashAttribute("message", "Master password changed.");
        return "redirect:/account";
    }

    @GetMapping("/activity")
    public String activity(@AuthenticationPrincipal VaultSession session, Model model) {
        List<ActivityRow> rows = vault.auditTrail(session).stream()
                .map(e -> new ActivityRow(Dates.format(e.getOccurredAt()), e.getAction().name(),
                        e.isSuccess(), e.getDetail() == null ? "" : e.getDetail()))
                .toList();
        model.addAttribute("events", rows);
        return "activity";
    }
}
