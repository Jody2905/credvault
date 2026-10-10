package com.jody.credvault.web;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.jody.credvault.service.UsernameTakenException;
import com.jody.credvault.service.VaultService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

/**
 * Login page and registration. The login form itself is processed by
 * Spring Security (POST /login), not by this controller.
 */
@Controller
public class AuthController {

    private final VaultService vault;

    public AuthController(VaultService vault) {
        this.vault = vault;
    }

    @GetMapping("/")
    public String home() {
        return "redirect:/vault";
    }

    @GetMapping("/login")
    public String login(HttpServletRequest request, Model model) {
        if (request.getParameter("error") != null) {
            String message = "Invalid username or master password";
            HttpSession session = request.getSession(false);
            if (session != null
                    && session.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION) instanceof AuthenticationException e) {
                message = e.getMessage();
            }
            model.addAttribute("loginError", message);
        }
        if (request.getParameter("logout") != null) {
            model.addAttribute("message", "You have been logged out and your vault is locked.");
        }
        return "login";
    }

    @GetMapping("/register")
    public String registerForm() {
        return "register";
    }

    @PostMapping("/register")
    public String register(@RequestParam(name = "username", defaultValue = "") String username,
                           @RequestParam(name = "password", defaultValue = "") String password,
                           @RequestParam(name = "confirm", defaultValue = "") String confirm,
                           Model model, RedirectAttributes redirect) {
        model.addAttribute("username", username);
        if (!password.equals(confirm)) {
            model.addAttribute("error", "The two passwords don't match.");
            return "register";
        }
        try {
            vault.register(username, password.toCharArray());
        } catch (IllegalArgumentException | UsernameTakenException e) {
            model.addAttribute("error", e.getMessage());
            return "register";
        }
        redirect.addFlashAttribute("message", "Account created. Log in with your master password.");
        return "redirect:/login";
    }
}
