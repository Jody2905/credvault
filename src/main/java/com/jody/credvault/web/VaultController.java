package com.jody.credvault.web;

import java.util.List;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.jody.credvault.service.EntryNotFoundException;
import com.jody.credvault.service.RevealedEntry;
import com.jody.credvault.service.VaultIntegrityException;
import com.jody.credvault.service.VaultService;
import com.jody.credvault.service.VaultSession;

/**
 * The vault pages. Every method takes the logged-in VaultSession and passes
 * it to VaultService, which does the ownership checks. This controller only
 * handles web concerns.
 */
@Controller
@RequestMapping("/vault")
public class VaultController {

    private final VaultService vault;

    public VaultController(VaultService vault) {
        this.vault = vault;
    }

    public record Row(UUID id, String title, String url, String updated) {
    }

    @GetMapping
    public String list(@AuthenticationPrincipal VaultSession session, Model model) {
        List<Row> rows = vault.listEntries(session).stream()
                .map(e -> new Row(e.id(), e.title(), e.url(), Dates.format(e.updatedAt())))
                .toList();
        model.addAttribute("entries", rows);
        return "vault/list";
    }

    @GetMapping("/new")
    public String newForm(Model model) {
        model.addAttribute("form", new EntryForm());
        return "vault/form";
    }

    @PostMapping
    public String create(@AuthenticationPrincipal VaultSession session,
                         @ModelAttribute("form") EntryForm form,
                         Model model, RedirectAttributes redirect) {
        try {
            UUID id = vault.addEntry(session, form.toInput());
            redirect.addFlashAttribute("message", "Entry saved.");
            return "redirect:/vault/" + id;
        } catch (IllegalArgumentException e) {
            model.addAttribute("error", e.getMessage());
            return "vault/form";
        }
    }

    @GetMapping("/{id}")
    public String show(@AuthenticationPrincipal VaultSession session,
                       @PathVariable("id") UUID id, Model model) {
        RevealedEntry entry = vault.reveal(session, id);
        model.addAttribute("entry", entry);
        model.addAttribute("updated", Dates.format(entry.updatedAt()));
        return "vault/show";
    }

    @GetMapping("/{id}/edit")
    public String editForm(@AuthenticationPrincipal VaultSession session,
                           @PathVariable("id") UUID id, Model model) {
        model.addAttribute("form", EntryForm.from(vault.reveal(session, id)));
        model.addAttribute("entryId", id);
        return "vault/form";
    }

    @PostMapping("/{id}")
    public String update(@AuthenticationPrincipal VaultSession session,
                         @PathVariable("id") UUID id,
                         @ModelAttribute("form") EntryForm form,
                         Model model, RedirectAttributes redirect) {
        try {
            vault.updateEntry(session, id, form.toInput());
            redirect.addFlashAttribute("message", "Entry updated.");
            return "redirect:/vault/" + id;
        } catch (IllegalArgumentException e) {
            model.addAttribute("error", e.getMessage());
            model.addAttribute("entryId", id);
            return "vault/form";
        }
    }

    @PostMapping("/{id}/delete")
    public String delete(@AuthenticationPrincipal VaultSession session,
                         @PathVariable("id") UUID id, RedirectAttributes redirect) {
        vault.deleteEntry(session, id);
        redirect.addFlashAttribute("message", "Entry deleted.");
        return "redirect:/vault";
    }

    // ---- Errors ---------------------------------------------------------

    /** Missing entry, someone else's entry, or a malformed ID: all look the same. */
    @ExceptionHandler({EntryNotFoundException.class, MethodArgumentTypeMismatchException.class})
    public ModelAndView notFound() {
        return message(HttpStatus.NOT_FOUND, "Not found", "That entry doesn't exist.");
    }

    @ExceptionHandler(VaultIntegrityException.class)
    public ModelAndView integrityFailure(VaultIntegrityException e) {
        return message(HttpStatus.CONFLICT, "Integrity check failed", e.getMessage()
                + " The event has been recorded in your activity log.");
    }

    private static ModelAndView message(HttpStatus status, String title, String text) {
        ModelAndView mav = new ModelAndView("message");
        mav.setStatus(status);
        mav.addObject("title", title);
        mav.addObject("text", text);
        return mav;
    }
}
