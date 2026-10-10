package com.jody.credvault.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.HttpCookie;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import com.jody.credvault.model.AuditAction;
import com.jody.credvault.repository.AuditEventRepository;

/**
 * End-to-end security tests. The real application starts on a random port
 * and each test drives it over HTTP like a browser would: cookies, CSRF
 * tokens, redirects and all. Nothing is mocked.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "spring.datasource.url=jdbc:h2:mem:credvault-webtest;DB_CLOSE_DELAY=-1")
class WebSecurityTest {

    private static final String PASSWORD = "correct-horse-battery-staple";
    private static final String SECRET = "Treasury-Admin-Pa55!";
    private static final AtomicInteger COUNTER = new AtomicInteger();
    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\"[^>]*value=\"([^\"]+)\"");
    private static final Pattern ENTRY_ID = Pattern.compile("/vault/([0-9a-f-]{36})");

    @Value("${local.server.port}")
    private int port;

    @Autowired
    private AuditEventRepository auditEvents;

    /** A tiny browser: keeps cookies, does NOT follow redirects so tests can check them. */
    class Browser {
        final CookieManager cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        final HttpClient client = HttpClient.newBuilder()
                .cookieHandler(cookies)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        HttpResponse<String> get(String path) throws Exception {
            return client.send(HttpRequest.newBuilder(url(path)).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
        }

        HttpResponse<String> post(String path, Map<String, String> form) throws Exception {
            String body = form.entrySet().stream()
                    .map(e -> enc(e.getKey()) + "=" + enc(e.getValue()))
                    .collect(Collectors.joining("&"));
            return client.send(HttpRequest.newBuilder(url(path))
                            .header("Content-Type", "application/x-www-form-urlencoded")
                            .POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                    HttpResponse.BodyHandlers.ofString());
        }

        /** Loads a page and posts a form from it, including that page's CSRF token. */
        HttpResponse<String> submit(String pagePath, String actionPath, Map<String, String> form) throws Exception {
            Map<String, String> withToken = new LinkedHashMap<>(form);
            withToken.put("_csrf", csrfToken(get(pagePath).body()));
            return post(actionPath, withToken);
        }

        String sessionId() {
            return cookies.getCookieStore().getCookies().stream()
                    .filter(c -> c.getName().equals("JSESSIONID"))
                    .map(HttpCookie::getValue).findFirst().orElse(null);
        }
    }

    private URI url(String path) {
        return URI.create("http://127.0.0.1:" + port + path);
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static String csrfToken(String html) {
        Matcher m = CSRF.matcher(html);
        assertTrue(m.find(), "page has no CSRF token");
        return m.group(1);
    }

    private static String location(HttpResponse<?> response) {
        return response.headers().firstValue("Location").orElse("");
    }

    private static String newUsername() {
        return "user" + COUNTER.incrementAndGet();
    }

    private Browser registeredAndLoggedIn(String username) throws Exception {
        Browser b = new Browser();
        HttpResponse<String> reg = b.submit("/register", "/register",
                Map.of("username", username, "password", PASSWORD, "confirm", PASSWORD));
        assertEquals(302, reg.statusCode(), "registration should redirect");
        HttpResponse<String> login = login(b, username, PASSWORD);
        assertTrue(location(login).endsWith("/vault"), "login should go to the vault");
        return b;
    }

    private HttpResponse<String> login(Browser b, String username, String password) throws Exception {
        return b.submit("/login", "/login", Map.of("username", username, "password", password));
    }

    private String addEntry(Browser b, String title, String password) throws Exception {
        HttpResponse<String> r = b.submit("/vault/new", "/vault", Map.of(
                "title", title, "url", "https://example.com", "username", "me@example.com",
                "password", password, "notes", ""));
        assertEquals(302, r.statusCode());
        Matcher m = ENTRY_ID.matcher(location(r));
        assertTrue(m.find(), "should redirect to the new entry");
        return m.group(1);
    }

    // ---------------------------------------------------------------------

    @Test
    void vaultRequiresLogin() throws Exception {
        HttpResponse<String> r = new Browser().get("/vault");
        assertEquals(302, r.statusCode());
        assertTrue(location(r).contains("/login"));
    }

    @Test
    void fullFlowRegisterLoginAddRevealLogout() throws Exception {
        Browser b = registeredAndLoggedIn(newUsername());
        String id = addEntry(b, "Treasury Portal", SECRET);

        HttpResponse<String> list = b.get("/vault");
        assertEquals(200, list.statusCode());
        assertTrue(list.body().contains("Treasury Portal"));
        assertFalse(list.body().contains(SECRET), "the list must not include passwords");

        HttpResponse<String> show = b.get("/vault/" + id);
        assertEquals(200, show.statusCode());
        assertTrue(show.body().contains(SECRET));

        HttpResponse<String> logout = b.submit("/vault", "/logout", Map.of());
        assertTrue(location(logout).contains("/login?logout"));
        assertTrue(location(b.get("/vault")).contains("/login"));
    }

    @Test
    void formsWithoutCsrfTokenAreRejected() throws Exception {
        Browser b = registeredAndLoggedIn(newUsername());
        HttpResponse<String> r = b.post("/vault", Map.of("title", "x", "password", "y"));
        assertEquals(403, r.statusCode());
    }

    @Test
    void anotherUserCannotOpenMyEntryByChangingTheUrl() throws Exception {
        Browser alice = registeredAndLoggedIn(newUsername());
        String aliceEntry = addEntry(alice, "Payroll", SECRET);

        String bobName = newUsername();
        Browser bob = registeredAndLoggedIn(bobName);
        HttpResponse<String> r = bob.get("/vault/" + aliceEntry);

        assertEquals(404, r.statusCode());
        assertFalse(r.body().contains(SECRET));
        assertFalse(r.body().contains("Payroll"));
        assertEquals(1, auditEvents.countByUsernameAndAction(bobName, AuditAction.ACCESS_DENIED));

        HttpResponse<String> delete = bob.submit("/vault", "/vault/" + aliceEntry + "/delete", Map.of());
        assertEquals(404, delete.statusCode());
        assertEquals(200, alice.get("/vault/" + aliceEntry).statusCode(), "entry must survive");
    }

    @Test
    void malformedEntryIdIsJustNotFound() throws Exception {
        Browser b = registeredAndLoggedIn(newUsername());
        assertEquals(404, b.get("/vault/not-a-real-id").statusCode());
    }

    @Test
    void accountLocksAfterFiveFailedLogins() throws Exception {
        String user = newUsername();
        Browser b = registeredAndLoggedIn(user);
        b.submit("/vault", "/logout", Map.of());

        // Four failures, then the right password still works (and resets the count)
        for (int i = 0; i < 4; i++) {
            assertTrue(location(login(b, user, "wrong-password-" + i)).contains("/login?error"));
        }
        assertTrue(location(login(b, user, PASSWORD)).endsWith("/vault"));
        b.submit("/vault", "/logout", Map.of());

        // Five failures lock the account: even the right password is refused
        for (int i = 0; i < 5; i++) {
            login(b, user, "wrong-password-" + i);
        }
        assertTrue(location(login(b, user, PASSWORD)).contains("/login?error"));
        assertTrue(b.get("/login?error").body().contains("Too many failed attempts"));
        assertEquals(1, auditEvents.countByUsernameAndAction(user, AuditAction.LOGIN_BLOCKED));
    }

    @Test
    void sessionIdChangesAtLogin() throws Exception {
        Browser b = new Browser();
        String user = newUsername();
        b.submit("/register", "/register", Map.of("username", user, "password", PASSWORD, "confirm", PASSWORD));
        b.get("/login");
        String before = b.sessionId();
        login(b, user, PASSWORD);
        String after = b.sessionId();
        assertNotNull(before);
        assertNotNull(after);
        assertNotEquals(before, after, "a fixed session ID would allow session fixation");
    }

    @Test
    void stolenSessionCookieIsUselessAfterLogout() throws Exception {
        Browser victim = registeredAndLoggedIn(newUsername());
        String stolenSessionId = victim.sessionId();
        victim.submit("/vault", "/logout", Map.of());

        Browser attacker = new Browser();
        HttpCookie cookie = new HttpCookie("JSESSIONID", stolenSessionId);
        cookie.setPath("/");
        cookie.setVersion(0);
        attacker.cookies.getCookieStore().add(url("/"), cookie);

        HttpResponse<String> r = attacker.get("/vault");
        assertEquals(302, r.statusCode());
        assertTrue(location(r).contains("/login"));
    }

    @Test
    void securityHeadersAreSet() throws Exception {
        Browser b = registeredAndLoggedIn(newUsername());
        HttpResponse<String> r = b.get("/vault");
        var h = r.headers();
        assertTrue(h.firstValue("Content-Security-Policy").orElse("").contains("script-src 'self'"));
        assertEquals("DENY", h.firstValue("X-Frame-Options").orElse(""));
        assertEquals("nosniff", h.firstValue("X-Content-Type-Options").orElse(""));
        assertTrue(h.firstValue("Cache-Control").orElse("").contains("no-store"),
                "pages with secrets must not be cached");
        assertEquals("no-referrer", h.firstValue("Referrer-Policy").orElse(""));
    }

    @Test
    void htmlInEntriesIsEscaped() throws Exception {
        Browser b = registeredAndLoggedIn(newUsername());
        addEntry(b, "<script>alert(1)</script>", SECRET);
        String page = b.get("/vault").body();
        assertFalse(page.contains("<script>alert(1)</script>"));
        assertTrue(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    @Test
    void wrongPasswordAndUnknownUserLookIdentical() throws Exception {
        String user = newUsername();
        registeredAndLoggedIn(user);

        Browser b = new Browser();
        login(b, user, "wrong-password-123");
        String wrongPassword = b.get("/login?error").body();
        login(b, "nobody-" + user, "wrong-password-123");
        String unknownUser = b.get("/login?error").body();

        assertTrue(wrongPassword.contains("Invalid username or master password"));
        assertEquals(wrongPassword.replaceAll(CSRF.pattern(), ""), unknownUser.replaceAll(CSRF.pattern(), ""));
    }
}
