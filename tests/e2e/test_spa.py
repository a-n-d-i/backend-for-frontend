"""
The Vue SPA in a real browser (headless Chromium via Playwright): login
through the BFF and Dex, API call, logout.

Runs against http://localhost:9080, the origin of the BFF's redirect URI;
Chromium treats localhost as secure, so the Secure session cookie works
without TLS.
"""
import re

import pytest
from playwright.sync_api import Page, expect

from tests.traffic import recorder as traffic

from spa_settings import APP_URL


@pytest.fixture
def app(page: Page):
    page.goto(APP_URL + "/")
    expect(page.get_by_test_id("status")).to_have_text("You are not logged in.")
    return page


def log_in(page: Page):
    page.get_by_test_id("login").click()
    # Dex's login form
    page.locator("input[name=login]").fill("admin@example.com")
    page.locator("input[name=password]").fill("password")
    page.locator("button[type=submit]").click()
    expect(page.get_by_test_id("user")).to_have_text("admin@example.com")


def test_login_call_api_logout(app: Page):
    log_in(app)
    assert app.url == APP_URL + "/"

    app.get_by_test_id("call-api").click()
    result = app.get_by_test_id("api-result")
    expect(result).to_contain_text('"Bearer [redacted]"')
    expect(result).not_to_contain_text("Cookie")

    app.get_by_test_id("logout").click()
    expect(app.get_by_test_id("status")).to_have_text("You are not logged in.")
    app.reload()
    expect(app.get_by_test_id("status")).to_have_text("You are not logged in.")


def test_login_returns_to_the_page_it_started_on(page: Page):
    page.goto(APP_URL + "/some/page?x=1")
    log_in(page)

    assert page.url == APP_URL + "/some/page?x=1"


def test_session_survives_reload(app: Page):
    log_in(app)
    app.reload()

    expect(app.get_by_test_id("user")).to_have_text("admin@example.com")


def test_tokens_and_session_are_out_of_javascripts_reach(app: Page):
    log_in(app)

    # HttpOnly: the session cookie is invisible to scripts (and so to XSS)
    assert app.evaluate("document.cookie") == ""
    cookie, = [c for c in app.context.cookies() if c["name"] == "__Host-Http-bff-session"]
    assert cookie["httpOnly"] and cookie["secure"] and cookie["sameSite"] == "Strict"
    # nothing token-like in web storage
    assert app.evaluate("Object.keys(localStorage).length + Object.keys(sessionStorage).length") == 0


def test_cross_origin_page_cannot_use_the_session(app: Page):
    log_in(app)
    # A page on another origin (Chromium sees 127.0.0.1 and localhost as
    # different sites) tries to call the API with the user's cookie.
    app.goto(APP_URL.replace("localhost", "127.0.0.1") + "/")
    status = app.evaluate("""async (url) => {
        try {
            const r = await fetch(url, {credentials: "include", headers: {"X-BFF-CSRF": "1"}});
            return r.status;
        } catch (e) {
            return "blocked";
        }
    }""", APP_URL + "/api/headers")

    # the preflight for the custom header is refused, so the request never happens
    assert status == "blocked"
    traffic.note("fetch(localhost:9080/api/headers, X-BFF-CSRF) from the 127.0.0.1 page: Chromium needs a CORS "
                 "preflight for the custom header, the BFF refuses it, so the request is never sent "
                 "(not even visible to Playwright).", ["BBA 6.1.3.3.2", "OWASP CSRF"])


def test_spa_runs_under_strict_csp(page: Page):
    violations = []
    page.on("console", lambda msg: violations.append(msg.text) if "Content Security Policy" in msg.text else None)

    page.goto(APP_URL + "/")

    expect(page.get_by_test_id("login")).to_be_visible()
    assert not violations
    assert re.search(r"script-src 'self'", page.request.get(APP_URL + "/").headers["content-security-policy"])
