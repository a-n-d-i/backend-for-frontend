"""
The Vue SPA in a real browser (headless Chromium via Playwright), over https
with the dev CA trusted: login through the BFF and Keycloak, calls to both
services, logout, and single sign-on / single logout with Keycloak's account
console as the other application.
"""
import re

import pytest
from playwright.sync_api import Page, expect

from tests.traffic import recorder as traffic

from spa_settings import APP_URL, EMAIL, ISSUER, PASSWORD, USERNAME

ACCOUNT_CONSOLE = f"{ISSUER}/account/"


@pytest.fixture
def app(page: Page):
    page.goto(APP_URL + "/")
    expect(page.get_by_test_id("status")).to_have_text("You are not logged in.")
    return page


def log_in(page: Page):
    page.get_by_test_id("login").click()
    # Keycloak's login form
    page.locator("#username").fill(USERNAME)
    page.locator("#password").fill(PASSWORD)
    page.locator("#kc-login").click()
    expect(page.get_by_test_id("user")).to_have_text(EMAIL)


def test_login_call_services_logout(app: Page):
    log_in(app)
    assert app.url == APP_URL + "/"

    for service in ("a", "b"):
        app.get_by_test_id(f"call-api-{service}").click()
        result = app.get_by_test_id("api-result")
        expect(result).to_contain_text(f'"service": "service-{service}"')
        expect(result).to_contain_text(f'"aud": "service-{service}"')
        expect(result).not_to_contain_text('"cookie"')

    # logout here also ends the Keycloak session (RP-initiated logout) and comes back
    app.get_by_test_id("logout").click()
    expect(app.get_by_test_id("status")).to_have_text("You are not logged in.")
    assert app.url == APP_URL + "/"
    # no SSO session left: logging in asks for the password again
    app.get_by_test_id("login").click()
    expect(app.locator("#password")).to_be_visible()


def test_login_returns_to_the_page_it_started_on(page: Page):
    page.goto(APP_URL + "/some/page?x=1")
    log_in(page)

    assert page.url == APP_URL + "/some/page?x=1"


def test_session_survives_reload(app: Page):
    log_in(app)
    app.reload()

    expect(app.get_by_test_id("user")).to_have_text(EMAIL)


def test_tokens_and_session_are_out_of_javascripts_reach(app: Page):
    log_in(app)

    # HttpOnly: the session cookie is invisible to scripts (and so to XSS)
    assert app.evaluate("document.cookie") == ""
    cookie, = [c for c in app.context.cookies() if c["name"] == "__Host-Http-bff-session"]
    assert cookie["httpOnly"] and cookie["secure"] and cookie["sameSite"] == "Strict"
    # nothing token-like in web storage
    assert app.evaluate("Object.keys(localStorage).length + Object.keys(sessionStorage).length") == 0


def test_single_sign_on_and_single_logout_with_another_application(app: Page):
    log_in(app)

    # single sign-on: Keycloak's account console opens without a password
    console = app.context.new_page()
    console.goto(ACCOUNT_CONSOLE)
    expect(console.locator("#password")).to_have_count(0)
    expect(console.get_by_text("Alice Example").first).to_be_visible(timeout=15000)

    # single logout: signing out at Keycloak ends the SPA's session too
    console.goto(f"{ISSUER}/protocol/openid-connect/logout")
    console.locator("#kc-logout").click()
    traffic.note("Logout at Keycloak (from another application): Keycloak POSTs a logout token to "
                 "https://app.example.test/bff/backchannel-logout, the BFF ends the matching session.",
                 ["OIDC BCL 2.5"], lane="keycloak")

    app.reload()
    expect(app.get_by_test_id("status")).to_have_text("You are not logged in.")


def test_other_origin_cannot_use_the_session(app: Page):
    log_in(app)
    # A page on another origin of the same site (auth.example.test, a sibling
    # subdomain: SameSite does not help here) tries to call the API with the
    # user's cookie.
    app.goto(f"{ISSUER}/.well-known/openid-configuration")
    status = app.evaluate("""async (url) => {
        try {
            const r = await fetch(url, {credentials: "include", headers: {"X-BFF-CSRF": "1"}});
            return r.status;
        } catch (e) {
            return "blocked";
        }
    }""", APP_URL + "/api/a/whoami")

    # the preflight for the custom header is refused, so the request never happens
    assert status == "blocked"
    traffic.note("fetch(app.example.test/api/a/whoami, X-BFF-CSRF) from a page on auth.example.test: "
                 "Chromium needs a CORS preflight for the custom header, the BFF refuses it, so the request "
                 "is never sent (not even visible to Playwright).", ["BBA 6.1.3.3.2", "OWASP CSRF"])


def test_spa_runs_under_strict_csp(page: Page):
    violations = []
    page.on("console", lambda msg: violations.append(msg.text) if "Content Security Policy" in msg.text else None)

    headers = page.goto(APP_URL + "/").headers

    expect(page.get_by_test_id("login")).to_be_visible()
    assert not violations
    assert re.search(r"script-src 'self'", headers["content-security-policy"])
    assert headers["strict-transport-security"].startswith("max-age=")
