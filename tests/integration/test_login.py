"""The BFF login flow against the real Keycloak, through APISIX."""
from urllib.parse import parse_qs, urlsplit

from bff_client import (APP_URL, COOKIE_NAME, CSRF, USERNAME, keycloak_logout, log_in, start_login,
                        submit_login)


def cookie_attributes(header):
    return {part.strip().split("=")[0] for part in header.split(";")[1:]}


def test_login_redirects_to_authorization_server_with_pkce(browser, oidc):
    resp = browser.get(f"{APP_URL}/bff/login", allow_redirects=False, timeout=5)

    assert resp.status_code == 302
    location = resp.headers["Location"]
    assert location.startswith(oidc["authorization_endpoint"] + "?")
    params = parse_qs(urlsplit(location).query)
    assert params["response_type"] == ["code"]
    assert params["redirect_uri"] == [f"{APP_URL}/bff/callback"]
    assert params["code_challenge_method"] == ["S256"]
    assert len(params["code_challenge"][0]) == 43
    assert len(params["state"][0]) >= 43
    assert len(params["nonce"][0]) >= 43
    # no offline_access: offline tokens would outlive a single logout
    assert params["scope"][0].split() == ["openid", "profile", "email"]
    assert resp.headers["Cache-Control"] == "no-store"

    # the pending login is bound to the browser by a Lax cookie (it must survive the redirect back)
    (cookie,) = browser.bff_cookies
    assert cookie.startswith(f"{COOKIE_NAME}=")
    assert cookie_attributes(cookie) == {"Path", "Secure", "HttpOnly", "SameSite"}
    assert "SameSite=Lax" in cookie


def test_login_with_valid_credentials(browser, oidc):
    form = start_login(browser, return_to="/somewhere?tab=2")
    pending_id = browser.session_id

    resp = submit_login(browser, form)

    # Keycloak redirects back to the BFF with code, state and its issuer [RFC 9207]
    assert resp.status_code == 302
    callback = resp.headers["Location"]
    params = parse_qs(urlsplit(callback).query)
    assert {"code", "state", "iss"} <= params.keys()
    assert params["iss"] == [oidc["issuer"]]

    resp = browser.get(callback, allow_redirects=False, timeout=10)

    # back to where the SPA was, with a fresh, Strict session cookie
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/somewhere?tab=2"
    cookie = browser.bff_cookies[-1]
    assert "SameSite=Strict" in cookie and "HttpOnly" in cookie and "Secure" in cookie
    assert browser.session_id != pending_id

    info = browser.get(f"{APP_URL}/bff/session", headers=CSRF, timeout=5)
    assert info.status_code == 200
    assert info.headers["Cache-Control"] == "no-store"
    body = info.json()
    assert body["authenticated"] is True
    assert body["user"]["preferred_username"] == USERNAME
    # the SPA gets claims, never tokens
    assert "token" not in info.text.lower()


def test_login_with_wrong_password(browser):
    resp = submit_login(browser, start_login(browser), password="wrong")

    # the form is shown again with an error, no redirect to the BFF
    assert resp.status_code == 200
    assert "Location" not in resp.headers
    assert "Invalid username or password" in resp.text


def test_callback_rejects_wrong_state(browser):
    resp = submit_login(browser, start_login(browser))
    callback = resp.headers["Location"].replace("state=", "state=x")

    resp = browser.get(callback, allow_redirects=False, timeout=5)

    assert resp.status_code == 400
    assert resp.json()["reason"] == "state mismatch"
    assert browser.session_id is None
    assert browser.get(f"{APP_URL}/bff/session", headers=CSRF, timeout=5).json() == {"authenticated": False}


def test_callback_rejects_foreign_issuer(browser):
    # mix-up: the response claims to come from another authorization server [RFC 9207]
    resp = submit_login(browser, start_login(browser))
    callback = resp.headers["Location"].replace("iss=", "iss=https%3A%2F%2Fevil.example.test%2F")

    resp = browser.get(callback, allow_redirects=False, timeout=5)

    assert resp.status_code == 400
    assert resp.json()["reason"] == "issuer mismatch"


def test_callback_cannot_be_replayed(browser):
    resp = submit_login(browser, start_login(browser))
    callback = resp.headers["Location"]
    pending_id = browser.session_id
    assert browser.get(callback, allow_redirects=False, timeout=10).status_code == 302

    # same callback with the same pending cookie again: the login is used up
    browser.set_session_id(pending_id)
    resp = browser.get(callback, allow_redirects=False, timeout=5)

    assert resp.status_code == 400
    assert resp.json()["reason"] == "no login in progress"


def test_callback_in_another_browser_is_rejected(browser):
    # login CSRF: the attacker's callback URL opened in the victim's browser
    resp = submit_login(browser, start_login(browser))
    browser.cookies.clear()

    resp = browser.get(resp.headers["Location"], allow_redirects=False, timeout=5)

    assert resp.status_code == 400


def test_pre_login_session_id_is_not_authenticated(browser):
    # session fixation: the id known before login never becomes the session
    form = start_login(browser)
    pending_id = browser.session_id
    resp = submit_login(browser, form)
    browser.get(resp.headers["Location"], allow_redirects=False, timeout=10)

    browser.set_session_id(pending_id)
    assert browser.get(f"{APP_URL}/bff/session", headers=CSRF, timeout=5).json() == {"authenticated": False}


def test_return_to_is_not_an_open_redirect(browser):
    for evil in ("//evil.example", "https://evil.example/", "/\\evil.example", "javascript:alert(1)"):
        resp = log_in(browser, return_to=evil)
        assert resp.headers["Location"] == "/", evil
        # a fresh Keycloak login for the next round
        keycloak_logout(browser)


def test_logout_returns_the_rp_initiated_logout_url(logged_in, oidc):
    resp = logged_in.post(f"{APP_URL}/bff/logout", headers=CSRF, timeout=5)

    assert resp.status_code == 200
    logout_url = resp.json()["logout_url"]
    assert logout_url.startswith(oidc["end_session_endpoint"] + "?")
    params = parse_qs(urlsplit(logout_url).query)
    assert params["post_logout_redirect_uri"] == [f"{APP_URL}/"]
    assert params["client_id"] == ["bff"]
    assert "id_token_hint" in params
    assert "Max-Age=0" in logged_in.bff_cookies[-1]
    assert logged_in.session_id is None


def test_rp_initiated_logout_ends_the_keycloak_session(logged_in):
    logout_url = logged_in.post(f"{APP_URL}/bff/logout", headers=CSRF, timeout=5).json()["logout_url"]

    # the SPA navigates there; Keycloak logs out without asking and returns to the app
    resp = logged_in.get(logout_url, allow_redirects=False, timeout=10)

    assert resp.status_code == 302
    assert resp.headers["Location"] == f"{APP_URL}/"
    # no single sign-on any more: the next login asks for the password again
    start_login(logged_in)


def test_session_is_gone_after_logout_even_with_the_old_cookie(logged_in):
    session_id = logged_in.session_id
    logged_in.post(f"{APP_URL}/bff/logout", headers=CSRF, timeout=5)

    logged_in.set_session_id(session_id)

    assert logged_in.get(f"{APP_URL}/bff/session", headers=CSRF, timeout=5).json() == {"authenticated": False}
    assert logged_in.get(f"{APP_URL}/api/a/whoami", headers=CSRF, timeout=5).status_code == 401


def test_logout_needs_post_and_csrf_header(logged_in):
    assert logged_in.get(f"{APP_URL}/bff/logout", headers=CSRF, timeout=5).status_code == 405
    assert logged_in.post(f"{APP_URL}/bff/logout", timeout=5).status_code == 403
    assert logged_in.get(f"{APP_URL}/bff/session", headers=CSRF, timeout=5).json()["authenticated"] is True
