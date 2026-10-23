"""The BFF login flow against the real Dex, through APISIX."""
from urllib.parse import parse_qs, urlsplit

from bff_client import COOKIE_NAME, CSRF, USERNAME, start_login, submit_login


def cookie_attributes(header):
    return {part.strip().split("=")[0] for part in header.split(";")[1:]}


def test_login_redirects_to_authorization_server_with_pkce(browser, gateway, oidc):
    resp = browser.get(f"{gateway}/bff/login", allow_redirects=False, timeout=5)

    assert resp.status_code == 302
    location = resp.headers["Location"]
    assert location.startswith(oidc["authorization_endpoint"] + "?")
    params = parse_qs(urlsplit(location).query)
    assert params["response_type"] == ["code"]
    assert params["code_challenge_method"] == ["S256"]
    assert len(params["code_challenge"][0]) == 43
    assert len(params["state"][0]) >= 43
    assert len(params["nonce"][0]) >= 43
    assert "offline_access" in params["scope"][0].split()
    assert resp.headers["Cache-Control"] == "no-store"

    # the pending login is bound to the browser by a Lax cookie (it must survive the redirect back)
    (cookie,) = browser.bff_cookies
    assert cookie.startswith(f"{COOKIE_NAME}=")
    assert cookie_attributes(cookie) == {"Path", "Secure", "HttpOnly", "SameSite"}
    assert "SameSite=Lax" in cookie


def test_login_with_valid_credentials(browser, gateway):
    form = start_login(browser, gateway, return_to="/somewhere?tab=2")
    pending_id = browser.session_id

    resp = submit_login(browser, form)

    # approval screen is skipped: Dex redirects straight back to the BFF
    assert resp.status_code == 303
    callback = resp.headers["Location"]
    assert parse_qs(urlsplit(callback).query)["state"]

    resp = browser.get(callback, allow_redirects=False, timeout=10)

    # back to where the SPA was, with a fresh, Strict session cookie
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/somewhere?tab=2"
    cookie = browser.bff_cookies[-1]
    assert "SameSite=Strict" in cookie and "HttpOnly" in cookie and "Secure" in cookie
    assert browser.session_id != pending_id

    info = browser.get(f"{gateway}/bff/session", headers=CSRF, timeout=5)
    assert info.status_code == 200
    assert info.headers["Cache-Control"] == "no-store"
    body = info.json()
    assert body["authenticated"] is True
    assert body["user"]["email"] == USERNAME
    # the SPA gets claims, never tokens
    assert "token" not in info.text.lower()


def test_login_with_wrong_password(browser, gateway):
    resp = submit_login(browser, start_login(browser, gateway), password="wrong")

    # the form is shown again with an error, no redirect to the BFF
    assert resp.status_code == 401
    assert "Location" not in resp.headers
    assert "Invalid Email Address and password" in resp.text


def test_callback_rejects_wrong_state(browser, gateway):
    resp = submit_login(browser, start_login(browser, gateway))
    callback = resp.headers["Location"].replace("state=", "state=x")

    resp = browser.get(callback, allow_redirects=False, timeout=5)

    assert resp.status_code == 400
    assert resp.json()["reason"] == "state mismatch"
    assert browser.session_id is None
    assert browser.get(f"{gateway}/bff/session", headers=CSRF, timeout=5).json() == {"authenticated": False}


def test_callback_cannot_be_replayed(browser, gateway):
    resp = submit_login(browser, start_login(browser, gateway))
    callback = resp.headers["Location"]
    pending_id = browser.session_id
    assert browser.get(callback, allow_redirects=False, timeout=10).status_code == 302

    # same callback with the same pending cookie again: the login is used up
    browser.cookies.set(COOKIE_NAME, pending_id)
    resp = browser.get(callback, allow_redirects=False, timeout=5)

    assert resp.status_code == 400
    assert resp.json()["reason"] == "no login in progress"


def test_callback_in_another_browser_is_rejected(browser, gateway):
    # login CSRF: the attacker's callback URL opened in the victim's browser
    resp = submit_login(browser, start_login(browser, gateway))
    browser.cookies.clear()

    resp = browser.get(resp.headers["Location"], allow_redirects=False, timeout=5)

    assert resp.status_code == 400


def test_pre_login_session_id_is_not_authenticated(browser, gateway):
    # session fixation: the id known before login never becomes the session
    form = start_login(browser, gateway)
    pending_id = browser.session_id
    resp = submit_login(browser, form)
    browser.get(resp.headers["Location"], allow_redirects=False, timeout=10)

    browser.cookies.set(COOKIE_NAME, pending_id)
    assert browser.get(f"{gateway}/bff/session", headers=CSRF, timeout=5).json() == {"authenticated": False}


def test_return_to_is_not_an_open_redirect(browser, gateway):
    for evil in ("//evil.example", "https://evil.example/", "/\\evil.example", "javascript:alert(1)"):
        resp = submit_login(browser, start_login(browser, gateway, return_to=evil))
        resp = browser.get(resp.headers["Location"], allow_redirects=False, timeout=10)
        assert resp.headers["Location"] == "/", evil


def test_logout(logged_in, gateway):
    resp = logged_in.post(f"{gateway}/bff/logout", headers=CSRF, timeout=5)

    assert resp.status_code == 200
    # Dex supports no RP-initiated logout, so there is nothing to navigate to
    assert resp.json() == {"logout_url": None}
    assert "Max-Age=0" in logged_in.bff_cookies[-1]
    assert logged_in.session_id is None


def test_session_is_gone_after_logout_even_with_the_old_cookie(logged_in, gateway):
    session_id = logged_in.session_id
    logged_in.post(f"{gateway}/bff/logout", headers=CSRF, timeout=5)

    logged_in.cookies.set(COOKIE_NAME, session_id)

    assert logged_in.get(f"{gateway}/bff/session", headers=CSRF, timeout=5).json() == {"authenticated": False}
    assert logged_in.get(f"{gateway}/api/headers", headers=CSRF, timeout=5).status_code == 401


def test_logout_needs_post_and_csrf_header(logged_in, gateway):
    assert logged_in.get(f"{gateway}/bff/logout", headers=CSRF, timeout=5).status_code == 405
    assert logged_in.post(f"{gateway}/bff/logout", timeout=5).status_code == 403
    assert logged_in.get(f"{gateway}/bff/session", headers=CSRF, timeout=5).json()["authenticated"] is True
