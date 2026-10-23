"""Routing through APISIX: TLS, SPA, BFF endpoints and the APIs behind the BFF."""
import pytest
import requests
from bff_client import APP_URL, CSRF


def test_plain_http_redirects_to_https(gateway):
    resp = requests.get(APP_URL.replace("https://", "http://") + "/some/page?x=1", allow_redirects=False, timeout=5)

    assert resp.status_code == 301
    assert resp.headers["Location"] == f"{APP_URL}/some/page?x=1"


def test_spa_is_served_with_security_headers(gateway):
    resp = requests.get(f"{APP_URL}/", timeout=5)

    assert resp.status_code == 200
    assert '<div id="app">' in resp.text
    csp = resp.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "unsafe" not in csp
    assert "frame-ancestors 'none'" in csp
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Strict-Transport-Security"].startswith("max-age=")


def test_spa_routes_fall_back_to_index(gateway):
    resp = requests.get(f"{APP_URL}/some/client/route", timeout=5)

    assert resp.status_code == 200
    assert '<div id="app">' in resp.text


def test_unknown_bff_endpoint(gateway):
    assert requests.get(f"{APP_URL}/bff/nope", timeout=5).status_code == 404


def test_session_without_cookie(gateway):
    resp = requests.get(f"{APP_URL}/bff/session", headers=CSRF, timeout=5)

    assert resp.status_code == 200
    assert resp.json() == {"authenticated": False}


@pytest.mark.parametrize("path", ["/api/a/whoami", "/api/b/whoami"])
def test_api_without_session(gateway, path):
    resp = requests.get(f"{APP_URL}{path}", headers=CSRF, timeout=5)

    assert resp.status_code == 401
    assert resp.json() == {"error": "unauthenticated"}


def test_api_outside_the_allowlist(logged_in):
    resp = logged_in.get(f"{APP_URL}/api/c/whoami", headers=CSRF, timeout=5)

    assert resp.status_code == 404


@pytest.mark.parametrize("path", ["/bff/session", "/api/a/whoami"])
def test_requests_without_csrf_header_are_refused(gateway, path):
    assert requests.get(f"{APP_URL}{path}", timeout=5).status_code == 403


def test_cors_preflight_is_refused(gateway):
    # without a granted preflight, no other origin can send the CSRF header
    resp = requests.options(f"{APP_URL}/api/a/whoami", timeout=5, headers={
        "Origin": "https://evil.example",
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "x-bff-csrf",
    })

    assert resp.status_code == 403
    assert "Access-Control-Allow-Origin" not in resp.headers


@pytest.mark.parametrize("api, service", [("a", "service-a"), ("b", "service-b")])
def test_api_call_gets_a_token_for_that_service_instead_of_the_cookie(logged_in, api, service):
    resp = logged_in.get(f"{APP_URL}/api/{api}/whoami", headers=CSRF, timeout=10)

    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == service
    assert body["aud"] == service
    # what reached the service: a bearer token, neither the session cookie nor the CSRF header
    assert "authorization" in body["received_headers"]
    assert "cookie" not in body["received_headers"]
    assert "x-bff-csrf" not in body["received_headers"]


def test_api_path_prefix_is_stripped(logged_in):
    # /api/a/whoami reaches service A as /whoami; /api/a/items as /items
    resp = logged_in.post(f"{APP_URL}/api/a/items", headers=CSRF, timeout=10)

    # the BFF's token for A has scope api-a, not api-a.write
    assert resp.status_code == 403
    assert 'error="insufficient_scope"' in resp.headers["WWW-Authenticate"]


@pytest.mark.parametrize("headers", [
    {"Sec-Fetch-Site": "cross-site"},
    {"Sec-Fetch-Site": "same-site"},
    {"Origin": "https://evil.example"},
])
def test_api_refuses_cross_origin_requests(logged_in, headers):
    resp = logged_in.get(f"{APP_URL}/api/a/whoami", headers={**CSRF, **headers}, timeout=5)

    assert resp.status_code == 403


def test_browser_supplied_authorization_is_replaced(logged_in):
    # a forged token from the browser never reaches the service
    resp = logged_in.get(f"{APP_URL}/api/a/whoami", headers={**CSRF, "Authorization": "Bearer forged"}, timeout=10)

    assert resp.status_code == 200
    assert resp.json()["service"] == "service-a"
