"""Routing through APISIX: SPA, BFF endpoints and the API behind the BFF."""
import pytest
import requests
from bff_client import CSRF


def test_spa_is_served_with_security_headers(gateway):
    resp = requests.get(f"{gateway}/", timeout=5)

    assert resp.status_code == 200
    assert '<div id="app">' in resp.text
    csp = resp.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "unsafe" not in csp
    assert "frame-ancestors 'none'" in csp
    assert resp.headers["X-Frame-Options"] == "DENY"


def test_spa_routes_fall_back_to_index(gateway):
    resp = requests.get(f"{gateway}/some/client/route", timeout=5)

    assert resp.status_code == 200
    assert '<div id="app">' in resp.text


def test_unknown_bff_endpoint(gateway):
    assert requests.get(f"{gateway}/bff/nope", timeout=5).status_code == 404


def test_session_without_cookie(gateway):
    resp = requests.get(f"{gateway}/bff/session", headers=CSRF, timeout=5)

    assert resp.status_code == 200
    assert resp.json() == {"authenticated": False}


def test_api_without_session(gateway):
    resp = requests.get(f"{gateway}/api/headers", headers=CSRF, timeout=5)

    assert resp.status_code == 401
    assert resp.json() == {"error": "unauthenticated"}


@pytest.mark.parametrize("path", ["/bff/session", "/api/headers"])
def test_requests_without_csrf_header_are_refused(gateway, path):
    assert requests.get(f"{gateway}{path}", timeout=5).status_code == 403


def test_cors_preflight_is_refused(gateway):
    # without a granted preflight, no other origin can send the CSRF header
    resp = requests.options(f"{gateway}/api/headers", timeout=5, headers={
        "Origin": "https://evil.example",
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "x-bff-csrf",
    })

    assert resp.status_code == 403
    assert "Access-Control-Allow-Origin" not in resp.headers


def test_api_call_gets_access_token_instead_of_cookie(logged_in, gateway):
    resp = logged_in.get(f"{gateway}/api/headers", headers=CSRF, timeout=5)

    assert resp.status_code == 200
    # httpbin echoes what it received; the gateway redacts the token on the way back
    headers = resp.json()["headers"]
    assert headers["Authorization"] == ["Bearer [redacted]"]
    assert "Cookie" not in headers
    assert "X-Bff-Csrf" not in headers


def test_api_path_prefix_is_stripped(logged_in, gateway):
    resp = logged_in.get(f"{gateway}/api/anything/items", params={"q": "1"}, headers=CSRF, timeout=5)

    assert resp.status_code == 200
    assert resp.json()["url"].endswith("/anything/items?q=1")


@pytest.mark.parametrize("headers", [
    {"Sec-Fetch-Site": "cross-site"},
    {"Sec-Fetch-Site": "same-site"},
    {"Origin": "https://evil.example"},
])
def test_api_refuses_cross_origin_requests(logged_in, gateway, headers):
    resp = logged_in.get(f"{gateway}/api/headers", headers={**CSRF, **headers}, timeout=5)

    assert resp.status_code == 403


def test_browser_supplied_authorization_is_replaced(logged_in, gateway):
    resp = logged_in.get(f"{gateway}/api/headers", headers={**CSRF, "Authorization": "Bearer forged"}, timeout=5)

    assert resp.json()["headers"]["Authorization"] == ["Bearer [redacted]"]
