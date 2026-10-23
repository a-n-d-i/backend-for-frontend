"""
Token exchange, zero trust between the services, and single sign-on / single
logout, against the real Keycloak and services.

The services are called directly here, bypassing the gateway: they must not
rely on the network or the gateway, only on the token.
"""
import base64
import json

import pytest
import requests
from bff_client import (APP_URL, CSRF, OIDC, SERVICE_A, SERVICE_B, Browser, claims, exchange, header,
                        keycloak_logout, keycloak_tokens, log_in)


@pytest.fixture
def tokens(oidc):
    """Tokens of the bff client, plus ones exchanged for service A and B."""
    t = keycloak_tokens()
    for name, audience, scope in (("a", "service-a", "api-a"), ("b", "service-b", "api-b")):
        resp = exchange(t["access_token"], audience, scope)
        assert resp.status_code == 200, resp.text
        t[name] = resp.json()["access_token"]
    return t


def whoami(service_url, token, method="GET", path="/whoami"):
    return requests.request(method, f"{service_url}{path}", timeout=10,
                            headers={"Authorization": f"Bearer {token}"} if token else {})


# -- token exchange -------------------------------------------------------------

def test_exchanged_token_is_only_for_one_service(tokens):
    subject = claims(tokens["access_token"])
    a = claims(tokens["a"])

    # the login token is meant for no service at all
    assert "aud" not in subject
    # the exchanged one for exactly one, same user and same Keycloak session
    assert a["aud"] == "service-a"
    assert "api-a" in a["scope"].split() and "api-b" not in a["scope"].split()
    assert (a["sub"], a["sid"], a["azp"]) == (subject["sub"], subject["sid"], "bff")
    # an explicitly typed access token [RFC 9068]
    assert header(tokens["a"])["typ"] == "at+jwt"


def test_exchange_response(oidc):
    t = keycloak_tokens()

    resp = exchange(t["access_token"], "service-a", "api-a")

    body = resp.json()
    assert body["issued_token_type"] == "urn:ietf:params:oauth:token-type:access_token"
    assert body["token_type"].lower() == "bearer"
    assert resp.headers["Cache-Control"].startswith("no-store")


@pytest.mark.parametrize("audience, scope, error", [
    ("service-b", "api-a", "Requested audience not available"),  # scope of A, audience of B
    ("service-c", "api-a", "Audience not found"),                # unknown service
])
def test_exchange_refuses_mismatched_requests(oidc, audience, scope, error):
    t = keycloak_tokens()

    resp = exchange(t["access_token"], audience, scope)

    assert resp.status_code == 400
    assert error in resp.json()["error_description"]


def test_exchange_needs_client_authentication(oidc):
    t = keycloak_tokens()

    resp = exchange(t["access_token"], "service-a", "api-a", client=("bff", "wrong"))

    assert resp.status_code == 401
    assert resp.json()["error"] == "unauthorized_client"


def test_exchange_refuses_a_forged_subject_token(oidc):
    t = keycloak_tokens()
    head, payload, sig = t["access_token"].split(".")
    forged = json.loads(base64.urlsafe_b64decode(payload + "=="))
    forged["sub"] = "someone-else"
    forged_token = f"{head}.{base64.urlsafe_b64encode(json.dumps(forged).encode()).rstrip(b'=').decode()}.{sig}"

    assert exchange(forged_token, "service-a", "api-a").status_code == 400


# -- zero trust: each service accepts only its own tokens -----------------------------

@pytest.mark.parametrize("service, token, status", [
    (SERVICE_A, "a", 200),
    (SERVICE_A, "b", 401),             # B's token at A
    (SERVICE_B, "b", 200),
    (SERVICE_B, "a", 401),             # A's token at B
    (SERVICE_A, "access_token", 401),  # the BFF's login token: no audience
    (SERVICE_B, "access_token", 401),
    (SERVICE_A, "id_token", 401),      # an ID token is no access token
    (SERVICE_A, None, 401),
])
def test_services_accept_only_tokens_meant_for_them(tokens, service, token, status):
    resp = whoami(service, tokens[token] if token else None)

    assert resp.status_code == status
    if status == 401:
        assert resp.headers["WWW-Authenticate"].startswith("Bearer ")
        assert 'error="invalid_token"' in resp.headers["WWW-Authenticate"] or token is None


def test_rejection_says_why(tokens):
    resp = whoami(SERVICE_B, tokens["a"])

    assert resp.json()["error_description"] == "token is not meant for service-b"


def test_scope_is_enforced(tokens):
    resp = whoami(SERVICE_A, tokens["a"], method="POST", path="/items")

    assert resp.status_code == 403
    assert resp.headers["WWW-Authenticate"] == \
        'Bearer realm="service-a", error="insufficient_scope", scope="api-a.write"'


def test_tampered_token_is_rejected(tokens):
    head, payload, sig = tokens["a"].split(".")
    tampered = json.loads(base64.urlsafe_b64decode(payload + "=="))
    tampered["aud"] = "service-b"
    token = f"{head}.{base64.urlsafe_b64encode(json.dumps(tampered).encode()).rstrip(b'=').decode()}.{sig}"

    assert whoami(SERVICE_B, token).status_code == 401


def test_services_check_with_keycloak_that_a_token_is_still_active(tokens):
    # ending the Keycloak session (here: RP-initiated logout) ...
    requests.post(f"{OIDC}/logout", timeout=10, data={"id_token_hint": tokens["id_token"], "client_id": "bff"})

    # ... makes the unexpired tokens worthless at once (token introspection)
    for service, token in ((SERVICE_A, "a"), (SERVICE_B, "b")):
        resp = whoami(service, tokens[token])
        assert resp.status_code == 401
        assert "no longer active" in resp.json()["error_description"]


# -- single sign-on / single logout ---------------------------------------------------

def test_single_sign_on_one_login_for_both_services(logged_in):
    a = logged_in.get(f"{APP_URL}/api/a/whoami", headers=CSRF, timeout=10).json()
    b = logged_in.get(f"{APP_URL}/api/b/whoami", headers=CSRF, timeout=10).json()

    assert (a["service"], b["service"]) == ("service-a", "service-b")
    assert a["sub"] == b["sub"] and a["sid"] == b["sid"]


def test_single_sign_on_another_application_needs_no_password(logged_in):
    # Keycloak's account console, another client of the realm: the SSO session logs it in silently
    resp = logged_in.get(f"{OIDC}/auth", allow_redirects=False, timeout=10, params={
        "client_id": "account-console", "redirect_uri": "https://auth.example.test/realms/demo/account/",
        "response_type": "code", "scope": "openid", "code_challenge": "x" * 43,
        "code_challenge_method": "S256"})

    assert resp.status_code == 302
    assert "code=" in resp.headers["Location"]


def test_single_logout_back_channel(logged_in):
    assert logged_in.get(f"{APP_URL}/api/a/whoami", headers=CSRF, timeout=10).status_code == 200

    # logout elsewhere, at Keycloak (as from the account console): Keycloak
    # POSTs a logout token to the BFF's back-channel logout endpoint
    keycloak_logout(logged_in)

    assert logged_in.get(f"{APP_URL}/bff/session", headers=CSRF, timeout=5).json() == {"authenticated": False}
    assert logged_in.get(f"{APP_URL}/api/a/whoami", headers=CSRF, timeout=10).status_code == 401


def test_single_logout_ends_every_bff_session_of_that_keycloak_session(gateway, oidc):
    # two BFF sessions in the same browser profile share one Keycloak session (SSO)
    first = Browser()
    log_in(first)
    second = Browser()
    # Keycloak's SSO cookies, as two tabs of one browser would share them
    for c in first.cookies:
        if c.domain.startswith("auth."):
            second.cookies.set_cookie(c)
    resp = second.get(f"{APP_URL}/bff/login", allow_redirects=False, timeout=10)
    resp = second.get(resp.headers["Location"], allow_redirects=False, timeout=10)
    assert resp.status_code == 302, "no SSO: Keycloak asked for the password"
    second.get(resp.headers["Location"], allow_redirects=False, timeout=10)
    assert second.get(f"{APP_URL}/bff/session", headers=CSRF, timeout=5).json()["authenticated"] is True

    keycloak_logout(first)

    for b in (first, second):
        assert b.get(f"{APP_URL}/bff/session", headers=CSRF, timeout=5).json() == {"authenticated": False}


@pytest.mark.parametrize("body", [
    {},
    {"logout_token": "not-a-jwt"},
    {"logout_token": "id_token"},  # replaced by a real ID token below
])
def test_back_channel_logout_refuses_invalid_logout_tokens(logged_in, body):
    if body.get("logout_token") == "id_token":
        # a valid, signed ID token of this client: still no logout token (no events claim, has a nonce)
        body = {"logout_token": keycloak_tokens()["id_token"]}

    resp = requests.post(f"{APP_URL}/bff/backchannel-logout", data=body, timeout=10)

    assert resp.status_code == 400
    assert resp.headers["Cache-Control"] == "no-store"
    assert logged_in.get(f"{APP_URL}/bff/session", headers=CSRF, timeout=5).json()["authenticated"] is True
