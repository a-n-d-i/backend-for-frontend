import base64
import hashlib
import json
import logging
import socket
import time
from urllib.parse import parse_qs, urlsplit

import pytest
from apisix.runner.http.request import Request
from apisix.runner.http.response import Response
from apisix.runner.plugin.core import PLUGINS, PluginProcess
from apisix.runner.server.logger import Logger
from apisix.runner.server.server import RPCRequest

from apisix.plugins import tokenhandler, trace
from apisix.plugins.oidc import IdTokenError, OidcError
from apisix.plugins.sessions import Session, SessionStore
from apisix.plugins.tokenhandler import TokenHandler, _local_path

CONF = {
    "issuer": "https://idp.example",
    "client_id": "bff",
    "client_secret": "secret",
    "redirect_uri": "https://app.example/bff/callback",
    "apis": {"/api/a/": {"audience": "service-a", "scope": "api-a"},
             "/api/b/": {"audience": "service-b", "scope": "api-b"}},
}
COOKIE = "__Host-Http-bff-session"
CSRF = {"x-bff-csrf": "1"}
CLAIMS = {"iss": "https://idp.example", "sub": "user-1", "email": "a@example.com", "groups": ["admins"]}


class FakeProvider:
    """Stands in for oidc.Provider; records what the BFF asked for."""

    issuer = CONF["issuer"]

    def __init__(self):
        self.metadata = {}
        self.authorization_requests = []
        self.token_response = {"access_token": "at-1", "token_type": "Bearer", "expires_in": 600,
                               "refresh_token": "rt-1", "id_token": "id-1"}
        self.token_error = None
        self.id_token_error = None
        self.validated = []
        self.refreshed = []
        self.revoked = []
        self.exchanges = []
        self.exchange_error = None
        self.logout_claims = {"iss": CONF["issuer"], "sid": "idp-sid-1", "sub": "user-1"}
        self.logout_error = None

    def authorization_url(self, redirect_uri, scope, state, nonce, code_challenge):
        self.authorization_requests.append(dict(redirect_uri=redirect_uri, scope=scope, state=state,
                                                nonce=nonce, code_challenge=code_challenge))
        return f"https://idp.example/auth?state={state}"

    def exchange_code(self, code, redirect_uri, code_verifier):
        if self.token_error:
            raise self.token_error
        self.exchanged = dict(code=code, redirect_uri=redirect_uri, code_verifier=code_verifier)
        return dict(self.token_response)

    def refresh(self, refresh_token):
        self.refreshed.append(refresh_token)
        if self.token_error:
            raise self.token_error
        return dict(self.token_response)

    def validate_id_token(self, id_token, nonce, expected_sub=None):
        self.validated.append(dict(id_token=id_token, nonce=nonce, expected_sub=expected_sub))
        if self.id_token_error:
            raise self.id_token_error
        return dict(CLAIMS, nonce=nonce)

    def exchange_token(self, subject_token, audience, scope):
        self.exchanges.append(dict(subject_token=subject_token, audience=audience, scope=scope))
        if self.exchange_error:
            raise self.exchange_error
        return {"access_token": f"{audience}-token-{len(self.exchanges)}", "token_type": "Bearer",
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token", "expires_in": 300}

    def validate_logout_token(self, logout_token):
        self.logout_token = logout_token
        if self.logout_error:
            raise self.logout_error
        return dict(self.logout_claims)

    def revoke(self, token, token_type_hint="refresh_token"):
        self.revoked.append(token)
        return True

    def end_session_url(self, id_token_hint, post_logout_redirect_uri):
        return None


@pytest.fixture(autouse=True)
def provider(monkeypatch):
    fake = FakeProvider()
    monkeypatch.setattr(tokenhandler, "get_provider", lambda *args, **kwargs: fake)
    return fake


@pytest.fixture(autouse=True)
def store(monkeypatch):
    fresh = SessionStore()
    monkeypatch.setattr(tokenhandler, "store", fresh)
    return fresh


def call(method, uri, headers=None, args=None, conf=None, body=None):
    """Runs the plugin on a request; returns (request, response)."""
    # an RPC request without payload yields an empty Request to fill in
    with socket.socket() as sock:
        request = Request(RPCRequest(sock, Logger(logging.INFO)))
    request.set_method(method)
    request.set_uri(uri)
    request.set_headers({"host": "app.example", **(headers or {})})
    request.set_args(args or {})
    if body is not None:
        request.set_body(body)
    response = Response()
    plugin = TokenHandler()
    plugin.filter(plugin.config(json.dumps({**CONF, **(conf or {})})), request, response)
    return request, response


def body(response):
    return json.loads(response.get_body())


def cookie_of(response):
    """Session id from the response's Set-Cookie."""
    header = response.get_header("Set-Cookie")
    return header.split(";")[0].split("=", 1)[1]


def with_cookie(session_id, headers=None):
    return {"cookie": f"other=1; {COOKIE}={session_id}", **(headers or {})}


def logged_in(store, **fields):
    session = Session(expires_at=time.time() + 3600, idle_timeout=600,
                      user={"sub": "user-1", "email": "a@example.com"}, id_token="id-1",
                      access_token="at-1", access_token_expires_at=time.time() + 600, refresh_token="rt-1")
    for name, value in fields.items():
        setattr(session, name, value)
    return store.create(session), session


def start_login(provider, return_to=None):
    _, response = call("GET", "/bff/login", args={"return_to": return_to} if return_to else {})
    return cookie_of(response), provider.authorization_requests[-1]["state"]


# -- plugin -------------------------------------------------------------------

def test_registered_under_its_name():
    PluginProcess.register()
    assert PLUGINS["tokenhandler"] is TokenHandler


def test_config_applies_defaults():
    conf = TokenHandler().config(json.dumps(CONF))

    assert conf["client_id"] == "bff"
    assert conf["cookie_name"] == COOKIE
    # no offline_access: offline tokens outlive the SSO session (and a single logout)
    assert conf["scope"] == "openid profile email"
    assert conf["apis"] == CONF["apis"]


@pytest.mark.parametrize("missing", ["issuer", "client_id", "client_secret", "redirect_uri"])
def test_config_requires_client_settings(missing):
    with pytest.raises(ValueError, match=missing):
        TokenHandler().config(json.dumps({k: v for k, v in CONF.items() if k != missing}))


def test_unexpected_error_becomes_500(provider):
    provider.authorization_url = None

    _, response = call("GET", "/bff/login")

    assert response.get_status_code() == 500
    assert body(response) == {"error": "internal_error"}


def test_unreachable_authorization_server_becomes_502(provider):
    def fail(*args):
        raise OidcError("connection refused")
    provider.authorization_url = fail

    _, response = call("GET", "/bff/login")

    assert response.get_status_code() == 502


def test_unknown_bff_path():
    _, response = call("GET", "/bff/other")

    assert response.get_status_code() == 404


# -- login ----------------------------------------------------------------------

def test_login_redirects_with_pkce(provider, store):
    _, response = call("GET", "/bff/login", args={"return_to": "/page?x=1"})

    assert response.get_status_code() == 302
    assert response.get_header("Location").startswith("https://idp.example/auth?")
    request = provider.authorization_requests[0]
    assert request["redirect_uri"] == CONF["redirect_uri"]
    session = store.get(cookie_of(response))
    assert session.pending and not session.authenticated
    assert session.state == request["state"] and session.nonce == request["nonce"]
    assert session.return_to == "/page?x=1"
    # S256: the challenge is the hash of the verifier that stays in the session
    digest = hashlib.sha256(session.code_verifier.encode()).digest()
    assert request["code_challenge"] == base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    assert len(session.code_verifier) >= 43


def test_login_cookie_attributes():
    _, response = call("GET", "/bff/login")

    attributes = response.get_header("Set-Cookie").split("; ")[1:]
    assert attributes == ["Path=/", "Secure", "HttpOnly", "SameSite=Lax"]


def test_each_login_gets_fresh_secrets(provider):
    call("GET", "/bff/login")
    call("GET", "/bff/login")

    first, second = provider.authorization_requests
    for key in ("state", "nonce", "code_challenge"):
        assert first[key] != second[key]


def test_login_drops_the_previous_session(store):
    old_id, _ = logged_in(store)

    call("GET", "/bff/login", headers=with_cookie(old_id))

    assert store.get(old_id) is None


def test_login_needs_get():
    _, response = call("POST", "/bff/login")

    assert response.get_status_code() == 405


@pytest.mark.parametrize("value, expected", [
    (None, "/"),
    ("", "/"),
    ("/", "/"),
    ("/a/b?c=d#e", "/a/b?c=d#e"),
    ("//evil.example", "/"),
    ("/\\evil.example", "/"),
    ("https://evil.example/", "/"),
    ("javascript:alert(1)", "/"),
    ("/a\r\nSet-Cookie: x=1", "/"),
    ("/a b", "/"),
    ("/" + "a" * 3000, "/"),
])
def test_return_to_must_be_a_local_path(value, expected):
    assert _local_path(value) == expected


# -- callback ---------------------------------------------------------------------

def test_callback_creates_session(provider, store):
    pending_id, state = start_login(provider, return_to="/page")
    pending = store.get(pending_id)

    _, response = call("GET", "/bff/callback", headers=with_cookie(pending_id),
                       args={"code": "the-code", "state": state})

    assert response.get_status_code() == 302
    assert response.get_header("Location") == "/page"
    assert provider.exchanged == {"code": "the-code", "redirect_uri": CONF["redirect_uri"],
                                  "code_verifier": pending.code_verifier}
    assert provider.validated == [{"id_token": "id-1", "nonce": pending.nonce, "expected_sub": None}]
    # new id, the pending one is gone
    session_id = cookie_of(response)
    assert session_id != pending_id
    assert store.get(pending_id) is None
    assert response.get_header("Set-Cookie").endswith("SameSite=Strict")
    session = store.get(session_id)
    assert session.access_token == "at-1" and session.refresh_token == "rt-1" and session.id_token == "id-1"
    # only the selected claims are kept for the SPA
    assert session.user == {"sub": "user-1", "email": "a@example.com"}


def test_callback_without_pending_login(provider, store):
    _, response = call("GET", "/bff/callback", args={"code": "c", "state": "s"})

    assert response.get_status_code() == 400
    assert body(response)["reason"] == "no login in progress"


def test_callback_with_authenticated_session_is_no_login(provider, store):
    session_id, _ = logged_in(store)

    _, response = call("GET", "/bff/callback", headers=with_cookie(session_id), args={"code": "c", "state": "s"})

    assert response.get_status_code() == 400


@pytest.mark.parametrize("args, reason", [
    ({"code": "c", "state": "wrong"}, "state mismatch"),
    ({"code": "c"}, "state mismatch"),
    ({"error": "access_denied", "state": None}, "authorization server: access_denied"),
    ({"state": None}, "no code"),
    ({"code": "c", "state": None, "iss": "https://evil.example"}, "issuer mismatch"),
])
def test_callback_rejects(provider, store, args, reason):
    pending_id, state = start_login(provider)
    args = {k: state if v is None else v for k, v in args.items()}

    _, response = call("GET", "/bff/callback", headers=with_cookie(pending_id), args=args)

    assert response.get_status_code() == 400
    assert body(response)["reason"] == reason
    assert "Max-Age=0" in response.get_header("Set-Cookie")
    # the pending login is used up either way
    assert store.get(pending_id) is None
    assert not hasattr(provider, "exchanged")


def test_callback_requires_iss_when_the_server_advertises_it(provider):
    provider.metadata["authorization_response_iss_parameter_supported"] = True
    pending_id, state = start_login(provider)

    _, response = call("GET", "/bff/callback", headers=with_cookie(pending_id), args={"code": "c", "state": state})

    assert body(response)["reason"] == "issuer mismatch"


def test_callback_accepts_matching_iss(provider):
    provider.metadata["authorization_response_iss_parameter_supported"] = True
    pending_id, state = start_login(provider)

    _, response = call("GET", "/bff/callback", headers=with_cookie(pending_id),
                       args={"code": "c", "state": state, "iss": CONF["issuer"]})

    assert response.get_status_code() == 302


def test_callback_rejects_invalid_id_token(provider, store):
    provider.id_token_error = IdTokenError("ID token nonce mismatch")
    pending_id, state = start_login(provider)

    _, response = call("GET", "/bff/callback", headers=with_cookie(pending_id), args={"code": "c", "state": state})

    assert response.get_status_code() == 400
    assert len(store) == 0


def test_callback_rejects_refused_code(provider):
    provider.token_error = OidcError("400", "invalid_grant")
    pending_id, state = start_login(provider)

    _, response = call("GET", "/bff/callback", headers=with_cookie(pending_id), args={"code": "c", "state": state})

    assert response.get_status_code() == 400
    assert body(response)["reason"] == "token endpoint: invalid_grant"


def test_callback_needs_id_token(provider):
    del provider.token_response["id_token"]
    pending_id, state = start_login(provider)

    _, response = call("GET", "/bff/callback", headers=with_cookie(pending_id), args={"code": "c", "state": state})

    assert response.get_status_code() == 400


# -- session info and CSRF ----------------------------------------------------------

def test_session_info(store):
    session_id, _ = logged_in(store)

    _, response = call("GET", "/bff/session", headers=with_cookie(session_id, CSRF))

    assert response.get_status_code() == 200
    assert body(response) == {"authenticated": True, "user": {"sub": "user-1", "email": "a@example.com"}}
    assert response.get_header("Cache-Control") == "no-store"


def test_session_info_without_session():
    _, response = call("GET", "/bff/session", headers=CSRF)

    assert body(response) == {"authenticated": False}


@pytest.mark.parametrize("headers", [
    {},
    {"x-bff-csrf": "0"},
    {**CSRF, "sec-fetch-site": "cross-site"},
    {**CSRF, "sec-fetch-site": "same-site"},
    {**CSRF, "origin": "https://evil.example"},
    {**CSRF, "origin": "null"},
])
@pytest.mark.parametrize("method, path", [("GET", "/bff/session"), ("POST", "/bff/logout"), ("GET", "/api/a/x")])
def test_csrf_check(store, headers, method, path):
    session_id, _ = logged_in(store)

    request, response = call(method, path, headers=with_cookie(session_id, headers))

    assert response.get_status_code() == 403
    assert request.get_header("Authorization") is None
    assert store.get(session_id) is not None


def test_csrf_check_accepts_same_origin_browser_request(store):
    session_id, _ = logged_in(store)
    headers = {**CSRF, "sec-fetch-site": "same-origin", "origin": "https://app.example"}

    _, response = call("GET", "/bff/session", headers=with_cookie(session_id, headers))

    assert response.get_status_code() == 200


# -- API proxy -------------------------------------------------------------------

def test_api_request_gets_a_token_exchanged_for_that_api(provider, store):
    session_id, _ = logged_in(store)

    request, response = call("GET", "/api/a/items",
                             headers=with_cookie(session_id, {**CSRF, "authorization": "Bearer from-browser"}))

    assert not response.changed()
    assert provider.exchanges == [{"subject_token": "at-1", "audience": "service-a", "scope": "api-a"}]
    headers = request.get_headers()
    assert headers["Authorization"] == "Bearer service-a-token-1"
    # removed upstream (the gateway drops empty headers)
    assert headers["cookie"] == "" and headers["x-bff-csrf"] == ""
    assert "authorization" not in headers


def test_each_api_gets_its_own_token(provider, store):
    session_id, _ = logged_in(store)

    a, _ = call("GET", "/api/a/x", headers=with_cookie(session_id, CSRF))
    b, _ = call("GET", "/api/b/x", headers=with_cookie(session_id, CSRF))

    assert [e["audience"] for e in provider.exchanges] == ["service-a", "service-b"]
    assert a.get_header("Authorization") == "Bearer service-a-token-1"
    assert b.get_header("Authorization") == "Bearer service-b-token-2"


def test_exchanged_token_is_cached_until_it_nearly_expires(provider, store):
    session_id, session = logged_in(store)

    call("GET", "/api/a/x", headers=with_cookie(session_id, CSRF))
    second, _ = call("GET", "/api/a/y", headers=with_cookie(session_id, CSRF))

    assert len(provider.exchanges) == 1
    assert second.get_header("Authorization") == "Bearer service-a-token-1"

    # about to expire: exchanged again
    token, _ = session.service_tokens["service-a"]
    session.service_tokens["service-a"] = (token, time.time() + 10)
    third, _ = call("GET", "/api/a/z", headers=with_cookie(session_id, CSRF))

    assert len(provider.exchanges) == 2
    assert third.get_header("Authorization") == "Bearer service-a-token-2"


def test_api_outside_the_allowlist(provider, store):
    session_id, _ = logged_in(store)

    request, response = call("GET", "/api/c/x", headers=with_cookie(session_id, CSRF))

    assert response.get_status_code() == 404
    assert provider.exchanges == []
    assert request.get_header("Authorization") is None


def test_longest_api_prefix_wins(provider, store):
    session_id, _ = logged_in(store)
    apis = {**CONF["apis"], "/api/a/admin/": {"audience": "admin", "scope": "admin"}}

    call("GET", "/api/a/admin/x", headers=with_cookie(session_id, CSRF), conf={"apis": apis})

    assert provider.exchanges[0]["audience"] == "admin"


def test_api_request_without_session():
    _, response = call("GET", "/api/a/items", headers=CSRF)

    assert response.get_status_code() == 401


def test_api_request_with_pending_login_only(provider):
    pending_id, _ = start_login(provider)

    _, response = call("GET", "/api/a/items", headers=with_cookie(pending_id, CSRF))

    assert response.get_status_code() == 401


def test_refused_exchange_ends_session(provider, store):
    # e.g. the session at the authorization server is over
    session_id, _ = logged_in(store)
    provider.exchange_error = OidcError("400", "invalid_request")

    _, response = call("GET", "/api/a/items", headers=with_cookie(session_id, CSRF))

    assert response.get_status_code() == 401
    assert body(response) == {"error": "session_expired"}
    assert store.get(session_id) is None


def test_unreachable_authorization_server_during_exchange_is_502(provider, store):
    session_id, _ = logged_in(store)
    provider.exchange_error = OidcError("connection refused")

    _, response = call("GET", "/api/a/items", headers=with_cookie(session_id, CSRF))

    assert response.get_status_code() == 502
    assert store.get(session_id) is not None


def test_expiring_access_token_is_refreshed_before_the_exchange(provider, store):
    session_id, session = logged_in(store, access_token_expires_at=time.time() + 5)
    provider.token_response = {"access_token": "at-2", "token_type": "Bearer", "expires_in": 600,
                               "refresh_token": "rt-2", "id_token": "id-2"}

    call("GET", "/api/a/items", headers=with_cookie(session_id, CSRF))

    assert provider.refreshed == ["rt-1"]
    assert provider.validated == [{"id_token": "id-2", "nonce": None, "expected_sub": "user-1"}]
    # the fresh token is what gets exchanged
    assert provider.exchanges[0]["subject_token"] == "at-2"
    # rotated refresh token replaces the spent one
    assert session.refresh_token == "rt-2" and session.id_token == "id-2"


def test_refresh_keeps_refresh_token_without_rotation(provider, store):
    session_id, session = logged_in(store, access_token_expires_at=time.time() - 1)
    provider.token_response = {"access_token": "at-2", "token_type": "Bearer", "expires_in": 600}

    call("GET", "/api/a/items", headers=with_cookie(session_id, CSRF))

    assert session.refresh_token == "rt-1"


def test_valid_access_token_is_not_refreshed(provider, store):
    session_id, _ = logged_in(store)

    call("GET", "/api/a/items", headers=with_cookie(session_id, CSRF))

    assert provider.refreshed == []


@pytest.mark.parametrize("problem", ["invalid_grant", "bad_id_token", "no_refresh_token"])
def test_failed_refresh_ends_session(provider, store, problem):
    session_id, _ = logged_in(store, access_token_expires_at=time.time() - 1)
    if problem == "invalid_grant":
        provider.token_error = OidcError("400", "invalid_grant")
    elif problem == "bad_id_token":
        provider.id_token_error = IdTokenError("refreshed ID token is about another user")
    else:
        store.get(session_id).refresh_token = None

    _, response = call("GET", "/api/a/items", headers=with_cookie(session_id, CSRF))

    assert response.get_status_code() == 401
    assert body(response) == {"error": "session_expired"}
    assert "Max-Age=0" in response.get_header("Set-Cookie")
    assert store.get(session_id) is None
    assert provider.exchanges == []


# -- back-channel logout -------------------------------------------------------------

def test_back_channel_logout_ends_the_sessions_of_that_sid(provider, store):
    mine, _ = logged_in(store, sid="idp-sid-1")
    also_mine, _ = logged_in(store, sid="idp-sid-1")
    other, _ = logged_in(store, sid="idp-sid-2")

    # server to server: no cookie, no CSRF header
    _, response = call("POST", "/bff/backchannel-logout", body="logout_token=the.logout.token",
                       headers={"content-type": "application/x-www-form-urlencoded"})

    assert response.get_status_code() == 200
    assert response.get_header("Cache-Control") == "no-store"
    assert provider.logout_token == "the.logout.token"
    assert store.get(mine) is None and store.get(also_mine) is None
    assert store.get(other) is not None


def test_back_channel_logout_without_sid_ends_all_sessions_of_the_user(provider, store):
    provider.logout_claims = {"iss": CONF["issuer"], "sub": "user-1"}
    first, _ = logged_in(store, sid="s1")
    second, _ = logged_in(store, sid="s2")
    someone_else, _ = logged_in(store, sid="s3", user={"sub": "user-2"})

    call("POST", "/bff/backchannel-logout", body="logout_token=t")

    assert store.get(first) is None and store.get(second) is None
    assert store.get(someone_else) is not None


@pytest.mark.parametrize("body_", ["", "other=1", "logout_token=forged"])
def test_back_channel_logout_refuses_invalid_requests(provider, store, body_):
    provider.logout_error = IdTokenError("invalid logout token: Signature verification failed")
    session_id, _ = logged_in(store, sid="idp-sid-1")

    _, response = call("POST", "/bff/backchannel-logout", body=body_)

    assert response.get_status_code() == 400
    assert body(response)["error"] == "invalid_request"
    assert store.get(session_id) is not None


def test_back_channel_logout_needs_post(provider):
    _, response = call("GET", "/bff/backchannel-logout")

    assert response.get_status_code() == 405


def test_callback_keeps_the_idp_session_id(provider, store):
    provider.validate_id_token = lambda id_token, nonce, expected_sub=None: dict(CLAIMS, sid="idp-sid-9")
    pending_id, state = start_login(provider)

    _, response = call("GET", "/bff/callback", headers=with_cookie(pending_id), args={"code": "c", "state": state})

    assert store.get(cookie_of(response)).sid == "idp-sid-9"


# -- logout ------------------------------------------------------------------------

def test_logout(provider, store):
    session_id, _ = logged_in(store)

    _, response = call("POST", "/bff/logout", headers=with_cookie(session_id, CSRF))

    assert response.get_status_code() == 200
    assert body(response) == {"logout_url": None}
    assert store.get(session_id) is None
    assert provider.revoked == ["rt-1"]
    assert response.get_header("Set-Cookie") == f"{COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0"


def test_logout_returns_end_session_url(provider, store):
    calls = []
    provider.end_session_url = lambda hint, redirect: calls.append((hint, redirect)) or "https://idp.example/logout"
    session_id, _ = logged_in(store)

    _, response = call("POST", "/bff/logout", headers=with_cookie(session_id, CSRF))

    assert body(response) == {"logout_url": "https://idp.example/logout"}
    assert calls == [("id-1", "https://app.example/")]


def test_logout_without_session(provider):
    _, response = call("POST", "/bff/logout", headers=CSRF)

    assert response.get_status_code() == 200
    assert provider.revoked == []


def test_logout_needs_post(store):
    session_id, _ = logged_in(store)

    _, response = call("GET", "/bff/logout", headers=with_cookie(session_id, CSRF))

    assert response.get_status_code() == 405
    assert store.get(session_id) is not None


def test_cookie_name_is_configurable(store):
    session_id, _ = logged_in(store)

    _, response = call("GET", "/bff/session", conf={"cookie_name": "sid"},
                       headers={**CSRF, "cookie": f"sid={session_id}"})

    assert body(response)["authenticated"] is True


def test_callback_path_follows_redirect_uri(provider):
    _, response = call("GET", "/auth/done", conf={"redirect_uri": "https://app.example/auth/done"})

    assert response.get_status_code() == 400
    assert body(response)["reason"] == "no login in progress"


def test_authorization_url_carries_state(provider):
    _, response = call("GET", "/bff/login")

    state = parse_qs(urlsplit(response.get_header("Location")).query)["state"][0]
    assert state == provider.authorization_requests[0]["state"]


# -- dev trace (plugins/trace.py) ---------------------------------------------------

def events(path):
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def test_login_is_traced_with_file_and_header(tmp_path):
    path = tmp_path / "trace.jsonl"
    path.touch()  # the test run creates it; components only append

    call("GET", "/bff/login", headers={"x-trace-id": "T0001"}, conf={"trace_file": str(path)})

    (note,) = events(path)
    assert note["trace"] == "T0001" and note["type"] == "note"
    assert {"state", "nonce", "code_verifier", "code_challenge"} == note["values"].keys()
    assert not trace.active()


@pytest.mark.parametrize("headers, conf", [
    ({}, True),                                  # no trace id
    ({"x-trace-id": "T0001"}, False),            # tracing not configured
    ({"x-trace-id": "../../etc/passwd x"}, True),  # malformed trace id
])
def test_nothing_is_traced_otherwise(tmp_path, headers, conf):
    path = tmp_path / "trace.jsonl"
    path.touch()

    call("GET", "/bff/login", headers=headers, conf={"trace_file": str(path)} if conf else {})

    assert events(path) == []


def test_forwarded_api_request_is_traced(tmp_path, store):
    path = tmp_path / "trace.jsonl"
    path.touch()
    session_id, _ = logged_in(store)

    call("GET", "/api/a/items", headers=with_cookie(session_id, {**CSRF, "x-trace-id": "T2"}),
         conf={"trace_file": str(path)})

    exchange_note, fwd = events(path)
    assert exchange_note["type"] == "note" and exchange_note["values"] == {"audience": "service-a"}
    assert fwd["type"] == "forward" and fwd["audience"] == "service-a"
    assert ["Authorization", "Bearer service-a-token-1"] in fwd["headers"]
    assert set(fwd["removed"]) == {"cookie", "x-bff-csrf"}


def test_trace_file_is_never_created(tmp_path):
    path = tmp_path / "trace.jsonl"

    call("GET", "/bff/login", headers={"x-trace-id": "T1"}, conf={"trace_file": str(path)})

    assert not path.exists()


def test_back_channel_logout_is_traced_under_the_login_trace(tmp_path, provider, store):
    path = tmp_path / "trace.jsonl"
    path.touch()
    logged_in(store, sid="idp-sid-1", trace_id="T7")

    # the authorization server sends no trace id
    call("POST", "/bff/backchannel-logout", body="logout_token=t", conf={"trace_file": str(path)})

    incoming, note = events(path)
    assert incoming["trace"] == "T7" and incoming["type"] == "incoming"
    assert incoming["req_body"] == "logout_token=t" and incoming["status"] == 200
    assert note["values"] == {"sid": "idp-sid-1"}


# -- secrets from Vault (plugins/vault.py) ---------------------------------------------

def test_client_secret_comes_from_vault(provider, monkeypatch):
    seen = []
    monkeypatch.setattr(tokenhandler.vault, "read", lambda ref, addr, token_file: seen.append(
        (ref, addr, token_file)) or "from-vault")
    created = []
    monkeypatch.setattr(tokenhandler, "get_provider", lambda *args, **kwargs: created.append(args) or provider)

    call("GET", "/bff/login", conf={"client_secret": "vault:kv/bff#client_secret",
                                    "vault": {"addr": "http://vault:8200", "token_file": "/t/bff"}})

    assert seen == [("vault:kv/bff#client_secret", "http://vault:8200", "/t/bff")]
    assert created[0][2] == "from-vault"


def test_unavailable_secrets_answer_503(monkeypatch):
    def fail(*args):
        raise tokenhandler.vault.VaultError("Vault answered 403 for kv/bff")
    monkeypatch.setattr(tokenhandler.vault, "read", fail)

    _, response = call("GET", "/bff/login", conf={"client_secret": "vault:kv/bff#client_secret",
                                                  "vault": {"addr": "http://vault:8200", "token_file": "/t/bff"}})

    assert response.get_status_code() == 503
    assert body(response) == {"error": "secrets_unavailable"}
