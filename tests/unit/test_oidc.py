import base64
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from apisix.plugins.oidc import IdTokenError, OidcError, Provider

ISSUER = "https://idp.example"
METADATA = {
    "issuer": ISSUER,
    "authorization_endpoint": f"{ISSUER}/auth",
    "token_endpoint": f"{ISSUER}/token",
    "jwks_uri": f"{ISSUER}/keys",
    "code_challenge_methods_supported": ["S256", "plain"],
    "id_token_signing_alg_values_supported": ["RS256"],
}
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class Keys:
    """Stands in for PyJWKClient: always our public key."""

    class _Key:
        key = KEY.public_key()

    def get_signing_key_from_jwt(self, token):
        return self._Key()


@pytest.fixture
def provider():
    p = Provider(ISSUER, "bff", "secret")
    p._metadata = p._validate_metadata(dict(METADATA))
    p._jwks = Keys()
    return p


def id_token(key=KEY, algorithm="RS256", **overrides):
    now = int(time.time())
    claims = {"iss": ISSUER, "sub": "user-1", "aud": "bff", "iat": now, "exp": now + 300, "nonce": "n-1",
              "email": "a@example.com"}
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm=algorithm)


# -- ID token -----------------------------------------------------------------

def test_valid_id_token(provider):
    claims = provider.validate_id_token(id_token(), "n-1")

    assert claims["sub"] == "user-1"
    assert claims["email"] == "a@example.com"


def test_refreshed_id_token_needs_no_nonce_but_same_user(provider):
    assert provider.validate_id_token(id_token(nonce=None), None, expected_sub="user-1")["sub"] == "user-1"

    with pytest.raises(IdTokenError, match="another user"):
        provider.validate_id_token(id_token(nonce=None), None, expected_sub="user-2")


@pytest.mark.parametrize("overrides", [
    {"nonce": "n-2"},
    {"nonce": None},
    {"iss": "https://evil.example"},
    {"aud": "other-client"},
    {"aud": ["bff", "other-client"]},
    {"azp": "other-client"},
    {"exp": int(time.time()) - 120},
    {"iat": None},
    {"sub": None},
], ids=lambda o: ",".join(f"{k}={v}" for k, v in o.items()))
def test_invalid_claims_are_rejected(provider, overrides):
    with pytest.raises(IdTokenError):
        provider.validate_id_token(id_token(**overrides), "n-1")


def test_wrong_signature_is_rejected(provider):
    with pytest.raises(IdTokenError):
        provider.validate_id_token(id_token(key=OTHER_KEY), "n-1")


def test_alg_none_is_rejected(provider):
    token = jwt.encode({"iss": ISSUER, "sub": "u", "aud": "bff", "iat": 1, "exp": 2**31, "nonce": "n-1"},
                       None, algorithm="none")

    with pytest.raises(IdTokenError):
        provider.validate_id_token(token, "n-1")


def test_hmac_with_client_secret_is_rejected(provider):
    # an attacker knowing (or guessing) the client secret must not be able to mint tokens
    with pytest.raises(IdTokenError):
        provider.validate_id_token(id_token(key="secret" * 6, algorithm="HS256"), "n-1")


def test_small_clock_skew_is_tolerated(provider):
    provider.validate_id_token(id_token(exp=int(time.time()) - 30), "n-1")


# -- metadata -----------------------------------------------------------------

def test_metadata_issuer_must_match(provider):
    with pytest.raises(OidcError, match="does not match"):
        provider._validate_metadata({**METADATA, "issuer": "https://evil.example"})


def test_metadata_must_offer_pkce_s256(provider):
    with pytest.raises(OidcError, match="PKCE"):
        provider._validate_metadata({**METADATA, "code_challenge_methods_supported": ["plain"]})
    with pytest.raises(OidcError, match="PKCE"):
        provider._validate_metadata({k: v for k, v in METADATA.items() if k != "code_challenge_methods_supported"})


def test_plain_http_needs_opt_in():
    with pytest.raises(OidcError, match="non-https"):
        Provider("http://idp.example", "bff", "secret")
    Provider("http://idp.example", "bff", "secret", allow_insecure_http=True)


def test_http_endpoints_in_metadata_are_refused(provider):
    with pytest.raises(OidcError, match="non-https"):
        provider._validate_metadata({**METADATA, "token_endpoint": "http://idp.example/token"})


# -- front channel ------------------------------------------------------------

def test_authorization_url(provider):
    url = provider.authorization_url("https://app.example/cb", "openid", "st", "no", "ch")

    assert url == ("https://idp.example/auth?response_type=code&client_id=bff"
                   "&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=openid&state=st&nonce=no"
                   "&code_challenge=ch&code_challenge_method=S256")


def test_end_session_url(provider):
    assert provider.end_session_url("id", "https://app.example/") is None

    provider._metadata["end_session_endpoint"] = f"{ISSUER}/logout"
    assert provider.end_session_url("id", "https://app.example/") == (
        "https://idp.example/logout?client_id=bff"
        "&post_logout_redirect_uri=https%3A%2F%2Fapp.example%2F&id_token_hint=id")


def test_revoke_without_endpoint(provider):
    assert provider.revoke("rt") is False


# -- back channel -------------------------------------------------------------

class TokenEndpoint(BaseHTTPRequestHandler):
    """Records requests; answers with the class attributes `status` and `reply`."""
    requests = []
    status = 200
    reply = {"access_token": "at", "token_type": "Bearer"}
    headers_out = {}

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        TokenEndpoint.requests.append((dict(self.headers), parse_qs(self.rfile.read(length).decode())))
        self.send_response(self.status)
        for name, value in self.headers_out.items():
            self.send_header(name, value)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(self.reply).encode())

    def log_message(self, *args):
        pass


@pytest.fixture
def token_endpoint(monkeypatch):
    server = HTTPServer(("127.0.0.1", 0), TokenEndpoint)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    TokenEndpoint.requests = []
    yield server
    server.shutdown()
    for name in ("status", "reply", "headers_out"):
        monkeypatch.delattr(TokenEndpoint, name, raising=False)


@pytest.fixture
def http_provider(token_endpoint):
    url = f"http://127.0.0.1:{token_endpoint.server_port}/token"
    p = Provider(ISSUER, "bff client", "s3cr:t", allow_insecure_http=True)
    p._metadata = p._validate_metadata({**METADATA, "token_endpoint": url})
    return p


def test_code_exchange_authenticates_client(http_provider):
    tokens = http_provider.exchange_code("the-code", "https://app.example/cb", "verifier")

    assert tokens["access_token"] == "at"
    (headers, form), = TokenEndpoint.requests
    # client_secret_basic, id and secret form-urlencoded first [RFC 6749 2.3.1]
    assert headers["Authorization"] == "Basic " + base64.b64encode(b"bff%20client:s3cr%3At").decode()
    assert form == {"grant_type": ["authorization_code"], "code": ["the-code"],
                    "redirect_uri": ["https://app.example/cb"], "code_verifier": ["verifier"]}


def test_oauth_error_is_reported(http_provider, monkeypatch):
    monkeypatch.setattr(TokenEndpoint, "status", 400)
    monkeypatch.setattr(TokenEndpoint, "reply", {"error": "invalid_grant"})

    with pytest.raises(OidcError) as e:
        http_provider.refresh("rt")
    assert e.value.error == "invalid_grant"


def test_token_response_must_be_bearer(http_provider, monkeypatch):
    monkeypatch.setattr(TokenEndpoint, "reply", {"access_token": "at", "token_type": "DPoP"})

    with pytest.raises(OidcError):
        http_provider.refresh("rt")


def test_redirects_are_not_followed(http_provider, monkeypatch):
    monkeypatch.setattr(TokenEndpoint, "status", 307)
    monkeypatch.setattr(TokenEndpoint, "headers_out", {"Location": "https://evil.example/token"})

    with pytest.raises(OidcError, match="307"):
        http_provider.refresh("rt")
    assert len(TokenEndpoint.requests) == 1


def test_token_exchange_request(http_provider, monkeypatch):
    monkeypatch.setattr(TokenEndpoint, "reply", {
        "access_token": "a-token", "token_type": "Bearer",
        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"})

    tokens = http_provider.exchange_token("subject", "service-a", "api-a")

    assert tokens["access_token"] == "a-token"
    (headers, form), = TokenEndpoint.requests
    assert headers["Authorization"].startswith("Basic ")
    assert form == {
        "grant_type": ["urn:ietf:params:oauth:grant-type:token-exchange"],
        "subject_token": ["subject"],
        "subject_token_type": ["urn:ietf:params:oauth:token-type:access_token"],
        "requested_token_type": ["urn:ietf:params:oauth:token-type:access_token"],
        "audience": ["service-a"],
        "scope": ["api-a"],
    }


def test_token_exchange_must_issue_an_access_token(http_provider, monkeypatch):
    monkeypatch.setattr(TokenEndpoint, "reply", {
        "access_token": "x", "token_type": "Bearer", "issued_token_type": "urn:ietf:params:oauth:token-type:id_token"})

    with pytest.raises(OidcError, match="not an access token"):
        http_provider.exchange_token("subject", "service-a", "api-a")


# -- back-channel logout token [OIDC Back-Channel Logout 1.0, 2.6] -------------------------

def logout_token(key=KEY, typ="logout+jwt", **overrides):
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": "bff", "iat": now, "exp": now + 120, "jti": base64.b64encode(os.urandom(9)).decode(),
              "sid": "s1", "sub": "u1", "events": {"http://schemas.openid.net/event/backchannel-logout": {}}}
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm="RS256", headers={"typ": typ} if typ else None)


def test_valid_logout_token(provider):
    claims = provider.validate_logout_token(logout_token())

    assert (claims["sid"], claims["sub"]) == ("s1", "u1")


def test_logout_token_with_only_sub_or_only_sid(provider):
    provider.validate_logout_token(logout_token(sid=None))
    provider.validate_logout_token(logout_token(sub=None))


def test_logout_token_cannot_be_replayed(provider):
    token = logout_token()
    provider.validate_logout_token(token)

    with pytest.raises(IdTokenError, match="replayed"):
        provider.validate_logout_token(token)


@pytest.mark.parametrize("overrides, error", [
    ({"events": None}, "logout event"),
    ({"events": {"http://schemas.openid.net/event/backchannel-logout": "x"}}, "logout event"),
    ({"events": {"something-else": {}}}, "logout event"),
    ({"nonce": "n"}, "nonce"),
    ({"sid": None, "sub": None}, "neither sid nor sub"),
    ({"aud": "other-client"}, "invalid logout token"),
    ({"iss": "https://evil.example"}, "invalid logout token"),
    ({"jti": None}, "invalid logout token"),
    ({"iat": None}, "invalid logout token"),
    ({"iat": int(time.time()) - 3600, "exp": int(time.time()) + 60}, "too old"),
    ({"exp": int(time.time()) - 3600}, "invalid logout token"),
], ids=lambda v: str(v)[:40])
def test_invalid_logout_tokens(provider, overrides, error):
    with pytest.raises(IdTokenError, match=error):
        provider.validate_logout_token(logout_token(**overrides))


def test_logout_token_signed_by_another_key(provider):
    with pytest.raises(IdTokenError):
        provider.validate_logout_token(logout_token(key=OTHER_KEY))


def test_other_jwt_types_are_no_logout_tokens(provider):
    with pytest.raises(IdTokenError, match="typ"):
        provider.validate_logout_token(logout_token(typ="at+jwt"))


def test_id_token_is_no_logout_token(provider):
    with pytest.raises(IdTokenError):
        provider.validate_logout_token(id_token(aud="bff"))
