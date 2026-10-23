"""
Minimal OpenID Connect client for the BFF: the back channel to the
authorization server (discovery, token endpoint, ID token validation).

The BFF is a confidential client [BBA 6.1.3.1]: it authenticates at the token
endpoint with its client secret, and only it ever sees tokens.
"""
import base64
import hmac
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

import jwt

from apisix.plugins import trace

# Asymmetric algorithms only: never `none`, and no HMAC, which would make the
# client secret a signing key [OIDC Core 3.1.3.7 (7)].
SIGNING_ALGORITHMS = ("RS256", "PS256", "ES256")
# tolerated clock skew for exp/iat
LEEWAY = 60


class OidcError(Exception):
    """The authorization server is unreachable or answered with an error."""

    def __init__(self, message: str, error: Optional[str] = None):
        super().__init__(message)
        # OAuth error code (`invalid_grant`, ...) if the server sent one
        self.error = error


class IdTokenError(Exception):
    """An ID token failed validation."""


class Provider:

    def __init__(self, issuer: str, client_id: str, client_secret: str,
                 allow_insecure_http: bool = False, timeout: float = 5):
        self.issuer = issuer
        self.client_id = client_id
        self._client_secret = client_secret
        self._allow_insecure_http = allow_insecure_http
        self._timeout = timeout
        self._metadata = None
        self._jwks = None
        # reentrant: `jwks` reads `metadata` while holding it
        self._lock = threading.RLock()
        self._require_https(issuer)

    # -- metadata ----------------------------------------------------------

    @property
    def metadata(self) -> dict:
        """
        Discovery document, fetched once [RFC 8414; RFC 9700 2.6]. Endpoints
        come from here instead of configuration, so they always belong to the
        configured issuer.
        """
        with self._lock:
            if self._metadata is None:
                self._metadata = self._validate_metadata(
                    self._get_json(self.issuer.rstrip("/") + "/.well-known/openid-configuration"))
            return self._metadata

    def _validate_metadata(self, metadata: dict) -> dict:
        # the issuer in the document MUST be identical to the one it was fetched
        # for, otherwise an attacker-controlled document could be used [RFC 8414 3.3]
        if metadata.get("issuer") != self.issuer:
            raise OidcError(f"discovery issuer {metadata.get('issuer')!r} does not match {self.issuer!r}")
        for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            if not metadata.get(name):
                raise OidcError(f"discovery document lacks {name}")
            self._require_https(metadata[name])
        # PKCE is our protection against code injection; make sure the server
        # supports it instead of silently relying on it [RFC 9700 2.1.1; OWASP OAuth2 #2]
        if "S256" not in metadata.get("code_challenge_methods_supported", []):
            raise OidcError("authorization server does not support PKCE with S256")
        return metadata

    def _require_https(self, url: str):
        # authorization responses and tokens MUST NOT travel unencrypted
        # [RFC 9700 2.6]; plain http is only for the local dev stack
        if urllib.parse.urlsplit(url).scheme != "https" and not self._allow_insecure_http:
            raise OidcError(f"refusing non-https endpoint {url}")

    @property
    def jwks(self) -> jwt.PyJWKClient:
        with self._lock:
            if self._jwks is None:
                # keys are cached; an unknown `kid` refetches the set, which handles key rotation
                self._jwks = _JwksClient(self.metadata["jwks_uri"], cache_jwk_set=True,
                                         lifespan=300, timeout=self._timeout)
            return self._jwks

    # -- front channel -----------------------------------------------------

    def authorization_url(self, redirect_uri: str, scope: str, state: str, nonce: str, code_challenge: str) -> str:
        params = {
            # authorization code grant only, no implicit or hybrid flow [RFC 9700 2.1.2; BBA 6.1.3.1]
            "response_type": "code",
            "client_id": self.client_id,
            # registered at the server and matched exactly there [RFC 9700 2.1]
            "redirect_uri": redirect_uri,
            "scope": scope,
            # CSRF protection of the redirect, bound to the browser by the session cookie [RFC 9700 4.7]
            "state": state,
            # binds the ID token to this login [OIDC Core 3.1.2.1; RFC 9700 4.5.3.2]
            "nonce": nonce,
            # PKCE; S256 so the verifier never appears in the front channel [RFC 7636; OWASP OAuth2 #7]
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        endpoint = self.metadata["authorization_endpoint"]
        return endpoint + ("&" if "?" in endpoint else "?") + urllib.parse.urlencode(params)

    # -- token endpoint ----------------------------------------------------

    def exchange_code(self, code: str, redirect_uri: str, code_verifier: str) -> dict:
        return self._token_request({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        })

    def refresh(self, refresh_token: str) -> dict:
        # [BBA 6.1.2.2] refresh with client authentication, tokens stay in the BFF
        return self._token_request({"grant_type": "refresh_token", "refresh_token": refresh_token})

    def revoke(self, token: str, token_type_hint: str = "refresh_token") -> bool:
        """Revokes `token` if the server has a revocation endpoint [RFC 7009]. Best effort."""
        endpoint = self.metadata.get("revocation_endpoint")
        if not endpoint:
            return False
        self._require_https(endpoint)
        try:
            self._post(endpoint, {"token": token, "token_type_hint": token_type_hint})
        except OidcError:
            return False
        return True

    def end_session_url(self, id_token_hint: Optional[str], post_logout_redirect_uri: str) -> Optional[str]:
        """RP-initiated logout URL, if the server supports it [OIDC RP-Initiated Logout 1.0]."""
        endpoint = self.metadata.get("end_session_endpoint")
        if not endpoint:
            return None
        params = {"client_id": self.client_id, "post_logout_redirect_uri": post_logout_redirect_uri}
        if id_token_hint:
            params["id_token_hint"] = id_token_hint
        return endpoint + ("&" if "?" in endpoint else "?") + urllib.parse.urlencode(params)

    def _token_request(self, form: dict) -> dict:
        tokens = self._post(self.metadata["token_endpoint"], form)
        if not tokens.get("access_token") or tokens.get("token_type", "").lower() != "bearer":
            raise OidcError("token response without bearer access token")
        return tokens

    def _post(self, url: str, form: dict) -> dict:
        # client_secret_basic: id and secret are form-urlencoded before base64 [RFC 6749 2.3.1]
        credentials = f"{urllib.parse.quote(self.client_id, safe='')}:{urllib.parse.quote(self._client_secret, safe='')}"
        req = urllib.request.Request(url, data=urllib.parse.urlencode(form).encode(), method="POST", headers={
            "Authorization": "Basic " + base64.b64encode(credentials.encode()).decode(),
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        })
        return self._send(req)

    def _get_json(self, url: str) -> dict:
        return self._send(urllib.request.Request(url, headers={"Accept": "application/json"}))

    def _send(self, req: urllib.request.Request) -> dict:
        t_start = time.time()
        status, headers, body, ok, error = None, [], b"", False, None
        try:
            with _NO_REDIRECTS.open(req, timeout=self._timeout) as resp:
                status, headers, body, ok = resp.status, resp.getheaders(), resp.read(), True
        except urllib.error.HTTPError as e:
            status, headers, body = e.code, e.headers.items(), e.read()
        except (urllib.error.URLError, OSError) as e:
            error = str(e)
        if trace.active():
            trace.exchange(req.get_method(), req.full_url, req.header_items(),
                           req.data.decode() if req.data else None, status, headers,
                           body.decode(errors="replace"), t_start, error)

        if error is not None:
            raise OidcError(f"{req.full_url} failed: {error}")
        if not ok:
            try:
                oauth_error = json.loads(body).get("error")
            except (ValueError, AttributeError):
                oauth_error = None
            raise OidcError(f"{req.full_url} answered {status}", oauth_error)
        try:
            return json.loads(body) if body else {}
        except ValueError as e:
            raise OidcError(f"{req.full_url} sent no JSON: {e}") from None

    # -- ID token ----------------------------------------------------------

    def validate_id_token(self, id_token: str, nonce: Optional[str], expected_sub: Optional[str] = None) -> dict:
        """
        Validates an ID token as in [OIDC Core 3.1.3.7] and returns its claims.

        `nonce` is the one sent in the authorization request; None for tokens
        from a refresh, which carry no new nonce [OIDC Core 12.2]. Those must
        be about the same user (`expected_sub`).
        """
        allowed = [alg for alg in SIGNING_ALGORITHMS
                   if alg in self.metadata.get("id_token_signing_alg_values_supported", ["RS256"])]
        try:
            key = self.jwks.get_signing_key_from_jwt(id_token)
            claims = jwt.decode(
                id_token, key.key, algorithms=allowed,
                # (2) exact issuer, (3) our client id as audience, (9) exp, (10) iat
                issuer=self.issuer, audience=self.client_id, leeway=LEEWAY,
                options={"require": ["iss", "sub", "aud", "exp", "iat"]},
            )
        except (jwt.PyJWTError, OidcError) as e:
            raise IdTokenError(f"invalid ID token: {e}") from None

        # (3) no other audiences than us: we do not trust other clients' tokens
        audiences = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
        if audiences != [self.client_id]:
            raise IdTokenError("ID token has additional audiences")
        # (5) authorized party, if present, must be us
        if "azp" in claims and claims["azp"] != self.client_id:
            raise IdTokenError("ID token azp is not this client")
        # (11) nonce of this login, defeats code injection and replayed ID tokens [RFC 9700 4.5.3.2]
        if nonce is not None and not _equal(claims.get("nonce"), nonce):
            raise IdTokenError("ID token nonce mismatch")
        if expected_sub is not None and claims["sub"] != expected_sub:
            raise IdTokenError("refreshed ID token is about another user")
        return claims


def _equal(a: Optional[str], b: str) -> bool:
    return a is not None and hmac.compare_digest(a.encode(), b.encode())


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # back channel calls never follow redirects: a redirected token request
    # could hand the code and client credentials to another host [RFC 9700 4.12]
    def redirect_request(self, *args, **kwargs):
        return None


_NO_REDIRECTS = urllib.request.build_opener(_NoRedirect)


class _JwksClient(jwt.PyJWKClient):
    # PyJWKClient does its own HTTP; record its fetches in the dev trace too
    def fetch_data(self):
        t_start = time.time()
        data = super().fetch_data()
        if trace.active():
            trace.exchange("GET", self.uri, [], None, 200, [("Content-Type", "application/json")],
                           json.dumps(data), t_start)
        return data

# one provider per issuer/client, so discovery and keys are cached across requests
_providers = {}
_providers_lock = threading.Lock()


def get_provider(issuer: str, client_id: str, client_secret: str, allow_insecure_http: bool = False) -> Provider:
    key = (issuer, client_id, client_secret, allow_insecure_http)
    with _providers_lock:
        if key not in _providers:
            _providers[key] = Provider(issuer, client_id, client_secret, allow_insecure_http)
        return _providers[key]
