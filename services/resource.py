"""
Resource server for the demo: Service A and Service B run this with different
settings. Zero trust: it trusts neither the network nor the gateway, only
the token in each request, and checks that token itself, every time:

- locally: signature with a key from Keycloak's jwks_uri, `typ: at+jwt`
  (an access token, not an ID token) [RFC 9068 4], issuer, expiry, and
  `aud` = this service [RFC 9068 4; RFC 9700 2.3]; then the scope the
  endpoint needs [RFC 9068 4; RFC 6750 3.1];
- at Keycloak, by token introspection [RFC 7662]: whether the token is still
  active. That is how a logout reaches this service immediately: Keycloak
  sends back-channel logout only to clients with a session (the BFF), but a
  token of an ended SSO session introspects as inactive.

A token exchanged for Service A is useless at Service B and vice versa, and
the BFF's own access token (no audience) is useless at both.

Environment: SERVICE_ID (its client id and the audience it accepts),
SERVICE_SECRET (client secret for introspection), SERVICE_SCOPE (scope its
read endpoint needs), ISSUER, PORT, TRACE_FILE (dev only),
SSL_CERT_FILE (trust anchor for Keycloak's TLS certificate).

    python -m services.resource
"""
import json
import os
import time
import urllib.request
from dataclasses import dataclass
from typing import Optional

import jwt

from plugins import trace
from services.web import Request, Response, TracedJwks, json_response, post_form, serve

ALGORITHMS = ["RS256", "PS256", "ES256"]
LEEWAY = 30


class Unauthorized(Exception):
    """The token is missing or invalid: 401 invalid_token [RFC 6750 3.1]."""


class Forbidden(Exception):
    """The token lacks the scope this endpoint needs: 403 insufficient_scope [RFC 6750 3.1]."""


@dataclass
class Settings:
    service_id: str
    secret: str
    scope: str
    issuer: str


class ResourceServer:

    def __init__(self, settings: Settings, keys=None, introspect=None, metadata: Optional[dict] = None):
        self.s = settings
        self._metadata = metadata
        self._keys = keys
        self._introspect = introspect or self._introspect_at_keycloak

    # -- configuration from Keycloak --------------------------------------------

    @property
    def metadata(self) -> dict:
        if self._metadata is None:
            url = self.s.issuer + "/.well-known/openid-configuration"
            with urllib.request.urlopen(url, timeout=5) as resp:
                metadata = json.loads(resp.read())
            # the document must be about the issuer we trust [RFC 8414 3.3]
            if metadata.get("issuer") != self.s.issuer:
                raise RuntimeError(f"discovery issuer {metadata.get('issuer')!r} is not {self.s.issuer!r}")
            self._metadata = metadata
        return self._metadata

    @property
    def keys(self):
        if self._keys is None:
            self._keys = TracedJwks(self.metadata["jwks_uri"], cache_jwk_set=True, lifespan=300)
        return self._keys

    # -- token checks ---------------------------------------------------------------

    def authenticate(self, req: Request, needed_scope: str) -> dict:
        """The claims of the request's access token, if it may use an endpoint needing `needed_scope`."""
        token = req.bearer()
        if not token:
            raise Unauthorized("no bearer token")
        try:
            header = jwt.get_unverified_header(token)
            # explicitly typed access token: an ID token or other JWT is no access token [RFC 9068 2.1, 4]
            if header.get("typ", "").lower() not in ("at+jwt", "application/at+jwt"):
                raise Unauthorized(f"not an access token (typ {header.get('typ')!r})")
            key = self.keys.get_signing_key_from_jwt(token)
            claims = jwt.decode(token, key.key, algorithms=ALGORITHMS, issuer=self.s.issuer,
                                audience=self.s.service_id, leeway=LEEWAY,
                                options={"require": ["iss", "sub", "aud", "exp", "iat"]})
        except jwt.InvalidAudienceError:
            # a token for another service: the heart of the zero-trust check
            raise Unauthorized(f"token is not meant for {self.s.service_id}") from None
        except jwt.PyJWTError as e:
            raise Unauthorized(f"invalid token: {e}") from None

        if needed_scope not in claims.get("scope", "").split():
            raise Forbidden(needed_scope)

        # still active? (ended SSO session, revoked, ...) [RFC 7662 2.2]
        if not self._introspect(token).get("active"):
            raise Unauthorized("token is no longer active (session ended or revoked)")
        trace.note(f"{self.s.service_id} accepts the token: signature, typ at+jwt, iss, aud={self.s.service_id}, "
                   f"exp, scope {needed_scope}, and Keycloak says it is active.",
                   ["RFC 9068 4", "RFC 7662 2.2", "RFC 9700 2.3"], sid=claims.get("sid"))
        return claims

    def _introspect_at_keycloak(self, token: str) -> dict:
        status, body = post_form(self.metadata["introspection_endpoint"],
                                 {"token": token, "token_type_hint": "access_token"},
                                 basic_auth=(self.s.service_id, self.s.secret))
        if status != 200:
            # fail closed: no answer is no permission
            raise Unauthorized(f"introspection failed ({status})")
        return json.loads(body)

    def _guarded(self, req: Request, needed_scope: str, handler) -> Response:
        try:
            claims = self.authenticate(req, needed_scope)
        except Unauthorized as e:
            trace.note(f"{self.s.service_id} rejects the request: {e}", ["RFC 6750 3.1", "RFC 9068 4"])
            return json_response(401, {"error": "invalid_token", "error_description": str(e)}, [
                ("WWW-Authenticate", f'Bearer realm="{self.s.service_id}", error="invalid_token", '
                                     f'error_description="{e}"')])
        except Forbidden as e:
            trace.note(f"{self.s.service_id} rejects the request: scope {e} missing", ["RFC 6750 3.1"])
            return json_response(403, {"error": "insufficient_scope", "scope": str(e)}, [
                ("WWW-Authenticate", f'Bearer realm="{self.s.service_id}", error="insufficient_scope", '
                                     f'scope="{e}"')])
        return handler(req, claims)

    # -- endpoints --------------------------------------------------------------

    def whoami(self, req: Request) -> Response:
        def handler(req, claims):
            return json_response(200, {
                "service": self.s.service_id,
                "sub": claims["sub"],
                "aud": claims["aud"],
                "scope": claims.get("scope"),
                "azp": claims.get("azp"),
                "sid": claims.get("sid"),
                "expires_in": int(claims["exp"] - time.time()),
                # what reached the service: the BFF swapped the cookie for the token
                "received_headers": sorted(req.headers),
            })
        return self._guarded(req, self.s.scope, handler)

    def create_item(self, req: Request) -> Response:
        # needs a scope nobody is granted: shows 403 insufficient_scope
        return self._guarded(req, f"{self.s.scope}.write", lambda req, claims: json_response(201, {"created": True}))

    def routes(self) -> dict:
        return {("GET", "/whoami"): self.whoami, ("POST", "/items"): self.create_item}


def main():
    settings = Settings(service_id=os.environ["SERVICE_ID"], secret=os.environ["SERVICE_SECRET"],
                        scope=os.environ["SERVICE_SCOPE"], issuer=os.environ["ISSUER"])
    serve(settings.service_id, ResourceServer(settings).routes(), os.environ.get("HOST", "0.0.0.0"),
          int(os.environ["PORT"]))


if __name__ == "__main__":
    main()
