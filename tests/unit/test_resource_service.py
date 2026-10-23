"""services/resource.py: each check of the zero-trust resource server, without Keycloak."""
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from services.resource import ResourceServer, Settings
from services.web import Request

ISSUER = "https://auth.example.test/realms/demo"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class Keys:
    class _Key:
        key = KEY.public_key()

    def get_signing_key_from_jwt(self, token):
        return self._Key()


@pytest.fixture
def active():
    """What the fake introspection answers; records what it was asked."""
    return {"answer": {"active": True}, "asked": []}


@pytest.fixture
def service(active):
    def introspect(token):
        active["asked"].append(token)
        return active["answer"]
    return ResourceServer(Settings("service-a", "secret", "api-a", ISSUER), keys=Keys(), introspect=introspect,
                          metadata={"issuer": ISSUER})


def token(key=KEY, typ="at+jwt", **overrides):
    now = int(time.time())
    claims = {"iss": ISSUER, "sub": "u1", "aud": "service-a", "azp": "bff", "scope": "profile api-a email",
              "sid": "s1", "iat": now, "exp": now + 300}
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm="RS256", headers={"typ": typ})


def get(service, bearer=None, path="/whoami", method="GET"):
    headers = {"authorization": f"Bearer {bearer}"} if bearer else {}
    req = Request(method, path, {}, {**headers, "host": "service-a"})
    handler = service.routes()[(method, path)]
    resp = handler(req)
    return resp.status, resp.body, dict(resp.headers)


def test_accepts_its_own_token(service, active):
    t = token()

    status, body, headers = get(service, t)

    assert status == 200
    assert (body["service"], body["sub"], body["aud"], body["sid"]) == ("service-a", "u1", "service-a", "s1")
    assert body["received_headers"] == ["authorization", "host"]
    assert headers["Cache-Control"] == "no-store"
    # every request is checked at Keycloak too
    assert active["asked"] == [t]


@pytest.mark.parametrize("bad, reason", [
    (dict(aud="service-b"), "not meant for service-a"),
    (dict(aud=["service-b", "account"]), "not meant for service-a"),
    (dict(aud=None), "invalid token"),
    (dict(iss="https://evil.example.test"), "invalid token"),
    (dict(exp=int(time.time()) - 120), "invalid token"),
    (dict(sub=None), "invalid token"),
], ids=lambda v: str(v)[:30])
def test_rejects_tokens_not_for_it(service, active, bad, reason):
    status, body, headers = get(service, token(**bad))

    assert status == 401
    assert reason in body["error_description"]
    assert headers["WWW-Authenticate"].startswith('Bearer realm="service-a", error="invalid_token"')
    # rejected locally, before asking Keycloak
    assert active["asked"] == []


def test_accepts_its_audience_among_several(service):
    assert get(service, token(aud=["service-a", "other"]))[0] == 200


def test_rejects_id_tokens(service):
    status, body, _ = get(service, token(typ="JWT"))

    assert status == 401
    assert body["error_description"] == "not an access token (typ 'JWT')"


def test_rejects_wrong_signature(service):
    assert get(service, token(key=OTHER_KEY))[0] == 401


def test_rejects_missing_token(service):
    status, body, headers = get(service)

    assert status == 401
    assert headers["WWW-Authenticate"].startswith("Bearer ")


def test_rejects_inactive_token(service, active):
    # e.g. the Keycloak session ended (logout) before the token expired
    active["answer"] = {"active": False}

    status, body, _ = get(service, token())

    assert status == 401
    assert "no longer active" in body["error_description"]


def test_scope_is_checked_before_introspection(service, active):
    status, body, headers = get(service, token(scope="profile api-b"))

    assert status == 403
    assert headers["WWW-Authenticate"] == 'Bearer realm="service-a", error="insufficient_scope", scope="api-a"'
    assert active["asked"] == []


def test_write_needs_a_scope_nobody_has(service):
    status, body, _ = get(service, token(), path="/items", method="POST")

    assert status == 403
    assert body == {"error": "insufficient_scope", "scope": "api-a.write"}


def test_failed_introspection_fails_closed(active):
    def broken(token):
        from services.resource import Unauthorized
        raise Unauthorized("introspection failed (503)")
    service = ResourceServer(Settings("service-a", "secret", "api-a", ISSUER), keys=Keys(), introspect=broken,
                             metadata={"issuer": ISSUER})

    assert get(service, token())[0] == 401


def test_response_is_json(service):
    _, body, _ = get(service, token())

    json.dumps(body)
