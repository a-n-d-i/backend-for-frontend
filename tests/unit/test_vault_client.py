"""services/vault.py against a fake Vault (KV v1), and its use by the services."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from services import vault
from services.resource import Settings

SECRETS = {"/v1/kv/bff": {"client_secret": "s3cret"}}
TOKEN = "hvs.bff-token"


class FakeVault(BaseHTTPRequestHandler):
    requests = []

    def do_GET(self):
        FakeVault.requests.append((self.path, self.headers.get("X-Vault-Token")))
        if self.headers.get("X-Vault-Token") != TOKEN:
            status, body = 403, {"errors": ["permission denied"]}
        elif self.path in SECRETS:
            status, body = 200, {"data": SECRETS[self.path], "lease_duration": 2764800}
        else:
            status, body = 404, {"errors": []}
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def log_message(self, *args):
        pass


@pytest.fixture
def addr():
    server = HTTPServer(("127.0.0.1", 0), FakeVault)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    FakeVault.requests = []
    vault._cache.clear()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture
def token_file(tmp_path):
    path = tmp_path / "token"
    path.write_text(TOKEN + "\n")
    return str(path)


def test_reads_a_field_with_the_components_token(addr, token_file):
    assert vault.read("vault:kv/bff#client_secret", addr, token_file) == "s3cret"
    assert FakeVault.requests == [("/v1/kv/bff", TOKEN)]


def test_values_are_cached(addr, token_file):
    vault.read("vault:kv/bff#client_secret", addr, token_file)
    vault.read("vault:kv/bff#client_secret", addr, token_file)

    assert len(FakeVault.requests) == 1


def test_expired_cache_reads_again(addr, token_file, monkeypatch):
    monkeypatch.setattr(vault, "CACHE_SECONDS", -1)

    vault.read("vault:kv/bff#client_secret", addr, token_file)
    vault.read("vault:kv/bff#client_secret", addr, token_file)

    assert len(FakeVault.requests) == 2


@pytest.mark.parametrize("ref, message", [
    ("vault:kv/service-a#client_secret", "404"),   # not there (or: not for this token)
    ("vault:kv/bff#other", "no field"),
    ("vault:kv/bff", "not a vault reference"),
    ("vault:#x", "not a vault reference"),
])
def test_errors(addr, token_file, ref, message):
    with pytest.raises(vault.VaultError, match=message):
        vault.read(ref, addr, token_file)


def test_policy_refusal_is_an_error(addr, tmp_path):
    other = tmp_path / "other-token"
    other.write_text("hvs.someone-else")

    with pytest.raises(vault.VaultError, match="403"):
        vault.read("vault:kv/bff#client_secret", addr, str(other))


def test_missing_token_file(addr, tmp_path):
    with pytest.raises(vault.VaultError, match="no Vault token"):
        vault.read("vault:kv/bff#client_secret", addr, str(tmp_path / "nope"))


def test_unreachable_vault(token_file):
    with pytest.raises(vault.VaultError, match="unreachable"):
        vault.read("vault:kv/bff#client_secret", "http://127.0.0.1:9", token_file)


def test_resolve_replaces_only_references(addr, token_file):
    conf = {"client_secret": "vault:kv/bff#client_secret", "client_id": "bff", "apis": {"x": "vault:kv/y#z"}}

    resolved = vault.resolve(conf, {"addr": addr, "token_file": token_file})

    # top-level references only; nested values stay as they are
    assert resolved == {**conf, "client_secret": "s3cret"}


def test_resolve_needs_vault_settings_for_references():
    with pytest.raises(vault.VaultError, match="not configured"):
        vault.resolve({"client_secret": "vault:kv/bff#client_secret"}, None)

    assert vault.resolve({"client_secret": "plain"}, None) == {"client_secret": "plain"}


def test_service_reads_its_secret_from_vault(addr, token_file):
    settings = Settings("bff", "vault:kv/bff#client_secret", "api-a", "https://idp", addr, token_file)

    assert settings.client_secret == "s3cret"
    assert Settings("x", "literal", "s", "i").client_secret == "literal"
