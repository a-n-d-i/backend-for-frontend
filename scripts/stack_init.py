"""
Initializes the dev stack's secrets in Vault. Run as one-shot compose jobs;
every step is idempotent, so it runs on every stack start.

    python scripts/stack_init.py vault      # before everything else (vault-init)
    python scripts/stack_init.py keycloak   # once Keycloak runs (keycloak-init)

`vault`:
  - initializes Vault (1 key share) and unseals it. Unseal key and root token
    go to .dev/vault-init.json: this is a dev stand-in for auto-unseal with a
    KMS/HSM and must never leave your machine;
  - PKI engine `pki`: a root CA whose private key never leaves Vault,
    name-constrained to example.test; a role for *.example.test; a server
    certificate (90 days, renewed 30 days before expiry), stored for the
    gateway in kv/gateway/tls. The CA certificate (public) goes to .dev/ca.pem
    for your browser and the containers;
  - KV engine `kv` (v1, as APISIX reads it): random client secrets for bff,
    service-a and service-b, and Keycloak's bootstrap admin password, created
    once and kept;
  - one policy and token per component (gateway, bff, service-a, service-b),
    each allowed to read only its own secrets. Tokens are re-issued on every
    run and written to .dev/tokens/ (dev stand-in for a platform auth method
    such as AppRole or Kubernetes auth). Keycloak's admin password also goes
    to .dev/, since Keycloak reads it before it can talk to anything.

`keycloak`:
  - sets the client secrets of bff, service-a and service-b in Keycloak (realm
    demo) to the ones in Vault. The realm file contains no secrets.

.dev/ is gitignored. Never commit or publish it.
"""
import datetime
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEV = Path(os.environ.get("DEV_DIR", ROOT / ".dev"))
VAULT = os.environ.get("VAULT_ADDR", "http://vault:8200")
KEYCLOAK = os.environ.get("KEYCLOAK_URL", "http://keycloak:8080")
REALM = "demo"
DOMAIN = "example.test"
SERVICES = ("bff", "service-a", "service-b")
CERT_TTL = "2160h"                               # 90 days
RENEW_BEFORE = datetime.timedelta(days=30)
TOKEN_TTL = "768h"                               # Vault's default max: 32 days, re-issued on every start

POLICIES = {
    # the gateway's TLS certificate and key
    "gateway": 'path "kv/gateway/*" { capabilities = ["read"] }',
    # each OAuth client only its own secret
    "bff": 'path "kv/bff" { capabilities = ["read"] }',
    "service-a": 'path "kv/service-a" { capabilities = ["read"] }',
    "service-b": 'path "kv/service-b" { capabilities = ["read"] }',
}


def log(msg):
    print(f"stack_init: {msg}", flush=True)


# -- HTTP ---------------------------------------------------------------------------

def request(method, url, body=None, headers=None, form=False, ok=(200, 204)):
    data = None
    headers = dict(headers or {})
    if body is not None:
        if form:
            data = urllib.parse.urlencode(body).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    if status not in ok:
        raise RuntimeError(f"{method} {url}: {status} {raw[:300]!r}")
    return status, json.loads(raw) if raw else {}


def wait_for(url, what, timeout=180):
    deadline = time.monotonic() + timeout
    while True:
        try:
            with urllib.request.urlopen(url, timeout=5):
                return
        except urllib.error.HTTPError:
            return  # it answers
        except (urllib.error.URLError, OSError):
            if time.monotonic() > deadline:
                raise SystemExit(f"stack_init: {what} not reachable at {url}")
            time.sleep(2)


def write_private(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(mode=0o600, exist_ok=True)
    path.chmod(0o600)
    path.write_text(content)


# -- Vault --------------------------------------------------------------------------

class Vault:
    def __init__(self, token):
        self.headers = {"X-Vault-Token": token}

    def call(self, method, path, body=None, ok=(200, 204)):
        return request(method, f"{VAULT}/v1/{path}", body, self.headers, ok=ok)[1]

    def read(self, path):
        status, body = request("GET", f"{VAULT}/v1/{path}", headers=self.headers, ok=(200, 404))
        return body.get("data") if status == 200 else None

    def mounted(self):
        return self.call("GET", "sys/mounts")["data"]


def init_and_unseal() -> str:
    """Root token; initializes and unseals Vault as needed."""
    wait_for(f"{VAULT}/v1/sys/health", "Vault")
    state_file = DEV / "vault-init.json"
    _, status = request("GET", f"{VAULT}/v1/sys/init")
    if not status["initialized"]:
        _, init = request("PUT", f"{VAULT}/v1/sys/init", {"secret_shares": 1, "secret_threshold": 1})
        write_private(state_file, json.dumps({"unseal_key": init["keys_base64"][0], "root_token": init["root_token"]},
                                             indent=2))
        log(f"Vault initialized; unseal key and root token in {state_file}")
    if not state_file.exists():
        raise SystemExit(f"stack_init: Vault is initialized but {state_file} is missing: "
                         "remove the vault-data volume to start over")
    state = json.loads(state_file.read_text())
    _, seal = request("GET", f"{VAULT}/v1/sys/seal-status")
    if seal["sealed"]:
        request("PUT", f"{VAULT}/v1/sys/unseal", {"key": state["unseal_key"]})
        log("Vault unsealed")
    return state["root_token"]


def setup_engines(v: Vault):
    mounts = v.mounted()
    if "kv/" not in mounts:
        # v1: the layout APISIX's Vault secret manager reads
        v.call("POST", "sys/mounts/kv", {"type": "kv", "options": {"version": "1"}})
    if "pki/" not in mounts:
        v.call("POST", "sys/mounts/pki", {"type": "pki", "config": {"max_lease_ttl": "87600h"}})


def setup_pki(v: Vault):
    if not v.read("pki/issuers?list=true"):
        # internal: the CA key is generated in Vault and never leaves it
        v.call("POST", "pki/root/generate/internal", {
            "common_name": f"{DOMAIN} dev CA (Vault)",
            "issuer_name": "dev-root",
            "key_type": "ec", "key_bits": 256,
            "ttl": "43800h",
            # name constraint: this CA can only vouch for example.test and its subdomains
            "permitted_dns_domains": [DOMAIN],
        })
        log("PKI: root CA created")
    v.call("POST", f"pki/roles/{DOMAIN.replace('.', '-')}", {
        "allowed_domains": [DOMAIN], "allow_subdomains": True, "allow_bare_domains": True,
        "allow_wildcard_certificates": True, "server_flag": True, "client_flag": False,
        "key_type": "ec", "key_bits": 256, "max_ttl": CERT_TTL,
    })
    ca = v.read("pki/cert/ca")["certificate"]
    (DEV).mkdir(parents=True, exist_ok=True)
    (DEV / "ca.pem").write_text(ca.strip() + "\n")

    current = v.read("kv/gateway/tls")
    expires = datetime.datetime.fromtimestamp(int(current["expiration"]), datetime.timezone.utc) if current else None
    if expires and expires - RENEW_BEFORE > datetime.datetime.now(datetime.timezone.utc):
        log(f"PKI: gateway certificate valid until {expires:%Y-%m-%d}")
        return
    issued = v.call("POST", f"pki/issue/{DOMAIN.replace('.', '-')}", {
        "common_name": f"*.{DOMAIN}", "alt_names": DOMAIN, "ttl": CERT_TTL})["data"]
    v.call("POST", "kv/gateway/tls", {"cert": issued["certificate"], "key": issued["private_key"],
                                      "expiration": str(issued["expiration"])})
    log(f"PKI: gateway certificate issued, valid until "
        f"{datetime.datetime.fromtimestamp(issued['expiration'], datetime.timezone.utc):%Y-%m-%d}")


def setup_secrets(v: Vault):
    for name in SERVICES:
        if not v.read(f"kv/{name}"):
            v.call("POST", f"kv/{name}", {"client_secret": secrets.token_urlsafe(32)})
            log(f"secret: client secret for {name} created")
    admin = v.read("kv/keycloak/admin")
    if not admin:
        admin = {"username": "admin", "password": secrets.token_urlsafe(24)}
        v.call("POST", "kv/keycloak/admin", admin)
        log("secret: Keycloak admin password created")
    # Keycloak reads its bootstrap admin password at start, before it can talk to anything
    write_private(DEV / "keycloak-admin", admin["password"])


def setup_tokens(v: Vault):
    for name, policy in POLICIES.items():
        v.call("PUT", f"sys/policies/acl/{name}", {"policy": policy})
        token_file = DEV / "tokens" / name
        if token_file.exists():
            # the previous token of this component is revoked, not left lying around
            v.call("POST", "auth/token/revoke", {"token": token_file.read_text().strip()}, ok=(200, 204, 400, 403))
        token = v.call("POST", "auth/token/create-orphan", {
            "policies": [name], "no_default_policy": True, "ttl": TOKEN_TTL, "renewable": True,
            "display_name": name, "meta": {"component": name}})["auth"]["client_token"]
        write_private(token_file, token)
    log(f"tokens: {', '.join(POLICIES)} (policies: read own secrets only) in {DEV / 'tokens'}")


def cmd_vault():
    v = Vault(init_and_unseal())
    setup_engines(v)
    setup_pki(v)
    setup_secrets(v)
    setup_tokens(v)


# -- Keycloak -----------------------------------------------------------------------

def cmd_keycloak():
    v = Vault(init_and_unseal())
    wait_for(f"{KEYCLOAK}/realms/{REALM}/.well-known/openid-configuration", "Keycloak", timeout=300)
    admin = v.read("kv/keycloak/admin")
    _, tokens = request("POST", f"{KEYCLOAK}/realms/master/protocol/openid-connect/token", form=True, body={
        "grant_type": "password", "client_id": "admin-cli",
        "username": admin["username"], "password": admin["password"]})
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    base = f"{KEYCLOAK}/admin/realms/{REALM}/clients"
    for name in SERVICES:
        secret = v.read(f"kv/{name}")["client_secret"]
        _, found = request("GET", f"{base}?clientId={name}", headers=headers)
        client = found[0]
        _, current = request("GET", f"{base}/{client['id']}/client-secret", headers=headers)
        if current.get("value") != secret:
            client["secret"] = secret
            request("PUT", f"{base}/{client['id']}", client, headers=headers)
            log(f"Keycloak: client secret of {name} set from Vault")
    log("Keycloak: client secrets match Vault")


if __name__ == "__main__":
    commands = {"vault": cmd_vault, "keycloak": cmd_keycloak}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        raise SystemExit(f"usage: {sys.argv[0]} {{{','.join(commands)}}}")
    commands[sys.argv[1]]()
