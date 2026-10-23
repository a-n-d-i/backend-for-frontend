"""
Vault as the stack's secret store and PKI, against the running Vault:
least-privilege tokens per component, the gateway's certificate from Vault's
PKI, and client secrets that exist only in Vault (and Keycloak).
"""
import json
import socket
import ssl

import pytest
import requests
from bff_client import APP_URL, BFF_CLIENT, DEV, OIDC, VAULT, vault_read
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

COMPONENTS = ("gateway", "bff", "service-a", "service-b")
OWN_SECRET = {"gateway": "kv/gateway/tls", "bff": "kv/bff", "service-a": "kv/service-a", "service-b": "kv/service-b"}


def vault(method, path, token_name, **kwargs):
    token = (DEV / "tokens" / token_name).read_text().strip()
    return requests.request(method, f"{VAULT}/v1/{path}", headers={"X-Vault-Token": token}, timeout=5, **kwargs)


@pytest.mark.parametrize("component", COMPONENTS)
def test_each_component_reads_its_own_secret(component):
    resp = vault_read(OWN_SECRET[component], component)

    assert resp.status_code == 200
    assert resp.json()["data"]


@pytest.mark.parametrize("component, other", [(c, o) for c in COMPONENTS for o in COMPONENTS if c != o])
def test_no_component_reads_another_ones_secret(component, other):
    # least privilege: a leaked service-a token does not reveal the BFF's secret
    assert vault_read(OWN_SECRET[other], component).status_code == 403


@pytest.mark.parametrize("component", COMPONENTS)
def test_component_tokens_cannot_change_or_issue_anything(component):
    assert vault("POST", OWN_SECRET[component], component, json={"x": "y"}).status_code == 403
    assert vault("POST", "pki/issue/example-test", component, json={"common_name": "x.example.test"}).status_code == 403
    assert vault("GET", "sys/mounts", component).status_code == 403


def root_token():
    return json.loads((DEV / "vault-init.json").read_text())["root_token"]


def test_component_token_is_scoped_and_expires():
    # not even Vault's default policy: the token can't look itself up
    assert vault("GET", "auth/token/lookup-self", "bff").status_code == 403

    token = (DEV / "tokens" / "bff").read_text().strip()
    info = requests.post(f"{VAULT}/v1/auth/token/lookup", json={"token": token},
                         headers={"X-Vault-Token": root_token()}, timeout=5).json()["data"]

    assert info["policies"] == ["bff"]
    assert info["orphan"] is True
    assert 0 < info["ttl"] <= 768 * 3600


def test_gateway_serves_the_certificate_from_vault():
    host = APP_URL.split("://")[1]
    with socket.create_connection((host, 443), timeout=5) as sock:
        with ssl.create_default_context(cafile=str(DEV / "ca.pem")).wrap_socket(sock, server_hostname=host) as tls:
            served = x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))
    stored = x509.load_pem_x509_certificate(vault_read("kv/gateway/tls", "gateway").json()["data"]["cert"].encode())

    assert served == stored
    san = served.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    assert set(san.get_values_for_type(x509.DNSName)) == {"*.example.test", "example.test"}


def test_ca_of_vaults_pki_is_name_constrained():
    ca = x509.load_pem_x509_certificate((DEV / "ca.pem").read_bytes())
    constraints = ca.extensions.get_extension_for_oid(ExtensionOID.NAME_CONSTRAINTS)

    # it can vouch for example.test only, even for someone who trusts it
    assert constraints.critical
    assert [n.value for n in constraints.value.permitted_subtrees] == ["example.test"]
    assert ca.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca


def test_the_ca_key_stays_in_vault():
    # Vault keeps the CA key internal: not even the root token can export it
    root = root_token()
    resp = requests.get(f"{VAULT}/v1/pki/issuers?list=true", headers={"X-Vault-Token": root}, timeout=5)
    issuer_id = resp.json()["data"]["keys"][0]
    issuer = requests.get(f"{VAULT}/v1/pki/issuer/{issuer_id}", headers={"X-Vault-Token": root}, timeout=5).json()

    assert "private_key" not in issuer["data"]
    assert requests.get(f"{VAULT}/v1/pki/key/{issuer['data']['key_id']}/export", headers={"X-Vault-Token": root},
                        timeout=5).status_code in (404, 405)


def test_keycloak_knows_the_client_secret_from_vault(oidc):
    # introspection needs client authentication: it works with the secret from Vault ...
    ok = requests.post(f"{OIDC}/token/introspect", auth=BFF_CLIENT, data={"token": "x"}, timeout=5)
    # ... and not with what used to be hard-coded in the repository
    old = requests.post(f"{OIDC}/token/introspect", auth=("bff", "bff-secret"), data={"token": "x"}, timeout=5)

    assert ok.status_code == 200 and ok.json() == {"active": False}
    assert old.status_code == 401


def test_no_secrets_in_the_realm_file():
    realm = (DEV.parent / "conf" / "keycloak" / "demo-realm.json").read_text()

    for component in ("bff", "service-a", "service-b"):
        secret = vault_read(f"kv/{component}", component).json()["data"]["client_secret"]
        assert secret not in realm
