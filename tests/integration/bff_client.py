"""
Helpers for driving the stack like a browser, shared by the integration tests.
(Not in conftest.py: test modules importing from `conftest` would get
whichever conftest pytest imported last.)

All URLs are the public https ones; the dev CA is trusted via
REQUESTS_CA_BUNDLE (root conftest.py).
"""
import base64
import hashlib
import json
import os
import re
import secrets
from html import unescape
from urllib.parse import parse_qs, urljoin, urlsplit

import requests

APP_URL = os.environ.get("APP_URL", "https://app.example.test")
ISSUER = os.environ.get("ISSUER", "https://auth.example.test/realms/demo")
OIDC = f"{ISSUER}/protocol/openid-connect"
# direct addresses of the services, bypassing the gateway (zero-trust tests)
SERVICE_A = os.environ.get("SERVICE_A_URL", "http://service-a:7001")
SERVICE_B = os.environ.get("SERVICE_B_URL", "http://service-b:7002")

# from conf/apisix.yaml and conf/keycloak/demo-realm.json
COOKIE_NAME = "__Host-Http-bff-session"
CSRF = {"X-BFF-CSRF": "1"}
USERNAME = "alice"
PASSWORD = "alice-password"
BFF_CLIENT = ("bff", "bff-secret")
REDIRECT_URI = f"{APP_URL}/bff/callback"
TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


class Browser(requests.Session):
    """
    A requests session as a browser stand-in: keeps cookies (the BFF's and
    Keycloak's SSO cookies) and records every Set-Cookie of the BFF cookie in
    `bff_cookies` for assertions.
    """

    def __init__(self):
        super().__init__()
        self.bff_cookies = []
        self.hooks["response"].append(self._track)

    def _track(self, resp, **kwargs):
        self.bff_cookies += [h for h in resp.raw.headers.getlist("Set-Cookie") if h.startswith(f"{COOKIE_NAME}=")]

    @property
    def session_id(self):
        return next((c.value for c in self.cookies if c.name == COOKIE_NAME), None)

    def set_session_id(self, value):
        """Plants a BFF cookie value, e.g. an old session id."""
        self.cookies.set(COOKIE_NAME, value, domain=urlsplit(APP_URL).hostname, path="/", secure=True)


def start_login(browser, return_to="/"):
    """Starts a login at the BFF; returns the response with Keycloak's login form."""
    resp = browser.get(f"{APP_URL}/bff/login", params={"return_to": return_to}, timeout=10)
    assert resp.status_code == 200, resp.text
    assert 'name="password"' in resp.text, "no login form: an SSO session already exists?"
    return resp


def submit_login(browser, form_page, password=PASSWORD):
    """Posts Keycloak's login form; returns its answer without following redirects."""
    action = re.search(r'<form[^>]*action="([^"]+)"', form_page.text).group(1)
    return browser.post(urljoin(form_page.url, unescape(action)),
                        data={"username": USERNAME, "password": password}, allow_redirects=False, timeout=10)


def log_in(browser, return_to="/"):
    """Full BFF login; returns the callback's response."""
    resp = submit_login(browser, start_login(browser, return_to))
    assert resp.status_code == 302, resp.text
    resp = browser.get(resp.headers["Location"], allow_redirects=False, timeout=10)
    assert resp.status_code == 302, resp.text
    return resp


def keycloak_logout(browser):
    """Ends the Keycloak SSO session from the browser, as another application would."""
    page = browser.get(f"{OIDC}/logout", timeout=10)
    form = re.search(r'<form[^>]*action="([^"]+)"', page.text)
    if form:  # Keycloak asks to confirm a logout without id_token_hint
        fields = dict(re.findall(r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', page.text))
        page = browser.post(urljoin(page.url, unescape(form.group(1))), data=fields, timeout=10)
    return page


def keycloak_tokens(browser=None):
    """
    Tokens of the `bff` client, obtained directly from Keycloak (code flow
    with PKCE, the code taken out of the redirect to the BFF), for tests
    that need real tokens the BFF would never hand out.
    """
    browser = browser or Browser()
    verifier = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    page = browser.get(f"{OIDC}/auth", params={
        "client_id": BFF_CLIENT[0], "redirect_uri": REDIRECT_URI, "response_type": "code",
        "scope": "openid profile email", "state": "test", "nonce": "test",
        "code_challenge": challenge, "code_challenge_method": "S256"}, allow_redirects=False, timeout=10)
    resp = page if page.status_code == 302 else submit_login(browser, page)
    code = parse_qs(urlsplit(resp.headers["Location"]).query)["code"][0]
    tokens = requests.post(f"{OIDC}/token", auth=BFF_CLIENT, timeout=10, data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI,
        "code_verifier": verifier})
    assert tokens.status_code == 200, tokens.text
    return tokens.json()


def exchange(subject_token, audience, scope, client=BFF_CLIENT):
    """RFC 8693 token exchange at Keycloak; returns the response."""
    return requests.post(f"{OIDC}/token", auth=client, timeout=10, data={
        "grant_type": TOKEN_EXCHANGE, "subject_token": subject_token, "subject_token_type": ACCESS_TOKEN_TYPE,
        "requested_token_type": ACCESS_TOKEN_TYPE, "audience": audience, "scope": scope})


def claims(token):
    """Claims of a JWT, unverified (for assertions only)."""
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def header(token):
    head = token.split(".")[0]
    return json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4)))
