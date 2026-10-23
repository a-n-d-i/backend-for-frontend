import time

import pytest
import requests
from bff_client import APP_URL, ISSUER, Browser, log_in


def _wait_for(url, ok, what, timeout=90):
    deadline = time.monotonic() + timeout
    while True:
        try:
            resp = requests.get(url, timeout=3)
            if ok(resp):
                return resp
            detail = resp.status_code
        except requests.ConnectionError as e:
            detail = e
        if time.monotonic() > deadline:
            pytest.fail(f"{what} not reachable at {url}: {detail}")
        time.sleep(1)


@pytest.fixture(scope="session")
def gateway():
    """Base URL of the app, waiting until APISIX answers with the BFF."""
    _wait_for(f"{APP_URL}/bff/session", lambda r: r.status_code == 403, "APISIX with the tokenhandler")
    return APP_URL


@pytest.fixture(scope="session")
def oidc(gateway):
    """Discovery document of Keycloak (it starts slowly)."""
    return _wait_for(f"{ISSUER}/.well-known/openid-configuration", lambda r: r.status_code == 200,
                     "Keycloak (is the keycloak container running?)").json()


@pytest.fixture
def browser(gateway, oidc):
    with Browser() as b:
        yield b


@pytest.fixture
def logged_in(browser):
    """A browser with an authenticated BFF session (and a Keycloak SSO session)."""
    log_in(browser)
    return browser
