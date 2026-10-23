import time

import pytest
import requests
from bff_client import GATEWAY_URL, Browser, start_login, submit_login


@pytest.fixture(scope="session")
def gateway():
    """Base URL of the running APISIX, waiting until it proxies requests."""
    deadline = time.monotonic() + 30
    while True:
        try:
            if requests.get(f"{GATEWAY_URL}/bff/session", timeout=2).status_code == 403:
                return GATEWAY_URL
        except requests.ConnectionError:
            pass
        if time.monotonic() > deadline:
            pytest.fail(f"APISIX with the tokenhandler not reachable at {GATEWAY_URL}")
        time.sleep(1)


@pytest.fixture(scope="session")
def oidc(gateway):
    """Discovery document of Dex, proxied by APISIX under /dex."""
    deadline = time.monotonic() + 10
    while True:
        resp = requests.get(f"{gateway}/dex/.well-known/openid-configuration", timeout=2)
        if resp.status_code == 200:
            return resp.json()
        if time.monotonic() > deadline:
            pytest.fail(f"Dex not reachable through APISIX: {resp.status_code} (is the dex container running?)")
        time.sleep(1)


@pytest.fixture
def browser(gateway):
    with Browser() as b:
        yield b


@pytest.fixture
def logged_in(browser, gateway):
    """A browser with an authenticated BFF session."""
    resp = submit_login(browser, start_login(browser, gateway))
    assert resp.status_code == 303
    resp = browser.get(resp.headers["Location"], allow_redirects=False, timeout=10)
    assert resp.status_code == 302, resp.text
    return browser
