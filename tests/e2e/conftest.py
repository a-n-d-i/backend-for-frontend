import re
from html import unescape

import pytest
import requests
from spa_settings import APP_URL


@pytest.fixture(scope="session", autouse=True)
def login_page_reachable():
    """
    Fails fast with Dex's own error if a login cannot start (e.g. Dex still runs
    with an old redirect URI), instead of each browser test timing out.
    """
    try:
        resp = requests.get(f"{APP_URL}/bff/login", timeout=5)
    except requests.ConnectionError as e:
        pytest.fail(f"gateway not reachable at {APP_URL}: {e}")
    if resp.status_code != 200 or 'name="password"' not in resp.text:
        text = " ".join(unescape(re.sub(r"<[^>]+>", " ", resp.text)).split())
        pytest.fail(f"login does not reach the Dex login form ({resp.status_code}): {text[:200]} "
                    "-- after changing conf/dex.yaml, run `docker compose restart dex` in .devcontainer/")
