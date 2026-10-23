"""
Helpers for driving the BFF like a browser, shared by the integration tests.
(Not in conftest.py: test modules importing from `conftest` would get
whichever conftest pytest imported last.)
"""
import os
import re
from html import unescape
from http.cookiejar import DefaultCookiePolicy
from urllib.parse import urljoin

import requests

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://127.0.0.1:9080")

# from conf/apisix.yaml and conf/dex.yaml
COOKIE_NAME = "__Host-Http-bff-session"
CSRF = {"X-BFF-CSRF": "1"}
USERNAME = "admin@example.com"
PASSWORD = "password"


class _IgnoreBffCookie(DefaultCookiePolicy):
    # keeps the jar from storing its own (Secure, never sent) copy of the cookie
    def set_ok(self, cookie, request):
        return cookie.name != COOKIE_NAME and super().set_ok(cookie, request)


class Browser(requests.Session):
    """
    A requests session that keeps the BFF cookie like a browser on localhost.

    The cookie is `Secure`; browsers send it to http://localhost, but
    http.cookiejar only over https. So it is tracked here by hand, and
    every Set-Cookie for it is recorded in `bff_cookies` for assertions.
    """

    def __init__(self):
        super().__init__()
        self.bff_cookies = []
        self.cookies.set_policy(_IgnoreBffCookie())
        self.hooks["response"].append(self._track)

    def _track(self, resp, **kwargs):
        for header in resp.raw.headers.getlist("Set-Cookie"):
            name, _, rest = header.partition("=")
            if name != COOKIE_NAME:
                continue
            self.bff_cookies.append(header)
            value = rest.split(";")[0]
            if "Max-Age=0" in header:
                self.cookies.pop(COOKIE_NAME, None)
            else:
                self.cookies.set(COOKIE_NAME, value)

    @property
    def session_id(self):
        return self.cookies.get(COOKIE_NAME)


def start_login(browser, gateway, return_to="/"):
    """Starts a login at the BFF; returns the response with the Dex login form."""
    resp = browser.get(f"{gateway}/bff/login", params={"return_to": return_to}, timeout=5)
    assert resp.status_code == 200, resp.text
    return resp


def submit_login(browser, form_page, password=PASSWORD):
    """Posts the Dex login form; returns Dex's answer without following redirects."""
    action = re.search(r'<form[^>]*action="([^"]+)"', form_page.text).group(1)
    return browser.post(urljoin(form_page.url, unescape(action)),
                        data={"login": USERNAME, "password": password}, allow_redirects=False, timeout=5)
