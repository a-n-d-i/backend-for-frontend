"""
Token handler: a Backend for Frontend (BFF) for browser-based apps, as in
draft-ietf-oauth-browser-based-apps-27 section 6.1 [BBA 6.1].

The SPA never sees a token. It talks to the BFF with a session cookie; the
BFF runs the OpenID Connect login as a confidential client and keeps the
tokens server side. When it forwards an API request, it adds a token that
was exchanged for exactly that API [RFC 8693], so no token is good for more
than one service.

    GET  /bff/login?return_to=/x     start the login, redirect to the authorization server
    GET  <path of redirect_uri>      callback: exchange the code, start the session
    GET  /bff/session                "check session": is the user logged in, and who [BBA 6.1.2.1]
    POST /bff/logout                 end the session (and get the RP-initiated logout URL)
    POST /bff/backchannel-logout     the authorization server ended the user's session
                                     [OIDC Back-Channel Logout 1.0]
    *    a path prefix in `apis`     API: forwarded upstream with a token for that API

Citations in comments: BBA = draft-ietf-oauth-browser-based-apps-27, the
others are RFCs, OpenID specs and OWASP cheat sheets; docs/oauth-best-practices.md
lists all of them and maps them to this code.
"""
import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
import time
from typing import Any, Optional
from urllib.parse import parse_qs, urlsplit

from apisix.runner.http.request import Request
from apisix.runner.http.response import Response
from apisix.runner.plugin.core import PluginBase

from apisix.plugins import trace
from apisix.plugins.oidc import IdTokenError, OidcError, get_provider
from apisix.plugins.sessions import Session, SessionStore

log = logging.getLogger("tokenhandler")

DEFAULTS = {
    # openid for the ID token; the refresh token comes with the code flow
    # [BBA 6.1.2.2]. No offline_access: offline tokens outlive the SSO session
    # and would survive a single logout.
    "scope": "openid profile email",
    "bff_path": "/bff/",
    # The name prefix sets no attributes, Bff._cookie does. The prefix makes
    # the browser reject the cookie unless those attributes are present
    # [BBA 6.1.3.2]:
    # __Host-: Secure, Path=/, no Domain, from a secure origin. So a subdomain
    #   cannot plant or overwrite it (cookie tossing / session fixation).
    # __Host-Http-: additionally HttpOnly, so it can only come from a
    #   Set-Cookie header, never from document.cookie (injected script).
    # Browsers without prefix support accept the cookie anyway.
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#cookie_prefixes
    # https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis#name-cookie-name-prefixes
    "cookie_name": "__Host-Http-bff-session",
    # static header every SPA request must carry [BBA 6.1.3.3.2]
    "csrf_header": "X-BFF-CSRF",
    # absolute session lifetime; should not exceed the refresh token's [BBA 6.1.2.2]
    "session_lifetime": 8 * 3600,
    # [OWASP Session: idle timeout]
    "session_idle_timeout": 30 * 60,
    # how long a started login may take until the callback
    "login_timeout": 10 * 60,
    # refresh the access token this long before it expires
    "refresh_margin": 30,
    # where the authorization server sends the user after RP-initiated logout;
    # default: the app's origin
    "post_logout_redirect_uri": None,
    # plain http to the authorization server, for a local dev stack only
    "allow_insecure_http": False,
    # trust anchor for TLS to the authorization server (PEM); default: system CAs
    "ca_file": None,
    # the APIs behind the BFF: path prefix -> {"audience", "scope"} the
    # token for it is exchanged for. The allowlist of APIs [BBA 6.1.3.6]:
    # other paths are refused.
    "apis": {},
    # DEV/TEST ONLY: file for the traffic trace of requests with X-Trace-Id,
    # see plugins/trace.py. Holds tokens in clear text.
    "trace_file": None,
}
REQUIRED = ("issuer", "client_id", "client_secret", "redirect_uri")

# claims the SPA gets from /bff/session; tokens and everything else stay here [BBA 6.1.2.4]
USER_CLAIMS = ("sub", "name", "preferred_username", "email", "email_verified")

# all sessions of this runner, shared by every request (plugin objects are per request)
store = SessionStore()


class TokenHandler(PluginBase):

    def name(self) -> str:
        """
        Name the plugin is registered under; referenced from apisix.yaml.
        """
        return "tokenhandler"

    def config(self, conf: Any) -> Any:
        """
        Parse the `value` string configured in ext-plugin-pre-req.
        """
        conf = {**DEFAULTS, **json.loads(conf or "{}")}
        missing = [key for key in REQUIRED if not conf.get(key)]
        if missing:
            raise ValueError(f"tokenhandler config lacks {', '.join(missing)}")
        return conf

    def filter(self, conf: Any, request: Request, response: Response):
        """
        Runs before the request is proxied upstream. BFF endpoints answer here
        (a status on `response` stops the request in the gateway); API
        requests get their access token and continue upstream.
        """
        trace.start(conf["trace_file"], _header(request, trace.TRACE_HEADER))
        try:
            Bff(conf, request, response).handle()
        except OidcError as e:
            log.error("authorization server error: %s", e)
            _json(response, 502, {"error": "authorization_server_unavailable"})
        except Exception:
            # the runner would turn an exception into an opaque gateway error
            log.exception("tokenhandler failed")
            _json(response, 500, {"error": "internal_error"})
        finally:
            trace.stop()


class Bff:
    """Handles one request."""

    def __init__(self, conf: dict, request: Request, response: Response):
        self.conf = conf
        self.request = request
        self.response = response
        self.provider = get_provider(conf["issuer"], conf["client_id"], conf["client_secret"],
                                     conf["allow_insecure_http"], ca_file=conf["ca_file"])
        redirect = urlsplit(conf["redirect_uri"])
        self.callback_path = redirect.path
        self.origin = f"{redirect.scheme}://{redirect.netloc}"

    def handle(self):
        path = self.request.get_uri()
        bff = self.conf["bff_path"]
        if path == self.callback_path:
            self.callback()
        elif path == bff + "login":
            self.login()
        elif path == bff + "session":
            self.session_info()
        elif path == bff + "logout":
            self.logout()
        elif path == bff + "backchannel-logout":
            self.backchannel_logout()
        elif path.startswith(bff):
            _json(self.response, 404, {"error": "not_found"})
        else:
            # Everything else that the route sends here is an API. The `apis`
            # config and the routes are the allowlist of upstreams: the
            # destination never comes from the request [BBA 6.1.3.6].
            self.proxy()

    # -- endpoints ---------------------------------------------------------

    def login(self):
        if not self._method("GET"):
            return
        # A login always starts a new session: whatever the browser had is dropped.
        store.delete(self._session_id())

        state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
        pending = Session(
            expires_at=time.time() + self.conf["login_timeout"],
            idle_timeout=self.conf["login_timeout"],
            state=state, nonce=nonce, code_verifier=verifier,
            return_to=_local_path(self.request.get_arg("return_to")),
        )
        # PKCE S256 challenge [RFC 7636 4.2]
        challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
        url = self.provider.authorization_url(self.conf["redirect_uri"], self.conf["scope"], state, nonce, challenge)
        trace.note("New login: random state, nonce and PKCE code_verifier, kept in a pending session. "
                   "code_challenge = BASE64URL(SHA256(code_verifier)); the verifier itself stays here.",
                   ["RFC 7636 4.1", "RFC 7636 4.2", "RFC 9700 4.7.1", "OIDC Core 3.1.2.1"],
                   state=state, nonce=nonce, code_verifier=verifier, code_challenge=challenge)

        # The pending login is bound to this browser by the cookie, which is
        # what makes `state` a CSRF defense [RFC 9700 4.7.1]. SameSite=Lax,
        # not Strict: the callback is a top-level navigation coming from the
        # authorization server, a cross-site one if that server is on another
        # site, and a Strict cookie would not be sent along.
        self._redirect(url, cookie=self._cookie(store.create(pending), "Lax"))

    def callback(self):
        if not self._method("GET"):
            return
        session_id = self._session_id()
        pending = store.get(session_id)
        # single use: the pending login is gone whatever happens next
        store.delete(session_id)
        if pending is None or not pending.pending:
            return self._login_failed("no login in progress")

        if not _equal(self.request.get_arg("state"), pending.state):
            return self._login_failed("state mismatch")
        trace.note("state matches the pending login bound to this browser's cookie; "
                   "the pending login is used up.", ["RFC 9700 4.7.1", "RFC 6749 10.12"], state=pending.state)

        # mix-up defense: the response must come from our issuer [RFC 9207; RFC 9700 4.4.2.1]
        iss = self.request.get_arg("iss")
        if (iss is not None or self.provider.metadata.get("authorization_response_iss_parameter_supported")) \
                and iss != self.provider.issuer:
            return self._login_failed("issuer mismatch")

        error = self.request.get_arg("error")
        if error:
            return self._login_failed(f"authorization server: {error}")
        code = self.request.get_arg("code")
        if not code:
            return self._login_failed("no code")

        # confidential client: code + PKCE verifier + client secret [BBA 6.1.3.1; RFC 7636 4.5]
        try:
            tokens = self.provider.exchange_code(code, self.conf["redirect_uri"], pending.code_verifier)
        except OidcError as e:
            if e.error is None:
                raise
            return self._login_failed(f"token endpoint: {e.error}")
        if not tokens.get("id_token"):
            return self._login_failed("no ID token, is `openid` in the scope?")
        try:
            claims = self.provider.validate_id_token(tokens["id_token"], pending.nonce)
        except IdTokenError as e:
            return self._login_failed(str(e))
        trace.note("ID token valid: signature with a key from jwks_uri, iss, aud, exp, iat and the nonce "
                   "of this login.", ["OIDC Core 3.1.3.7", "RFC 9700 4.5.3.2"], nonce=pending.nonce, sub=claims["sub"])

        now = time.time()
        session = Session(
            expires_at=now + self.conf["session_lifetime"],
            idle_timeout=self.conf["session_idle_timeout"],
            user={k: claims[k] for k in USER_CLAIMS if k in claims},
            # the authorization server's session, for back-channel logout
            sid=claims.get("sid"),
            trace_id=trace.current_id(),
        )
        self._store_tokens(session, tokens)
        log.info("login of %s", claims["sub"])
        # A new id after authentication: an id the browser had before login
        # (planted or not) never becomes an authenticated session
        # [OWASP Session: renew the session ID after login].
        # The session cookie is SameSite=Strict [BBA 6.1.3.2]: the SPA calls
        # the BFF same-site only.
        session_id = store.create(session)
        trace.note("Session created under a new id; tokens stay in the server-side session, the browser "
                   "gets only the id.", ["BBA 6.1.2.3", "OWASP Session"], session_id=session_id)
        self._redirect(pending.return_to, cookie=self._cookie(session_id, "Strict"))

    def session_info(self):
        if not self._method("GET") or not self._csrf_ok():
            return
        session = store.get(self._session_id())
        if session is None or not session.authenticated:
            return _json(self.response, 200, {"authenticated": False})
        _json(self.response, 200, {"authenticated": True, "user": session.user})

    def logout(self):
        # POST + custom header: a cross-site page cannot log the user out [OWASP CSRF]
        if not self._method("POST") or not self._csrf_ok():
            return
        session = store.delete(self._session_id())
        logout_url = None
        if session is not None and session.authenticated:
            if session.refresh_token:
                # the refresh token outlives the session otherwise [RFC 7009]
                self.provider.revoke(session.refresh_token)
            logout_url = self.provider.end_session_url(
                session.id_token, self.conf["post_logout_redirect_uri"] or self.origin + "/")
        # the SPA navigates to logout_url (if any) to end the session at the authorization server too
        _json(self.response, 200, {"logout_url": logout_url}, cookie=self._cookie("", "Strict", clear=True))

    def proxy(self):
        if not self._csrf_ok():
            return
        api = self._api()
        if api is None:
            # not in the allowlist of APIs [BBA 6.1.3.6]
            return _json(self.response, 404, {"error": "not_found"})
        session = store.get(self._session_id())
        if session is None or not session.authenticated:
            return _json(self.response, 401, {"error": "unauthenticated"})
        token = self._api_token(session, api)
        if token is None:
            store.delete(self._session_id())
            return _json(self.response, 401, {"error": "session_expired"},
                         cookie=self._cookie("", "Strict", clear=True))

        # The token is added here, on the way upstream; it never reaches the
        # browser [BBA 6.1.1]. It replaces any Authorization header the
        # browser sent. The session cookie and the CSRF header are BFF
        # internals and are not passed on (an empty value removes the header).
        headers = self.request.get_headers()
        for name in list(headers):
            if name.lower() == "authorization":
                del headers[name]
            elif name.lower() in ("cookie", self.conf["csrf_header"].lower()):
                headers[name] = ""
        headers["Authorization"] = f"Bearer {token}"
        self.request.set_headers(headers)
        trace.emit("forward", method=self.request.get_method(), path=self.request.get_uri(), audience=api["audience"],
                   headers=[[k, v] for k, v in headers.items() if v], removed=[k for k, v in headers.items() if not v])

    def backchannel_logout(self):
        """
        The authorization server ended the user's session there, e.g. after a
        logout in another application: end ours too [OIDC Back-Channel Logout
        1.0, 2.5-2.8]. Server to server: no cookie, no CSRF header; the signed
        logout token is the authentication.
        """
        if not self._method("POST"):
            return
        t_start = time.time()
        body = self.request.get_body() or ""
        logout_token = parse_qs(body).get("logout_token", [None])[0]
        try:
            if not logout_token:
                raise IdTokenError("no logout_token")
            claims = self.provider.validate_logout_token(logout_token)
        except IdTokenError as e:
            log.warning("back-channel logout refused: %s", e)
            return _json(self.response, 400, {"error": "invalid_request", "error_description": str(e)})

        # by session id if given, else every session of the user [2.4]
        sid, sub = claims.get("sid"), claims.get("sub")
        ended = store.delete_where(lambda s: s.authenticated and (s.sid == sid if sid else s.user["sub"] == sub))
        log.info("back-channel logout of sid %s: %d session(s) ended", sid, len(ended))
        # [2.8] 200 OK, not cached
        _json(self.response, 200, {})
        self._trace_backchannel(ended, body, t_start, sid)

    def _trace_backchannel(self, ended: list, body: str, t_start: float, sid: Optional[str]):
        # DEV ONLY: the authorization server sends no X-Trace-Id; record the
        # request in the trace of the login whose session it ended
        for session in ended:
            trace.start(self.conf["trace_file"], session.trace_id)
            trace.emit("incoming", method="POST", url=self.origin + self.request.get_uri(),
                       req_headers=[[k, v] for k, v in self.request.get_headers().items()], req_body=body,
                       status=self.response.get_status_code(),
                       resp_headers=[[k, v] for k, v in self.response.get_headers().items()],
                       resp_body=self.response.get_body(), t_start=t_start, t_end=time.time())
            trace.note("Back-channel logout: the logout token is valid (signature, iss, aud, iat, jti not seen "
                       "before, the logout event, no nonce), so the BFF session with this sid is gone.",
                       ["OIDC BCL 2.6", "OIDC BCL 2.8"], sid=sid)
            trace.stop()

    # -- tokens ------------------------------------------------------------

    def _api(self) -> Optional[dict]:
        """The `apis` entry for this request: longest matching path prefix."""
        path = self.request.get_uri()
        prefix = max((p for p in self.conf["apis"] if path.startswith(p)), key=len, default=None)
        return None if prefix is None else {"prefix": prefix, **self.conf["apis"][prefix]}

    def _api_token(self, session: Session, api: dict) -> Optional[str]:
        """
        A token only for this API: the session's access token exchanged for
        the API's audience and scope [RFC 8693; RFC 9700 2.3]. Cached until
        shortly before it expires; None if the session is over.
        """
        audience = api["audience"]
        with session.lock:
            cached = session.service_tokens.get(audience)
            if cached and cached[1] - self.conf["refresh_margin"] > time.time():
                return cached[0]
            subject = self._fresh_access_token(session)
            if subject is None:
                return None
            try:
                tokens = self.provider.exchange_token(subject, audience, api["scope"])
            except OidcError as e:
                if e.error is None:
                    raise
                # the subject token was refused: the session at the authorization server is over
                log.warning("token exchange for %s failed for %s: %s", audience, session.user["sub"], e.error)
                return None
            session.service_tokens[audience] = (tokens["access_token"],
                                                time.time() + int(tokens.get("expires_in") or 60))
            trace.note(f"Token exchange: the session's access token became one for {audience} only "
                       f"(scope {api['scope']}), cached until shortly before it expires.",
                       ["RFC 8693 2.1", "RFC 9700 2.3"], audience=audience)
            return tokens["access_token"]

    def _store_tokens(self, session: Session, tokens: dict):
        session.access_token = tokens["access_token"]
        expires_in = tokens.get("expires_in")
        session.access_token_expires_at = time.time() + int(expires_in) if expires_in else None
        # with refresh token rotation the server hands out a new one each time
        if tokens.get("refresh_token"):
            session.refresh_token = tokens["refresh_token"]
        if tokens.get("id_token"):
            session.id_token = tokens["id_token"]

    def _fresh_access_token(self, session: Session) -> Optional[str]:
        """The session's access token, refreshed if it is about to expire; None if that is impossible."""
        with session.lock:
            expires_at = session.access_token_expires_at
            if expires_at is None or expires_at - self.conf["refresh_margin"] > time.time():
                return session.access_token
            if not session.refresh_token:
                return None
            trace.note("Access token about to expire: refresh it with the refresh token and client "
                       "authentication.", ["BBA 6.1.2.2", "RFC 6749 6"], refresh_token=session.refresh_token)
            try:
                tokens = self.provider.refresh(session.refresh_token)
                if tokens.get("id_token"):
                    self.provider.validate_id_token(tokens["id_token"], None, expected_sub=session.user["sub"])
            except OidcError as e:
                if e.error is None:
                    raise
                # invalid_grant: revoked, expired or (rotation) reused refresh token
                log.warning("refresh failed for %s: %s", session.user["sub"], e.error)
                return None
            except IdTokenError as e:
                log.warning("refresh for %s returned a bad ID token: %s", session.user["sub"], e)
                return None
            self._store_tokens(session, tokens)
            return session.access_token

    # -- request checks ----------------------------------------------------

    def _csrf_ok(self) -> bool:
        """
        CSRF defense for everything the SPA calls with the session cookie [BBA 6.1.3.3].
        """
        # The custom header: a cross-origin page can only send it after a CORS
        # preflight, and the BFF answers no preflight (it sends no CORS
        # headers at all), so only same-origin JavaScript gets here
        # [BBA 6.1.3.3.2; OWASP CSRF: custom request headers].
        ok = self._header(self.conf["csrf_header"]) == "1"
        # Fetch Metadata and Origin, where the browser sends them, as a second
        # line of defense [OWASP CSRF: Fetch Metadata, verifying origin].
        site = self._header("Sec-Fetch-Site")
        if site is not None and site != "same-origin":
            ok = False
        origin = self._header("Origin")
        if origin is not None and origin != self.origin:
            ok = False
        if not ok:
            log.warning("CSRF check failed for %s %s", self.request.get_method(), self.request.get_uri())
            trace.note(f"CSRF check failed: {self.conf['csrf_header']}={self._header(self.conf['csrf_header'])!r}, "
                       f"Sec-Fetch-Site={site!r}, Origin={origin!r}", ["BBA 6.1.3.3", "OWASP CSRF"])
            _json(self.response, 403, {"error": "csrf_check_failed"})
        return ok

    def _method(self, method: str) -> bool:
        if self.request.get_method() != method:
            _json(self.response, 405, {"error": "method_not_allowed"}, extra={"Allow": method})
            return False
        return True

    def _header(self, name: str) -> Optional[str]:
        return _header(self.request, name)

    def _session_id(self) -> Optional[str]:
        """Value of our cookie in the Cookie header."""
        for pair in (self._header("Cookie") or "").split(";"):
            name, _, value = pair.strip().partition("=")
            if name == self.conf["cookie_name"]:
                return value
        return None

    # -- responses ---------------------------------------------------------

    def _cookie(self, value: str, same_site: str, clear: bool = False) -> str:
        # The attributes are set here [BBA 6.1.3.2]. HttpOnly: no JavaScript
        # access, XSS cannot steal the session. Secure, HttpOnly, Path=/ and no
        # Domain are also what the __Host-Http- name prefix requires (see
        # DEFAULTS["cookie_name"]); without them the browser drops the cookie.
        # No Expires/Max-Age: gone when the browser closes, the server enforces
        # the lifetimes anyway.
        cookie = f"{self.conf['cookie_name']}={value}; Path=/; Secure; HttpOnly; SameSite={same_site}"
        return cookie + "; Max-Age=0" if clear else cookie

    def _redirect(self, location: str, cookie: Optional[str] = None):
        headers = {"Location": location, "Cache-Control": "no-store",
                   # the callback URL holds code and state: never leak it as Referer [RFC 9700 4.2.4]
                   "Referrer-Policy": "no-referrer"}
        if cookie:
            headers["Set-Cookie"] = cookie
        self.response.set_status_code(302)
        self.response.set_headers(headers)
        # the runner only sends a response that has a body
        self.response.set_body(" ")

    def _login_failed(self, reason: str):
        log.warning("login failed: %s", reason)
        trace.note(f"Login refused: {reason}. The pending login is dropped, the cookie cleared.",
                   ["RFC 9700 4.7", "OIDC Core 3.1.3.7"])
        _json(self.response, 400, {"error": "login_failed", "reason": reason},
              cookie=self._cookie("", "Lax", clear=True))


def _json(response: Response, status: int, body: dict, cookie: Optional[str] = None, extra: Optional[dict] = None):
    headers = {
        "Content-Type": "application/json",
        # session state and user data must not be cached anywhere [OWASP Session: caching]
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        **(extra or {}),
    }
    if cookie:
        headers["Set-Cookie"] = cookie
    response.set_status_code(status)
    response.set_headers(headers)
    response.set_body(json.dumps(body))


_SAFE_PATH = re.compile(r"/(?![/\\])[\x21-\x7e]*")


def _local_path(value: Optional[str]) -> str:
    """
    `value` if it is a path on this origin, else "/". The BFF must not become
    an open redirector [RFC 9700 4.11.1; OWASP OAuth2 #1]: no scheme, no
    `//host` or `/\\host`, no whitespace or control characters.
    """
    if value and len(value) <= 2048 and _SAFE_PATH.fullmatch(value):
        return value
    return "/"


def _header(request: Request, name: str) -> Optional[str]:
    name = name.lower()
    for key, value in request.get_headers().items():
        if key.lower() == name:
            return value
    return None


def _equal(a: Optional[str], b: Optional[str]) -> bool:
    # constant time, so `state` cannot be guessed byte by byte from timing
    return a is not None and b is not None and hmac.compare_digest(a.encode(), b.encode())


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
