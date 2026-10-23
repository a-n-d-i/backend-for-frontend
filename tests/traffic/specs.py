"""
What each recorded message is an example of: rules matching the traffic to
the RFCs, drafts and OWASP cheat sheets it illustrates, and links to them.
The same tags as in the code comments and docs/oauth-best-practices.md.
"""
import json
import re
from urllib.parse import parse_qs, urlsplit

BBA = "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps-27"
OIDC_CORE = "https://openid.net/specs/openid-connect-core-1_0.html"
OIDC_CORE_ANCHORS = {
    "3.1.2.1": "AuthRequest",
    "3.1.2.5": "AuthResponse",
    "3.1.3.3": "TokenResponse",
    "3.1.3.7": "IDTokenValidation",
    "12.2": "RefreshTokenResponse",
}
OWASP = {
    "OWASP OAuth2": "https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html",
    "OWASP Session": "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
    "OWASP CSRF": "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
    "OWASP Headers": "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
}


def ref_url(ref: str) -> str:
    """Link for a citation tag such as `RFC 7636 4.2`, `BBA 6.1.3.2` or `OIDC Core 3.1.3.7`."""
    m = re.fullmatch(r"RFC (\d+)(?: ([\d.]+))?", ref)
    if m:
        url = f"https://www.rfc-editor.org/rfc/rfc{m[1]}"
        return url + (f"#section-{m[2]}" if m[2] else "")
    m = re.fullmatch(r"BBA ([\d.]+)", ref)
    if m:
        return f"{BBA}#section-{m[1]}"
    m = re.fullmatch(r"OIDC Core ([\d.]+)", ref)
    if m:
        anchor = OIDC_CORE_ANCHORS.get(m[1])
        return OIDC_CORE + (f"#{anchor}" if anchor else "")
    if ref == "OIDC Discovery":
        return "https://openid.net/specs/openid-connect-discovery-1_0.html"
    if ref.startswith("OIDC BCL"):
        return "https://openid.net/specs/openid-connect-backchannel-1_0.html"
    if ref.startswith("OIDC RP-Initiated Logout"):
        return "https://openid.net/specs/openid-connect-rpinitiated-1_0.html"
    for prefix, url in OWASP.items():
        if ref.startswith(prefix):
            return url
    return ""


def header(headers, name: str) -> list:
    return [v for k, v in headers if k.lower() == name.lower()]


def form(body) -> dict:
    if not body or "=" not in body or body.lstrip().startswith(("{", "<")):
        return {}
    return {k: v[0] for k, v in parse_qs(body, keep_blank_values=True).items()}


def json_body(body):
    try:
        return json.loads(body) if body else None
    except ValueError:
        return None


def annotate(ex, cookie_prefix="__Host-") -> list:
    """[(explanation, [refs])] for one exchange."""
    out = []
    url = urlsplit(ex.url)
    path = url.path
    query = {k: v[0] for k, v in parse_qs(url.query).items()}
    req_form = form(ex.req_body)
    resp_json = json_body(ex.resp_body)
    location = (header(ex.resp_headers, "location") or [""])[0]
    loc_query = {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}
    set_cookies = [c for c in header(ex.resp_headers, "set-cookie") if c.startswith(cookie_prefix)]
    from_browser = ex.src == "browser"
    to_keycloak = ex.dst == "keycloak"
    to_service = ex.dst in ("service-a", "service-b")
    oidc = "/protocol/openid-connect/"

    def add(text, *refs):
        out.append((text, list(refs)))

    # -- front channel: browser and gateway/BFF ---------------------------------
    if from_browser and ex.method == "OPTIONS":
        add("CORS preflight: the BFF grants none (no Access-Control-* headers), so no other origin "
            "can send the custom CSRF header.", "BBA 6.1.3.3.2")
    if from_browser and path == "/bff/login":
        add("Login endpoint of the BFF. The SPA navigates here (no fetch), so the browser itself follows "
            "the redirect to the authorization server.", "BBA 6.1.2.1")
        if "return_to" in query:
            add("return_to is only accepted as a local path, else the BFF would be an open redirector.",
                "RFC 9700 4.11.1", "OWASP OAuth2 #1")
    if "code_challenge" in loc_query:
        add("Authorization request (code flow) as a redirect: response_type=code, the registered "
            "redirect_uri, a PKCE S256 code_challenge (the verifier stays in the BFF), state against CSRF, "
            "nonce for the ID token.",
            "RFC 6749 4.1.1", "RFC 7636 4.3", "RFC 9700 2.1.1", "RFC 9700 4.7.1", "OIDC Core 3.1.2.1")
    for cookie in set_cookies:
        if "Max-Age=0" in cookie:
            add("The session cookie is deleted (Max-Age=0).", "OWASP Session")
        elif "SameSite=Lax" in cookie:
            add("Cookie of the pending login: __Host-Http- prefix, Secure, HttpOnly, Path=/, no Domain. "
                "SameSite=Lax so it survives the top-level redirect back from the authorization server.",
                "BBA 6.1.3.2", "RFC 9700 4.7.1")
        elif "SameSite=Strict" in cookie:
            add("Session cookie after login: a new id (never the pre-login one), SameSite=Strict, HttpOnly. "
                "It holds only an opaque id, the tokens stay in the BFF.",
                "BBA 6.1.3.2", "BBA 6.1.2.3", "OWASP Session")
    if from_browser and to_keycloak and path.endswith(oidc + "auth"):
        add("Authorization endpoint of Keycloak (through the gateway, TLS). With an SSO session it answers "
            "at once with a code, without asking for the password: single sign-on.", "RFC 6749 3.1")
    if from_browser and to_keycloak and "/login-actions/authenticate" in path and "password" in req_form:
        add("The user's credentials go to the authorization server only, never to the SPA or the BFF "
            "(no password grant).", "RFC 9700 2.4")
    if "code" in loc_query and "state" in loc_query:
        add(f"Authorization response: code and state to the registered redirect_uri, plus iss to identify "
            f"the authorization server (mix-up defense). A {ex.status} redirect, never 307, which would make "
            f"the browser resend the posted credentials.",
            "RFC 6749 4.1.2", "RFC 9207", "RFC 9700 4.12", "OIDC Core 3.1.2.5")
    if from_browser and path == "/bff/callback":
        add("Callback (redirection endpoint) of the BFF: checks state and iss against the pending login, "
            "exchanges the code, starts the session, redirects back to the SPA.",
            "BBA 6.1.2.1", "RFC 6749 3.1.2", "RFC 9207")
    if from_browser and path == "/bff/session":
        add("Check-session endpoint: whether and as whom the user is logged in, claims only, never tokens.",
            "BBA 6.1.2.1", "BBA 6.1.2.4")
    if from_browser and path == "/bff/logout":
        add("Logout: POST with the custom header, so other sites cannot trigger it. The BFF session is "
            "deleted server-side; the answer carries the URL for RP-initiated logout at Keycloak.",
            "BBA 6.1.2.1", "OWASP CSRF", "OWASP Session")
    if from_browser and to_keycloak and path.endswith(oidc + "logout"):
        if "id_token_hint" in query:
            add("RP-initiated logout: the browser ends the Keycloak SSO session, with the ID token as hint and "
                "the registered post_logout_redirect_uri back to the app.", "OIDC RP-Initiated Logout 2")
        else:
            add("Logout at Keycloak without id_token_hint (as from another application): Keycloak asks to "
                "confirm, then ends the SSO session and notifies the BFF by back-channel logout.",
                "OIDC RP-Initiated Logout 2", "OIDC BCL 2.5")
    if from_browser and path.startswith("/api/") and ex.method != "OPTIONS":
        add("API call of the SPA: only the session cookie and the custom header. The BFF swaps the cookie "
            "for a token exchanged for exactly this service.", "BBA 6.1.1", "RFC 8693")
    if from_browser and header(ex.req_headers, "x-bff-csrf"):
        add("Custom header X-BFF-CSRF: required on every SPA call. A cross-origin page cannot send it "
            "without a CORS preflight, which the BFF never grants.", "BBA 6.1.3.3.2", "OWASP CSRF")
    if from_browser and path == "/" and header(ex.resp_headers, "content-security-policy"):
        add("The SPA document comes with a strict Content-Security-Policy (no inline script, no eval), "
            "anti-framing headers and HSTS.", "BBA 6.1.4.1", "RFC 9700 4.16", "OWASP Headers")
    if from_browser and ex.status == 301 and location.startswith("https://"):
        add("Plain http only redirects to https.", "RFC 9700 2.6")

    # -- outcomes ---------------------------------------------------------------
    error = resp_json.get("error") if isinstance(resp_json, dict) else None
    if error == "csrf_check_failed":
        add("Refused by the CSRF check.", "BBA 6.1.3.3", "OWASP CSRF")
    elif error == "unauthenticated":
        add("No authenticated session: the API is not reached.", "BBA 6.1.1")
    elif error == "session_expired":
        add("The session is over (refresh or token exchange refused).", "BBA 6.1.2.2")
    elif error == "method_not_allowed":
        add("Wrong method: state-changing endpoints take POST only.", "OWASP CSRF")
    elif error == "login_failed":
        reason = resp_json.get("reason", "")
        refs = {"state mismatch": ["RFC 9700 4.7", "RFC 6749 10.12"],
                "no login in progress": ["RFC 9700 4.7", "RFC 9700 4.5"],
                "issuer mismatch": ["RFC 9207", "RFC 9700 4.4"]}.get(reason, ["OIDC Core 3.1.3.7"])
        add(f"Login refused ({reason}).", *refs)
    if ex.error:
        add(f"The request did not complete ({ex.error}). In the browser, a cross-origin call with the custom "
            "header ends here: its CORS preflight is refused.", "BBA 6.1.3.3.2")

    # -- back channels ------------------------------------------------------------
    if not from_browser and to_keycloak:
        if path.endswith("/.well-known/openid-configuration"):
            add("Discovery: endpoints come from the issuer's metadata, whose issuer must be exactly the "
                "configured one; PKCE S256 support is required. Cached afterwards.",
                "RFC 8414 3", "RFC 8414 3.3", "OIDC Discovery", "RFC 9700 2.1.1")
        if path.endswith(oidc + "certs"):
            add("JWKS: public keys to verify token signatures; cached, refetched for an unknown kid.",
                "OIDC Core 3.1.3.7", "RFC 7517")
        grant = req_form.get("grant_type")
        if grant == "authorization_code":
            add("Token request of the confidential client: the code, the PKCE code_verifier (only the "
                "BFF knows it) and client authentication with client_secret_basic. The same redirect_uri "
                "as in the authorization request.",
                "RFC 6749 4.1.3", "RFC 7636 4.5", "RFC 6749 2.3.1", "BBA 6.1.3.1")
        if grant == "refresh_token":
            add("Refresh request with client authentication; the tokens never leave the BFF.",
                "RFC 6749 6", "BBA 6.1.2.2")
        if grant == "urn:ietf:params:oauth:grant-type:token-exchange":
            add(f"Token exchange: the session's access token (no audience, useless at the services) for one "
                f"whose aud is only {req_form.get('audience')} and whose scope is {req_form.get('scope')!r}. "
                f"Keycloak refuses audiences the client may not request.",
                "RFC 8693 2.1", "RFC 9700 2.3", "RFC 8707")
        if path.endswith("/token/introspect"):
            add("Token introspection by the service with its own credentials: is the token still active "
                "(session not ended, not revoked) and meant for this service? A token for another "
                "audience introspects as inactive.", "RFC 7662 2.1", "RFC 7662 2.2")
        if isinstance(resp_json, dict) and resp_json.get("access_token"):
            if resp_json.get("issued_token_type"):
                add("Token exchange response: an access token of type issued_token_type, not cached.",
                    "RFC 8693 2.2.1", "RFC 9068")
            else:
                add("Token response: bearer access token, refresh token and ID token, Cache-Control: no-store. "
                    "The BFF validates the ID token before it creates a session.",
                    "RFC 6749 5.1", "OIDC Core 3.1.3.3", "OIDC Core 3.1.3.7")
            if grant == "refresh_token" and resp_json.get("refresh_token") not in (None, req_form.get("refresh_token")):
                add("Refresh token rotation: a new refresh token, the used one is spent.", "RFC 9700 4.14.2")
        if isinstance(resp_json, dict) and resp_json.get("error") and ex.status and ex.status >= 400:
            add(f"OAuth error response: {resp_json['error']}.", "RFC 6749 5.2")
    if ex.src == "keycloak" and path == "/bff/backchannel-logout":
        add("Back-channel logout: Keycloak POSTs a signed logout token (sid, events, no nonce) to the BFF, "
            "server to server, when the SSO session ends. The BFF validates it and ends the matching "
            "sessions; 200, not cached.", "OIDC BCL 2.5", "OIDC BCL 2.6", "OIDC BCL 2.8")

    # -- the services -----------------------------------------------------------------
    if to_service:
        challenge = " ".join(header(ex.resp_headers, "www-authenticate"))
        if ex.status == 200:
            add("The service checked the token itself (signature, typ at+jwt, iss, aud = this service, exp, "
                "scope) and asked Keycloak whether it is still active: zero trust, nothing is taken from the "
                "network or the gateway.", "RFC 9068 4", "RFC 7662", "RFC 9700 2.3")
        elif "insufficient_scope" in challenge:
            add("403 insufficient_scope: valid token, but without the scope this endpoint needs.", "RFC 6750 3.1")
        elif "invalid_token" in challenge or ex.status == 401:
            add("401 with a WWW-Authenticate challenge: no token, a token for another audience, no access "
                "token (an ID token), or one that is no longer active.", "RFC 6750 3.1", "RFC 9068 4")
    return out


def annotate_forward(fwd) -> list:
    return [(f"Forwarded to {fwd.dst}: the BFF added the token exchanged for it as bearer token and removed "
             f"the session cookie and the CSRF header. The destination is fixed by the route, never taken "
             f"from the request.", ["RFC 6750 2.1", "BBA 6.1.1", "BBA 6.1.3.6"])]
