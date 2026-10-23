# OAuth / OpenID Connect best practices: where the token handler stands

This document lists the IETF and OWASP best practices that apply to the token handler
([`plugins/tokenhandler.py`](../plugins/tokenhandler.py)). It is a Backend for Frontend (BFF)
for the Vue SPA in [`spa/`](../spa/). For each practice it says where the code implements it,
or why the code doesn't.

The code comments cite the same sources with these short tags:

| Tag | Source |
|---|---|
| `BBA x` | [draft-ietf-oauth-browser-based-apps-27](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps), *OAuth 2.0 for Browser-Based Applications* (July 2026; the datatracker lists it as published as RFC 10017) |
| `RFC 9700 x` | [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700), *Best Current Practice for OAuth 2.0 Security* (BCP 240) |
| `RFC 7636` | [PKCE](https://www.rfc-editor.org/rfc/rfc7636) |
| `RFC 9207` | [Authorization Server Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207) |
| `RFC 8414` | [Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414) |
| `RFC 6749` | [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749) |
| `RFC 7009` | [Token Revocation](https://www.rfc-editor.org/rfc/rfc7009) |
| `OIDC Core x` | [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) |
| `OWASP OAuth2 #n` | [OWASP OAuth 2.0 Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html), recommendation *n* in its order |
| `OWASP Session` | [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) |
| `OWASP CSRF` | [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) |

Status legend:

- ✅ **implemented**: in this repository's code or configuration.
- 🔧 **deployment**: the code supports it, but the local dev stack doesn't meet it on purpose. A production deployment must.
- 🅰️ **authorization server**: a duty of the authorization server (Dex here), not of a client. Listed with what Dex does.
- ❌ **not implemented**: with the reason.
- ➖ **not applicable**: the practice concerns a feature this setup doesn't use.

## Architecture in one paragraph

The browser loads the SPA from `http://localhost:9080/`. Login is a full-page navigation to
`/bff/login`. The BFF, a confidential client, runs the authorization code flow with PKCE
against Dex and validates the ID token. It keeps all tokens in a server-side session and gives
the browser only an opaque `HttpOnly` session cookie. The SPA calls `/bff/session` ("who am
I") and `/api/*`. On `/api/*` the BFF swaps the cookie for the access token, refreshing it
when needed, and APISIX forwards the request to the API (httpbin in the demo). Every call
from the SPA carries the static header `X-BFF-CSRF: 1`. SPA, BFF and Dex share one origin
through APISIX.

```
Browser (Vue SPA)                APISIX + tokenhandler (BFF)               Dex / API
  ── GET /bff/login ───────────▶  pending session, PKCE, state, nonce
  ◀── 302 /dex/auth?… + cookie (Lax)
  ── login at Dex ─────────────────────────────────────────────────────▶  /dex/auth
  ── GET /bff/callback?code&state ▶ check state ─ code+verifier+secret ─▶  /dex/token
                                   validate ID token, new session id
  ◀── 302 return_to + cookie (Strict, HttpOnly)
  ── GET /api/x  cookie, X-BFF-CSRF ▶ (refresh) + Authorization: Bearer ─▶  API
```

## 1. Backend for Frontend (BBA 6.1)

### Architecture and implementation (BBA 6.1.1, 6.1.2)

| Requirement | Status | Where / why |
|---|---|---|
| The BFF handles the OAuth flow, keeps the tokens, and forwards API requests with the access token. Tokens are never exposed to the browser (6.1.1). | ✅ | `Bff.login`, `Bff.callback`, `Bff.proxy`. `/bff/session` returns selected claims only. The demo API echoes request headers, so the `api` route in [`conf/apisix.yaml`](../conf/apisix.yaml) redacts the bearer token on the way back. Tested in `test_tokens_and_session_are_out_of_javascripts_reach` (e2e) and `test_api_call_gets_access_token_instead_of_cookie`. |
| Endpoints: check session, login, callback, logout (6.1.2.1). | ✅ | `GET /bff/session`, `GET /bff/login?return_to=`, `GET /bff/callback` (path taken from `redirect_uri`), `POST /bff/logout`. |
| Refresh tokens: stored in the session, used with client authentication; the session lifetime should match the refresh token lifetime (6.1.2.2). | ✅ | `Bff._fresh_access_token` refreshes 30 s (`refresh_margin`) before the access token expires and keeps a rotated refresh token. Session lifetime is 8 h absolute and 30 min idle (`DEFAULTS`). This matches Dex's `absoluteLifetime: 8h` and `validIfNotUsedFor: 30m` in [`conf/dex.yaml`](../conf/dex.yaml). Refreshes of one session are serialized, so rotation can't spend a refresh token twice. |
| Cookie-based session state: server-side, or client-side signed and encrypted (6.1.2.3). | ✅ | Server-side: [`plugins/sessions.py`](../plugins/sessions.py). The cookie holds only a 256-bit random id. |
| Combining OAuth and OIDC: `openid` scope, keep ID token info in the session, return it on session check (6.1.2.4). | ✅ | Scope `openid email profile offline_access`. `USER_CLAIMS` limits what the SPA sees to `sub`, `name`, `preferred_username`, `email` and `email_verified`. |
| Practical deployment (6.1.2.5). | ✅ | The BFF is a gateway plugin in front of SPA and API, so everything is same-origin. |

### Security considerations (BBA 6.1.3)

| Requirement | Status | Where / why |
|---|---|---|
| **MUST** be a confidential client (6.1.3.1). | ✅ | `client_secret_basic` at the token endpoint, `Provider._post`. |
| **MUST** use the authorization code grant (6.1.3.1). | ✅ | `response_type=code` only, `Provider.authorization_url`. |
| PKCE (6.1.1; 6.3.2.1). | ✅ | S256, verifier of 256 random bits, `Bff.login`. The BFF refuses to run if the metadata doesn't list `S256` (`Provider._validate_metadata`). |
| Cookie: **MUST** `Secure` (6.1.3.2). | ✅ | `Bff._cookie`. |
| Cookie: **MUST** `HttpOnly` (6.1.3.2). | ✅ | `Bff._cookie`. The e2e test checks that `document.cookie` is empty. |
| Cookie: **SHOULD** `SameSite=Strict` (6.1.3.2). | ✅ with one exception | The session cookie is `Strict`. The cookie of a login in flight is `Lax`: the callback is a top-level navigation coming from the authorization server, which is cross-site in general, and browsers don't send a `Strict` cookie on it. That cookie can't do anything but finish this one login, which also needs the matching `state`. It is replaced by a new `Strict` cookie at the callback. |
| Cookie: **SHOULD** `Path=/`, **SHOULD NOT** `Domain` (6.1.3.2). | ✅ | `Bff._cookie`. |
| Cookie name **SHOULD** use a prefix showing it was set via HTTP, e.g. `__Host-Http-` (6.1.3.2). | ✅ | `__Host-Http-bff-session` (`DEFAULTS["cookie_name"]`). Browsers that don't know `__Host-Http-` still enforce `__Host-`. |
| **SHOULD** encrypt cookie contents with client-side sessions (6.1.3.2). | ➖ | Server-side sessions: the cookie is an opaque id. |
| **MUST** implement a CSRF defense (6.1.3.3). | ✅ | `Bff._csrf_ok` on `/bff/session`, `/bff/logout` and every API request. |
| SameSite as CSRF defense, adequate only if never same-site with other apps (6.1.3.3.1). | ✅ (not relied on alone) | `Strict` session cookie, combined with the custom header below. |
| CORS: **SHOULD** require a custom request header; **MUST** check that every request carries it (6.1.3.3.2). | ✅ | `X-BFF-CSRF: 1` is required. The BFF sends no CORS headers and refuses preflights (403), so other origins can't send the header. Tested in `test_cors_preflight_is_refused` and in the e2e test `test_cross_origin_page_cannot_use_the_session`. |
| Anti-forgery / double-submit cookies (6.1.3.3.3). | ➖ | Optional alternative; the custom-header defense is used instead. |
| Privacy: the BFF sees all API traffic (6.1.3.4). | ➖ | SPA, BFF and API are run by one party. The BFF logs no request content. |
| Operational: resource servers should know about the BFF, because its single IP affects rate limiting (6.1.3.5). | ❌ | No rate limiting is configured. APISIX's `limit-req`/`limit-count` can be added to the `bff` and `api` routes. The right limits depend on the deployment. |
| Proxy restrictions: **MUST** validate destination hosts with an explicit allowlist (6.1.3.6). | ✅ | The destination never comes from the request. The BFF runs only on the `bff` and `api` routes, each with a fixed upstream in `conf/apisix.yaml`. That route list is the allowlist. |
| Advanced security: key-based client authentication, sender-constrained tokens (6.1.3.7). | ❌ | Optional. Dex supports neither `private_key_jwt` nor DPoP/mTLS-bound tokens. See RFC 9700 2.2 and 2.5 below. |

### Threats (BBA 5, 6.1.4) and browser storage (BBA 8)

| Practice | Status | Where / why |
|---|---|---|
| Malicious JavaScript must not be able to get tokens (BBA 5, 6.1.4). | ✅ | No token ever reaches the browser. The cookie is `HttpOnly`. Injected script can still call the API through the BFF while the page is open; that is an inherent limit of the pattern, stated in 6.1.4. |
| Content Security Policy against script injection (BBA 5, 6.1.4.1). | ✅ | The SPA server in [`conf/config.yaml`](../conf/config.yaml) sends `default-src 'none'; script-src 'self'; …; frame-ancestors 'none'`. The SPA uses Vue's runtime-only build with render functions, so no `unsafe-eval` and no inline script are needed. The e2e test checks there are no CSP violations. |
| Token storage in the browser: no tokens in `localStorage` / `sessionStorage` / IndexedDB / JS memory (BBA 8). | ✅ | Nothing to store. The e2e test checks web storage is empty. |
| Cookies (BBA 8.1). | ✅ | See the cookie rows above. |

## 2. RFC 9700: OAuth 2.0 Security Best Current Practice

### Section 2: best practices

| Practice | Status | Where / why |
|---|---|---|
| 2.1 Exact redirect URI matching by the authorization server. | 🅰️ ✅ | Dex matches `redirectURIs` exactly. One URI is registered (`conf/dex.yaml`). |
| 2.1 Clients **MUST NOT** expose open redirectors. | ✅ | `return_to` must be a path on this origin (`_local_path`). Rejected values fall back to `/`. Tested for `//host`, `/\host`, schemes, CR/LF and over-long values. |
| 2.1 CSRF protection of the redirect: PKCE, OIDC `nonce`, or `state` bound to the user agent. | ✅ | All three. `state` and `nonce` are bound to the browser through the pending-login cookie and compared in constant time (`Bff.callback`). |
| 2.1 Mix-up defense when talking to several authorization servers; use `iss` (RFC 9207). | ✅ (conditional) | The BFF has one issuer. If the callback carries `iss`, or the metadata advertises `authorization_response_iss_parameter_supported`, then `iss` must equal the issuer (`Bff.callback`). Dex sends no `iss`. |
| 2.1 Don't forward user credentials on redirects (307). | ✅ / 🅰️ | The BFF never receives credentials. Back-channel calls never follow redirects (`_NoRedirect`, tested in `test_redirects_are_not_followed`). Dex answers its login form with 303. |
| 2.1.1 Public clients **MUST**, confidential clients **SHOULD** use PKCE. | ✅ | S256 always. |
| 2.1.1 Authorization servers **MUST** support PKCE and prevent PKCE downgrade. | 🅰️ | Dex supports S256. The client side is covered: the BFF refuses to run without advertised S256 and never sends `plain`. |
| 2.1.2 No implicit grant (`response_type=token`). | ✅ | Code flow only. |
| 2.2.1 Sender-constrained access tokens (mTLS / DPoP), **SHOULD**. | ❌ | Dex supports neither. The browser holds no token, which removes the main theft vector these address. The BFF→API hop is server-to-server. |
| 2.2.2 Refresh tokens of public clients sender-constrained or rotated. | ➖ / 🅰️ ✅ | The BFF is confidential: its refresh tokens need the client secret. Rotation is still on: `disableRotation: false` in `conf/dex.yaml`, and `_store_tokens` keeps the new token. |
| 2.3 Least privilege, audience-restricted access tokens. | 🅰️ / partial | The scope requests only what the demo uses. Dex can't audience-restrict access tokens to an API (no RFC 8707 resource indicators); its tokens have `aud` = client id. Resource servers must check audience and scope; httpbin here checks nothing. |
| 2.4 No resource owner password credentials grant. | ✅ | Not used; the user enters the password only at Dex. |
| 2.5 Client authentication, asymmetric preferred (`private_key_jwt`, mTLS). | ✅ / ❌ | `client_secret_basic` (form-urlencoded per RFC 6749 2.3.1). No asymmetric method: Dex doesn't offer one. |
| 2.6 Use authorization server metadata (RFC 8414). | ✅ | Endpoints come from discovery. `issuer` in the document must equal the configured issuer (RFC 8414 3.3). |
| 2.6 Clients **SHOULD NOT** influence `client_id` / `sub` confusion. | 🅰️ | Dex's static client config. |
| 2.6 End-to-end TLS; authorization responses **MUST NOT** go over unencrypted connections; no `http` redirect URIs. | 🔧 | The dev stack runs plain `http://localhost` without certificates, so the config sets `allow_insecure_http: true`. Without it the BFF refuses any non-https issuer or endpoint (`Provider._require_https`). Production needs TLS on APISIX (plus HSTS) and to Dex, and an `https` redirect URI. |
| 2.6 No CORS at the authorization endpoint. | 🅰️ | Dex's authorization endpoint sends no CORS headers. |
| 2.6 Strict origin checks for in-browser messaging (`postMessage`). | ➖ | Not used. |

### Section 4: attacks and mitigations

| Attack | Status | Where / why |
|---|---|---|
| 4.1 Insufficient redirect URI validation. | 🅰️ ✅ | Exact matching at Dex. One fixed `redirect_uri` in the BFF config. |
| 4.2 Credential leakage via Referer. | ✅ | The callback answers with an immediate 302 and `Referrer-Policy: no-referrer`. The SPA is also served with `Referrer-Policy: no-referrer`. The code is single-use and PKCE-bound anyway. |
| 4.3 Credentials in browser history. | ✅ | The code URL is only a redirect hop. A replayed code is useless without the verifier and is refused by the authorization server. The callback refuses a second use of the pending login (`test_callback_cannot_be_replayed`). No access token is ever in a URL. |
| 4.4 Mix-up. | ✅ (conditional) | See RFC 9207 above. |
| 4.5 Authorization code injection. | ✅ | PKCE plus `nonce` checked in the ID token (4.5.3.1, 4.5.3.2). |
| 4.6 Access token injection. | ➖ | No access token in the front channel. |
| 4.7 CSRF. | ✅ | `state` bound to the browser via cookie. `test_callback_in_another_browser_is_rejected` covers login CSRF. |
| 4.8 PKCE downgrade. | ✅ / 🅰️ | S256 required in metadata and always sent. Rejecting verifiers without a challenge is Dex's job. |
| 4.9 Access token leakage at the resource server. | 🅰️ / ❌ | Needs audience-restricted or sender-constrained tokens, which Dex doesn't issue. The BFF sends tokens only to routes in `apisix.yaml`. |
| 4.10 Misuse of stolen access tokens. | ❌ | Same as 2.2.1 and 2.3. Access tokens are short-lived (`idTokens: 10m` in Dex, which also sets the access token lifetime). |
| 4.11 Open redirection (client and authorization server). | ✅ / 🅰️ | `_local_path` for the client. |
| 4.12 307 redirect. | ✅ / 🅰️ | Back channel follows no redirects. Dex uses 303. |
| 4.13 TLS-terminating reverse proxies. | 🔧 | APISIX would terminate TLS in production. The BFF trusts no forwarded headers: it gets its origin from the configured `redirect_uri`, not from `Host` or `X-Forwarded-*`. |
| 4.14 Refresh token protection. | ✅ | Confidential client, rotation, idle and absolute expiry. Revocation at logout when the server supports it (`Provider.revoke`); Dex has no revocation endpoint. |
| 4.15 Client impersonating the resource owner. | 🅰️ | Dex config. |
| 4.16 Clickjacking. | ✅ / 🅰️ | SPA: `frame-ancestors 'none'` and `X-Frame-Options: DENY`. Protecting Dex's login page is Dex's job. |
| 4.17 In-browser communication flows. | ➖ | No `postMessage` or popup flows. |

## 3. Other IETF and OpenID specifications

| Practice | Status | Where / why |
|---|---|---|
| RFC 7636 PKCE: verifier of 43–128 characters from a CSPRNG; `S256`. | ✅ | `secrets.token_urlsafe(32)` gives 43 characters and 256 bits. The challenge is `BASE64URL(SHA256(verifier))`. |
| RFC 6749 10.12 / RFC 9700 4.7: unguessable `state`, bound to the user agent. | ✅ | 256-bit `state` in the pending session behind the cookie. |
| OIDC Core 3.1.2.1 / 3.1.3.7: `nonce` sent and checked. | ✅ | `Provider.validate_id_token`. |
| OIDC Core 3.1.3.7 ID token validation: issuer exact, audience is the client with no extra untrusted audiences, `azp` if present, signature with keys from `jwks_uri`, algorithm allowlist (no `none`, no HMAC), `exp`, `iat`, `nonce`. | ✅ | `Provider.validate_id_token`, tested in [`tests/unit/test_oidc.py`](../tests/unit/test_oidc.py) for every rule. A 60 s leeway allows for clock skew. Keys are cached and refetched for an unknown `kid` (key rotation). |
| OIDC Core 12.2: ID token from a refresh has the same `iss`, `sub` and `aud`. | ✅ | `validate_id_token(..., expected_sub=...)` in `_fresh_access_token`. |
| RFC 7009 token revocation at logout. | ✅ (conditional) | Used if `revocation_endpoint` exists; Dex has none. The BFF session dies either way. |
| OpenID RP-Initiated Logout 1.0. | ✅ (conditional) | `/bff/logout` returns `logout_url` with `id_token_hint` and `post_logout_redirect_uri` if `end_session_endpoint` exists, and the SPA navigates there. Dex has none, and Dex keeps no login session (every login asks for the password), so local logout is complete here. |
| OpenID Back-Channel / Front-Channel Logout. | ❌ | Dex doesn't support it. Sessions end at the latest when a refresh fails (revoked or expired refresh token) or when the BFF session lifetime is reached. |
| RFC 9449 DPoP / RFC 8705 mTLS-bound tokens. | ❌ | Not supported by Dex. See RFC 9700 2.2.1. |

## 4. OWASP OAuth 2.0 Cheat Sheet

| # | Recommendation (abridged) | Status | Where / why |
|---|---|---|---|
| 1 | No open redirectors in clients or authorization servers. | ✅ | `_local_path`. |
| 2 | If PKCE is the CSRF protection, make sure the server supports it; otherwise use one-time `state`; OIDC uses `nonce`. | ✅ | All three: S256 required in metadata, one-time `state` and `nonce`. |
| 3 | Use `iss` against mix-up when there are several authorization servers. | ✅ (conditional) | Checked when sent or advertised. |
| 4 | Without other mix-up defenses, use distinct redirect URIs per authorization server. | ➖ | One authorization server. |
| 5 | Authorization servers must not forward credentials on redirects. | 🅰️ | Dex uses 303. |
| 6 | PKCE or nonce against code injection, transaction-specific and bound to client and user agent. | ✅ | Fresh verifier and nonce per login, kept in the session behind this browser's cookie. |
| 7 | Challenge method that doesn't expose the verifier (S256). | ✅ | |
| 8–9 | Authorization server enforces the verifier and blocks downgrade. | 🅰️ | Dex. |
| 10 | No implicit grant; code with PKCE for all client types. | ✅ | |
| 11 | Sender-constrained tokens (mTLS / DPoP). | ❌ | Not supported by Dex. |
| 12 | Refresh tokens sender-constrained or rotated. | ✅ | Rotation (Dex config). The tokens are also bound to the confidential client. |
| 13–15 | Minimal privileges, audience-restricted tokens, resource servers check audience, scope and action. | 🅰️ / partial | Minimal scope requested. Audience restriction and per-request checks belong to the authorization server and the API. |
| 16 | No resource owner password credentials grant. | ✅ | |
| 17 | Client authentication, asymmetric preferred. | ✅ / ❌ | Client secret; Dex supports no asymmetric method. The secret is in `conf/apisix.yaml` for the dev stack, and production should inject it from a secret store. |
| 18 | Clients can't influence `client_id` / `sub`; end-to-end TLS. | 🅰️ / 🔧 | TLS: see RFC 9700 2.6. |
| 19 | No authorization responses over unencrypted connections; no `http` redirect URIs except native loopback. | 🔧 | Dev stack only. `allow_insecure_http` must stay off in production. |

## 5. OWASP Session Management Cheat Sheet

| Practice | Status | Where / why |
|---|---|---|
| Session id from a CSPRNG with at least 64 bits of entropy. | ✅ | 256 bits, `secrets.token_urlsafe(32)` (`SessionStore.create`). |
| Session id is meaningless (no data in it). | ✅ | Opaque id. The store keys sessions by SHA-256 of the id, so a dump of the store holds no usable cookie values. |
| Generic session cookie name (no fingerprinting). | ✅ / trade-off | `__Host-Http-bff-session` is required in part by the BBA cookie-prefix rule. "bff" reveals little. Configurable with `cookie_name`. |
| Cookie attributes `Secure`, `HttpOnly`, `SameSite`, narrow `Domain`/`Path`. | ✅ | See BBA 6.1.3.2. |
| Non-persistent cookie (no `Expires`/`Max-Age`). | ✅ | It disappears when the browser closes. The server enforces its own lifetimes. |
| Renew the session id on privilege change (login). | ✅ | The pending-login id is dropped at the callback and a new id is issued. Tested in `test_pre_login_session_id_is_not_authenticated`. Each `/bff/login` also discards the previous session. |
| Idle timeout and absolute timeout, enforced server-side. | ✅ | 30 min / 8 h (`session_idle_timeout`, `session_lifetime`), checked on every lookup (`SessionStore.get`). A login in flight expires after 10 min (`login_timeout`). |
| Logout invalidates the session server-side. | ✅ | `Bff.logout` deletes the session. The old cookie is useless afterwards (`test_session_is_gone_after_logout_even_with_the_old_cookie`). |
| Don't cache session-bearing responses (`Cache-Control: no-store`). | ✅ | All BFF responses (`_json`, `_redirect`). |
| Bind the session to client properties (IP, User-Agent) to detect hijacking. | ❌ | IP binding breaks mobile users and NAT, and User-Agent is attacker-controlled. `HttpOnly` + `Secure` + `__Host-` + short lifetimes are the protection. |
| Log session lifecycle and security events. | ✅ | Logins, failed callbacks (state, issuer, ID token), failed refreshes and CSRF rejections are logged by the `tokenhandler` logger into the APISIX error log (`make logs`). Session ids and tokens are never logged, except in the dev-only traffic trace (`trace_file`, see README), which records requests carrying `X-Trace-Id` in full for the test report and must stay unset in production. |
| Session store survives restarts, is shared across instances. | ❌ | In-memory in the runner process, which serves all APISIX workers. It is lost on runner restart (users log in again) and not shared between gateway instances. Production with more than one gateway needs a shared store (e.g. Redis) behind the `SessionStore` interface. |

## 6. OWASP CSRF Prevention Cheat Sheet

| Practice | Status | Where / why |
|---|---|---|
| State-changing requests not via GET. | ✅ | Logout is `POST` only (`405` otherwise). Login and callback are GET by protocol; both are harmless to trigger (see login CSRF). |
| Custom request headers for API/AJAX requests (with no permissive CORS). | ✅ | `X-BFF-CSRF: 1`, required on everything the SPA calls. |
| Fetch Metadata (`Sec-Fetch-Site`) checks. | ✅ | Must be `same-origin` when the browser sends it. |
| Verify `Origin` with standard headers. | ✅ | If present, it must equal the origin of `redirect_uri`. |
| `SameSite` cookies as defense in depth. | ✅ | `Strict` session cookie. |
| Login CSRF. | ✅ | `state` bound to the pending-login cookie. A callback opened in another browser fails. |
| Synchronizer token pattern. | ➖ | Not needed with the custom-header defense; the BBA draft prefers that defense over tokens (6.1.3.3.3). |

## 7. OWASP HTTP security headers (SPA and BFF responses)

| Header | Status | Where |
|---|---|---|
| `Content-Security-Policy` (strict, no `unsafe-*`) | ✅ | SPA, `conf/config.yaml`. |
| `X-Frame-Options: DENY` / `frame-ancestors 'none'` | ✅ | SPA. |
| `X-Content-Type-Options: nosniff` | ✅ | SPA and BFF JSON responses. |
| `Referrer-Policy: no-referrer` | ✅ | SPA and BFF redirects. |
| `Cache-Control: no-store` | ✅ | BFF responses. The SPA uses `no-cache` (revalidate), since it holds no user data. |
| `Strict-Transport-Security` | 🔧 | Only meaningful over TLS. Set it on the TLS listener in production. |

## Known limitations of the dev setup

- **Plain http.** Browsers accept `Secure` and `__Host-` cookies on `http://localhost` (Chromium and Firefox; Safari does not). The dev stack relies on that. Anything other than `localhost` needs TLS.
- **Client secret in a config file.** Fine for the local Dex. Production should load it from a secret store or environment.
- **In-memory sessions.** See section 5.
- **Dex features.** Dex has no revocation, RP-initiated logout, RFC 9207 `iss`, `private_key_jwt`, DPoP or resource indicators. The BFF uses revocation, logout and `iss` automatically when the provider advertises them.
