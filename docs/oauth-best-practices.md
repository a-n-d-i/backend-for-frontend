# OAuth / OpenID Connect best practices: where the token handler stands

This document lists the IETF and OWASP best practices that apply to the token handler
([`lua/apisix/plugins/tokenhandler.lua`](../lua/apisix/plugins/tokenhandler.lua), a native APISIX plugin). The token handler is a Backend for
Frontend (BFF) for the Vue SPA in [`spa/`](../spa/), in front of the two resource servers in
[`services/`](../services/), with Keycloak as the authorization server. For each practice it
says where the code or configuration implements it, or why it doesn't.

The code comments cite the same sources with these short tags:

| Tag | Source |
|---|---|
| `BBA x` | [draft-ietf-oauth-browser-based-apps-27](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps), *OAuth 2.0 for Browser-Based Applications* (July 2026; the datatracker lists it as published as RFC 10017) |
| `RFC 9700 x` | [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700), *Best Current Practice for OAuth 2.0 Security* (BCP 240) |
| `RFC 6749` | [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749) |
| `RFC 6750` | [Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750) |
| `RFC 7636` | [PKCE](https://www.rfc-editor.org/rfc/rfc7636) |
| `RFC 7009` | [Token Revocation](https://www.rfc-editor.org/rfc/rfc7009) |
| `RFC 7662` | [Token Introspection](https://www.rfc-editor.org/rfc/rfc7662) |
| `RFC 8414` | [Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414) |
| `RFC 8693` | [Token Exchange](https://www.rfc-editor.org/rfc/rfc8693) |
| `RFC 9068` | [JWT Profile for OAuth 2.0 Access Tokens](https://www.rfc-editor.org/rfc/rfc9068) |
| `RFC 9207` | [Authorization Server Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207) |
| `OIDC Core x` | [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) |
| `OIDC BCL x` | [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html) |
| `OIDC RP-Initiated Logout` | [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) |
| `OWASP OAuth2 #n` | [OWASP OAuth 2.0 Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html), recommendation *n* in its order |
| `OWASP Session` | [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) |
| `OWASP CSRF` | [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) |
| `OWASP Secrets` | [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) |

Status legend:

- ✅ **implemented**: in this repository's code or configuration ([`conf/keycloak/demo-realm.json`](../conf/keycloak/demo-realm.json) for Keycloak).
- 🔧 **deployment**: the code supports it, but the local dev stack doesn't meet it on purpose. A production deployment must.
- 🅰️ **authorization server**: a duty of the authorization server, listed with how Keycloak is configured for it.
- ❌ **not implemented**: with the reason.
- ➖ **not applicable**: the practice concerns a feature this setup doesn't use.

## Architecture

All public traffic is HTTPS on real host names under `example.test` (RFC 6761). APISIX
terminates TLS with a certificate from Vault's PKI engine, which it fetches from Vault:

- **`https://app.example.test`**: the SPA, the BFF endpoints `/bff/*`, and the APIs `/api/a/*` and `/api/b/*`.
- **`https://auth.example.test`**: Keycloak, realm `demo`.
- **`https://vault.example.test`**: Vault, which holds every secret and the PKI (section 9).

Login is a full-page navigation to `/bff/login`. The BFF, a confidential client, runs the
authorization code flow with PKCE against Keycloak and validates the ID token. It keeps all
tokens in a server-side session; the browser only gets an opaque `HttpOnly` session cookie.

The BFF's own access token has no audience, so no service accepts it. For each API call, the
BFF exchanges it at Keycloak (RFC 8693) for a token that is valid only for that service and
carries only that service's scope. The token is cached until shortly before it expires.

Service A and Service B trust nothing but the token. Each one checks every token itself and
introspects it at Keycloak, so a logout takes effect there immediately.

Keycloak's SSO session is shared with other applications of the realm, such as its account
console:
- **Single sign-on:** the account console opens without a password.
- **Single logout:** logging out in any of them makes Keycloak send a back-channel logout token
  to the BFF, which ends its session.

```
Browser (SPA)                    APISIX + BFF                         Keycloak           Service A/B
  ── GET /bff/login ───────────▶ pending session, PKCE, state, nonce
  ◀── 302 …/auth?… + cookie (Lax)
  ── login (or SSO session) ──────────────────────────────────────────▶ /auth
  ── GET /bff/callback?code&state&iss ▶ check state, iss ── code+verifier+secret ─▶ /token
                                   validate ID token (sid), new session id
  ◀── 302 return_to + cookie (Strict, HttpOnly)
  ── GET /api/a/whoami  cookie, X-BFF-CSRF ▶ token exchange (aud=service-a) ─▶ /token
                                   + Authorization: Bearer ──────────────────────────────▶ verify,
                                                                         /introspect ◀─── introspect
  … logout in another app ───────────────────────────────────────────▶ end SSO session
                                   ◀── POST /bff/backchannel-logout (logout token, sid)
```

## 1. Backend for Frontend (BBA 6.1)

### Architecture and implementation (BBA 6.1.1, 6.1.2)

| Requirement | Status | Where / why |
|---|---|---|
| The BFF handles the OAuth flow, keeps the tokens, and forwards API requests with an access token. Tokens are never exposed to the browser (6.1.1). | ✅ | `Bff:login`, `Bff:callback`, `Bff:proxy`. `/bff/session` returns selected claims only. Tested in `test_tokens_and_session_are_out_of_javascripts_reach` (e2e) and `test_api_call_gets_a_token_for_that_service_instead_of_the_cookie`. |
| Endpoints: check session, login, callback, logout (6.1.2.1). | ✅ | `GET /bff/session`, `GET /bff/login?return_to=`, `GET /bff/callback` (path taken from `redirect_uri`), `POST /bff/logout`, and `POST /bff/backchannel-logout` for Keycloak. |
| Refresh tokens: stored in the session, used with client authentication; the session lifetime should match the refresh token lifetime (6.1.2.2). | ✅ | `Bff:fresh_access_token` refreshes 30 s (`refresh_margin`) before the access token expires, including before a token exchange, and keeps the rotated refresh token. BFF session: 8 h absolute, 30 min idle (plugin schema defaults); Keycloak SSO session: the same (`ssoSessionMaxLifespan`, `ssoSessionIdleTimeout`). Refreshes and exchanges of one session are serialized, so rotation can't spend a refresh token twice. No `offline_access`: offline tokens would outlive the SSO session and a single logout. |
| Cookie-based session state: server-side, or client-side signed and encrypted (6.1.2.3). | ✅ | Server-side: [`tokenhandler/sessions.lua`](../lua/apisix/plugins/tokenhandler/sessions.lua), a shared memory dict of the gateway. The cookie holds only a 256-bit random id. |
| Combining OAuth and OIDC: `openid` scope, keep ID token info in the session, return it on session check (6.1.2.4). | ✅ | Scope `openid profile email`. `USER_CLAIMS` limits what the SPA sees to `sub`, `name`, `preferred_username`, `email` and `email_verified`. The ID token's `sid` is kept for back-channel logout. |
| Practical deployment (6.1.2.5). | ✅ | The BFF is a gateway plugin in front of SPA and APIs, so they share one origin (`app.example.test`). |

### Security considerations (BBA 6.1.3)

| Requirement | Status | Where / why |
|---|---|---|
| **MUST** be a confidential client (6.1.3.1). | ✅ | `client_secret_basic` at the token endpoint, `Provider:post`; client `bff` is confidential in the realm. |
| **MUST** use the authorization code grant (6.1.3.1). | ✅ | `response_type=code` only. In the realm, the `bff` client has the standard flow only (no implicit, no direct access grants). |
| PKCE (6.1.1; 6.3.2.1). | ✅ | S256, verifier of 256 random bits, `Bff:login`. The BFF refuses to run if the metadata doesn't list `S256`. Keycloak requires S256 for this client (`pkce.code.challenge.method`). |
| Cookie: **MUST** `Secure` (6.1.3.2). | ✅ | `Bff:cookie`. |
| Cookie: **MUST** `HttpOnly` (6.1.3.2). | ✅ | `Bff:cookie`. The e2e test checks that `document.cookie` is empty. |
| Cookie: **SHOULD** `SameSite=Strict` (6.1.3.2). | ✅ with one exception | The session cookie is `Strict`. The cookie of a login in flight is `Lax`, because the callback is a top-level navigation coming from the authorization server and browsers don't send a `Strict` cookie on it in general. That cookie can only finish this one login, which also needs the matching `state`. The callback replaces it with a new `Strict` cookie. |
| Cookie: **SHOULD** `Path=/`, **SHOULD NOT** `Domain` (6.1.3.2). | ✅ | `Bff:cookie`. |
| Cookie name **SHOULD** use a prefix showing it was set via HTTP, e.g. `__Host-Http-` (6.1.3.2). | ✅ | `__Host-Http-bff-session` (schema default `cookie_name`). The browser rejects it unless it is `Secure`, `HttpOnly`, `Path=/`, without `Domain`, from https. |
| **SHOULD** encrypt cookie contents with client-side sessions (6.1.3.2). | ➖ | Server-side sessions: the cookie is an opaque id. |
| **MUST** implement a CSRF defense (6.1.3.3). | ✅ | `Bff:csrf_ok` on `/bff/session`, `/bff/logout` and every API request. |
| SameSite as CSRF defense, adequate only if never same-site with other apps (6.1.3.3.1). | ✅ (not relied on alone) | `app.example.test` and `auth.example.test` *are* same-site, so SameSite alone would not do. The custom header below does, and the e2e test `test_other_origin_cannot_use_the_session` attacks from `auth.example.test`. |
| CORS: **SHOULD** require a custom request header; **MUST** check that every request carries it (6.1.3.3.2). | ✅ | `X-BFF-CSRF: 1` is required. The BFF sends no CORS headers and refuses preflights (403). The `bff` client has no web origins in Keycloak either. |
| Anti-forgery / double-submit cookies (6.1.3.3.3). | ➖ | Optional alternative; the custom-header defense is used instead. |
| Privacy: the BFF sees all API traffic (6.1.3.4). | ➖ | SPA, BFF and APIs are run by one party. The BFF logs no request content. |
| Operational: resource servers should know about the BFF, because its single IP affects rate limiting (6.1.3.5). | ❌ | No rate limiting is configured. APISIX's `limit-req`/`limit-count` can be added to the routes. The right limits depend on the deployment. |
| Proxy restrictions: **MUST** validate destination hosts with an explicit allowlist (6.1.3.6). | ✅ | The destination never comes from the request. `apis` in the BFF config maps path prefixes to services, and anything else under `/api/` gets 404 (`test_api_outside_the_allowlist`). Each route has a fixed upstream in `conf/apisix.yaml`. |
| Advanced security: key-based client authentication, sender-constrained tokens (6.1.3.7). | ❌ | Optional. Keycloak supports `private_key_jwt` and DPoP/mTLS-bound tokens; the BFF and the services don't use them yet. See RFC 9700 2.2 and 2.5 below. |

### Threats (BBA 5, 6.1.4) and browser storage (BBA 8)

| Practice | Status | Where / why |
|---|---|---|
| Malicious JavaScript must not be able to get tokens (BBA 5, 6.1.4). | ✅ | No token ever reaches the browser. The cookie is `HttpOnly`. Injected script can still call the APIs through the BFF while the page is open; that is an inherent limit of the pattern, stated in 6.1.4. |
| Content Security Policy against script injection (BBA 5, 6.1.4.1). | ✅ | The SPA server in [`conf/config.yaml`](../conf/config.yaml) sends `default-src 'none'; script-src 'self'; …; frame-ancestors 'none'`. The SPA uses Vue's runtime-only build with render functions, so no `unsafe-eval` and no inline script are needed. The e2e test checks there are no CSP violations. |
| Token storage in the browser: no tokens in `localStorage` / `sessionStorage` / IndexedDB / JS memory (BBA 8). | ✅ | Nothing to store. The e2e test checks web storage is empty. |
| Cookies (BBA 8.1). | ✅ | See the cookie rows above. |

## 2. Token exchange, zero trust between the services, single logon / logoff

| Practice | Status | Where / why |
|---|---|---|
| Audience-restricted access tokens: each token is good for one resource server only (RFC 9700 2.3, 4.10.2; OWASP OAuth2 #14). | ✅ | The BFF's login token has no `aud`. For each API it is exchanged (RFC 8693) for a token with `aud` = that service only (`Bff:api_token`, `Provider:exchange_token`). In the realm, the `api-a`/`api-b` client scopes add the audiences and are *optional* scopes of `bff`, so they appear only on request. Keycloak refuses audiences the client may not ask for (`test_exchange_refuses_mismatched_requests`). |
| Least privilege: minimal scope per token (RFC 9700 2.3; OWASP OAuth2 #13, #15). | ✅ | Each exchange asks for the one scope of that service (`apis` config). `POST /items` needs `api-a.write`, which nobody is granted, so it answers 403 `insufficient_scope` (`test_scope_is_enforced`). |
| Token exchange per RFC 8693: client authentication, `subject_token_type`, `requested_token_type`, `audience`; response `issued_token_type`, not cached (2.1, 2.2.1). | ✅ | `Provider:exchange_token` sends all of them and checks `issued_token_type`. Standard token exchange is enabled for the `bff` client only. Keycloak exchanges access tokens, not ID tokens. |
| Resource servers verify every token themselves: signature, issuer, expiry, audience, scope (RFC 9068 4; RFC 6750). | ✅ | [`services/resource.py`](../services/resource.py), `ResourceServer.authenticate`, on every request. A token for the other service, the BFF's own token, an ID token, a forged or tampered token are all rejected (`test_services_accept_only_tokens_meant_for_them`, run directly against the services, bypassing the gateway). |
| Explicitly typed access tokens, so an ID token can't pass as one (RFC 9068 2.1, 4). | ✅ | Keycloak issues `typ: at+jwt` for the `bff` client (`access.token.header.type.rfc9068`). The services require it. |
| Revocation reaches the resource servers (RFC 7662). | ✅ | The services introspect every token with their own client credentials. A token of an ended SSO session, or one meant for another audience, introspects as inactive (`test_services_check_with_keycloak_that_a_token_is_still_active`). Failure to introspect fails closed. The trade-off is one call to Keycloak per request; caching active results for a few seconds would be the usual optimization. |
| Rejections per RFC 6750: `401` with `WWW-Authenticate: Bearer error="invalid_token"`, `403` with `insufficient_scope`. | ✅ | `ResourceServer._guarded`. |
| Single sign-on: one login for all applications of the realm. | ✅ | Keycloak SSO session. One BFF login gives tokens for both services with the same `sub` and `sid`. Keycloak's account console, another client of the realm, opens without a password (`test_single_sign_on_*`, e2e `test_single_sign_on_and_single_logout_with_another_application`). |
| Single logout, back-channel (OIDC BCL): the RP receives a logout token when the session at the OP ends, and ends its own sessions. | ✅ | The `bff` client has `backchannel.logout.url` and `backchannel.logout.session.required`. `Bff:backchannel_logout` handles it without cookie or CSRF header, since the signed logout token is the authentication. It ends every BFF session with that `sid` (or of that `sub`) and answers 200 with `no-store` (2.8). Tested in `test_single_logout_back_channel` and `test_single_logout_ends_every_bff_session_of_that_keycloak_session`. |
| Logout token validation (OIDC BCL 2.6): signature, `iss`, `aud`, `iat`, `jti`, `sid` or `sub`, the `events` member, no `nonce`, explicit type, replay detection. | ✅ | `Provider:validate_logout_token`, every rule unit-tested in [`tests/lua/test_oidc.lua`](../tests/lua/test_oidc.lua). An ID token is refused as logout token (`test_back_channel_logout_refuses_invalid_logout_tokens`). |
| Back-channel logout to the resource servers. | ➖ | Keycloak sends back-channel logout only to clients with a session; the services only receive exchanged tokens. Their introspection gives the same effect. |
| Zero-trust network: mutual TLS between gateway and services. | ❌ | The hops inside the Docker network (APISIX → Keycloak, APISIX → services) are plain http. The services don't depend on it; they trust only the token. Production: mTLS or a service mesh. |

## 3. RFC 9700: OAuth 2.0 Security Best Current Practice

### Section 2: best practices

| Practice | Status | Where / why |
|---|---|---|
| 2.1 Exact redirect URI matching by the authorization server. | 🅰️ ✅ | One redirect URI registered for `bff`, matched exactly by Keycloak. |
| 2.1 Clients **MUST NOT** expose open redirectors. | ✅ | `return_to` must be a path on this origin (`util.local_path`). Rejected values fall back to `/`. Tested for `//host`, `/\host`, schemes, CR/LF and over-long values. |
| 2.1 CSRF protection of the redirect: PKCE, OIDC `nonce`, or `state` bound to the user agent. | ✅ | All three. `state` and `nonce` are bound to the browser through the pending-login cookie and compared in constant time (`Bff:callback`). |
| 2.1 Mix-up defense; use `iss` (RFC 9207). | ✅ | Keycloak sends `iss` in the authorization response and advertises it; the BFF requires it to equal the issuer (`test_callback_rejects_foreign_issuer`). |
| 2.1 Don't forward user credentials on redirects (307). | ✅ / 🅰️ | The BFF never receives credentials. Back-channel calls never follow redirects (`util.http`). Keycloak answers its login form with 302. |
| 2.1.1 Public clients **MUST**, confidential clients **SHOULD** use PKCE. | ✅ | S256 always. |
| 2.1.1 Authorization servers **MUST** support PKCE and prevent PKCE downgrade. | 🅰️ ✅ | Keycloak requires S256 for `bff`. The BFF never sends `plain`. |
| 2.1.2 No implicit grant (`response_type=token`). | ✅ / 🅰️ | Code flow only; implicit flow disabled for `bff`. |
| 2.2.1 Sender-constrained access tokens (mTLS / DPoP), **SHOULD**. | ❌ | Keycloak supports DPoP and mTLS-bound tokens; not used yet. The browser holds no token, which removes the main theft vector. The tokens that travel (BFF → services) are audience-restricted, short-lived (5 min) and introspected. |
| 2.2.2 Refresh tokens of public clients sender-constrained or rotated. | ➖ / 🅰️ ✅ | The BFF is confidential: its refresh tokens need the client secret. Rotation is on anyway (`revokeRefreshToken`, `refreshTokenMaxReuse: 0`), and `store_tokens` keeps the new token. |
| 2.3 Least privilege, audience-restricted access tokens. | ✅ | See section 2. |
| 2.4 No resource owner password credentials grant. | ✅ / 🅰️ | Not used; direct access grants are disabled for `bff`. The user enters the password only at Keycloak. |
| 2.5 Client authentication, asymmetric preferred (`private_key_jwt`, mTLS). | ✅ / ❌ | `client_secret_basic` (form-urlencoded per RFC 6749 2.3.1) for the BFF and for the services' introspection. Keycloak supports `private_key_jwt`; not used yet. |
| 2.6 Use authorization server metadata (RFC 8414). | ✅ | Endpoints come from discovery. `issuer` in the document must equal the configured issuer (RFC 8414 3.3), in the BFF and in the services. |
| 2.6 Clients **SHOULD NOT** influence `client_id` / `sub` confusion. | 🅰️ | Keycloak's client config; no dynamic client registration is used. |
| 2.6 End-to-end TLS; authorization responses **MUST NOT** go over unencrypted connections; no `http` redirect URIs. | ✅ / 🔧 | Browser ↔ gateway and BFF ↔ Keycloak are HTTPS on the public names, verified against the system trust store, which holds the CA of Vault's PKI (`lua_ssl_trusted_certificate`; the BFF refuses non-https endpoints unless `allow_insecure_http`). The redirect URI is https. Plain http only redirects. Inside the Docker network, behind the TLS-terminating gateway, hops are http (🔧, see section 2). |
| 2.6 No CORS at the authorization endpoint. | 🅰️ ✅ | `bff` has no web origins. |
| 2.6 Strict origin checks for in-browser messaging (`postMessage`). | ➖ | Not used by the SPA. |

### Section 4: attacks and mitigations

| Attack | Status | Where / why |
|---|---|---|
| 4.1 Insufficient redirect URI validation. | 🅰️ ✅ | Exact matching at Keycloak. One fixed `redirect_uri` in the BFF config. |
| 4.2 Credential leakage via Referer. | ✅ | The callback answers with an immediate 302 and `Referrer-Policy: no-referrer`. The SPA is also served with `Referrer-Policy: no-referrer`. The code is single-use and PKCE-bound anyway. |
| 4.3 Credentials in browser history. | ✅ | The code URL is only a redirect hop. A replayed code is useless without the verifier. The callback refuses a second use of the pending login (`test_callback_cannot_be_replayed`). No access token is ever in a URL. |
| 4.4 Mix-up. | ✅ | `iss` checked (RFC 9207). |
| 4.5 Authorization code injection. | ✅ | PKCE plus `nonce` checked in the ID token (4.5.3.1, 4.5.3.2). |
| 4.6 Access token injection. | ➖ | No access token in the front channel. |
| 4.7 CSRF. | ✅ | `state` bound to the browser via cookie. `test_callback_in_another_browser_is_rejected` covers login CSRF. |
| 4.8 PKCE downgrade. | ✅ / 🅰️ | S256 required in metadata, always sent, and required by Keycloak for this client. |
| 4.9 Access token leakage at the resource server. | ✅ | A token that leaks at Service A is useless at Service B (audience), at the latest after 5 minutes, and immediately after logout (introspection). |
| 4.10 Misuse of stolen access tokens. | ✅ (partly) | Audience restriction and introspection as above; no sender-constraining (2.2.1). |
| 4.11 Open redirection (client and authorization server). | ✅ / 🅰️ | `util.local_path` for the client; Keycloak validates `redirect_uri` and `post_logout_redirect_uri` against the registered ones. |
| 4.12 307 redirect. | ✅ / 🅰️ | Back channel follows no redirects. Keycloak uses 302. |
| 4.13 TLS-terminating reverse proxies. | ✅ / 🔧 | APISIX terminates TLS and sets `X-Forwarded-*`. Keycloak has a fixed public URL (`KC_HOSTNAME`) and reads `X-Forwarded-*` (`KC_PROXY_HEADERS`). From outside it is reachable only through the gateway; production should also limit those headers to the proxy's address (`proxy-trusted-addresses`). The BFF trusts no forwarded headers: its origin comes from the configured `redirect_uri`. |
| 4.14 Refresh token protection. | ✅ | Confidential client, rotation, idle and absolute expiry, no offline tokens. At logout the refresh token is revoked (RFC 7009, `Provider:revoke`), and the SSO session ends via RP-initiated logout. |
| 4.15 Client impersonating the resource owner. | 🅰️ | Keycloak config. |
| 4.16 Clickjacking. | ✅ / 🅰️ | SPA: `frame-ancestors 'none'` and `X-Frame-Options: DENY`. Keycloak protects its own pages. |
| 4.17 In-browser communication flows. | ➖ | No `postMessage` or popup flows in the SPA. |

## 4. Other IETF and OpenID specifications

| Practice | Status | Where / why |
|---|---|---|
| RFC 7636 PKCE: verifier of 43–128 characters from a CSPRNG; `S256`. | ✅ | `util.random_token(32)` (`resty.random`, strong) gives 43 characters and 256 bits. The challenge is `BASE64URL(SHA256(verifier))` (tested against RFC 7636 appendix B). |
| RFC 6749 10.12 / RFC 9700 4.7: unguessable `state`, bound to the user agent. | ✅ | 256-bit `state` in the pending session behind the cookie. |
| OIDC Core 3.1.2.1 / 3.1.3.7: `nonce` sent and checked. | ✅ | `Provider:validate_id_token`. |
| OIDC Core 3.1.3.7 ID token validation: issuer exact, audience is the client with no extra untrusted audiences, `azp` if present, signature with keys from `jwks_uri`, algorithm allowlist (no `none`, no HMAC), `exp`, `iat`, `nonce`. | ✅ | `Provider:validate_id_token`, tested for every rule. A 60 s leeway allows for clock skew. Keys are cached and refetched for an unknown `kid` (key rotation). |
| OIDC Core 12.2: ID token from a refresh has the same `iss`, `sub` and `aud`. | ✅ | `Provider:validate_id_token(token, nil, expected_sub)` in `Bff:fresh_access_token`. |
| RFC 7009 token revocation at logout. | ✅ | `Bff:logout` revokes the refresh token. |
| OpenID RP-Initiated Logout 1.0. | ✅ | `/bff/logout` returns `logout_url` with `id_token_hint`, `client_id` and the registered `post_logout_redirect_uri`. The SPA navigates there, and Keycloak ends the SSO session without asking and returns to the app (`test_rp_initiated_logout_ends_the_keycloak_session`). |
| OpenID Back-Channel Logout 1.0. | ✅ | See section 2. |
| OpenID Front-Channel Logout. | ➖ | Back-channel is used instead; it needs no third-party iframes or cookies. |
| RFC 9449 DPoP / RFC 8705 mTLS-bound tokens. | ❌ | See RFC 9700 2.2.1. |

## 5. OWASP OAuth 2.0 Cheat Sheet

| # | Recommendation (abridged) | Status | Where / why |
|---|---|---|---|
| 1 | No open redirectors in clients or authorization servers. | ✅ | `util.local_path`; Keycloak's exact redirect URI matching. |
| 2 | If PKCE is the CSRF protection, make sure the server supports it; otherwise use one-time `state`; OIDC uses `nonce`. | ✅ | All three. |
| 3 | Use `iss` against mix-up. | ✅ | RFC 9207, checked. |
| 4 | Without other mix-up defenses, use distinct redirect URIs per authorization server. | ➖ | One authorization server, and `iss` is checked. |
| 5 | Authorization servers must not forward credentials on redirects. | 🅰️ | Keycloak uses 302. |
| 6 | PKCE or nonce against code injection, transaction-specific and bound to client and user agent. | ✅ | Fresh verifier and nonce per login, kept in the session behind this browser's cookie. |
| 7 | Challenge method that doesn't expose the verifier (S256). | ✅ | |
| 8–9 | Authorization server enforces the verifier and blocks downgrade. | 🅰️ ✅ | Keycloak, S256 required for `bff`. |
| 10 | No implicit grant; code with PKCE for all client types. | ✅ | |
| 11 | Sender-constrained tokens (mTLS / DPoP). | ❌ | See RFC 9700 2.2.1. |
| 12 | Refresh tokens sender-constrained or rotated. | ✅ | Rotation, and bound to the confidential client. |
| 13–15 | Minimal privileges, audience-restricted tokens, resource servers check audience, scope and action on every request. | ✅ | See section 2. |
| 16 | No resource owner password credentials grant. | ✅ | |
| 17 | Client authentication, asymmetric preferred. | ✅ / ❌ | Client secrets, random, kept in Vault and read by each client with its own token (section 9). No asymmetric method yet. |
| 18 | Clients can't influence `client_id` / `sub`; end-to-end TLS. | 🅰️ / ✅ | TLS: see RFC 9700 2.6. |
| 19 | No authorization responses over unencrypted connections; no `http` redirect URIs. | ✅ | https redirect URI; plain http only redirects to https. |

## 6. OWASP Session Management Cheat Sheet

| Practice | Status | Where / why |
|---|---|---|
| Session id from a CSPRNG with at least 64 bits of entropy. | ✅ | 256 bits from the OS CSPRNG, `util.random_token(32)` (`sessions.create`). |
| Session id is meaningless (no data in it). | ✅ | Opaque id. The store keys sessions by SHA-256 of the id, so a dump of the store holds no usable cookie values. |
| Generic session cookie name (no fingerprinting). | ✅ / trade-off | `__Host-Http-bff-session` is required in part by the BBA cookie-prefix rule. "bff" reveals little. Configurable with `cookie_name`. |
| Cookie attributes `Secure`, `HttpOnly`, `SameSite`, narrow `Domain`/`Path`. | ✅ | See BBA 6.1.3.2. |
| Non-persistent cookie (no `Expires`/`Max-Age`). | ✅ | It disappears when the browser closes. The server enforces its own lifetimes. |
| Renew the session id on privilege change (login). | ✅ | The pending-login id is dropped at the callback and a new id is issued (`test_pre_login_session_id_is_not_authenticated`). Each `/bff/login` also discards the previous session. |
| Idle timeout and absolute timeout, enforced server-side. | ✅ | 30 min / 8 h, checked on every lookup (`sessions.get`), the same as the Keycloak SSO session. A login in flight expires after 10 min. |
| Logout invalidates the session server-side, also when it happens elsewhere. | ✅ | `Bff:logout` deletes the session, and back-channel logout deletes it when the SSO session ends elsewhere. The old cookie is useless afterwards. |
| Don't cache session-bearing responses (`Cache-Control: no-store`). | ✅ | All BFF and service responses. |
| Bind the session to client properties (IP, User-Agent) to detect hijacking. | ❌ | IP binding breaks mobile users and NAT, and User-Agent is attacker-controlled. `HttpOnly` + `Secure` + `__Host-` + short lifetimes are the protection. |
| Log session lifecycle and security events. | ✅ | Logins, failed callbacks, failed refreshes and exchanges, back-channel logouts and CSRF rejections are logged by the `tokenhandler` logger into the APISIX error log (`make logs`). Session ids and tokens are never logged, except in the dev-only traffic trace (`trace_file` / `TRACE_FILE`, see README), which records requests carrying `X-Trace-Id` in full for the test report and must stay unset in production. |
| Session store survives restarts, is shared across instances. | ❌ / partly | A shared memory dict (`lua_shared_dict tokenhandler-sessions`) shared by all nginx workers. It survives `make reload` but not a gateway restart (users log in again, silently thanks to SSO), and isn't shared between gateway instances. Production with more than one gateway needs a shared store (e.g. Redis) behind the functions of `sessions.lua`. |

## 7. OWASP CSRF Prevention Cheat Sheet

| Practice | Status | Where / why |
|---|---|---|
| State-changing requests not via GET. | ✅ | Logout is `POST` only (`405` otherwise). Login and callback are GET by protocol; both are harmless to trigger (see login CSRF). |
| Custom request headers for API/AJAX requests (with no permissive CORS). | ✅ | `X-BFF-CSRF: 1`, required on everything the SPA calls. |
| Fetch Metadata (`Sec-Fetch-Site`) checks. | ✅ | Must be `same-origin` when the browser sends it, so `same-site` requests from `auth.example.test` are refused too. |
| Verify `Origin` with standard headers. | ✅ | If present, it must equal the origin of `redirect_uri`. |
| `SameSite` cookies as defense in depth. | ✅ | `Strict` session cookie. |
| Login CSRF. | ✅ | `state` bound to the pending-login cookie. A callback opened in another browser fails. |
| Synchronizer token pattern. | ➖ | Not needed with the custom-header defense; the BBA draft prefers that defense over tokens (6.1.3.3.3). |

## 8. OWASP HTTP security headers

| Header | Status | Where |
|---|---|---|
| `Strict-Transport-Security` | ✅ | All responses, global rule in `conf/apisix.yaml`. |
| `Content-Security-Policy` (strict, no `unsafe-*`) | ✅ | SPA, `conf/config.yaml`. |
| `X-Frame-Options: DENY` / `frame-ancestors 'none'` | ✅ | SPA. |
| `X-Content-Type-Options: nosniff` | ✅ | SPA and BFF JSON responses. |
| `Referrer-Policy: no-referrer` | ✅ | SPA and BFF redirects. |
| `Cache-Control: no-store` | ✅ | BFF and service responses. The SPA uses `no-cache` (revalidate), since it holds no user data. |

## 9. OWASP Secrets Management Cheat Sheet

All secrets of the stack and its PKI are in Vault: one server with persistent storage, set up by
[`scripts/stack_init.py`](../scripts/stack_init.py) (`vault-init` and `keycloak-init` jobs).

| Practice | Status | Where / why |
|---|---|---|
| Centralize secrets in a secrets manager instead of code, config files and images. | ✅ | KV engine `kv`: the client secrets of `bff`, `service-a` and `service-b`, Keycloak's admin password, the gateway's TLS key. None of them is in the repository or an image. `conf/apisix.yaml` references them (`$secret://vault/1/tls/…`, `vault:kv/bff#client_secret`), the realm file has no secrets, and the compose file only names Vault paths. |
| Least privilege: each consumer gets access to its own secrets only. | ✅ | One policy and token per component (gateway, bff, service-a, service-b), read-only on its own path, without even Vault's default policy. Tested: no component can read another one's secret, write, or issue certificates (`tests/integration/test_vault.py`). |
| Generate secrets with enough entropy; no default or shared values. | ✅ | `secrets.token_urlsafe(32)` per client, created once in Vault. The previous hard-coded `bff-secret` is refused by Keycloak (`test_keycloak_knows_the_client_secret_from_vault`). |
| Short-lived credentials, rotation. | ✅ / partly | Component tokens expire after 32 days and are re-issued (the old ones revoked) on every start. The TLS certificate lives 90 days and is renewed 30 days before expiry. Consumers re-read secrets after a few minutes, so a rotated secret arrives without a restart. The client secrets themselves are not rotated automatically. |
| Keep private keys in the secrets manager or an HSM; never export CA keys. | ✅ | The PKI engine generates the root CA key internally; it can't be read or exported, not even with the root token (`test_the_ca_key_stays_in_vault`). The CA is name-constrained to `example.test`. |
| Secrets in transit are encrypted. | 🔧 | Vault listens on plain http, reachable only inside the Docker network (and through the gateway with TLS as `vault.example.test`). Production: a TLS listener. |
| Secure the secrets manager itself: no root token at rest, auto-unseal, authenticate workloads by platform identity. | 🔧 | Dev stand-ins: the unseal key and root token are in `.dev/vault-init.json`, the component tokens in `.dev/tokens/` (gitignored, mode 600). Production: auto-unseal with a KMS/HSM, the root token revoked after setup, and Kubernetes or AppRole authentication instead of token files. |
| Audit access to secrets. | ❌ | No Vault audit device is enabled; `vault audit enable file …` would log every access. |
| Don't log secrets. | ✅ / 🔧 | The BFF and the services never log secrets, except in the dev-only traffic trace (see section 6). |

## Known limitations of the dev setup

- **Vault's root token and unseal key on disk** (`.dev/`, gitignored, never published). Whoever has them can read every secret and issue certificates that browsers trusting this CA accept for `*.example.test` (see the warning in the README).
- **Plain http inside the Docker network** (also to Vault). See sections 2 and 9.
- **Sessions in the gateway's shared memory**, not shared between gateway instances. See section 6.
- **Keycloak in dev mode** (`start-dev`, in-memory H2 database): the realm is re-imported on every fresh container, and sessions are lost on restart.
- **Not yet used, though Keycloak supports them:** DPoP / mTLS-bound tokens and `private_key_jwt`.
