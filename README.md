# APISIX tokenhandler

A native Lua plugin for [Apache APISIX](https://apisix.apache.org/),
`tokenhandler` (`lua/apisix/plugins/tokenhandler.lua`).

The plugin is a **Backend for Frontend** (BFF) for browser apps, following
[draft-ietf-oauth-browser-based-apps, section 6.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps#name-backend-for-frontend-bff).
It runs the OpenID Connect login against Keycloak as a confidential client,
keeps all tokens in a server-side session, and gives the browser only an
`HttpOnly` session cookie.

Behind it are two APIs, Service A and Service B. For each call the BFF
exchanges the session's token (RFC 8693) for one that only that service
accepts. Each service checks every token itself and introspects it at Keycloak
(zero trust), so a token for A is useless at B and vice versa.

Single sign-on and single logout work through Keycloak:
- Keycloak's account console opens without a password once you're logged in.
- Logging out anywhere ends the BFF session through a back-channel logout.

A Vue SPA in `spa/` shows all of it.

[docs/oauth-best-practices.md](docs/oauth-best-practices.md) lists the IETF and
OWASP OAuth/OIDC best practices and where each is implemented, or why not.

## Hosts, HTTPS and secrets

Everything runs on real names over HTTPS, in the reserved test domain
`example.test`:

| URL                          | what                                         |
|------------------------------|----------------------------------------------|
| <https://app.example.test>   | the SPA, the BFF (`/bff/*`), the APIs (`/api/a/*`, `/api/b/*`) |
| <https://auth.example.test>  | Keycloak (realm `demo`; admin `admin`, password in Vault at `kv/keycloak/admin`) |
| <https://vault.example.test> | Vault UI (sign in with the root token from `.dev/vault-init.json`) |

Secrets and the PKI live in [Vault](https://developer.hashicorp.com/vault). It
is a single server with persistent storage (the `vault-data` volume), which the
`vault-init` job (`scripts/stack_init.py`) initializes, unseals and sets up on
every start:

- **PKI engine `pki`:** a root CA whose private key never leaves Vault,
  name-constrained to `example.test`. It issues the gateway's certificate for
  `*.example.test` (90 days, renewed automatically). APISIX fetches that
  certificate from Vault at the TLS handshake.
- **KV engine `kv`:** random client secrets for `bff`, `service-a` and
  `service-b`, and Keycloak's admin password. They are created once and never
  written into the repository. The realm file contains no secrets; the
  `keycloak-init` job sets them in Keycloak.
- **One token per component** (gateway, bff, service-a, service-b), whose
  policy allows reading only that component's own secrets. The tokens are
  re-issued on every start.

One-time setup on your machine:

1. Add to `/etc/hosts` (Windows: `C:\Windows\System32\drivers\etc\hosts`):

   ```
   127.0.0.1 app.example.test auth.example.test vault.example.test
   ```

2. Start the stack once. `vault-init` writes the public CA certificate to
   `.dev/ca.pem`.

3. Trust `.dev/ca.pem` in your browser's or OS's certificate settings, as an
   authority for websites. Inside the dev container it is trusted
   automatically. The CA lives in Vault's volume, so you import it once.

User: `alice` / `alice-password`.

> **Warning: never commit or publish `.dev/`.** It is in `.gitignore`; keep it
> that way. It holds:
> - Vault's unseal key and root token (`vault-init.json`), with which anyone can
>   read every secret and issue certificates for `*.example.test`;
> - the component tokens;
> - Keycloak's admin password.
>
> A CA in your browser's trust store vouches for every certificate made with
> its key. If that key, or Vault's root token, were public, for example in a
> GitHub repository, anyone could impersonate the sites the CA covers to you,
> without a browser warning.
>
> This setup limits the damage in two ways:
> - The CA's key never leaves Vault, not even for the root token.
> - The CA is name-constrained to `example.test`, so it can't vouch for any
>   other domain.
>
> Never trust a CA whose key someone else has (including one from another
> project's repository). Remove this CA from your trust store when you no
> longer need it.
>
> For production: auto-unseal with a KMS/HSM, no root token at rest, and a
> platform auth method (Kubernetes, AppRole) instead of token files.

To start over with a new CA and new secrets, run `docker compose down -v` in
`.devcontainer/` (this deletes the `vault-data` volume), delete `.dev/`, start
again, and re-import the CA.

## BFF endpoints

| endpoint                         | does                                                          |
|----------------------------------|---------------------------------------------------------------|
| `GET /bff/login?return_to=/x`    | start the login, redirect to Keycloak                         |
| `GET /bff/callback`              | check state and `iss`, code exchange, ID token validation, session cookie, back to `return_to` |
| `GET /bff/session`               | `{"authenticated": true, "user": {...}}` or `{"authenticated": false}` |
| `POST /bff/logout`               | end the session; `{"logout_url": ...}` for RP-initiated logout at Keycloak |
| `POST /bff/backchannel-logout`   | Keycloak ended the SSO session: end the matching BFF sessions |
| `* /api/a/...`, `* /api/b/...`   | forwarded to Service A / B with a token exchanged for that service, prefix stripped |

The SPA's requests (everything except login, callback and back-channel logout)
need the header `X-BFF-CSRF: 1` (CSRF defense); cross-origin requests are
refused. The options are in the plugin's schema in `lua/apisix/plugins/tokenhandler.lua`; the route
config in `conf/apisix.yaml` sets issuer, client, redirect URI and the `apis`
allowlist.

## Dev container

Open the folder in VS Code and run **Dev Containers: Reopen in Container**.
After changing `.devcontainer/` (or pulling such a change), use **Rebuild
Container** or `docker compose up -d --build` in `.devcontainer/`.

The container *is* the gateway: APISIX 3.19 (standalone, no etcd) runs in it,
loads the plugin from `lua/`, and listens on 80 (redirects only) and 443, both
published to the host. At start, `.devcontainer/gateway-entrypoint.sh` hands
APISIX its Vault token and trusts the CA of Vault's PKI inside the container.
The compose stack adds:

- **`vault`**, plus the one-shot jobs **`vault-init`** and **`keycloak-init`**
  (see above).

- **`keycloak`**: Keycloak 26.8 in dev mode, behind the gateway. The realm
  is imported from `conf/keycloak/demo-realm.json` on every fresh start.
- **`service-a`, `service-b`**: the resource servers (`services/resource.py`).

`app.example.test`, `auth.example.test` and `vault.example.test` are network
aliases of the gateway, so inside the stack every component uses the same public HTTPS URLs
as your browser.

The SPA is served by a static server block in the gateway's nginx
(`conf/config.yaml`) behind the catch-all route of `app.example.test`, so SPA,
BFF and APIs share one origin.

Claude Code is installed (`claude` CLI plus the VS Code extension). Its config
and login are kept in the `claude-config` volume, so they survive rebuilds.

The container user's uid/gid default to 1000. If yours differ, export
`USER_UID` / `USER_GID` before building.

```
.devcontainer/          image, compose stack, VS Code settings
conf/config.yaml        APISIX static config incl. the SPA server (`make reload`)
conf/apisix.yaml        routes and BFF config, hot reloaded on save
conf/keycloak/          realm: clients, scopes, user, no secrets (restart the keycloak container)
conf/vault/             Vault server config
.dev/                   written by vault-init: CA certificate, tokens, unseal key; gitignored
lua/apisix/plugins/      the tokenhandler plugin (APISIX `extra_lua_path`)
  tokenhandler.lua      the BFF: endpoints, cookies, CSRF checks, token exchange, API proxying
  tokenhandler/oidc.lua OIDC client: discovery, token endpoint, token exchange,
                        ID and logout token validation (JWS via lua-resty-openssl)
  tokenhandler/sessions.lua  server-side sessions in Redis
  tokenhandler/vault.lua     reads `vault:<path>#<field>` secrets with the BFF's own token
  tokenhandler/util.lua      encoding, randomness, back-channel HTTP client
services/               the resource servers Service A and B (Python), with their
                        Vault client
spa/                    the Vue SPA (no build step, vendored Vue runtime)
scripts/stack_init.py   vault-init / keycloak-init: Vault setup, PKI, secrets, tokens
docs/                   OAuth/OIDC best practices and where they are implemented
tests/lua/              Lua unit tests of the plugin modules (run by tests/unit/test_lua.py)
tests/unit/             service and Lua tests, no stack needed
tests/integration/      login, routing, token exchange, zero trust, SSO/SLO, Vault against the running stack
tests/e2e/              the SPA in headless Chromium (Playwright)
```

## Workflow

| command                 | does                                                    |
|-------------------------|---------------------------------------------------------|
| `make test`             | all tests                                               |
| `make test-unit`        | unit tests only                                         |
| `make test-integration` | tests against the running stack                         |
| `make test-e2e`         | SPA browser tests against the running stack             |
| `make reload`           | apply plugin code and `config.yaml` changes             |
| `make logs`             | follow the APISIX error log (includes the plugin's log)  |
| `make lint`             | ruff                                                    |

Plugin code is loaded when nginx workers start: after editing `lua/`, run
`make reload` before running the integration tests (sessions survive it, they
live in Redis). The services pick up code changes when their
containers restart.

## Notes

- The plugin keeps sessions, the per-session locks for token refresh and
  exchange, and the ids of seen logout tokens in Redis (the `redis` service;
  plugin option `redis`), so all nginx workers and gateway instances agree,
  and sessions survive a gateway restart. Cached Vault secrets stay in the
  shared memory dict `tokenhandler-cache` declared in `conf/config.yaml`, per
  gateway.
  `tests/lua/test_sessions.lua` needs the Redis (`TOKENHANDLER_TEST_REDIS`,
  default `redis`) and is skipped without one.
- `conf/config.yaml` lists the plugins in use (`plugins:` replaces APISIX's
  default list); add a plugin there before using it in `apisix.yaml`.
- The realm file is a Keycloak export (built through the admin API, then
  exported), so the built-in clients and scopes are complete. The parts that
  matter here: clients `bff`, `service-a`, `service-b` and client scopes
  `api-a`, `api-b`.
- The SPA uses Vue's runtime-only build with render functions instead of
  templates. The template compiler would need `unsafe-eval` in the CSP. A
  Vite build would allow templates/SFCs under the same CSP; the BFF doesn't
  care either way.
