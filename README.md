# APISIX tokenhandler

Python plugin for [Apache APISIX](https://apisix.apache.org/), run through the
[python plugin runner](https://github.com/apache/apisix-python-plugin-runner)
via `ext-plugin-pre-req`.

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
refused. The options are in `DEFAULTS` in `plugins/tokenhandler.py`; the route
config in `conf/apisix.yaml` sets issuer, client, redirect URI and the `apis`
allowlist.

## Dev container

Open the folder in VS Code and run **Dev Containers: Reopen in Container**.
After changing `.devcontainer/` (or pulling such a change), use **Rebuild
Container** or `docker compose up -d --build` in `.devcontainer/`.

The container *is* the gateway: APISIX 3.19 (standalone, no etcd) runs in it,
spawns the python runner, and listens on 80 (redirects only) and 443, both
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
plugins/                mounted as the runner's `apisix.plugins` package
  tokenhandler.py       the BFF: endpoints, cookies, CSRF checks, token exchange, API proxying
  oidc.py               OIDC client: discovery, token endpoint, token exchange,
                        ID and logout token validation
  sessions.py           server-side session store (in memory)
  vault.py              reads `vault:<path>#<field>` secrets with the component's own token
  trace.py              dev-only traffic trace for the test report
services/               the resource servers Service A and B
spa/                    the Vue SPA (no build step, vendored Vue runtime)
scripts/stack_init.py   vault-init / keycloak-init: Vault setup, PKI, secrets, tokens
docs/                   OAuth/OIDC best practices and where they are implemented
traffic-report/         generated by the tests: sequence diagrams of their traffic
tests/unit/             plugin and service tests, no stack needed
tests/integration/      login, routing, token exchange, zero trust, SSO/SLO, Vault against the running stack
tests/e2e/              the SPA in headless Chromium (Playwright)
tests/traffic/          pytest plugin recording the traffic, report renderer
```

## Workflow

| command                 | does                                                    |
|-------------------------|---------------------------------------------------------|
| `make test`             | all tests                                               |
| `make test-unit`        | unit tests only                                         |
| `make test-integration` | tests against the running stack                         |
| `make test-e2e`         | SPA browser tests against the running stack             |
| `make reload`           | apply plugin code and `config.yaml` changes             |
| `make logs`             | follow the APISIX error log (includes runner output)    |
| `make lint`             | ruff                                                    |

Plugin code is loaded once at runner start: after editing `plugins/`, run
`make reload` before running the integration tests. The services pick up code
changes when their containers restart.

## Traffic report

Every test run that talks to the stack writes `traffic-report/index.html`.
It has one page per test, with a sequence diagram of the test's HTTP traffic
between Browser, Gateway/BFF, Keycloak, Service A and Service B.
- **Message details:** each message links to its full headers and body, decoded
  JWTs and Basic credentials, the PKCE check, and the RFC / OWASP sections it is
  an example of.
- **Highlighting:** values the test uses and protocol values (`state`, `code`,
  `code_verifier`, tokens, session ids) get one color each across the page;
  click one to follow it through the flow.

The tests record their own side (`requests` and the Playwright browser). The
BFF and the services record the rest into `traffic-report/bff-trace.jsonl`:
their back-channel calls (token exchange, introspection), the forwarded API
requests, Keycloak's back-channel logouts, and notes on their decisions.

They record only requests with an `X-Trace-Id` header (only the tests send
one), and only because the dev config sets `trace_file` / `TRACE_FILE`. The
report contains the dev stack's real tokens and client secrets; never enable
tracing in production.

The recorder lives in `tests/traffic/` (`-p no:tests.traffic.recorder` turns it
off). A test can add its own explanation to the diagram with
`tests.traffic.recorder.note(...)`.

## Notes

- The runner has had no release since 0.2.0 (2022). It is cloned at a
  pinned commit, its dependencies are installed with relaxed pins (PyYAML 5.4.1
  does not build on Python 3.11), and one bug is patched (request id 0
  was treated as an error). See `.devcontainer/Dockerfile`.
- `TokenHandler.config()` gets the route's `value` string as-is and parses it
  as JSON.
- The runner can't send two headers of the same name in one response, so the
  BFF uses a single cookie: a login in flight and the logged-in session are
  the same cookie with a new id.
- Sessions live in the runner's memory: `make reload` ends them. Thanks to the
  Keycloak SSO session, the next login is silent.
- The realm file is a Keycloak export (built through the admin API, then
  exported), so the built-in clients and scopes are complete. The parts that
  matter here: clients `bff`, `service-a`, `service-b` and client scopes
  `api-a`, `api-b`.
- The SPA uses Vue's runtime-only build with render functions instead of
  templates. The template compiler would need `unsafe-eval` in the CSP. A
  Vite build would allow templates/SFCs under the same CSP; the BFF doesn't
  care either way.
