// Vue SPA that logs in through the BFF (plugins/tokenhandler.py).
//
// It never sees a token: the login is a plain navigation to /bff/login, the
// session is an HttpOnly cookie JavaScript cannot read, and API calls go to
// /api/*, where the BFF swaps the cookie for the access token.
//
// No build step: Vue's runtime-only ESM build (vendored, see vendor/) with
// render functions instead of templates. Templates would need Vue's runtime
// compiler, which needs `unsafe-eval` in the Content-Security-Policy.
import { createApp, h, onMounted, ref } from "/vendor/vue.runtime.esm-browser.prod.js";

// The BFF rejects requests without this header. A cross-origin page cannot
// send it without a CORS preflight the BFF never grants (CSRF defense).
const CSRF_HEADER = { "X-BFF-CSRF": "1" };

// another application of the same Keycloak realm, to show single sign-on and single logout
const ACCOUNT_CONSOLE = "https://auth.example.test/realms/demo/account/";

async function bff(path, options = {}) {
  const resp = await fetch(path, {
    ...options,
    // the session cookie goes along, but only to our own origin
    credentials: "same-origin",
    headers: { ...CSRF_HEADER, ...options.headers },
  });
  const body = await resp.json().catch(() => null);
  return { status: resp.status, body };
}

const App = {
  setup() {
    const loading = ref(true);
    const user = ref(null);
    const apiResult = ref(null);
    const error = ref(null);

    async function checkSession() {
      const { status, body } = await bff("/bff/session");
      if (status !== 200) throw new Error(`session check failed: ${status}`);
      user.value = body.authenticated ? body.user : null;
    }

    function login() {
      // A full-page navigation, not fetch: the browser follows the redirect
      // to the authorization server and comes back to the current page.
      const returnTo = window.location.pathname + window.location.search;
      window.location.assign("/bff/login?return_to=" + encodeURIComponent(returnTo));
    }

    // Service A and Service B: the BFF exchanges the session's token for one
    // that only the called service accepts.
    async function callApi(service) {
      error.value = null;
      const path = `/api/${service}/whoami`;
      const { status, body } = await bff(path);
      if (status === 401) {
        // session gone (expired, logged out here or at Keycloak): back to logged out
        user.value = null;
        apiResult.value = null;
        return;
      }
      apiResult.value = { path, status, body };
    }

    async function logout() {
      error.value = null;
      const { status, body } = await bff("/bff/logout", { method: "POST" });
      if (status !== 200) {
        error.value = `logout failed: ${status}`;
        return;
      }
      user.value = null;
      apiResult.value = null;
      // end the session at the authorization server too, if it supports that
      if (body.logout_url) window.location.assign(body.logout_url);
    }

    onMounted(async () => {
      try {
        await checkSession();
      } catch (e) {
        error.value = e.message;
      } finally {
        loading.value = false;
      }
    });

    return () => h("main", [
      h("h1", "Token handler demo"),
      h("p", { class: "lead" },
        "A Vue SPA logged in through a Backend for Frontend. Tokens stay in the gateway; " +
        "each service gets a token only it accepts."),
      error.value && h("p", { class: "error", "data-testid": "error" }, error.value),
      loading.value
        ? h("p", "Checking session…")
        : user.value
          ? loggedIn()
          : h("section", { class: "card" }, [
            h("p", { "data-testid": "status" }, "You are not logged in."),
            h("button", { onClick: login, "data-testid": "login" }, "Log in"),
          ]),
    ]);

    function loggedIn() {
      const u = user.value;
      return h("section", { class: "card" }, [
        h("p", { "data-testid": "status" }, [
          "Logged in as ",
          h("strong", { "data-testid": "user" }, u.email || u.preferred_username || u.sub),
        ]),
        h("dl", Object.entries(u).flatMap(([k, v]) => [h("dt", k), h("dd", String(v))])),
        h("div", { class: "actions" }, [
          h("button", { onClick: () => callApi("a"), "data-testid": "call-api-a" }, "Call service A"),
          h("button", { onClick: () => callApi("b"), "data-testid": "call-api-b" }, "Call service B"),
          h("button", { onClick: logout, class: "secondary", "data-testid": "logout" }, "Log out"),
        ]),
        apiResult.value && h("div", { class: "api" }, [
          h("h2", `GET ${apiResult.value.path} → ${apiResult.value.status}`),
          h("p", { class: "hint" },
            "The service checked a token that was exchanged for it alone; it lists the headers it " +
            "received: a bearer token, no session cookie."),
          h("pre", { "data-testid": "api-result" }, JSON.stringify(apiResult.value.body, null, 2)),
        ]),
        h("p", { class: "hint" }, [
          "Single sign-on: the ",
          h("a", { href: ACCOUNT_CONSOLE, target: "_blank", "data-testid": "account-console" },
            "Keycloak account console"),
          " opens without a password. Signing out there logs you out here too (back-channel logout).",
        ]),
      ]);
    }
  },
};

createApp(App).mount("#app");
