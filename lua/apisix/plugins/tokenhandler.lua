--
-- Token handler: a Backend for Frontend (BFF) for browser-based apps, as in
-- draft-ietf-oauth-browser-based-apps-27 section 6.1 [BBA 6.1], as a native
-- APISIX plugin.
--
-- The SPA never sees a token. It talks to the BFF with a session cookie; the
-- BFF runs the OpenID Connect login as a confidential client and keeps the
-- tokens server side. When it forwards an API request, it adds a token that
-- was exchanged for exactly that API [RFC 8693], so no token is good for more
-- than one service.
--
--     GET  /bff/login?return_to=/x     start the login, redirect to the authorization server
--     GET  <path of redirect_uri>      callback: exchange the code, start the session
--     GET  /bff/session                "check session": is the user logged in, and who [BBA 6.1.2.1]
--     POST /bff/logout                 end the session (and get the RP-initiated logout URL)
--     POST /bff/backchannel-logout     the authorization server ended the user's session
--                                      [OIDC Back-Channel Logout 1.0]
--     *    a path prefix in `apis`     API: forwarded upstream with a token for that API
--
-- Citations in comments: BBA = draft-ietf-oauth-browser-based-apps-27, the
-- others are RFCs, OpenID specs and OWASP cheat sheets; docs/oauth-best-practices.md
-- lists all of them and maps them to this code.
--
local core = require("apisix.core")
local oidc = require("apisix.plugins.tokenhandler.oidc")
local sessions = require("apisix.plugins.tokenhandler.sessions")
local util = require("apisix.plugins.tokenhandler.util")
local vault = require("apisix.plugins.tokenhandler.vault")

local plugin_name = "tokenhandler"

local schema = {
    type = "object",
    properties = {
        issuer = {type = "string", minLength = 1},
        client_id = {type = "string", minLength = 1},
        -- or a Vault reference `vault:<path>#<field>`, see vault.lua
        client_secret = {type = "string", minLength = 1},
        redirect_uri = {type = "string", minLength = 1},
        -- openid for the ID token; the refresh token comes with the code flow
        -- [BBA 6.1.2.2]. No offline_access: offline tokens outlive the SSO
        -- session and would survive a single logout.
        scope = {type = "string", default = "openid profile email"},
        bff_path = {type = "string", default = "/bff/"},
        -- The name prefix sets no attributes, cookie() does. The prefix makes
        -- the browser reject the cookie unless those attributes are present
        -- [BBA 6.1.3.2]:
        -- __Host-: Secure, Path=/, no Domain, from a secure origin. So a subdomain
        --   cannot plant or overwrite it (cookie tossing / session fixation).
        -- __Host-Http-: additionally HttpOnly, so it can only come from a
        --   Set-Cookie header, never from document.cookie (injected script).
        -- Browsers without prefix support accept the cookie anyway.
        -- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#cookie_prefixes
        -- https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis#name-cookie-name-prefixes
        cookie_name = {type = "string", default = "__Host-Http-bff-session"},
        -- static header every SPA request must carry [BBA 6.1.3.3.2]
        csrf_header = {type = "string", default = "X-BFF-CSRF"},
        -- absolute session lifetime; should not exceed the refresh token's [BBA 6.1.2.2]
        session_lifetime = {type = "integer", minimum = 60, default = 8 * 3600},
        -- [OWASP Session: idle timeout]
        session_idle_timeout = {type = "integer", minimum = 60, default = 30 * 60},
        -- how long a started login may take until the callback
        login_timeout = {type = "integer", minimum = 30, default = 10 * 60},
        -- refresh / re-exchange tokens this long before they expire
        refresh_margin = {type = "integer", minimum = 0, default = 30},
        -- where the authorization server sends the user after RP-initiated
        -- logout; default: the app's origin
        post_logout_redirect_uri = {type = "string"},
        -- plain http to the authorization server, for a local dev stack only
        allow_insecure_http = {type = "boolean", default = false},
        -- the APIs behind the BFF: path prefix -> audience and scope the token
        -- for it is exchanged for. The allowlist of APIs [BBA 6.1.3.6]: other
        -- paths are refused.
        apis = {
            type = "object",
            additionalProperties = {
                type = "object",
                properties = {audience = {type = "string"}, scope = {type = "string"}},
                required = {"audience", "scope"},
            },
            default = {},
        },
        -- Vault for secrets; any top-level value `vault:<path>#<field>` is read
        -- from there with this component's own token, see vault.lua
        vault = {
            type = "object",
            properties = {addr = {type = "string"}, token_file = {type = "string"}},
            required = {"addr", "token_file"},
        },
        -- the session store, shared by all gateway instances, see sessions.lua
        redis = {
            type = "object",
            properties = {
                host = {type = "string", minLength = 1},
                port = {type = "integer", minimum = 1, maximum = 65535, default = 6379},
                database = {type = "integer", minimum = 0, default = 0},
                -- key prefix, for a Redis shared with other applications
                prefix = {type = "string", default = "tokenhandler:"},
                -- connect, send and read timeout, milliseconds
                timeout = {type = "integer", minimum = 1, default = 1000},
            },
            required = {"host"},
        },
    },
    required = {"issuer", "client_id", "client_secret", "redirect_uri", "redis"},
}

local _M = {
    version = 0.1,
    priority = 2519,
    name = plugin_name,
    schema = schema,
}

-- claims the SPA gets from /bff/session; tokens and everything else stay here [BBA 6.1.2.4]
local USER_CLAIMS = {"sub", "name", "preferred_username", "email", "email_verified"}

function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end

-- -- responses -------------------------------------------------------------------

local function json(status, body, cookie, extra)
    core.response.set_header("Content-Type", "application/json")
    -- session state and user data must not be cached anywhere [OWASP Session: caching]
    core.response.set_header("Cache-Control", "no-store")
    core.response.set_header("X-Content-Type-Options", "nosniff")
    for k, v in pairs(extra or {}) do
        core.response.set_header(k, v)
    end
    if cookie then
        core.response.set_header("Set-Cookie", cookie)
    end
    return status, util.json_encode(body)
end

local function redirect(location, cookie)
    core.response.set_header("Location", location)
    core.response.set_header("Cache-Control", "no-store")
    -- the callback URL holds code and state: never leak it as Referer [RFC 9700 4.2.4]
    core.response.set_header("Referrer-Policy", "no-referrer")
    if cookie then
        core.response.set_header("Set-Cookie", cookie)
    end
    return 302
end

-- -- request state ---------------------------------------------------------------

-- one request
local Bff = {}
Bff.__index = Bff

local function origin_of(url)
    local parts = util.split_url(url)
    local default = (parts.scheme == "https" and parts.port == 443) or (parts.scheme == "http" and parts.port == 80)
    return parts.scheme .. "://" .. parts.host .. (default and "" or (":" .. parts.port)), parts.path:gsub("%?.*$", "")
end

function Bff.new(conf, ctx)
    local self = setmetatable({conf = conf, ctx = ctx}, Bff)
    self.sessions = sessions.new(conf.redis)
    self.provider = oidc.get({
        issuer = conf.issuer, client_id = conf.client_id, client_secret = conf.client_secret,
        allow_insecure_http = conf.allow_insecure_http,
        -- seen logout-token jti, in Redis: shared by all workers and gateway instances
        replay = self.sessions,
    })
    self.origin, self.callback_path = origin_of(conf.redirect_uri)
    return self
end

function Bff:header(name)
    return core.request.header(self.ctx, name)
end

function Bff:arg(name)
    local v = core.request.get_uri_args(self.ctx)[name]
    return type(v) == "string" and v or nil
end

-- value of our cookie in the Cookie header
function Bff:session_id()
    for pair in (self:header("Cookie") or ""):gmatch("[^;]+") do
        local name, value = pair:match("^%s*([^=]+)=(.*)$")
        if name == self.conf.cookie_name then
            return value
        end
    end
    return nil
end

function Bff:cookie(value, same_site, clear)
    -- HttpOnly: no JavaScript access, XSS cannot steal the session. Secure,
    -- HttpOnly, Path=/ and no Domain are also what the __Host-Http- name
    -- prefix requires; without them the browser drops the cookie. No
    -- Expires/Max-Age: gone when the browser closes, the server enforces the
    -- lifetimes anyway [BBA 6.1.3.2].
    local c = self.conf.cookie_name .. "=" .. value .. "; Path=/; Secure; HttpOnly; SameSite=" .. same_site
    return clear and (c .. "; Max-Age=0") or c
end

function Bff:method_is(method)
    return core.request.get_method() == method
end

function Bff:wrong_method(method)
    return json(405, {error = "method_not_allowed"}, nil, {Allow = method})
end

-- CSRF defense for everything the SPA calls with the session cookie [BBA 6.1.3.3].
function Bff:csrf_ok()
    -- The custom header: a cross-origin page can only send it after a CORS
    -- preflight, and the BFF answers no preflight (it sends no CORS headers at
    -- all), so only same-origin JavaScript gets here
    -- [BBA 6.1.3.3.2; OWASP CSRF: custom request headers].
    local csrf = self:header(self.conf.csrf_header)
    local ok = csrf == "1"
    -- Fetch Metadata and Origin, where the browser sends them, as a second
    -- line of defense [OWASP CSRF: Fetch Metadata, verifying origin].
    local site = self:header("Sec-Fetch-Site")
    if site ~= nil and site ~= "same-origin" then
        ok = false
    end
    local origin = self:header("Origin")
    if origin ~= nil and origin ~= self.origin then
        ok = false
    end
    if not ok then
        core.log.warn("CSRF check failed for ", core.request.get_method(), " ", self.ctx.var.uri)
    end
    return ok
end

function Bff:csrf_refused()
    return json(403, {error = "csrf_check_failed"})
end

function Bff:login_failed(reason)
    core.log.warn("login failed: ", reason)
    return json(400, {error = "login_failed", reason = reason}, self:cookie("", "Lax", true))
end

-- -- endpoints -------------------------------------------------------------------

function Bff:login()
    if not self:method_is("GET") then
        return self:wrong_method("GET")
    end
    -- A login always starts a new session: whatever the browser had is dropped.
    self.sessions:delete(self:session_id())

    local state, nonce, verifier = util.random_token(32), util.random_token(32), util.random_token(32)
    local now = ngx.now()
    local pending = {
        expires_at = now + self.conf.login_timeout, idle_timeout = self.conf.login_timeout,
        state = state, nonce = nonce, code_verifier = verifier,
        return_to = util.local_path(self:arg("return_to")),
    }
    -- PKCE S256 challenge [RFC 7636 4.2]
    local challenge = util.b64url(util.sha256(verifier))
    local url = self.provider:authorization_url(self.conf.redirect_uri, self.conf.scope, state, nonce, challenge)

    -- The pending login is bound to this browser by the cookie, which is what
    -- makes `state` a CSRF defense [RFC 9700 4.7.1]. SameSite=Lax, not Strict:
    -- the callback is a top-level navigation coming from the authorization
    -- server, a cross-site one if that server is on another site, and a
    -- Strict cookie would not be sent along.
    return redirect(url, self:cookie(self.sessions:create(pending), "Lax"))
end

local function store_tokens(session, tokens)
    session.access_token = tokens.access_token
    session.access_token_expires_at = tokens.expires_in and (ngx.now() + tonumber(tokens.expires_in)) or nil
    -- with refresh token rotation the server hands out a new one each time
    if tokens.refresh_token then
        session.refresh_token = tokens.refresh_token
    end
    if tokens.id_token then
        session.id_token = tokens.id_token
    end
end

-- runs fn; an error of `kind` is returned as (nil, err), others are re-raised
local function catch(kind, fn, ...)
    local ok, result = pcall(fn, ...)
    if ok then
        return result
    end
    if type(result) == "table" and result.kind == kind then
        return nil, result
    end
    error(result, 0)
end

function Bff:callback()
    if not self:method_is("GET") then
        return self:wrong_method("GET")
    end
    local session_id = self:session_id()
    local pending = self.sessions:get(session_id)
    -- single use: the pending login is gone whatever happens next
    self.sessions:delete(session_id)
    if not pending or not pending.state then
        return self:login_failed("no login in progress")
    end
    if not util.const_eq(self:arg("state"), pending.state) then
        return self:login_failed("state mismatch")
    end

    -- mix-up defense: the response must come from our issuer [RFC 9207; RFC 9700 4.4.2.1]
    local iss = self:arg("iss")
    if (iss ~= nil or self.provider:metadata().authorization_response_iss_parameter_supported)
            and iss ~= self.provider.issuer then
        return self:login_failed("issuer mismatch")
    end

    local err = self:arg("error")
    if err then
        return self:login_failed("authorization server: " .. err)
    end
    local code = self:arg("code")
    if not code then
        return self:login_failed("no code")
    end

    -- confidential client: code + PKCE verifier + client secret [BBA 6.1.3.1; RFC 7636 4.5]
    local tokens, failure = catch("oidc", self.provider.exchange_code, self.provider, code, self.conf.redirect_uri,
                                  pending.code_verifier)
    if not tokens then
        if failure.error == nil then
            error(failure, 0)
        end
        return self:login_failed("token endpoint: " .. failure.error)
    end
    if not tokens.id_token then
        return self:login_failed("no ID token, is `openid` in the scope?")
    end
    local claims, invalid = catch("token", self.provider.validate_id_token, self.provider, tokens.id_token,
                                  pending.nonce)
    if not claims then
        return self:login_failed("invalid ID token: " .. invalid.message)
    end

    local user = {}
    for _, name in ipairs(USER_CLAIMS) do
        user[name] = claims[name]
    end
    local now = ngx.now()
    local session = {
        expires_at = now + self.conf.session_lifetime, idle_timeout = self.conf.session_idle_timeout,
        user = user,
        -- the authorization server's session, for back-channel logout
        sid = claims.sid,
        service_tokens = {},
    }
    store_tokens(session, tokens)
    core.log.info("login of ", claims.sub)
    -- A new id after authentication: an id the browser had before login
    -- (planted or not) never becomes an authenticated session
    -- [OWASP Session: renew the session ID after login].
    local new_id = self.sessions:create(session)
    -- The session cookie is SameSite=Strict [BBA 6.1.3.2]: the SPA calls the BFF same-site only.
    return redirect(pending.return_to, self:cookie(new_id, "Strict"))
end

function Bff:session_info()
    if not self:method_is("GET") then
        return self:wrong_method("GET")
    end
    if not self:csrf_ok() then
        return self:csrf_refused()
    end
    local session = self.sessions:get(self:session_id())
    if not session or not session.user then
        return json(200, {authenticated = false})
    end
    return json(200, {authenticated = true, user = session.user})
end

function Bff:logout()
    -- POST + custom header: a cross-site page cannot log the user out [OWASP CSRF]
    if not self:method_is("POST") then
        return self:wrong_method("POST")
    end
    if not self:csrf_ok() then
        return self:csrf_refused()
    end
    local session = self.sessions:delete(self:session_id())
    local logout_url
    if session and session.user then
        if session.refresh_token then
            -- the refresh token outlives the session otherwise [RFC 7009]
            self.provider:revoke(session.refresh_token)
        end
        logout_url = self.provider:end_session_url(session.id_token,
                                                   self.conf.post_logout_redirect_uri or (self.origin .. "/"))
    end
    -- the SPA navigates to logout_url (if any) to end the session at the authorization server too
    return json(200, {logout_url = util.nullable(logout_url)}, self:cookie("", "Strict", true))
end

-- The authorization server ended the user's session there, e.g. after a
-- logout in another application: end ours too [OIDC Back-Channel Logout 1.0,
-- 2.5-2.8]. Server to server: no cookie, no CSRF header; the signed logout
-- token is the authentication.
function Bff:backchannel_logout()
    if not self:method_is("POST") then
        return self:wrong_method("POST")
    end
    local body = core.request.get_body() or ""
    local logout_token = ngx.decode_args(body).logout_token
    local claims, invalid
    if type(logout_token) ~= "string" then
        invalid = {message = "no logout_token"}
    else
        claims, invalid = catch("token", self.provider.validate_logout_token, self.provider, logout_token)
    end
    if not claims then
        core.log.warn("back-channel logout refused: ", invalid.message)
        return json(400, {error = "invalid_request", error_description = invalid.message})
    end

    -- by session id if given, else every session of the user [2.4]
    local ended = self.sessions:delete_by(claims.sid, claims.sub)
    core.log.info("back-channel logout of sid ", tostring(claims.sid), ": ", #ended, " session(s) ended")
    -- [2.8] 200 OK, not cached
    return json(200, {})
end

-- -- tokens ------------------------------------------------------------------------

-- The session's access token, refreshed if it is about to expire; nil if that is impossible.
function Bff:fresh_access_token(session)
    local expires_at = session.access_token_expires_at
    if expires_at == nil or expires_at - self.conf.refresh_margin > ngx.now() then
        return session.access_token
    end
    if not session.refresh_token then
        return nil
    end
    local ok, err = pcall(function()
        local tokens = self.provider:refresh(session.refresh_token)
        if tokens.id_token then
            self.provider:validate_id_token(tokens.id_token, nil, session.user.sub)
        end
        store_tokens(session, tokens)
    end)
    if ok then
        return session.access_token
    end
    if type(err) == "table" and (err.kind == "token" or (err.kind == "oidc" and err.error)) then
        -- invalid_grant: revoked, expired or (rotation) reused refresh token; or a bad ID token
        core.log.warn("refresh failed for ", session.user.sub, ": ", err.error or err.message)
        return nil
    end
    error(err, 0)
end

-- The `apis` entry for this request: longest matching path prefix.
function Bff:api()
    local path, best = self.ctx.var.uri, nil
    for prefix, api in pairs(self.conf.apis) do
        if path:sub(1, #prefix) == prefix and (not best or #prefix > #best.prefix) then
            best = {prefix = prefix, audience = api.audience, scope = api.scope}
        end
    end
    return best
end

-- A token only for this API: the session's access token exchanged for the
-- API's audience and scope [RFC 8693; RFC 9700 2.3]. Cached in the session
-- until shortly before it expires; nil if the session is over.
function Bff:api_token(session_id, api)
    return self.sessions:locked(session_id, function()
        -- the session as it is now, another worker may have refreshed it meanwhile
        local session = self.sessions:get(session_id)
        if not session or not session.user then
            return nil
        end
        local cached = (session.service_tokens or {})[api.audience]
        if cached and cached.expires_at - self.conf.refresh_margin > ngx.now() then
            return cached.token
        end
        local subject = self:fresh_access_token(session)
        if not subject then
            return nil
        end
        local tokens, failure = catch("oidc", self.provider.exchange_token, self.provider, subject, api.audience,
                                      api.scope)
        if not tokens then
            if failure.error == nil then
                error(failure, 0)
            end
            -- the subject token was refused: the session at the authorization server is over
            core.log.warn("token exchange for ", api.audience, " failed for ", session.user.sub, ": ", failure.error)
            return nil
        end
        session.service_tokens = session.service_tokens or {}
        session.service_tokens[api.audience] = {
            token = tokens.access_token, expires_at = ngx.now() + (tonumber(tokens.expires_in) or 60),
        }
        self.sessions:save(session_id, session)
        return tokens.access_token
    end)
end

function Bff:proxy()
    if not self:csrf_ok() then
        return self:csrf_refused()
    end
    local api = self:api()
    if not api then
        -- not in the allowlist of APIs [BBA 6.1.3.6]
        return json(404, {error = "not_found"})
    end
    local session_id = self:session_id()
    local session = self.sessions:get(session_id)
    if not session or not session.user then
        return json(401, {error = "unauthenticated"})
    end
    local token = self:api_token(session_id, api)
    if not token then
        self.sessions:delete(session_id)
        return json(401, {error = "session_expired"}, self:cookie("", "Strict", true))
    end

    -- The token is added here, on the way upstream; it never reaches the
    -- browser [BBA 6.1.1]. It replaces any Authorization header the browser
    -- sent. The session cookie and the CSRF header are BFF internals and are
    -- not passed on.
    core.request.set_header(self.ctx, "Authorization", "Bearer " .. token)
    core.request.set_header(self.ctx, "Cookie", nil)
    core.request.set_header(self.ctx, self.conf.csrf_header, nil)
    return nil
end

function Bff:handle()
    local path, bff = self.ctx.var.uri, self.conf.bff_path
    if path == self.callback_path then
        return self:callback()
    elseif path == bff .. "login" then
        return self:login()
    elseif path == bff .. "session" then
        return self:session_info()
    elseif path == bff .. "logout" then
        return self:logout()
    elseif path == bff .. "backchannel-logout" then
        return self:backchannel_logout()
    elseif path:sub(1, #bff) == bff then
        return json(404, {error = "not_found"})
    end
    -- Everything else that the route sends here is an API. The `apis` config
    -- and the routes are the allowlist of upstreams: the destination never
    -- comes from the request [BBA 6.1.3.6].
    return self:proxy()
end

-- -- the plugin ------------------------------------------------------------------

function _M.access(conf, ctx)
    local ok, status, body = pcall(function()
        return Bff.new(vault.resolve(conf, conf.vault), ctx):handle()
    end)
    if ok then
        return status, body
    end
    local err = status
    if type(err) == "table" and err.kind == "vault" then
        core.log.error("secrets unavailable: ", err.message)
        return json(503, {error = "secrets_unavailable"})
    elseif type(err) == "table" and err.kind == "oidc" then
        core.log.error("authorization server error: ", err.message)
        return json(502, {error = "authorization_server_unavailable"})
    end
    core.log.error("tokenhandler failed: ", type(err) == "table" and (err.message or core.json.encode(err)) or err)
    return json(500, {error = "internal_error"})
end

return _M
