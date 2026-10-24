--
-- Minimal OpenID Connect client for the BFF: the back channel to the
-- authorization server (discovery, token endpoint, token exchange,
-- revocation) and the validation of ID and logout tokens.
--
-- The BFF is a confidential client [BBA 6.1.3.1]: it authenticates at the
-- token endpoint with its client secret, and only it ever sees tokens.
--
-- Errors are raised as tables {kind = "oidc", message = ..., error = <OAuth
-- error code or nil>} or {kind = "token", message = ...} (an ID or logout
-- token failed validation).
--
local pkey = require("resty.openssl.pkey")
local trace = require("apisix.plugins.tokenhandler.trace")
local util = require("apisix.plugins.tokenhandler.util")

local _M = {}

-- Asymmetric algorithms only: never `none`, and no HMAC, which would make the
-- client secret a signing key [OIDC Core 3.1.3.7 (7)].
local SIGNING_ALGORITHMS = {RS256 = true, PS256 = true, ES256 = true}
-- tolerated clock skew for exp/iat
local LEEWAY = 60
local TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
local ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
local BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"
-- how long a logout token's jti is remembered against replay
local LOGOUT_TOKEN_MAX_AGE = 300
local JWKS_LIFETIME = 300

_M.ACCESS_TOKEN_TYPE = ACCESS_TOKEN_TYPE

-- a JSON list, or {} for anything else (null, missing, ...)
local function list(value)
    return type(value) == "table" and value or {}
end

local function oidc_error(message, oauth_error)
    error({kind = "oidc", message = message, error = oauth_error}, 0)
end

local function token_error(message)
    error({kind = "token", message = message}, 0)
end

-- default transport: util.http, recorded in the dev trace; it passes the
-- trace id on, so the next hop traces too
local function traced_http(method, url, opts)
    opts = opts or {}
    if trace.active() then
        opts.headers = opts.headers or {}
        opts.headers[trace.HEADER] = trace.current_id()
    end
    local t_start = trace.now()
    local status, body, headers, err = util.http(method, url, opts)
    if trace.active() then
        trace.exchange(method, url, opts.headers, opts.body, status, headers, body, t_start, err)
    end
    return status, body, err
end

local Provider = {}
Provider.__index = Provider

-- opts: issuer, client_id, client_secret, allow_insecure_http, http (for tests),
-- replay (a shared dict for seen logout-token jti; nil: worker-local table), clock
function _M.new(opts)
    local self = setmetatable({
        issuer = opts.issuer,
        client_id = opts.client_id,
        client_secret = opts.client_secret,
        allow_insecure_http = opts.allow_insecure_http,
        http = opts.http or traced_http,
        replay = opts.replay,
        clock = opts.clock or ngx.time,
        seen_jti = {},
        jwks = nil,
        jwks_fetched = 0,
    }, Provider)
    self:require_https(opts.issuer)
    return self
end

-- one provider per issuer/client and worker, so discovery and keys are cached across requests
local providers = {}

function _M.get(opts)
    local key = table.concat({opts.issuer, opts.client_id, opts.client_secret, tostring(opts.allow_insecure_http)}, "\0")
    if not providers[key] then
        providers[key] = _M.new(opts)
    end
    return providers[key]
end

-- authorization responses and tokens MUST NOT travel unencrypted [RFC 9700 2.6];
-- plain http is only for a local dev stack
function Provider:require_https(url)
    if not self.allow_insecure_http and not tostring(url):find("^https://") then
        oidc_error("refusing non-https endpoint " .. tostring(url))
    end
end

-- -- metadata ---------------------------------------------------------------

-- Discovery document, fetched once [RFC 8414; RFC 9700 2.6]. Endpoints come
-- from here instead of configuration, so they always belong to the configured issuer.
function Provider:metadata()
    if self._metadata then
        return self._metadata
    end
    local url = self.issuer:gsub("/$", "") .. "/.well-known/openid-configuration"
    self._metadata = self:validate_metadata(self:get_json(url))
    return self._metadata
end

function Provider:validate_metadata(metadata)
    -- the issuer in the document MUST be identical to the one it was fetched
    -- for, otherwise an attacker-controlled document could be used [RFC 8414 3.3]
    if metadata.issuer ~= self.issuer then
        oidc_error("discovery issuer " .. tostring(metadata.issuer) .. " does not match " .. self.issuer)
    end
    for _, name in ipairs({"authorization_endpoint", "token_endpoint", "jwks_uri"}) do
        if not metadata[name] then
            oidc_error("discovery document lacks " .. name)
        end
        self:require_https(metadata[name])
    end
    -- PKCE is our protection against code injection; make sure the server
    -- supports it instead of silently relying on it [RFC 9700 2.1.1; OWASP OAuth2 #2]
    local s256 = false
    for _, m in ipairs(list(metadata.code_challenge_methods_supported)) do
        s256 = s256 or m == "S256"
    end
    if not s256 then
        oidc_error("authorization server does not support PKCE with S256")
    end
    return metadata
end

-- -- front channel ------------------------------------------------------------

function Provider:authorization_url(redirect_uri, scope, state, nonce, code_challenge)
    local endpoint = self:metadata().authorization_endpoint
    return endpoint .. (endpoint:find("?", 1, true) and "&" or "?") .. ngx.encode_args({
        -- authorization code grant only, no implicit or hybrid flow [RFC 9700 2.1.2; BBA 6.1.3.1]
        response_type = "code",
        client_id = self.client_id,
        -- registered at the server and matched exactly there [RFC 9700 2.1]
        redirect_uri = redirect_uri,
        scope = scope,
        -- CSRF protection of the redirect, bound to the browser by the session cookie [RFC 9700 4.7]
        state = state,
        -- binds the ID token to this login [OIDC Core 3.1.2.1; RFC 9700 4.5.3.2]
        nonce = nonce,
        -- PKCE; S256 so the verifier never appears in the front channel [RFC 7636; OWASP OAuth2 #7]
        code_challenge = code_challenge,
        code_challenge_method = "S256",
    })
end

-- RP-initiated logout URL, if the server supports it [OIDC RP-Initiated Logout 1.0].
function Provider:end_session_url(id_token_hint, post_logout_redirect_uri)
    local endpoint = self:metadata().end_session_endpoint
    if not endpoint then
        return nil
    end
    local params = {client_id = self.client_id, post_logout_redirect_uri = post_logout_redirect_uri}
    params.id_token_hint = id_token_hint
    return endpoint .. (endpoint:find("?", 1, true) and "&" or "?") .. ngx.encode_args(params)
end

-- -- token endpoint -----------------------------------------------------------

function Provider:exchange_code(code, redirect_uri, code_verifier)
    return self:token_request({grant_type = "authorization_code", code = code, redirect_uri = redirect_uri,
                               code_verifier = code_verifier})
end

-- [BBA 6.1.2.2] refresh with client authentication, tokens stay in the BFF
function Provider:refresh(refresh_token)
    return self:token_request({grant_type = "refresh_token", refresh_token = refresh_token})
end

-- OAuth 2.0 Token Exchange [RFC 8693 2.1]: trades the session's access token
-- for one that is only meant for `audience`, with only `scope`
-- [RFC 9700 2.3: audience-restricted, least privilege].
function Provider:exchange_token(subject_token, audience, scope)
    local tokens = self:token_request({
        grant_type = TOKEN_EXCHANGE,
        subject_token = subject_token,
        subject_token_type = ACCESS_TOKEN_TYPE,
        requested_token_type = ACCESS_TOKEN_TYPE,
        audience = audience,
        scope = scope,
    })
    if tokens.issued_token_type ~= ACCESS_TOKEN_TYPE then
        oidc_error("token exchange issued " .. tostring(tokens.issued_token_type) .. ", not an access token")
    end
    return tokens
end

-- Revokes `token` if the server has a revocation endpoint [RFC 7009]. Best effort.
function Provider:revoke(token, token_type_hint)
    local endpoint = self:metadata().revocation_endpoint
    if not endpoint then
        return false
    end
    local ok = pcall(function()
        self:require_https(endpoint)
        self:post(endpoint, {token = token, token_type_hint = token_type_hint or "refresh_token"})
    end)
    return ok
end

function Provider:token_request(form)
    local tokens = self:post(self:metadata().token_endpoint, form)
    if not tokens.access_token or tostring(tokens.token_type or ""):lower() ~= "bearer" then
        oidc_error("token response without bearer access token")
    end
    return tokens
end

function Provider:post(url, form)
    -- client_secret_basic: id and secret are form-urlencoded before base64 [RFC 6749 2.3.1]
    local credentials = util.form_urlencode(self.client_id) .. ":" .. util.form_urlencode(self.client_secret)
    return self:send("POST", url, {
        headers = {
            ["Authorization"] = "Basic " .. ngx.encode_base64(credentials),
            ["Content-Type"] = "application/x-www-form-urlencoded",
            ["Accept"] = "application/json",
        },
        body = ngx.encode_args(form),
    })
end

function Provider:get_json(url)
    return self:send("GET", url, {headers = {["Accept"] = "application/json"}})
end

function Provider:send(method, url, opts)
    local status, body, err = self.http(method, url, opts)
    if err then
        oidc_error(url .. " failed: " .. tostring(err))
    end
    local data = body and body ~= "" and util.json_decode(body) or {}
    if status ~= 200 then
        oidc_error(url .. " answered " .. tostring(status), type(data) == "table" and data.error or nil)
    end
    if type(data) ~= "table" then
        oidc_error(url .. " sent no JSON")
    end
    return data
end

-- -- JWTs ----------------------------------------------------------------------

-- keys are cached; an unknown `kid` refetches the set, which handles key rotation
function Provider:signing_key(kid)
    local function find()
        for _, jwk in ipairs(list((self.jwks or {}).keys)) do
            if jwk.kid == kid and (jwk.use == nil or jwk.use == "sig") then
                return jwk
            end
        end
    end
    local jwk = find()
    if not jwk or ngx.now() - self.jwks_fetched > JWKS_LIFETIME then
        self.jwks = self:get_json(self:metadata().jwks_uri)
        self.jwks_fetched = ngx.now()
        jwk = find()
    end
    if not jwk then
        token_error("no key " .. tostring(kid) .. " in jwks_uri")
    end
    local key, err = pkey.new(util.json_encode(jwk), {format = "JWK"})
    if not key then
        token_error("unusable key " .. tostring(kid) .. ": " .. tostring(err))
    end
    return key
end

local function decode_part(part)
    local raw = part and util.unb64url(part)
    local data = raw and util.json_decode(raw)
    if type(data) ~= "table" then
        token_error("malformed JWT")
    end
    return data
end

-- Header and claims of `token` after checking its signature with the
-- issuer's key; only algorithms the issuer announces and we allow.
function Provider:verify_jwt(token)
    if type(token) ~= "string" then
        token_error("no JWT")
    end
    local h, p, s = token:match("^([%w_-]+)%.([%w_-]+)%.([%w_-]*)$")
    if not h then
        token_error("malformed JWT")
    end
    local header, claims = decode_part(h), decode_part(p)
    local announced = {}
    local algs = self:metadata().id_token_signing_alg_values_supported
    for _, alg in ipairs(type(algs) == "table" and algs or {"RS256"}) do
        announced[alg] = true
    end
    local alg = header.alg
    if not SIGNING_ALGORITHMS[alg] or not announced[alg] then
        token_error("algorithm " .. tostring(alg) .. " not allowed")
    end
    local sig = util.unb64url(s)
    if not sig or sig == "" then
        token_error("no signature")
    end
    local key = self:signing_key(header.kid)
    local ok, err
    if alg == "RS256" then
        ok, err = key:verify(sig, h .. "." .. p, "sha256")
    elseif alg == "PS256" then
        ok, err = key:verify(sig, h .. "." .. p, "sha256", pkey.PADDINGS.RSA_PKCS1_PSS_PADDING)
    else -- ES256: JWS signatures are r || s, not DER
        ok, err = key:verify(sig, h .. "." .. p, "sha256", nil, {ecdsa_use_raw = true})
    end
    if not ok then
        token_error("signature verification failed" .. (err and (": " .. err) or ""))
    end
    return header, claims
end

local function audiences(aud)
    if type(aud) == "string" then
        return {aud}
    end
    return type(aud) == "table" and aud or {}
end

local function check_times(claims, now, require_exp)
    if type(claims.iat) ~= "number" then
        token_error("no iat")
    end
    if claims.iat > now + LEEWAY then
        token_error("issued in the future")
    end
    if require_exp and type(claims.exp) ~= "number" then
        token_error("no exp")
    end
    if claims.exp ~= nil and (type(claims.exp) ~= "number" or claims.exp + LEEWAY < now) then
        token_error("token expired")
    end
end

-- Validates an ID token as in [OIDC Core 3.1.3.7] and returns its claims.
-- `nonce` is the one sent in the authorization request; nil for tokens from a
-- refresh, which carry no new nonce [OIDC Core 12.2]. Those must be about the
-- same user (`expected_sub`).
function Provider:validate_id_token(id_token, nonce, expected_sub)
    local _, claims = self:verify_jwt(id_token)
    -- (2) exact issuer
    if claims.iss ~= self.issuer then
        token_error("wrong issuer")
    end
    if type(claims.sub) ~= "string" or claims.sub == "" then
        token_error("no sub")
    end
    -- (3) our client id as the only audience: we do not trust other clients' tokens
    local aud = audiences(claims.aud)
    if #aud ~= 1 or aud[1] ~= self.client_id then
        token_error(#aud > 1 and "ID token has additional audiences" or "ID token is not for this client")
    end
    -- (5) authorized party, if present, must be us
    if claims.azp ~= nil and claims.azp ~= self.client_id then
        token_error("ID token azp is not this client")
    end
    -- (9) exp, (10) iat
    check_times(claims, self.clock(), true)
    -- (11) nonce of this login, defeats code injection and replayed ID tokens [RFC 9700 4.5.3.2]
    if nonce ~= nil and not util.const_eq(claims.nonce, nonce) then
        token_error("ID token nonce mismatch")
    end
    if expected_sub ~= nil and claims.sub ~= expected_sub then
        token_error("refreshed ID token is about another user")
    end
    return claims
end

-- Validates a back-channel logout token as in [OIDC Back-Channel Logout 1.0,
-- 2.6] and returns its claims.
function Provider:validate_logout_token(logout_token)
    local header, claims = self:verify_jwt(logout_token)
    -- explicitly typed if typed at all, so no other JWT passes as logout token [2.4]
    local typ = header.typ and tostring(header.typ):lower()
    if typ and typ ~= "logout+jwt" and typ ~= "application/logout+jwt" and typ ~= "jwt" then
        token_error("logout token has typ " .. typ)
    end
    -- (3) iss, aud = this client, iat (and exp if present)
    if claims.iss ~= self.issuer then
        token_error("wrong issuer")
    end
    local for_us = false
    for _, a in ipairs(audiences(claims.aud)) do
        for_us = for_us or a == self.client_id
    end
    if not for_us then
        token_error("logout token is not for this client")
    end
    local now = self.clock()
    check_times(claims, now, false)
    if type(claims.jti) ~= "string" or claims.jti == "" then
        token_error("no jti")
    end
    -- (4) sub or sid; (5) the back-channel logout event; (6) no nonce, so no ID token passes as logout token
    if not claims.sid and not claims.sub then
        token_error("logout token has neither sid nor sub")
    end
    local events = claims.events
    if type(events) ~= "table" or type(events[BACKCHANNEL_LOGOUT_EVENT]) ~= "table" then
        token_error("logout token lacks the back-channel logout event")
    end
    if claims.nonce ~= nil then
        token_error("logout token must not contain a nonce")
    end
    -- (7) not too old, and no replay of a logout token already seen
    if claims.iat < now - LOGOUT_TOKEN_MAX_AGE then
        token_error("logout token is too old")
    end
    local ttl = LOGOUT_TOKEN_MAX_AGE + LEEWAY
    if self.replay then
        local ok = self.replay:add("jti:" .. claims.jti, true, ttl)
        if not ok then
            token_error("logout token replayed")
        end
    else
        for jti, expires in pairs(self.seen_jti) do
            if expires < now then
                self.seen_jti[jti] = nil
            end
        end
        if self.seen_jti[claims.jti] then
            token_error("logout token replayed")
        end
        self.seen_jti[claims.jti] = now + ttl
    end
    return claims
end

return _M
