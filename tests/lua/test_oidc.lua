-- lua/apisix/plugins/tokenhandler/oidc.lua: metadata, front channel, token
-- endpoint, and every rule of ID token and logout token validation, with real
-- signatures (RSA, RSA-PSS, ECDSA) and a fake transport.
local t = require("harness")
local pkey = require("resty.openssl.pkey")
local cjson = require("cjson")
local oidc = require("apisix.plugins.tokenhandler.oidc")
local util = require("apisix.plugins.tokenhandler.util")

local ISSUER = "https://idp.example"
local NOW = 1800000000

local rsa = pkey.new({type = "RSA", bits = 2048})
local ec = pkey.new({type = "EC", curve = "prime256v1"})
local other = pkey.new({type = "RSA", bits = 2048})

local function jwk(key, kid, alg)
    local j = cjson.decode(key:tostring("public", "JWK"))
    j.kid, j.alg, j.use = kid, alg, "sig"
    return j
end

local function metadata(overrides)
    local m = {
        issuer = ISSUER,
        authorization_endpoint = ISSUER .. "/auth",
        token_endpoint = ISSUER .. "/token",
        jwks_uri = ISSUER .. "/keys",
        code_challenge_methods_supported = {"S256", "plain"},
        id_token_signing_alg_values_supported = {"RS256", "PS256", "ES256", "HS256"},
    }
    for k, v in pairs(overrides or {}) do
        m[k] = v
    end
    return m
end

-- fake transport: discovery, JWKS and a programmable token endpoint
local function fake(meta)
    local f = {requests = {}, jwks_fetches = 0, token_status = 200,
               token_reply = {access_token = "at", token_type = "Bearer"}}
    f.keys = {keys = {jwk(rsa, "rsa1", "RS256"), jwk(ec, "ec1", "ES256")}}
    function f.http(method, url, opts)
        f.requests[#f.requests + 1] = {method = method, url = url, opts = opts}
        if url:find("/.well-known/openid-configuration", 1, true) then
            return 200, cjson.encode(meta or metadata())
        elseif url == ISSUER .. "/keys" then
            f.jwks_fetches = f.jwks_fetches + 1
            return 200, cjson.encode(f.keys)
        elseif url == ISSUER .. "/token" or url == ISSUER .. "/revoke" then
            return f.token_status, cjson.encode(f.token_reply)
        end
        return 404, "{}"
    end
    return f
end

local function provider(f, opts)
    opts = opts or {}
    return oidc.new({issuer = ISSUER, client_id = "bff", client_secret = opts.secret or "secret",
                     allow_insecure_http = opts.allow_insecure_http, http = (f or fake()).http,
                     clock = function() return NOW end})
end

local function jwt(claims, opts)
    opts = opts or {}
    local alg = opts.alg or "RS256"
    local header = {alg = alg, kid = opts.kid or (alg == "ES256" and "ec1" or "rsa1"), typ = opts.typ}
    local signing_input = util.b64url(cjson.encode(header)) .. "." .. util.b64url(cjson.encode(claims))
    local key = opts.key or (alg == "ES256" and ec or rsa)
    local sig
    if alg == "RS256" then
        sig = key:sign(signing_input, "sha256")
    elseif alg == "PS256" then
        sig = key:sign(signing_input, "sha256", pkey.PADDINGS.RSA_PKCS1_PSS_PADDING)
    elseif alg == "ES256" then
        sig = key:sign(signing_input, "sha256", nil, {ecdsa_use_raw = true})
    else
        sig = opts.sig or ""
    end
    return signing_input .. "." .. util.b64url(sig)
end

local function id_claims(overrides)
    local c = {iss = ISSUER, sub = "user-1", aud = "bff", iat = NOW, exp = NOW + 300, nonce = "n-1",
               email = "a@example.test"}
    for k, v in pairs(overrides or {}) do
        c[k] = v ~= cjson.null and v or nil
    end
    return c
end

local NULL = cjson.null

-- -- ID token -------------------------------------------------------------------------

t.test("valid ID token", function()
    local claims = provider():validate_id_token(jwt(id_claims()), "n-1")
    t.expect_eq(claims.sub, "user-1")
end)

t.test("PS256 and ES256 signatures are accepted", function()
    t.expect_eq(provider():validate_id_token(jwt(id_claims(), {alg = "PS256"}), "n-1").sub, "user-1")
    t.expect_eq(provider():validate_id_token(jwt(id_claims(), {alg = "ES256"}), "n-1").sub, "user-1")
end)

t.test("refreshed ID token needs no nonce but the same user", function()
    local p = provider()
    t.expect_eq(p:validate_id_token(jwt(id_claims({nonce = NULL})), nil, "user-1").sub, "user-1")
    t.expect_error(function() p:validate_id_token(jwt(id_claims({nonce = NULL})), nil, "user-2") end, "another user")
end)

for name, case in pairs({
    ["nonce mismatch"] = {{nonce = "n-2"}, "nonce mismatch"},
    ["missing nonce"] = {{nonce = NULL}, "nonce mismatch"},
    ["wrong issuer"] = {{iss = "https://evil.example"}, "wrong issuer"},
    ["other audience"] = {{aud = "other-client"}, "not for this client"},
    ["additional audience"] = {{aud = {"bff", "other-client"}}, "additional audiences"},
    ["azp of another client"] = {{azp = "other-client"}, "azp"},
    ["expired"] = {{exp = NOW - 120}, "expired"},
    ["no exp"] = {{exp = NULL}, "no exp"},
    ["no iat"] = {{iat = NULL}, "no iat"},
    ["issued in the future"] = {{iat = NOW + 3600}, "future"},
    ["no sub"] = {{sub = NULL}, "no sub"},
}) do
    t.test("ID token rejected: " .. name, function()
        t.expect_error(function() provider():validate_id_token(jwt(id_claims(case[1])), "n-1") end, case[2])
    end)
end

t.test("small clock skew is tolerated", function()
    provider():validate_id_token(jwt(id_claims({exp = NOW - 30})), "n-1")
end)

t.test("wrong signature is rejected", function()
    t.expect_error(function() provider():validate_id_token(jwt(id_claims(), {key = other}), "n-1") end,
                   "signature verification failed")
end)

t.test("alg none and HMAC are rejected", function()
    t.expect_error(function() provider():validate_id_token(jwt(id_claims(), {alg = "none"}), "n-1") end,
                   "not allowed")
    -- an attacker knowing (or guessing) the client secret must not be able to mint tokens
    t.expect_error(function() provider():validate_id_token(jwt(id_claims(), {alg = "HS256", sig = "x"}), "n-1") end,
                   "not allowed")
end)

t.test("an algorithm the issuer does not announce is rejected", function()
    local p = provider(fake(metadata({id_token_signing_alg_values_supported = {"RS256"}})))
    t.expect_error(function() p:validate_id_token(jwt(id_claims(), {alg = "ES256"}), "n-1") end, "not allowed")
end)

t.test("malformed tokens are rejected", function()
    for _, token in ipairs({"", "a.b", "not a jwt", "x.y.z"}) do
        t.expect_error(function() provider():validate_id_token(token, "n-1") end)
    end
end)

t.test("an unknown kid refetches the key set (key rotation)", function()
    local f = fake()
    local p = provider(f)
    p:validate_id_token(jwt(id_claims()), "n-1")
    t.expect_eq(f.jwks_fetches, 1)
    p:validate_id_token(jwt(id_claims()), "n-1")
    t.expect_eq(f.jwks_fetches, 1, "keys are cached")
    local new = pkey.new({type = "RSA", bits = 2048})
    f.keys.keys[#f.keys.keys + 1] = jwk(new, "rsa2", "RS256")
    p:validate_id_token(jwt(id_claims(), {key = new, kid = "rsa2"}), "n-1")
    t.expect_eq(f.jwks_fetches, 2)
    t.expect_error(function() p:validate_id_token(jwt(id_claims(), {kid = "nope"}), "n-1") end, "no key nope")
end)

-- -- metadata --------------------------------------------------------------------------

t.test("discovery issuer must match", function()
    t.expect_error(function() provider(fake(metadata({issuer = "https://evil.example"}))):metadata() end,
                   "does not match")
end)

t.test("discovery must offer PKCE S256", function()
    t.expect_error(function()
        provider(fake(metadata({code_challenge_methods_supported = {"plain"}}))):metadata()
    end, "PKCE")
    t.expect_error(function()
        provider(fake(metadata({code_challenge_methods_supported = NULL}))):metadata()
    end, "PKCE")
end)

t.test("plain http needs opt-in", function()
    t.expect_error(function() oidc.new({issuer = "http://idp.example", client_id = "x", client_secret = "y"}) end,
                   "non-https")
    oidc.new({issuer = "http://idp.example", client_id = "x", client_secret = "y", allow_insecure_http = true})
    t.expect_error(function()
        provider(fake(metadata({token_endpoint = "http://idp.example/token"}))):metadata()
    end, "non-https")
end)

-- -- front channel ---------------------------------------------------------------------

t.test("authorization URL", function()
    local url = provider():authorization_url("https://app.example/cb", "openid", "st", "no", "ch")
    t.expect(url:find(ISSUER .. "/auth?", 1, true) == 1, url)
    local args = ngx.decode_args(url:match("%?(.*)$"))
    t.expect_eq(args.response_type, "code")
    t.expect_eq(args.client_id, "bff")
    t.expect_eq(args.redirect_uri, "https://app.example/cb")
    t.expect_eq(args.state, "st")
    t.expect_eq(args.nonce, "no")
    t.expect_eq(args.code_challenge, "ch")
    t.expect_eq(args.code_challenge_method, "S256")
end)

t.test("end session URL only if the server has one", function()
    t.expect_eq(provider():end_session_url("id", "https://app.example/"), nil)
    local p = provider(fake(metadata({end_session_endpoint = ISSUER .. "/logout"})))
    local args = ngx.decode_args(p:end_session_url("id", "https://app.example/"):match("%?(.*)$"))
    t.expect_eq(args.id_token_hint, "id")
    t.expect_eq(args.post_logout_redirect_uri, "https://app.example/")
    t.expect_eq(args.client_id, "bff")
end)

t.test("revoke without endpoint does nothing", function()
    t.expect_eq(provider():revoke("rt"), false)
end)

-- -- token endpoint ----------------------------------------------------------------------

t.test("code exchange authenticates the client (client_secret_basic)", function()
    local f = fake()
    local p = oidc.new({issuer = ISSUER, client_id = "bff client", client_secret = "s3cr:t", http = f.http})
    p:exchange_code("the-code", "https://app.example/cb", "verifier")
    local req = f.requests[#f.requests]
    -- id and secret are form-urlencoded before base64 [RFC 6749 2.3.1]
    t.expect_eq(req.opts.headers["Authorization"], "Basic " .. ngx.encode_base64("bff+client:s3cr%3At"))
    local form = ngx.decode_args(req.opts.body)
    t.expect_eq(form.grant_type, "authorization_code")
    t.expect_eq(form.code, "the-code")
    t.expect_eq(form.redirect_uri, "https://app.example/cb")
    t.expect_eq(form.code_verifier, "verifier")
end)

t.test("OAuth error codes are reported", function()
    local f = fake()
    f.token_status, f.token_reply = 400, {error = "invalid_grant"}
    local err = t.expect_error(function() provider(f):refresh("rt") end, "400")
    t.expect_eq(err.error, "invalid_grant")
end)

t.test("token response must be a bearer token", function()
    local f = fake()
    f.token_reply = {access_token = "at", token_type = "DPoP"}
    t.expect_error(function() provider(f):refresh("rt") end, "bearer")
end)

t.test("token exchange request", function()
    local f = fake()
    f.token_reply = {access_token = "a-token", token_type = "Bearer", issued_token_type = oidc.ACCESS_TOKEN_TYPE}
    t.expect_eq(provider(f):exchange_token("subject", "service-a", "api-a").access_token, "a-token")
    local form = ngx.decode_args(f.requests[#f.requests].opts.body)
    t.expect_eq(form.grant_type, "urn:ietf:params:oauth:grant-type:token-exchange")
    t.expect_eq(form.subject_token, "subject")
    t.expect_eq(form.subject_token_type, oidc.ACCESS_TOKEN_TYPE)
    t.expect_eq(form.requested_token_type, oidc.ACCESS_TOKEN_TYPE)
    t.expect_eq(form.audience, "service-a")
    t.expect_eq(form.scope, "api-a")
end)

t.test("token exchange must issue an access token", function()
    local f = fake()
    f.token_reply = {access_token = "x", token_type = "Bearer",
                     issued_token_type = "urn:ietf:params:oauth:token-type:id_token"}
    t.expect_error(function() provider(f):exchange_token("s", "service-a", "api-a") end, "not an access token")
end)

t.test("unreachable authorization server", function()
    local p = oidc.new({issuer = ISSUER, client_id = "bff", client_secret = "s",
                        http = function() return nil, nil, "connection refused" end})
    local err = t.expect_error(function() p:metadata() end, "connection refused")
    t.expect_eq(err.kind, "oidc")
end)

-- -- logout token [OIDC Back-Channel Logout 1.0, 2.6] -------------------------------------

local jti = 0
local function logout_claims(overrides)
    jti = jti + 1
    local c = {iss = ISSUER, aud = "bff", iat = NOW, exp = NOW + 120, jti = "jti-" .. jti, sid = "s1", sub = "u1",
               events = {["http://schemas.openid.net/event/backchannel-logout"] = {}}}
    for k, v in pairs(overrides or {}) do
        c[k] = v ~= NULL and v or nil
    end
    return c
end

local function logout_token(overrides, opts)
    opts = opts or {}
    opts.typ = opts.typ or "logout+jwt"
    return jwt(logout_claims(overrides), opts)
end

t.test("valid logout token", function()
    local c = provider():validate_logout_token(logout_token())
    t.expect_eq(c.sid, "s1")
    t.expect_eq(c.sub, "u1")
end)

t.test("logout token with only sid or only sub", function()
    local p = provider()
    p:validate_logout_token(logout_token({sid = NULL}))
    p:validate_logout_token(logout_token({sub = NULL}))
end)

t.test("logout token cannot be replayed (worker-local and shared)", function()
    local p = provider()
    local token = logout_token()
    p:validate_logout_token(token)
    t.expect_error(function() p:validate_logout_token(token) end, "replayed")

    local shared = oidc.new({issuer = ISSUER, client_id = "bff", client_secret = "s", http = fake().http,
                             replay = ngx.shared["tokenhandler-sessions"], clock = function() return NOW end})
    local second = oidc.new({issuer = ISSUER, client_id = "bff", client_secret = "s", http = fake().http,
                             replay = ngx.shared["tokenhandler-sessions"], clock = function() return NOW end})
    token = logout_token()
    shared:validate_logout_token(token)
    -- another worker's provider sees it too
    t.expect_error(function() second:validate_logout_token(token) end, "replayed")
end)

for name, case in pairs({
    ["no events"] = {{events = NULL}, "logout event"},
    ["event not an object"] = {{events = {["http://schemas.openid.net/event/backchannel-logout"] = "x"}}, "logout event"},
    ["other event"] = {{events = {["something-else"] = {}}}, "logout event"},
    ["nonce"] = {{nonce = "n"}, "nonce"},
    ["neither sid nor sub"] = {{sid = NULL, sub = NULL}, "neither sid nor sub"},
    ["other audience"] = {{aud = "other-client"}, "not for this client"},
    ["wrong issuer"] = {{iss = "https://evil.example"}, "wrong issuer"},
    ["no jti"] = {{jti = NULL}, "no jti"},
    ["no iat"] = {{iat = NULL}, "no iat"},
    ["too old"] = {{iat = NOW - 3600, exp = NOW + 60}, "too old"},
    ["expired"] = {{exp = NOW - 3600}, "expired"},
}) do
    t.test("logout token rejected: " .. name, function()
        t.expect_error(function() provider():validate_logout_token(logout_token(case[1])) end, case[2])
    end)
end

t.test("logout token signed by another key", function()
    t.expect_error(function() provider():validate_logout_token(logout_token(nil, {key = other})) end, "signature")
end)

t.test("other JWT types are no logout tokens", function()
    t.expect_error(function() provider():validate_logout_token(logout_token(nil, {typ = "at+jwt"})) end, "typ")
end)

t.test("an ID token is no logout token", function()
    t.expect_error(function() provider():validate_logout_token(jwt(id_claims())) end)
end)

t.done()
