-- lua/apisix/plugins/tokenhandler/vault.lua with a fake Vault.
local t = require("harness")
local cjson = require("cjson")
local vault = require("apisix.plugins.tokenhandler.vault")

local token_file = os.tmpname()
local f = io.open(token_file, "w")
f:write("hvs.bff-token\n")
f:close()

local function fake_vault()
    local calls = {}
    local function fetch(url, token)
        calls[#calls + 1] = {url = url, token = token}
        if token ~= "hvs.bff-token" then
            return 403, cjson.encode({errors = {"permission denied"}})
        elseif url == "http://vault:8200/v1/kv/bff" then
            return 200, cjson.encode({data = {client_secret = "s3cret"}})
        end
        return 404, cjson.encode({errors = {}})
    end
    return fetch, calls
end

-- a fresh cache per test (a table with the shared dict's get/set)
local function cache()
    local store = {}
    return {get = function(_, k) return store[k] end, set = function(_, k, v) store[k] = v end}
end

t.test("reads a field with the component's token", function()
    local fetch, calls = fake_vault()
    t.expect_eq(vault.read("vault:kv/bff#client_secret", "http://vault:8200", token_file, fetch, cache()), "s3cret")
    t.expect_eq(calls[1].url, "http://vault:8200/v1/kv/bff")
    t.expect_eq(calls[1].token, "hvs.bff-token")
end)

t.test("values are cached", function()
    local fetch, calls = fake_vault()
    local c = cache()
    vault.read("vault:kv/bff#client_secret", "http://vault:8200", token_file, fetch, c)
    vault.read("vault:kv/bff#client_secret", "http://vault:8200", token_file, fetch, c)
    t.expect_eq(#calls, 1)
end)

t.test("errors", function()
    local fetch = fake_vault()
    for ref, message in pairs({
        ["vault:kv/service-a#client_secret"] = "404",
        ["vault:kv/bff#other"] = "no field",
        ["vault:kv/bff"] = "not a vault reference",
        ["vault:#x"] = "not a vault reference",
    }) do
        local err = t.expect_error(function()
            vault.read(ref, "http://vault:8200", token_file, fetch, cache())
        end, message)
        t.expect_eq(err.kind, "vault")
    end
end)

t.test("a policy refusal is an error", function()
    local other = os.tmpname()
    local o = io.open(other, "w")
    o:write("hvs.someone-else")
    o:close()
    t.expect_error(function()
        vault.read("vault:kv/bff#client_secret", "http://vault:8200", other, fake_vault(), cache())
    end, "403")
end)

t.test("missing token file", function()
    t.expect_error(function()
        vault.read("vault:kv/bff#client_secret", "http://vault:8200", "/nonexistent", fake_vault(), cache())
    end, "no Vault token")
end)

t.test("unreachable Vault", function()
    t.expect_error(function()
        vault.read("vault:kv/bff#client_secret", "http://vault:8200", token_file,
                   function() return nil, nil, "connection refused" end, cache())
    end, "unreachable")
end)

t.test("resolve replaces top-level references only", function()
    local conf = {client_secret = "vault:kv/bff#client_secret", client_id = "bff", apis = {x = "vault:kv/y#z"}}
    local resolved = vault.resolve(conf, {addr = "http://vault:8200", token_file = token_file}, fake_vault(), cache())
    t.expect_eq(resolved.client_secret, "s3cret")
    t.expect_eq(resolved.client_id, "bff")
    t.expect_eq(resolved.apis.x, "vault:kv/y#z")
    -- the configuration itself is untouched
    t.expect_eq(conf.client_secret, "vault:kv/bff#client_secret")
end)

t.test("references need Vault settings", function()
    t.expect_error(function() vault.resolve({client_secret = "vault:kv/bff#client_secret"}, nil) end,
                   "not configured")
    t.expect_eq(vault.resolve({client_secret = "plain"}, nil).client_secret, "plain")
end)

os.remove(token_file)
t.done()
