--
-- Secrets from HashiCorp Vault (KV engine v1) for the BFF.
--
-- A configuration value `vault:<path>#<field>`, e.g. `vault:kv/bff#client_secret`,
-- is replaced by that field of the secret at `<path>`. The BFF reads with its
-- own token (policy: read kv/bff only), from a file, so a new token
-- (re-issued on every stack start) is picked up without a restart. Values
-- are cached in shared memory for a few minutes, so a rotated secret arrives
-- within that time.
--
-- Errors are raised as {kind = "vault", message = ...}.
--
local trace = require("apisix.plugins.tokenhandler.trace")
local util = require("apisix.plugins.tokenhandler.util")

local _M = {
    PREFIX = "vault:",
    CACHE_SECONDS = 300,
}

local function vault_error(message)
    error({kind = "vault", message = message}, 0)
end

function _M.is_ref(value)
    return type(value) == "string" and value:sub(1, #_M.PREFIX) == _M.PREFIX
end

function _M.parse(ref)
    local path, field = ref:sub(#_M.PREFIX + 1):match("^([^#]+)#(.+)$")
    if not path then
        vault_error("not a vault reference (vault:<path>#<field>): " .. ref)
    end
    return path, field
end

local function default_fetch(url, token)
    local headers = {["X-Vault-Token"] = token}
    if trace.active() then
        headers[trace.HEADER] = trace.current_id()
    end
    local t_start = trace.now()
    local status, body, resp_headers, err = util.http("GET", url, {headers = headers})
    if trace.active() then
        trace.exchange("GET", url, headers, nil, status, resp_headers, body, t_start, err)
    end
    return status, body, err
end

-- The value `vault:<path>#<field>` refers to. `fetch` and `cache` for tests.
function _M.read(ref, addr, token_file, fetch, cache)
    local path, field = _M.parse(ref)
    cache = cache or ngx.shared["tokenhandler-sessions"]
    local cache_key = "vault:" .. addr .. "|" .. ref
    local cached = cache and cache:get(cache_key)
    if cached then
        return cached
    end
    local f = io.open(token_file, "r")
    if not f then
        vault_error("no Vault token in " .. tostring(token_file))
    end
    local token = f:read("*a"):gsub("%s+$", "")
    f:close()

    local status, body, err = (fetch or default_fetch)(addr:gsub("/$", "") .. "/v1/" .. path, token)
    if err then
        vault_error("Vault unreachable: " .. tostring(err))
    end
    if status ~= 200 then
        -- 403: the token's policy doesn't cover this path (least privilege); 404: no such secret
        vault_error("Vault answered " .. tostring(status) .. " for " .. path)
    end
    local data = util.json_decode(body or "")
    local value = type(data) == "table" and type(data.data) == "table" and data.data[field] or nil
    if value == nil then
        vault_error("secret " .. path .. " has no field " .. field)
    end
    if cache then
        cache:set(cache_key, value, _M.CACHE_SECONDS)
    end
    return value
end

-- `conf` with every top-level `vault:` reference replaced by its secret.
function _M.resolve(conf, vault_conf, fetch, cache)
    local resolved
    for k, v in pairs(conf) do
        if _M.is_ref(v) then
            if not vault_conf or not vault_conf.addr or not vault_conf.token_file then
                vault_error(k .. " refers to Vault, but `vault` (addr, token_file) is not configured")
            end
            resolved = resolved or {}
            resolved[k] = _M.read(v, vault_conf.addr, vault_conf.token_file, fetch, cache)
        end
    end
    if not resolved then
        return conf
    end
    local copy = {}
    for k, v in pairs(conf) do
        copy[k] = v
    end
    for k, v in pairs(resolved) do
        copy[k] = v
    end
    return copy
end

return _M
