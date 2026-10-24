--
-- Small helpers of the token handler: encoding, randomness, constant-time
-- comparison, path checks and the back-channel HTTP client.
--
-- No dependency on apisix.core here (except in http(), loaded lazily), so the
-- module also runs under the `resty` CLI in the unit tests.
--
local b64 = require("ngx.base64")
local cjson = require("cjson.safe")
local resty_random = require("resty.random")
local resty_sha256 = require("resty.sha256")
local resty_string = require("resty.string")

local _M = {}

_M.json_decode = cjson.decode

-- JSON with [] for empty lists (refs, ...) where the trace reader expects lists
function _M.json_encode(value)
    return cjson.encode(value)
end

_M.empty_array = cjson.empty_array
_M.null = cjson.null

-- JSON null for nil, so the key is present
function _M.nullable(value)
    if value == nil then
        return cjson.null
    end
    return value
end

function _M.array(t)
    return setmetatable(t or {}, cjson.array_mt)
end

function _M.b64url(data)
    return b64.encode_base64url(data)
end

function _M.unb64url(data)
    return b64.decode_base64url(data)
end

-- `bytes` random bytes from the OS CSPRNG, base64url: 32 bytes = 256 bits, 43 characters
function _M.random_token(bytes)
    local raw = resty_random.bytes(bytes or 32, true)
    if not raw then
        error("no strong random bytes available")
    end
    return _M.b64url(raw)
end

function _M.sha256(data)
    local h = resty_sha256:new()
    h:update(data)
    return h:final()
end

function _M.sha256_hex(data)
    return resty_string.to_hex(_M.sha256(data))
end

-- constant time, so secrets like `state` can't be guessed byte by byte from timing
function _M.const_eq(a, b)
    if type(a) ~= "string" or type(b) ~= "string" or #a ~= #b then
        return false
    end
    local diff = 0
    for i = 1, #a do
        diff = bit.bor(diff, bit.bxor(a:byte(i), b:byte(i)))
    end
    return diff == 0
end

-- `value` if it is a path on this origin, else "/". The BFF must not become
-- an open redirector [RFC 9700 4.11.1; OWASP OAuth2 #1]: no scheme, no
-- `//host` or `/\host`, no whitespace or control characters.
function _M.local_path(value)
    if type(value) == "string" and #value <= 2048
            and ngx.re.find(value, [[^/(?![/\\])[\x21-\x7e]*$]], "jo") then
        return value
    end
    return "/"
end

-- application/x-www-form-urlencoded for one value [RFC 6749 2.3.1, appendix B]
function _M.form_urlencode(value)
    return (ngx.escape_uri(value):gsub("%%20", "+"))
end

function _M.split_url(url)
    local m = ngx.re.match(url, [[^(https?)://([^/:?#]+)(?::(\d+))?([^?#]*)(\?[^#]*)?]], "jo")
    if not m then
        return nil
    end
    local scheme = m[1]
    return {
        scheme = scheme,
        host = m[2],
        port = tonumber(m[3]) or (scheme == "https" and 443 or 80),
        path = (m[4] ~= "" and m[4] or "/") .. (m[5] or ""),
    }
end

-- Back-channel HTTP: TLS always verified (lua_ssl_trusted_certificate,
-- the system store, which holds the dev CA), redirects never followed
-- [RFC 9700 4.12]. Host names resolve through APISIX's resolver, which
-- also knows /etc/hosts. Returns status, body, response headers, error.
function _M.http(method, url, opts)
    opts = opts or {}
    local parts = _M.split_url(url)
    if not parts then
        return nil, nil, nil, "bad url " .. tostring(url)
    end
    local http = require("resty.http")
    local core = require("apisix.core")
    local ip = parts.host
    if not ngx.re.find(ip, [[^[\d.]+$|:]], "jo") then
        local resolved, err = core.resolver.parse_domain(parts.host)
        if not resolved then
            return nil, nil, nil, "cannot resolve " .. parts.host .. ": " .. tostring(err)
        end
        ip = resolved
    end
    local httpc = http.new()
    httpc:set_timeout(opts.timeout or 5000)
    local ok, err = httpc:connect({
        scheme = parts.scheme, host = ip, port = parts.port,
        ssl_server_name = parts.host, ssl_verify = true,
    })
    if not ok then
        return nil, nil, nil, err
    end
    local headers = opts.headers or {}
    headers["Host"] = parts.host .. ((parts.port == 443 or parts.port == 80) and "" or ":" .. parts.port)
    local res, rerr = httpc:request({method = method, path = parts.path, headers = headers, body = opts.body})
    if not res then
        httpc:close()
        return nil, nil, nil, rerr
    end
    local body = res:read_body()
    httpc:set_keepalive()
    return res.status, body, res.headers, nil
end

return _M
