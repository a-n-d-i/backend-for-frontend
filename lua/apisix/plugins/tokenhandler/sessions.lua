--
-- Server-side session store of the BFF.
--
-- The browser only ever holds an opaque, random session id in a cookie;
-- tokens stay here [BBA 6.1.2.3 server-side sessions]. Because nothing but
-- the id leaves the gateway, the cookie needs no encryption (the "SHOULD
-- encrypt" of BBA 6.1.3.2 applies to client-side sessions).
--
-- Kept in Redis (the plugin's `redis` config), so every nginx worker and
-- every gateway instance sees the same sessions, and they survive a gateway
-- restart. The ids of seen logout tokens are kept here as well (add()).
--
-- Entries are keyed by a hash of the session id, so a dump of the store
-- holds no usable cookie values. Each expires at the earlier of its absolute
-- lifetime and its idle timeout [OWASP Session: timeouts]; a lookup moves the
-- idle deadline. Indexes by the authorization server's session id (`sid`) and
-- by user (`sub`) serve back-channel logout.
--
local redis = require("resty.redis")
local util = require("apisix.plugins.tokenhandler.util")

local _M = {}

-- how long locked() waits for the lock, and when a lock left behind (crashed
-- worker) expires, seconds
local LOCK_TIMEOUT = 10
local LOCK_EXPIRY = 30

-- adds a session key to an index set; the set lives as long as its longest-lived session
local INDEX_ADD = [[
redis.call("SADD", KEYS[1], ARGV[1])
if redis.call("PTTL", KEYS[1]) < tonumber(ARGV[2]) then
    redis.call("PEXPIRE", KEYS[1], ARGV[2])
end
return 1
]]

-- releases the lock only if it is still ours (it may have expired and been taken meanwhile)
local UNLOCK = [[
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("DEL", KEYS[1])
end
return 0
]]

local Store = {}
Store.__index = Store

-- A store on the Redis of `conf` {host, port, database, prefix, timeout (ms)}.
function _M.new(conf)
    return setmetatable({
        host = conf.host, port = conf.port or 6379, database = conf.database or 0,
        prefix = conf.prefix or "tokenhandler:", timeout = conf.timeout or 1000,
    }, Store)
end

local function call(red, command, ...)
    local res, err = red[command](red, ...)
    if not res then
        error("session store: " .. tostring(err), 0)
    end
    return res
end

-- Runs fn(red) on a pooled connection; returns its result.
function Store:with_redis(fn)
    local red = redis:new()
    red:set_timeout(self.timeout)
    -- one pool per database: SELECT sticks to the connection
    local ok, err = red:connect(self.host, self.port,
                                {pool = self.host .. ":" .. self.port .. "/" .. self.database})
    if not ok then
        error("session store: " .. tostring(err), 0)
    end
    local success, result = pcall(function()
        if self.database ~= 0 and red:get_reused_times() == 0 then
            call(red, "select", self.database)
        end
        return fn(red)
    end)
    if not success then
        red:close()
        error(result, 0)
    end
    red:set_keepalive(10000, 100)
    return result
end

function Store:key(session_id)
    return self.prefix .. "s:" .. util.sha256_hex(session_id)
end

local function remaining(session, now)
    return math.min(session.expires_at - now, session.idle_timeout - (now - session.last_seen))
end

local function write(red, entry_key, session, now)
    local ttl = remaining(session, now)
    if ttl <= 0 then
        call(red, "del", entry_key)
        return false
    end
    call(red, "set", entry_key, util.json_encode(session), "PX", math.ceil(ttl * 1000))
    return true
end

local function load(red, entry_key, now)
    local raw = call(red, "get", entry_key)
    local session = raw ~= ngx.null and util.json_decode(raw) or nil
    if not session then
        return nil
    end
    if remaining(session, now) <= 0 then
        call(red, "del", entry_key)
        return nil
    end
    return session
end

-- Stores `session` under a fresh id and returns the id for the cookie.
-- 256 bits from the OS CSPRNG [OWASP Session: session ID entropy >= 64 bits].
function Store:create(session, now)
    now = now or ngx.now()
    local session_id = util.random_token(32)
    local entry_key = self:key(session_id)
    session.last_seen = now
    local ttl_ms = math.ceil((session.expires_at - now) * 1000)
    self:with_redis(function(red)
        write(red, entry_key, session, now)
        if session.sid then
            call(red, "eval", INDEX_ADD, 1, self.prefix .. "sid:" .. session.sid, entry_key, ttl_ms)
        end
        if session.user and session.user.sub then
            call(red, "eval", INDEX_ADD, 1, self.prefix .. "sub:" .. session.user.sub, entry_key, ttl_ms)
        end
    end)
    return session_id
end

-- The live session for `session_id`, or nil. Counts as activity for the idle timeout.
function Store:get(session_id, now)
    if not session_id or session_id == "" then
        return nil
    end
    now = now or ngx.now()
    local entry_key = self:key(session_id)
    return self:with_redis(function(red)
        local session = load(red, entry_key, now)
        if not session then
            return nil
        end
        session.last_seen = now
        write(red, entry_key, session, now)
        return session
    end)
end

-- Writes back changes of a session (refreshed or exchanged tokens).
function Store:save(session_id, session, now)
    local entry_key = self:key(session_id)
    return self:with_redis(function(red)
        return write(red, entry_key, session, now or ngx.now())
    end)
end

function Store:delete(session_id)
    if not session_id or session_id == "" then
        return nil
    end
    local entry_key = self:key(session_id)
    return self:with_redis(function(red)
        local session = load(red, entry_key, ngx.now())
        call(red, "del", entry_key)
        return session
    end)
end

-- Deletes and returns all live sessions of the authorization server's session
-- `sid`, or (without sid) of user `sub`.
function Store:delete_by(sid, sub)
    local ikey = self.prefix .. (sid and ("sid:" .. sid) or ("sub:" .. tostring(sub)))
    return self:with_redis(function(red)
        local ended = {}
        local now = ngx.now()
        for _, entry_key in ipairs(call(red, "smembers", ikey)) do
            local session = load(red, entry_key, now)
            if session and session.user and (sid == nil or session.sid == sid) then
                call(red, "del", entry_key)
                ended[#ended + 1] = session
            end
        end
        call(red, "del", ikey)
        return ended
    end)
end

-- Records `key` for `ttl` seconds; false if it is recorded already. The
-- interface of ngx.shared.DICT:add, for oidc.lua's replay check of logout
-- tokens, so a replay is caught whichever gateway instance it reaches.
function Store:add(key, _, ttl)
    return self:with_redis(function(red)
        return call(red, "set", self.prefix .. key, "1", "NX", "PX", math.ceil(ttl * 1000)) ~= ngx.null
    end)
end

-- Serializes token refreshes and exchanges of one session across workers and
-- gateway instances: with refresh token rotation a second, parallel refresh
-- would use an already spent refresh token. Runs fn() under the lock; returns
-- its result.
function Store:locked(session_id, fn)
    local lock_key = self.prefix .. "lock:" .. util.sha256_hex(session_id)
    local token = util.random_token(16)
    local deadline = ngx.now() + LOCK_TIMEOUT
    while not self:with_redis(function(red)
        return call(red, "set", lock_key, token, "NX", "PX", LOCK_EXPIRY * 1000) ~= ngx.null
    end) do
        if ngx.now() >= deadline then
            error("session lock: timeout", 0)
        end
        ngx.sleep(0.05)
    end
    local success, result = pcall(fn)
    self:with_redis(function(red)
        call(red, "eval", UNLOCK, 1, lock_key, token)
    end)
    if not success then
        error(result, 0)
    end
    return result
end

return _M
