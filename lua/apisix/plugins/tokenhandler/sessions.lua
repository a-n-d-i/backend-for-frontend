--
-- Server-side session store of the BFF.
--
-- The browser only ever holds an opaque, random session id in a cookie;
-- tokens stay here [BBA 6.1.2.3 server-side sessions]. Because nothing but
-- the id leaves the gateway, the cookie needs no encryption (the "SHOULD
-- encrypt" of BBA 6.1.3.2 applies to client-side sessions).
--
-- Kept in a shared memory dict (lua_shared_dict tokenhandler-sessions), so
-- every nginx worker sees the same sessions. Lost on a gateway restart (users
-- log in again, silently thanks to the SSO session) and not shared between
-- gateway instances; a production deployment with several gateways needs a
-- shared store (e.g. Redis) behind the same functions.
--
-- Entries are keyed by a hash of the session id, so a dump of the store
-- holds no usable cookie values. Each expires at the earlier of its absolute
-- lifetime and its idle timeout [OWASP Session: timeouts]; a lookup moves the
-- idle deadline. Indexes by the authorization server's session id (`sid`) and
-- by user (`sub`) serve back-channel logout.
--
local util = require("apisix.plugins.tokenhandler.util")

local _M = {}

local function store()
    return ngx.shared["tokenhandler-sessions"]
end

local function key(session_id)
    return "s:" .. util.sha256_hex(session_id)
end

local function remaining(session, now)
    return math.min(session.expires_at - now, session.idle_timeout - (now - session.last_seen))
end

local function index_add(name, value, entry_key, ttl)
    local dict = store()
    local ikey = name .. ":" .. value
    local list = util.json_decode(dict:get(ikey) or "[]") or {}
    list[#list + 1] = entry_key
    dict:set(ikey, util.json_encode(util.array(list)), ttl)
end

local function write(entry_key, session, now)
    local ttl = remaining(session, now)
    if ttl <= 0 then
        store():delete(entry_key)
        return false
    end
    local ok, err = store():set(entry_key, util.json_encode(session), ttl)
    if not ok then
        error("session store: " .. tostring(err))
    end
    return true
end

-- Stores `session` under a fresh id and returns the id for the cookie.
-- 256 bits from the OS CSPRNG [OWASP Session: session ID entropy >= 64 bits].
function _M.create(session, now)
    now = now or ngx.now()
    local session_id = util.random_token(32)
    local entry_key = key(session_id)
    session.last_seen = now
    write(entry_key, session, now)
    local ttl = session.expires_at - now
    if session.sid then
        index_add("sid", session.sid, entry_key, ttl)
    end
    if session.user and session.user.sub then
        index_add("sub", session.user.sub, entry_key, ttl)
    end
    return session_id
end

local function load(entry_key, now)
    local raw = store():get(entry_key)
    local session = raw and util.json_decode(raw)
    if not session then
        return nil
    end
    if remaining(session, now) <= 0 then
        store():delete(entry_key)
        return nil
    end
    return session
end

-- The live session for `session_id`, or nil. Counts as activity for the idle timeout.
function _M.get(session_id, now)
    if not session_id or session_id == "" then
        return nil
    end
    now = now or ngx.now()
    local entry_key = key(session_id)
    local session = load(entry_key, now)
    if not session then
        return nil
    end
    session.last_seen = now
    write(entry_key, session, now)
    return session
end

-- Writes back changes of a session (refreshed or exchanged tokens).
function _M.save(session_id, session, now)
    return write(key(session_id), session, now or ngx.now())
end

function _M.delete(session_id)
    if not session_id or session_id == "" then
        return nil
    end
    local entry_key = key(session_id)
    local session = load(entry_key, ngx.now())
    store():delete(entry_key)
    return session
end

-- Deletes and returns all live sessions of the authorization server's session
-- `sid`, or (without sid) of user `sub`.
function _M.delete_by(sid, sub)
    local ikey = sid and ("sid:" .. sid) or ("sub:" .. tostring(sub))
    local dict = store()
    local keys = util.json_decode(dict:get(ikey) or "[]") or {}
    local ended = {}
    local now = ngx.now()
    for _, entry_key in ipairs(keys) do
        local session = load(entry_key, now)
        if session and session.user and (sid == nil or session.sid == sid) then
            dict:delete(entry_key)
            ended[#ended + 1] = session
        end
    end
    dict:delete(ikey)
    return ended
end

-- Serializes token refreshes and exchanges of one session across workers:
-- with refresh token rotation a second, parallel refresh would use an already
-- spent refresh token. Runs fn() under the lock; returns its result.
function _M.locked(session_id, fn)
    local lock = require("resty.lock"):new("tokenhandler-locks", {timeout = 10, exptime = 30})
    local ok, err = lock:lock(key(session_id))
    if not ok then
        error("session lock: " .. tostring(err))
    end
    local success, result = pcall(fn)
    lock:unlock()
    if not success then
        error(result, 0)
    end
    return result
end

return _M
