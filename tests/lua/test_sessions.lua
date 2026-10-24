-- lua/apisix/plugins/tokenhandler/sessions.lua on a real Redis
-- (TOKENHANDLER_TEST_REDIS, default: the stack's `redis`), under a key
-- prefix of its own that is removed at the end.
local t = require("harness")
local sessions = require("apisix.plugins.tokenhandler.sessions")
local util = require("apisix.plugins.tokenhandler.util")

local prefix = "test-" .. util.random_token(8) .. ":"
local store = sessions.new({host = os.getenv("TOKENHANDLER_TEST_REDIS") or "redis", prefix = prefix})

local function keys()
    return store:with_redis(function(red) return red:keys(prefix .. "*") end)
end

local function session(now, lifetime, idle, extra)
    local s = {expires_at = now + (lifetime or 3600), idle_timeout = idle or 600}
    for k, v in pairs(extra or {}) do
        s[k] = v
    end
    return s
end

t.test("ids are random, 256 bits", function()
    local seen = {}
    for _ = 1, 100 do
        local id = store:create(session(ngx.now()))
        t.expect_eq(#id, 43)
        t.expect(not seen[id], "duplicate id")
        seen[id] = true
    end
end)

t.test("ids are not stored in clear", function()
    local id = store:create(session(ngx.now()))
    for _, key in ipairs(keys()) do
        t.expect(not key:find(id, 1, true), "raw session id in the store")
    end
end)

t.test("entries expire in Redis too", function()
    local id = store:create(session(ngx.now(), 3600, 600))
    local ttl = store:with_redis(function(red) return red:pttl(store:key(id)) end)
    t.expect(ttl > 590000 and ttl <= 600000, "ttl " .. tostring(ttl))
end)

t.test("get, save and delete", function()
    local id = store:create(session(ngx.now(), nil, nil, {user = {sub = "u"}}))
    local s = store:get(id)
    t.expect_eq(s.user.sub, "u")
    s.access_token = "at-2"
    store:save(id, s)
    t.expect_eq(store:get(id).access_token, "at-2")
    t.expect_eq(store:delete(id).access_token, "at-2")
    t.expect_eq(store:get(id), nil)
    t.expect_eq(store:get(nil), nil)
    t.expect_eq(store:get("unknown"), nil)
end)

t.test("a second store on the same Redis sees the sessions (another gateway)", function()
    local id = store:create(session(ngx.now(), nil, nil, {user = {sub = "u"}}))
    local other = sessions.new({host = store.host, prefix = prefix})
    t.expect_eq(other:get(id).user.sub, "u")
end)

t.test("idle timeout; activity moves it", function()
    local now = ngx.now()
    local id = store:create(session(now, 3600, 600), now)
    t.expect(store:get(id, now + 599), "still alive")
    t.expect(store:get(id, now + 1198), "activity resets the idle timer")
    t.expect_eq(store:get(id, now + 1800), nil)
end)

t.test("absolute lifetime", function()
    local now = ngx.now()
    local id = store:create(session(now, 1000, 600), now)
    for i = 1, 3 do
        t.expect(store:get(id, now + 300 * i), "alive at " .. 300 * i)
    end
    t.expect_eq(store:get(id, now + 1000), nil)
end)

t.test("delete_by sid ends every session of that authorization-server session", function()
    local now = ngx.now()
    local a = store:create(session(now, nil, nil, {sid = "kc-1", user = {sub = "u1"}}))
    local b = store:create(session(now, nil, nil, {sid = "kc-1", user = {sub = "u1"}}))
    local other = store:create(session(now, nil, nil, {sid = "kc-2", user = {sub = "u1"}}))
    t.expect_eq(#store:delete_by("kc-1"), 2)
    t.expect_eq(store:get(a), nil)
    t.expect_eq(store:get(b), nil)
    t.expect(store:get(other), "other sid untouched")
end)

t.test("delete_by sub ends all sessions of a user", function()
    local now = ngx.now()
    local a = store:create(session(now, nil, nil, {sid = "x1", user = {sub = "u7"}}))
    local b = store:create(session(now, nil, nil, {sid = "x2", user = {sub = "u7"}}))
    local someone = store:create(session(now, nil, nil, {sid = "x3", user = {sub = "u8"}}))
    t.expect_eq(#store:delete_by(nil, "u7"), 2)
    t.expect_eq(store:get(a), nil)
    t.expect_eq(store:get(b), nil)
    t.expect(store:get(someone), "other user untouched")
end)

t.test("pending logins are no sessions to log out", function()
    local id = store:create(session(ngx.now(), nil, nil, {sid = "kc-9", state = "st"}))
    t.expect_eq(#store:delete_by("kc-9"), 0)
    t.expect(store:get(id))
end)

t.test("add records a key once, for every store, until it expires", function()
    local other = sessions.new({host = store.host, prefix = prefix})
    t.expect_eq(store:add("jti:j1", true, 60), true)
    t.expect_eq(store:add("jti:j1", true, 60), false)
    t.expect_eq(other:add("jti:j1", true, 60), false, "another gateway")
    t.expect_eq(store:add("jti:j2", true, 0.1), true)
    ngx.sleep(0.2)
    t.expect_eq(store:add("jti:j2", true, 60), true, "expired")
end)

t.test("locked runs the function and passes errors on", function()
    local id = store:create(session(ngx.now()))
    t.expect_eq(store:locked(id, function() return 42 end), 42)
    t.expect_error(function() store:locked(id, function() error({kind = "oidc", message = "boom"}) end) end, "boom")
    -- the lock was released
    t.expect_eq(store:locked(id, function() return "again" end), "again")
end)

t.test("locked serializes, also between stores", function()
    local id = store:create(session(ngx.now()))
    local other = sessions.new({host = store.host, prefix = prefix})
    local order = {}
    local first = ngx.thread.spawn(function()
        store:locked(id, function()
            order[#order + 1] = "a in"
            ngx.sleep(0.2)
            order[#order + 1] = "a out"
        end)
    end)
    ngx.sleep(0.05)
    other:locked(id, function() order[#order + 1] = "b" end)
    ngx.thread.wait(first)
    t.expect_eq(table.concat(order, ","), "a in,a out,b")
end)

store:with_redis(function(red)
    for _, key in ipairs(red:keys(prefix .. "*")) do
        red:del(key)
    end
end)
t.done()
