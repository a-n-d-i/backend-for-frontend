-- lua/apisix/plugins/tokenhandler/sessions.lua on a real shared dict.
local t = require("harness")
local sessions = require("apisix.plugins.tokenhandler.sessions")

local dict = ngx.shared["tokenhandler-sessions"]

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
        local id = sessions.create(session(ngx.now()))
        t.expect_eq(#id, 43)
        t.expect(not seen[id], "duplicate id")
        seen[id] = true
    end
end)

t.test("ids are not stored in clear", function()
    local id = sessions.create(session(ngx.now()))
    for _, key in ipairs(dict:get_keys(0)) do
        t.expect(not key:find(id, 1, true), "raw session id in the store")
    end
end)

t.test("get, save and delete", function()
    local id = sessions.create(session(ngx.now(), nil, nil, {user = {sub = "u"}}))
    local s = sessions.get(id)
    t.expect_eq(s.user.sub, "u")
    s.access_token = "at-2"
    sessions.save(id, s)
    t.expect_eq(sessions.get(id).access_token, "at-2")
    t.expect_eq(sessions.delete(id).access_token, "at-2")
    t.expect_eq(sessions.get(id), nil)
    t.expect_eq(sessions.get(nil), nil)
    t.expect_eq(sessions.get("unknown"), nil)
end)

t.test("idle timeout; activity moves it", function()
    local now = ngx.now()
    local id = sessions.create(session(now, 3600, 600), now)
    t.expect(sessions.get(id, now + 599), "still alive")
    t.expect(sessions.get(id, now + 1198), "activity resets the idle timer")
    t.expect_eq(sessions.get(id, now + 1800), nil)
end)

t.test("absolute lifetime", function()
    local now = ngx.now()
    local id = sessions.create(session(now, 1000, 600), now)
    for i = 1, 3 do
        t.expect(sessions.get(id, now + 300 * i), "alive at " .. 300 * i)
    end
    t.expect_eq(sessions.get(id, now + 1000), nil)
end)

t.test("delete_by sid ends every session of that authorization-server session", function()
    local now = ngx.now()
    local a = sessions.create(session(now, nil, nil, {sid = "kc-1", user = {sub = "u1"}}))
    local b = sessions.create(session(now, nil, nil, {sid = "kc-1", user = {sub = "u1"}}))
    local other = sessions.create(session(now, nil, nil, {sid = "kc-2", user = {sub = "u1"}}))
    t.expect_eq(#sessions.delete_by("kc-1"), 2)
    t.expect_eq(sessions.get(a), nil)
    t.expect_eq(sessions.get(b), nil)
    t.expect(sessions.get(other), "other sid untouched")
end)

t.test("delete_by sub ends all sessions of a user", function()
    local now = ngx.now()
    local a = sessions.create(session(now, nil, nil, {sid = "x1", user = {sub = "u7"}}))
    local b = sessions.create(session(now, nil, nil, {sid = "x2", user = {sub = "u7"}}))
    local someone = sessions.create(session(now, nil, nil, {sid = "x3", user = {sub = "u8"}}))
    t.expect_eq(#sessions.delete_by(nil, "u7"), 2)
    t.expect_eq(sessions.get(a), nil)
    t.expect_eq(sessions.get(b), nil)
    t.expect(sessions.get(someone), "other user untouched")
end)

t.test("pending logins are no sessions to log out", function()
    local id = sessions.create(session(ngx.now(), nil, nil, {sid = "kc-9", state = "st"}))
    t.expect_eq(#sessions.delete_by("kc-9"), 0)
    t.expect(sessions.get(id))
end)

t.test("locked runs the function and passes errors on", function()
    local id = sessions.create(session(ngx.now()))
    t.expect_eq(sessions.locked(id, function() return 42 end), 42)
    t.expect_error(function() sessions.locked(id, function() error({kind = "oidc", message = "boom"}) end) end, "boom")
    -- the lock was released
    t.expect_eq(sessions.locked(id, function() return "again" end), "again")
end)

t.done()
