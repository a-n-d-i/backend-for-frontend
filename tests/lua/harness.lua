--
-- Minimal test harness for the plugin's Lua modules, run with the `resty`
-- CLI (tests/unit/test_lua.py does that for pytest):
--
--   resty --shdict "tokenhandler-cache 1m" \
--         -I lua -I /usr/local/apisix/deps/share/lua/5.1 tests/lua/test_oidc.lua
--
-- test("name", fn) runs fn; expect_* raise on failure. done() prints a
-- summary and exits non-zero if anything failed.
--
local _M = {passed = 0, failed = 0}

local function describe(v)
    if type(v) == "table" then
        local ok, json = pcall(require("cjson").encode, v)
        return ok and json or tostring(v)
    end
    return tostring(v)
end

function _M.test(name, fn)
    local ok, err = xpcall(fn, debug.traceback)
    if ok then
        _M.passed = _M.passed + 1
        print("ok - " .. name)
    else
        _M.failed = _M.failed + 1
        print("not ok - " .. name .. "\n    " .. tostring(err):gsub("\n", "\n    "))
    end
end

function _M.expect(cond, message)
    if not cond then
        error(message or "expectation failed", 2)
    end
end

function _M.expect_eq(actual, expected, message)
    if actual ~= expected then
        error((message and (message .. ": ") or "") .. "expected " .. describe(expected) .. ", got " .. describe(actual), 2)
    end
end

-- fn must raise; the error (a table {kind, message} or a string) must mention `pattern` (plain)
function _M.expect_error(fn, pattern)
    local ok, err = pcall(fn)
    if ok then
        error("expected an error matching " .. tostring(pattern), 2)
    end
    local text = type(err) == "table" and tostring(err.message) or tostring(err)
    if pattern and not text:find(pattern, 1, true) then
        error("error " .. describe(text) .. " does not mention " .. describe(pattern), 2)
    end
    return err
end

function _M.done()
    print(string.format("%d passed, %d failed", _M.passed, _M.failed))
    os.exit(_M.failed == 0 and 0 or 1)
end

return _M
