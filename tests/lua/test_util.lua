-- lua/apisix/plugins/tokenhandler/util.lua
local t = require("harness")
local util = require("apisix.plugins.tokenhandler.util")

t.test("local paths only (no open redirect)", function()
    local cases = {
        {nil, "/"}, {"", "/"}, {"/", "/"}, {"/a/b?c=d#e", "/a/b?c=d#e"},
        {"//evil.example", "/"}, {"/\\evil.example", "/"}, {"https://evil.example/", "/"},
        {"javascript:alert(1)", "/"}, {"/a\r\nSet-Cookie: x=1", "/"}, {"/a b", "/"},
        {"/" .. string.rep("a", 3000), "/"},
    }
    for _, case in ipairs(cases) do
        t.expect_eq(util.local_path(case[1]), case[2], tostring(case[1]))
    end
end)

t.test("constant-time comparison", function()
    t.expect(util.const_eq("abc", "abc"))
    t.expect(not util.const_eq("abc", "abd"))
    t.expect(not util.const_eq("abc", "ab"))
    t.expect(not util.const_eq(nil, "abc"))
    t.expect(not util.const_eq("abc", nil))
end)

t.test("random tokens", function()
    local a, b = util.random_token(32), util.random_token(32)
    t.expect_eq(#a, 43)
    t.expect(a ~= b)
    t.expect(a:match("^[%w_-]+$"), "base64url")
end)

t.test("PKCE S256 test vector [RFC 7636 appendix B]", function()
    t.expect_eq(util.b64url(util.sha256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")),
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
end)

t.test("form-urlencoding for client_secret_basic", function()
    t.expect_eq(util.form_urlencode("bff client"), "bff+client")
    t.expect_eq(util.form_urlencode("s3cr:t/+"), "s3cr%3At%2F%2B")
end)

t.test("URL parts", function()
    local p = util.split_url("https://auth.example.test/realms/demo?x=1")
    t.expect_eq(p.scheme, "https")
    t.expect_eq(p.host, "auth.example.test")
    t.expect_eq(p.port, 443)
    t.expect_eq(p.path, "/realms/demo?x=1")
    p = util.split_url("http://vault:8200")
    t.expect_eq(p.port, 8200)
    t.expect_eq(p.path, "/")
    t.expect_eq(util.split_url("ftp://x"), nil)
end)

t.test("JSON keeps empty lists as lists", function()
    t.expect_eq(util.json_encode({refs = util.array({})}), '{"refs":[]}')
    t.expect_eq(util.json_encode({v = util.nullable(nil)}), '{"v":null}')
end)

t.done()
