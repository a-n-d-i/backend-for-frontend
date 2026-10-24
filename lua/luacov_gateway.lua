--
-- Line coverage of the plugin inside the running gateway, for `make
-- coverage-e2e` (tests driving the stack, like the Playwright tests). Dev only.
--
-- Loaded by APISIX in init_by_lua (`apisix.lua_module_hook` in
-- conf/config.yaml), before the workers fork. Does nothing unless the file
-- .luacov-gateway/on exists in the workspace at that time, so it is switched
-- on and off with `make reload`. When on, it starts luacov (config:
-- .luacov) in the master, so every worker inherits the hook, and each worker
-- writes its counts to .luacov-gateway/<pid> when it exits (on the next
-- reload). scripts/luacov_merge.lua merges them for the report.
--
local root = debug.getinfo(1, "S").source:match("^@(.*)/lua/[^/]*$")
local dir = root and (root .. "/.luacov-gateway")

local probe = dir and io.open(dir .. "/on", "r")
if not probe then
    return
end
probe:close()

local runner = require("luacov.runner")
runner.load_config(root .. "/.luacov")
-- luacov's own init() is not used: it patches os.exit and saves from a __gc
-- handler, neither of which fits nginx workers. Saving is done below.
runner.initialized = true
runner.paused = false
-- the debug hook does not fire in JIT-compiled code
require("jit").off()
debug.sethook(runner.debug_hook, "l")

local apisix = require("apisix")
local http_exit_worker = apisix.http_exit_worker
apisix.http_exit_worker = function(...)
    http_exit_worker(...)
    debug.sethook()
    runner.configuration.statsfile = dir .. "/" .. ngx.worker.pid()
    runner.save_stats()
end
