--
-- Merges luacov stats files: lua scripts/luacov_merge.lua OUT IN...
-- (`make coverage-e2e`: one file per gateway worker, see lua/luacov_gateway.lua)
--
local runner = require("luacov.runner")
local stats = require("luacov.stats")

local out = assert(arg[1], "usage: luacov_merge.lua OUT IN...")
local merged = {}
for i = 2, #arg do
    for name, file_data in pairs(stats.load(arg[i]) or {}) do
        if merged[name] then
            runner.update_stats(merged[name], file_data)
        else
            merged[name] = file_data
        end
    end
end
stats.save(out, merged)
