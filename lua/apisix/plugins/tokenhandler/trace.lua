--
-- DEV/TEST ONLY: traffic trace for the test report (tests/traffic).
--
-- When `trace_file` is configured and a request carries `X-Trace-Id`,
-- everything the BFF does for that request is appended to the file as JSON
-- lines, in the format the Python services and tests/traffic/recorder.py
-- share: its back-channel calls (full requests and responses, so client
-- secrets, codes and tokens included), the request it forwards to an API,
-- and notes on its decisions.
--
-- Never enable it outside a development setup: the trace holds secrets and
-- tokens in clear text, which the BFF otherwise never logs.
--
local util = require("apisix.plugins.tokenhandler.util")

local _M = {
    HEADER = "X-Trace-Id",
}

local function ctx()
    return ngx.ctx.tokenhandler_trace
end

function _M.start(trace_file, trace_id)
    if trace_file and trace_id and ngx.re.find(trace_id, [[^[A-Za-z0-9_.:-]{1,64}$]], "jo") then
        ngx.ctx.tokenhandler_trace = {file = trace_file, id = trace_id}
    else
        ngx.ctx.tokenhandler_trace = nil
    end
end

function _M.stop()
    ngx.ctx.tokenhandler_trace = nil
end

function _M.active()
    return ctx() ~= nil
end

function _M.current_id()
    local c = ctx()
    return c and c.id
end

-- microseconds: ngx.now() has only milliseconds, too coarse to order the
-- events of one request in the report
local ffi = require("ffi")
-- APISIX or another library may have declared these already: each on its own
pcall(ffi.cdef, "struct timeval { long tv_sec; long tv_usec; };")
pcall(ffi.cdef, "int gettimeofday(struct timeval *tv, void *tz);")
local tv = ffi.new("struct timeval")

function _M.now()
    ffi.C.gettimeofday(tv, nil)
    return tonumber(tv.tv_sec) + tonumber(tv.tv_usec) / 1e6
end

function _M.emit(event_type, fields)
    local c = ctx()
    if not c then
        return
    end
    local event = {trace = c.id, source = "bff", type = event_type, t = _M.now()}
    for k, v in pairs(fields) do
        event[k] = v
    end
    local line = util.json_encode(event)
    -- only append to a file the test run created; several processes write to it
    local exists = io.open(c.file, "r")
    if not exists then
        return
    end
    exists:close()
    local f = io.open(c.file, "a")
    if f then
        -- one write() call: appends of a single write don't interleave
        f:setvbuf("full", #line + 2)
        f:write(line, "\n")
        f:close()
    end
end

-- A decision of the BFF; `values` are highlighted in the report.
function _M.note(text, refs, values)
    _M.emit("note", {text = text, refs = util.array(refs), values = values or {}})
end

local function header_list(headers)
    local list = util.array()
    for k, v in pairs(headers or {}) do
        if type(v) == "table" then
            for _, item in ipairs(v) do
                list[#list + 1] = util.array({k, item})
            end
        else
            list[#list + 1] = util.array({k, tostring(v)})
        end
    end
    return list
end

_M.header_list = header_list

-- A back-channel HTTP call of the BFF.
function _M.exchange(method, url, req_headers, req_body, status, resp_headers, resp_body, t_start, err)
    local null = util.nullable
    _M.emit("exchange", {
        method = method, url = url, req_headers = header_list(req_headers), req_body = null(req_body),
        status = null(status), resp_headers = header_list(resp_headers), resp_body = null(resp_body),
        t_start = t_start, t_end = _M.now(), error = null(err),
    })
end

return _M
