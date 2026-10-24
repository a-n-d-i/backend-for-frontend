"""
Runs the Lua unit tests of the tokenhandler plugin (tests/lua/test_*.lua)
with OpenResty's `resty` CLI, one pytest test per file. test_sessions needs a
Redis (TOKENHANDLER_TEST_REDIS, default: the stack's `redis`) and is skipped
without one.
"""
import os
import socket
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LUA_TESTS = sorted((ROOT / "tests" / "lua").glob("test_*.lua"))
# the shared dicts the plugin declares in conf/config.yaml
SHARED_DICTS = "lua_shared_dict tokenhandler-cache 1m;"
REDIS_HOST = os.environ.get("TOKENHANDLER_TEST_REDIS", "redis")
# `make coverage`: line coverage with luacov (config: .luacov). Started from
# -e, not from a require()d module: luacov's init runs a coroutine, which in
# OpenResty cannot yield across require(). The debug hook it counts lines with
# does not fire in JIT-compiled code, hence jit.off().
COVERAGE = ["-e", 'jit.off() require("luacov.runner").init()'] if os.environ.get("LUACOV") == "1" else []


def redis_reachable():
    try:
        socket.create_connection((REDIS_HOST, 6379), timeout=1).close()
        return True
    except OSError:
        return False


@pytest.mark.parametrize("path", LUA_TESTS, ids=lambda p: p.stem)
def test_lua(path):
    if path.stem == "test_sessions" and not redis_reachable():
        pytest.skip(f"no Redis at {REDIS_HOST}:6379")
    result = subprocess.run(
        ["resty", "--http-conf", SHARED_DICTS, "-I", str(ROOT / "lua"), "-I", str(ROOT / "tests" / "lua"),
         "-I", "/usr/local/apisix/deps/share/lua/5.1", "-I", "/usr/local/apisix", *COVERAGE, str(path)],
        capture_output=True, text=True, timeout=120, cwd=ROOT)
    failures = "\n".join(line for line in result.stdout.splitlines() if not line.startswith("ok - "))
    assert result.returncode == 0, f"{failures}\n{result.stderr}"
