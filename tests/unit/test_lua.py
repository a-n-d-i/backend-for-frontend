"""
Runs the Lua unit tests of the tokenhandler plugin (tests/lua/test_*.lua)
with OpenResty's `resty` CLI, one pytest test per file.
"""
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LUA_TESTS = sorted((ROOT / "tests" / "lua").glob("test_*.lua"))
# the shared dicts the plugin declares in conf/config.yaml
SHARED_DICTS = "lua_shared_dict tokenhandler-sessions 1m; lua_shared_dict tokenhandler-locks 1m;"


@pytest.mark.parametrize("path", LUA_TESTS, ids=lambda p: p.stem)
def test_lua(path):
    result = subprocess.run(
        ["resty", "--http-conf", SHARED_DICTS, "-I", str(ROOT / "lua"), "-I", str(ROOT / "tests" / "lua"),
         "-I", "/usr/local/apisix/deps/share/lua/5.1", "-I", "/usr/local/apisix", str(path)],
        capture_output=True, text=True, timeout=120, cwd=ROOT)
    failures = "\n".join(line for line in result.stdout.splitlines() if not line.startswith("ok - "))
    assert result.returncode == 0, f"{failures}\n{result.stderr}"
