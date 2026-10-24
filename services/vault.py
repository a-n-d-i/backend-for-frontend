"""
Secrets from HashiCorp Vault (KV engine v1) for the services (the BFF has the
same in Lua: lua/apisix/plugins/tokenhandler/vault.lua).

A configuration value `vault:<path>#<field>`, e.g. `vault:kv/bff#client_secret`,
is replaced by that field of the secret at `<path>`. Each component reads with
its own token, whose policy allows only its own secrets; the token comes from
a file, so a replaced one is picked up without a restart. Values are cached for a few minutes, so a rotated secret arrives
within that time.
"""
import json
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Optional

from services import trace

PREFIX = "vault:"
CACHE_SECONDS = 300

_cache = {}
_lock = threading.Lock()


class VaultError(Exception):
    """Vault is unreachable, refuses the token, or lacks the secret."""


def is_ref(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


def read(ref: str, addr: str, token_file: str, timeout: float = 5) -> str:
    """The value `vault:<path>#<field>` refers to."""
    path, sep, field = ref[len(PREFIX):].partition("#")
    if not sep or not path or not field:
        raise VaultError(f"not a vault reference (vault:<path>#<field>): {ref!r}")
    now = time.time()
    with _lock:
        hit = _cache.get((addr, ref))
        if hit and hit[1] > now:
            return hit[0]
    try:
        with open(token_file) as f:
            token = f.read().strip()
    except OSError as e:
        raise VaultError(f"no Vault token: {e}") from None

    url = f"{addr.rstrip('/')}/v1/{path}"
    req = urllib.request.Request(url, headers={"X-Vault-Token": token})
    if trace.active():
        req.add_header(trace.TRACE_HEADER, trace.current_id())
    t_start = time.time()
    status, headers, body, error = None, [], b"", None
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status, headers, body = resp.status, resp.getheaders(), resp.read()
    except urllib.error.HTTPError as e:
        status, headers, body = e.code, e.headers.items(), e.read()
    except (urllib.error.URLError, OSError) as e:
        error = str(e)
    if trace.active():
        # the token is the component's own, the trace is dev only (it records secrets anyway)
        trace.exchange("GET", url, req.header_items(), None, status, headers,
                       body.decode(errors="replace"), t_start, error)
    if error is not None:
        raise VaultError(f"Vault unreachable: {error}")
    if status != 200:
        # 403: the token's policy doesn't cover this path (least privilege); 404: no such secret
        raise VaultError(f"Vault answered {status} for {path}")
    value = json.loads(body).get("data", {}).get(field)
    if value is None:
        raise VaultError(f"secret {path} has no field {field!r}")
    with _lock:
        _cache[(addr, ref)] = (value, now + CACHE_SECONDS)
    return value


def resolve(conf: dict, vault_conf: Optional[dict]) -> dict:
    """`conf` with every top-level `vault:` reference replaced by its secret."""
    refs = {k: v for k, v in conf.items() if is_ref(v)}
    if not refs:
        return conf
    if not vault_conf or not vault_conf.get("addr") or not vault_conf.get("token_file"):
        raise VaultError(f"{', '.join(refs)} refer to Vault, but `vault` (addr, token_file) is not configured")
    return {**conf, **{k: read(v, vault_conf["addr"], vault_conf["token_file"]) for k, v in refs.items()}}
