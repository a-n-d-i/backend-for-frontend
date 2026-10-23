"""
DEV/TEST ONLY: traffic trace for the test report (tests/traffic).

When a trace file is configured and a request carries `X-Trace-Id`,
everything a component does for that request is appended to the file as JSON
lines: its outgoing back-channel calls (full requests and responses, so client
secrets, codes and tokens included), the request the BFF forwards to an API,
and notes on its decisions. The test run joins these with the traffic it saw
itself and renders sequence diagrams.

Used by the BFF plugin (`trace_file` in its route config) and by the services
in services/ (env TRACE_FILE). Each writer names itself as `source`.

Never enable it outside a development setup: the trace holds secrets and
tokens in clear text, which these components otherwise never log.
"""
import fcntl
import json
import os
import re
import threading
import time
from typing import Optional

TRACE_HEADER = "X-Trace-Id"
_TRACE_ID = re.compile(r"[A-Za-z0-9_.:-]{1,64}")

_local = threading.local()
_lock = threading.Lock()


def start(trace_file: Optional[str], trace_id: Optional[str], source: str = "bff"):
    """Traces the current request (thread) if both are set."""
    ok = trace_file and trace_id and _TRACE_ID.fullmatch(trace_id)
    _local.ctx = (trace_file, trace_id, source) if ok else None


def stop():
    _local.ctx = None


def active() -> bool:
    return getattr(_local, "ctx", None) is not None


def current_id() -> Optional[str]:
    """Trace id to pass on to the next hop, so it traces too."""
    ctx = getattr(_local, "ctx", None)
    return ctx[1] if ctx else None


def emit(event_type: str, **fields):
    ctx = getattr(_local, "ctx", None)
    if ctx is None:
        return
    trace_file, trace_id, source = ctx
    line = json.dumps({"trace": trace_id, "source": source, "type": event_type, "t": time.time(), **fields})
    # only append to a file the test run created; several processes write to it
    if not os.path.exists(trace_file):
        return
    try:
        with _lock, open(trace_file, "a") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.write(line + "\n")
    except OSError:
        pass


def note(text: str, refs=(), **values):
    """A decision of this component; `values` are highlighted in the report."""
    emit("note", text=text, refs=list(refs), values=values)


def exchange(method: str, url: str, req_headers, req_body: Optional[str], status: Optional[int],
             resp_headers, resp_body: Optional[str], t_start: float, error: Optional[str] = None):
    """An outgoing back-channel HTTP call."""
    emit("exchange", method=method, url=url, req_headers=[list(h) for h in req_headers], req_body=req_body,
         status=status, resp_headers=[list(h) for h in resp_headers], resp_body=resp_body,
         t_start=t_start, t_end=time.time(), error=error)
