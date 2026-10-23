"""
DEV/TEST ONLY: traffic trace of the BFF for the test report (tests/traffic).

When the route config sets `trace_file` and a request carries `X-Trace-Id`,
everything the BFF does for that request is appended to `trace_file` as JSON
lines: its back-channel calls to the authorization server (full requests and
responses, so client secret, codes and tokens included), the request it
forwards to the API, and notes on its decisions. The test run joins these
with the traffic it saw itself and renders sequence diagrams.

Never set `trace_file` outside a development setup: the trace holds secrets
and tokens in clear text, which the BFF otherwise never logs.
"""
import json
import re
import threading
import time
from typing import Optional

TRACE_HEADER = "X-Trace-Id"
_TRACE_ID = re.compile(r"[A-Za-z0-9_.:-]{1,64}")

_local = threading.local()
_lock = threading.Lock()


def start(trace_file: Optional[str], trace_id: Optional[str]):
    """Traces the current request (thread) if both are set."""
    _local.ctx = (trace_file, trace_id) if trace_file and trace_id and _TRACE_ID.fullmatch(trace_id) else None


def stop():
    _local.ctx = None


def active() -> bool:
    return getattr(_local, "ctx", None) is not None


def emit(event_type: str, **fields):
    ctx = getattr(_local, "ctx", None)
    if ctx is None:
        return
    trace_file, trace_id = ctx
    line = json.dumps({"trace": trace_id, "type": event_type, "t": time.time(), **fields})
    try:
        with _lock, open(trace_file, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


def note(text: str, refs=(), **values):
    """A decision of the BFF; `values` are highlighted in the report."""
    emit("note", text=text, refs=list(refs), values=values)


def exchange(method: str, url: str, req_headers, req_body: Optional[str], status: Optional[int],
             resp_headers, resp_body: Optional[str], t_start: float, error: Optional[str] = None):
    """A back-channel HTTP call of the BFF."""
    emit("exchange", method=method, url=url, req_headers=[list(h) for h in req_headers], req_body=req_body,
         status=status, resp_headers=[list(h) for h in resp_headers], resp_body=resp_body,
         t_start=t_start, t_end=time.time(), error=error)
