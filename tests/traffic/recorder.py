"""
pytest plugin: records the HTTP traffic of every test and renders it as a
report of sequence diagrams (see report.py), traffic-report/index.html.

Two sides are joined per test:
- what the test sees: every hop of `requests` (patched at the transport
  adapter, so each redirect is its own exchange) and every request of the
  Playwright browser context (static assets left out);
- what the BFF does for those requests (back-channel calls, the forwarded API
  request, its decisions), which it writes to BFF_TRACE when the request
  carries X-Trace-Id (plugins/trace.py; `trace_file` in conf/apisix.yaml).

Disable with `-p no:tests.traffic.recorder`.
"""
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlsplit

import pytest
import requests.adapters

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = Path(os.environ.get("TRAFFIC_REPORT_DIR", ROOT / "traffic-report"))
# where the BFF writes its side; must match `trace_file` in conf/apisix.yaml
BFF_TRACE = OUT_DIR / "bff-trace.jsonl"
TRACE_HEADER = "X-Trace-Id"
# browser requests that are not part of the protocol flows
SKIPPED_RESOURCES = {"script", "stylesheet", "image", "font", "media", "manifest", "texttrack"}


@dataclass
class Exchange:
    source: str             # "test" (requests), "browser" (Playwright) or "bff" (back channel)
    src: str                # lane of the client
    dst: str                # lane of the server
    method: str
    url: str
    req_headers: list
    req_body: Optional[str]
    status: Optional[int]
    reason: str
    resp_headers: list
    resp_body: Optional[str]
    t_start: float
    t_end: float
    error: Optional[str] = None


@dataclass
class Note:
    t: float
    text: str
    refs: list
    values: dict
    lane: str = "gw"


@dataclass
class Forward:
    """The request the BFF lets through to the API, after adding the token."""
    t: float
    method: str
    path: str
    headers: list
    removed: list


@dataclass
class Phase:
    t: float
    name: str


@dataclass
class Recording:
    item: pytest.Item
    trace_id: str
    events: list = field(default_factory=list)
    outcome: str = "passed"
    longrepr: Optional[str] = None

    @property
    def nodeid(self) -> str:
        return self.item.nodeid


_recordings: list = []
_current: Optional[Recording] = None


def lane(url: str) -> str:
    path = urlsplit(url).path
    return "dex" if path.startswith("/dex/") else "gw"


def _text(body) -> Optional[str]:
    if body is None:
        return None
    if isinstance(body, bytes):
        return body.decode("utf-8", errors="replace")
    return str(body)


def _without_trace_header(headers) -> list:
    return [(k, v) for k, v in headers if k.lower() != TRACE_HEADER.lower()]


def note(text: str, refs=(), lane: str = "browser"):
    """
    Adds an explanation to the current test's diagram, for what the recorder
    cannot see (e.g. a request the browser blocks before it is sent).
    """
    if _current is not None:
        _current.events.append(Note(time.time(), text, list(refs), {}, lane))


# -- requests ------------------------------------------------------------------

_orig_send = requests.adapters.HTTPAdapter.send


def _send(self, request, *args, **kwargs):
    rec = _current
    if rec is None:
        return _orig_send(self, request, *args, **kwargs)
    request.headers[TRACE_HEADER] = rec.trace_id
    t_start = time.time()
    common = dict(source="test", src="browser", dst=lane(request.url), method=request.method, url=request.url,
                  req_headers=_without_trace_header(request.headers.items()), req_body=_text(request.body))
    try:
        resp = _orig_send(self, request, *args, **kwargs)
    except Exception as e:
        rec.events.append(Exchange(**common, status=None, reason="", resp_headers=[], resp_body=None,
                                   t_start=t_start, t_end=time.time(), error=repr(e)))
        raise
    body = resp.content  # read now; the tests never stream
    rec.events.append(Exchange(**common, status=resp.status_code, reason=resp.reason or "",
                               resp_headers=list(resp.raw.headers.items()), resp_body=_text(body),
                               t_start=t_start, t_end=time.time()))
    return resp


# -- Playwright -------------------------------------------------------------------

def _record_browser_request(rec: Recording, req, failed: bool):
    if req.resource_type in SKIPPED_RESOURCES:
        return
    resp = None if failed else req.response()
    timing = req.timing
    t_start = timing["startTime"] / 1000 if timing.get("startTime", -1) > 0 else time.time()
    t_end = t_start + timing["responseEnd"] / 1000 if timing.get("responseEnd", -1) >= 0 else time.time()
    body = None
    if resp is not None:
        try:
            body = _text(resp.body())
        except Exception:
            # redirect responses have no body to fetch
            body = None
    rec.events.append(Exchange(
        source="browser", src="browser", dst=lane(req.url), method=req.method, url=req.url,
        req_headers=_without_trace_header((h["name"], h["value"]) for h in req.headers_array()),
        req_body=req.post_data, status=resp.status if resp else None, reason=resp.status_text if resp else "",
        resp_headers=[(h["name"], h["value"]) for h in resp.headers_array()] if resp else [],
        resp_body=body, t_start=t_start, t_end=max(t_end, t_start), error=req.failure if failed else None))


@pytest.fixture(autouse=True)
def _traffic_browser(request):
    """Records the browser's traffic in tests that use a Playwright page."""
    rec = _current
    if rec is None or "page" not in request.fixturenames:
        yield
        return
    context = request.getfixturevalue("context")
    context.set_extra_http_headers({TRACE_HEADER: rec.trace_id})
    context.on("requestfinished", lambda r: _record_browser_request(rec, r, failed=False))
    context.on("requestfailed", lambda r: _record_browser_request(rec, r, failed=True))
    yield


# -- pytest hooks -------------------------------------------------------------------

def pytest_configure(config):
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    BFF_TRACE.write_text("")
    requests.adapters.HTTPAdapter.send = _send


def pytest_unconfigure(config):
    requests.adapters.HTTPAdapter.send = _orig_send


def _phase(name: str):
    if _current is not None:
        _current.events.append(Phase(time.time(), name))


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_setup(item):
    global _current
    _current = Recording(item, f"T{len(_recordings) + 1:04d}")
    _recordings.append(_current)
    _phase("setup")
    yield


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    _phase("call")
    yield


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_teardown(item, nextitem):
    global _current
    _phase("teardown")
    yield
    _current = None


def pytest_runtest_logreport(report):
    rec = next((r for r in reversed(_recordings) if r.nodeid == report.nodeid), None)
    if rec is None:
        return
    if report.failed:
        rec.outcome = "failed" if report.when == "call" else "error"
        rec.longrepr = (rec.longrepr or "") + str(report.longrepr)
    elif report.skipped and rec.outcome == "passed":
        rec.outcome = "skipped"


def _fix_redirect_timing(rec: Recording):
    # Chromium reports a redirect's response end slightly after the redirected
    # request started; end each hop where the browser follows its Location.
    hops = sorted((e for e in rec.events if isinstance(e, Exchange) and e.source == "browser"),
                  key=lambda e: e.t_start)
    for i, ex in enumerate(hops):
        location = next((v for k, v in ex.resp_headers if k.lower() == "location"), None)
        if not location or not ex.status or not 300 <= ex.status < 400:
            continue
        target = urljoin(ex.url, location)
        nxt = next((e for e in hops[i + 1:] if e.url == target), None)
        if nxt is not None and nxt.t_start < ex.t_end:
            ex.t_end = max(ex.t_start, nxt.t_start - 1e-4)


def _merge_bff_trace():
    by_id = {r.trace_id: r for r in _recordings}
    try:
        lines = BFF_TRACE.read_text().splitlines()
    except OSError:
        return
    for line in lines:
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        rec = by_id.get(ev.get("trace"))
        if rec is None:
            continue
        if ev["type"] == "exchange":
            rec.events.append(Exchange(
                source="bff", src="gw", dst=lane(ev["url"]), method=ev["method"], url=ev["url"],
                req_headers=[tuple(h) for h in ev["req_headers"]], req_body=ev["req_body"], status=ev["status"],
                reason="", resp_headers=[tuple(h) for h in ev["resp_headers"]], resp_body=ev["resp_body"],
                t_start=ev["t_start"], t_end=ev["t_end"], error=ev.get("error")))
        elif ev["type"] == "note":
            rec.events.append(Note(ev["t"], ev["text"], ev["refs"], ev["values"]))
        elif ev["type"] == "forward":
            rec.events.append(Forward(ev["t"], ev["method"], ev["path"], ev["headers"], ev["removed"]))


def pytest_sessionfinish(session):
    if not any(isinstance(e, Exchange) for r in _recordings for e in r.events):
        return
    _merge_bff_trace()
    for rec in _recordings:
        _fix_redirect_timing(rec)
    from tests.traffic.report import render
    session.config._traffic_report = render(OUT_DIR, _recordings)


def pytest_terminal_summary(terminalreporter, config):
    index = getattr(config, "_traffic_report", None)
    if index:
        terminalreporter.write_line(f"traffic report: {index}")
