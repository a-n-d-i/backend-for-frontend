"""
Minimal HTTP plumbing for the demo services (stdlib only): a threaded server
with a route table, request parsing, JSON responses, the dev traffic trace
(plugins/trace.py) and an outgoing client that never follows redirects.
"""
import base64
import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Optional

import jwt

from plugins import trace

log = logging.getLogger("services")

NO_STORE = [("Cache-Control", "no-store"), ("Pragma", "no-cache")]


@dataclass
class Request:
    method: str
    path: str
    query: dict
    headers: dict          # lower-case names
    body: bytes = b""

    def header(self, name: str) -> Optional[str]:
        return self.headers.get(name.lower())

    def bearer(self) -> Optional[str]:
        scheme, _, value = (self.header("authorization") or "").partition(" ")
        return value.strip() if scheme.lower() == "bearer" and value.strip() else None


@dataclass
class Response:
    status: int
    body: object = None
    headers: list = field(default_factory=list)

    def encode(self) -> tuple:
        if isinstance(self.body, (dict, list)):
            return json.dumps(self.body).encode(), "application/json"
        return (self.body or "").encode() if isinstance(self.body, str) else (self.body or b""), "text/plain"


def json_response(status: int, body, extra_headers=()) -> Response:
    # nothing a service answers may be cached [RFC 6749 5.1; RFC 8693 2.2.1]
    return Response(status, body, [*NO_STORE, *extra_headers])


Handler = Callable[[Request], Response]


def serve(name: str, routes: dict, host: str, port: int):
    """Serves `routes` {(method, path): handler} until interrupted."""
    trace_file = os.environ.get("TRACE_FILE")

    class RequestHandler(BaseHTTPRequestHandler):
        server_version = name

        def _handle(self):
            url = urllib.parse.urlsplit(self.path)
            length = int(self.headers.get("Content-Length") or 0)
            req = Request(self.command, url.path, {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()},
                          {k.lower(): v for k, v in self.headers.items()}, self.rfile.read(length) if length else b"")
            handler = routes.get((req.method, req.path))
            trace.start(trace_file, req.header(trace.TRACE_HEADER), source=name)
            try:
                if handler is None:
                    allowed = sorted(m for m, p in routes if p == req.path)
                    resp = (json_response(405, {"error": "method_not_allowed"}, [("Allow", ", ".join(allowed))])
                            if allowed else json_response(404, {"error": "not_found"}))
                else:
                    resp = handler(req)
            except Exception:
                log.exception("%s %s failed", req.method, req.path)
                resp = json_response(500, {"error": "server_error"})
            finally:
                trace.stop()
            body, content_type = resp.encode()
            self.send_response(resp.status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for k, v in resp.headers:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _handle

        def log_message(self, fmt, *args):
            log.info("%s %s", self.address_string(), fmt % args)

    logging.basicConfig(level=logging.INFO, format=f"%(asctime)s {name} %(levelname)s %(message)s")
    server = ThreadingHTTPServer((host, port), RequestHandler)
    log.info("listening on %s:%d", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


# -- outgoing -----------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # back-channel calls never follow redirects [RFC 9700 4.12]
    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def post_form(url: str, form: dict, basic_auth: Optional[tuple] = None, timeout: float = 5) -> tuple:
    """
    POSTs a form, with client_secret_basic if `basic_auth` = (id, secret) is
    given; returns (status, body). Traced, and passes the trace id on. TLS is
    verified against the default trust store (SSL_CERT_FILE in the dev stack).
    """
    req = urllib.request.Request(url, data=urllib.parse.urlencode(form).encode(), method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded",
                                          "Accept": "application/json"})
    if basic_auth:
        # id and secret are form-urlencoded before base64 [RFC 6749 2.3.1]
        credentials = ":".join(urllib.parse.quote(v, safe="") for v in basic_auth)
        req.add_header("Authorization", "Basic " + base64.b64encode(credentials.encode()).decode())
    if trace.active():
        req.add_header(trace.TRACE_HEADER, trace.current_id())
    t_start = time.time()
    status, headers, body, error = None, [], b"", None
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            status, headers, body = resp.status, resp.getheaders(), resp.read()
    except urllib.error.HTTPError as e:
        status, headers, body = e.code, e.headers.items(), e.read()
    except (urllib.error.URLError, OSError) as e:
        error = str(e)
    if trace.active():
        trace.exchange("POST", url, req.header_items(), req.data.decode(), status, headers,
                       body.decode(errors="replace"), t_start, error)
    return status, body.decode(errors="replace")


class TracedJwks(jwt.PyJWKClient):
    """PyJWKClient whose key fetches show up in the dev trace."""

    def fetch_data(self):
        t_start = time.time()
        data = super().fetch_data()
        if trace.active():
            trace.exchange("GET", self.uri, [], None, 200, [("Content-Type", "application/json")],
                           json.dumps(data), t_start)
        return data
