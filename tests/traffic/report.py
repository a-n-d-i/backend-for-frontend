"""
Renders the recorded traffic (recorder.py) as static HTML:
traffic-report/index.html and one page per test with

- the test's source,
- a sequence diagram (Browser, Gateway/BFF, Keycloak, Service A/B) of every message, with
  the BFF's notes on its decisions, linking to
- the full messages: headers, bodies, decoded JWTs and Basic credentials,
  the PKCE S256 check, and the RFC/OWASP sections each message illustrates
  (specs.py).

Values are highlighted with one color each wherever they occur: values the
test itself uses (its variables, constants and literals, if they are sent),
protocol values (state, code, tokens, ...) and session ids. Clicking one
highlights it everywhere on the page.
"""
import ast
import base64
import hashlib
import html
import inspect
import json
import re
import shutil
import sys
import textwrap
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, quote, quote_plus, unquote, urlsplit

from tests.traffic.recorder import ROOT, Exchange, Forward, Note, Phase
from tests.traffic.specs import annotate, annotate_forward, form, header, json_body, ref_url

# all lanes in diagram order; a page shows the ones its test used
LANES = [
    ("browser", "Browser"),
    ("gw", "Gateway · BFF"),
    ("keycloak", "Keycloak"),
    ("vault", "Vault"),
    ("service-a", "Service A"),
    ("service-b", "Service B"),
]
# protocol parameters and fields whose values are tracked through the flow
PROTOCOL_KEYS = {
    "state", "nonce", "code", "code_challenge", "code_verifier", "access_token", "refresh_token", "id_token",
    "client_id", "redirect_uri", "return_to", "post_logout_redirect_uri", "logout_url", "sub", "iss",
    "session_id", "sid", "session_state", "subject_token", "audience", "logout_token", "id_token_hint", "token",
}
SESSION_COOKIE_PREFIX = "__Host-"
JWT = re.compile(r"eyJ[\w-]+\.eyJ[\w-]+\.[\w-]*")
# base URLs of the stack: as test values they would mark the start of every URL
BASE_URL = re.compile(r"https?://([\w.-]*example\.test|localhost|127\.0\.0\.1|service-[ab])(:\d+)?(/realms/\w+)?/?")
MIN_VALUE_LEN = 4
MAX_BODY = 6000
COLORS = 12

esc = html.escape


# -- values ------------------------------------------------------------------

@dataclass
class Value:
    value: str
    base: str
    origin: str          # "test", "protocol" or "bff"
    idx: int = 0
    label: str = ""
    first: str = ""      # anchor of the first message it occurs in

    @property
    def color(self) -> int:
        return self.idx % COLORS


class Values:
    """Registry of highlighted values, in order of first occurrence."""

    ORIGINS = {"test": "used by the test", "protocol": "protocol value", "bff": "BFF internal"}

    def __init__(self):
        self.items: list = []
        self._by_value: dict = {}
        self._regex = None
        self._variants: dict = {}

    def add(self, value, base: str, origin: str, where: str = ""):
        if not isinstance(value, str) or len(value) < MIN_VALUE_LEN or value in self._by_value:
            return
        v = Value(value, base, origin, first=where)
        self.items.append(v)
        self._by_value[value] = v

    def get(self, value: str):
        return self._by_value.get(value)

    def finalize(self):
        counts: dict = {}
        for v in self.items:
            counts[v.base] = counts.get(v.base, 0) + 1
        seen: dict = {}
        for i, v in enumerate(self.items):
            v.idx = i
            seen[v.base] = seen.get(v.base, 0) + 1
            v.label = v.base if counts[v.base] == 1 else f"{v.base} #{seen[v.base]}"
        for v in self.items:
            for variant in {v.value, quote(v.value, safe=""), quote_plus(v.value), quote(v.value, safe="/")}:
                self._variants.setdefault(variant, v)
        if self._variants:
            alternatives = sorted(self._variants, key=len, reverse=True)
            self._regex = re.compile("|".join(re.escape(a) for a in alternatives))

    def mark(self, v: Value, text: str) -> str:
        return (f'<mark class="v c{v.color}" data-v="{v.idx}" title="{esc(v.label)} · {self.ORIGINS[v.origin]}">'
                f"{esc(text)}</mark>")

    def hl(self, text) -> str:
        """`text`, HTML-escaped, with every known value marked."""
        if text is None:
            return ""
        text = str(text)
        if self._regex is None:
            return esc(text)
        out, pos = [], 0
        for m in self._regex.finditer(text):
            out.append(esc(text[pos:m.start()]))
            out.append(self.mark(self._variants[m.group(0)], m.group(0)))
            pos = m.end()
        out.append(esc(text[pos:]))
        return "".join(out)

    def present(self, *texts) -> list:
        """Values occurring in `texts`, in registry order."""
        if self._regex is None:
            return []
        found = {}
        for text in texts:
            for m in self._regex.finditer(text or ""):
                v = self._variants[m.group(0)]
                found[v.idx] = v
        return [found[i] for i in sorted(found)]

    def chip(self, v: Value) -> str:
        return f'<span class="chip c{v.color}" data-v="{v.idx}" title="{esc(v.value)}">{esc(v.label)}</span>'


def _test_values(item) -> tuple:
    """(source, [(label, value)]) of the values a test function uses."""
    fn = getattr(item, "obj", None)
    try:
        source = textwrap.dedent(inspect.getsource(fn))
    except (TypeError, OSError):
        return "", []
    tree = ast.parse(source)
    func = tree.body[0]
    docstring = func.body[0].value if func.body and isinstance(func.body[0], ast.Expr) else None
    # constant parts of f-strings are templates (paths, ...), not values
    templates = {id(part) for node in ast.walk(tree) if isinstance(node, ast.JoinedStr) for part in node.values}
    out = []

    def add(name, value):
        if isinstance(value, str):
            out.append((name, value))
        elif isinstance(value, dict):
            for k, v in value.items():
                if isinstance(v, str):
                    out.append((f"{name}[{k!r}]", v))
        elif isinstance(value, (list, tuple)):
            for i, v in enumerate(value):
                if isinstance(v, str):
                    out.append((f"{name}[{i}]", v))

    names = dict.fromkeys(n.id for n in ast.walk(tree) if isinstance(n, ast.Name))
    for name in names:
        add(name, fn.__globals__.get(name))
    for name, value in getattr(getattr(item, "callspec", None), "params", {}).items():
        add(name, value)
    # constants of the test helper modules (USERNAME, PASSWORD, ... used by fixtures)
    tests_dir = str(ROOT / "tests")
    for module in list(sys.modules.values()):
        file = getattr(module, "__file__", None) or ""
        # helper modules only: other test modules' constants are not this test's values
        if file.startswith(tests_dir) and "/traffic/" not in file and not Path(file).name.startswith("test_"):
            for name, value in vars(module).items():
                if name.isupper():
                    add(name, value)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                and node is not docstring and id(node) not in templates:
            label = node.value if len(node.value) <= 28 else node.value[:27] + "…"
            out.append((f"“{label}”", node.value))
    return source, [(label, value) for label, value in out if not BASE_URL.fullmatch(value)]


def _request_texts(ex: Exchange) -> list:
    return [unquote(ex.url), ex.url, ex.req_body or ""] + [v for _, v in ex.req_headers]


def _sent_values(ex: Exchange) -> set:
    """Whole values a request carries: path, parameters, header and cookie values, form fields."""
    url = urlsplit(ex.url)
    sent = {url.path, _path(ex.url), ex.req_body or ""}
    sent.update(v for vs in parse_qs(url.query).values() for v in vs)
    sent.update(form(ex.req_body).values())
    for name, value in ex.req_headers:
        sent.add(value)
        if name.lower() == "cookie":
            for pair in value.split(";"):
                cname, _, cvalue = pair.strip().partition("=")
                sent.update((cname, cvalue))
    return sent


def _collect_values(rec, ordered) -> tuple:
    values = Values()
    source, test_values = _test_values(rec.item)
    # only what the test actually sends, as a whole value (not "state" in "state=...")
    sent = set().union(*(_sent_values(e) for _, kind, e, _ in ordered if kind == "req"))
    for label, value in test_values:
        if value in sent:
            first = next((anchor for _, kind, e, anchor in ordered if kind == "req" and value in _sent_values(e)), "")
            values.add(value, label, "test", first)

    def from_mapping(mapping, where, url=""):
        # Keycloak's login pages (/login-actions/...) carry their own parameters, not the OAuth ones
        internal = "/login-actions/" in urlsplit(url).path
        for key, value in mapping.items():
            if key in PROTOCOL_KEYS:
                values.add(value, f"Keycloak UI {key}" if internal else key, "protocol", where)

    def from_json(obj, where):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, (dict, list)):
                    from_json(value, where)
                elif key in PROTOCOL_KEYS:
                    values.add(value, key, "protocol", where)
        elif isinstance(obj, list):
            for value in obj:
                from_json(value, where)

    def from_headers(headers, where):
        for name, value in headers:
            lname = name.lower()
            if lname in ("set-cookie", "cookie"):
                for pair in value.split(";") if lname == "cookie" else value.split(";")[:1]:
                    cname, _, cvalue = pair.strip().partition("=")
                    if cname.startswith(SESSION_COOKIE_PREFIX):
                        values.add(cvalue, "session id", "protocol", where)
            elif lname == "authorization":
                scheme, _, credential = value.partition(" ")
                if scheme.lower() == "bearer":
                    values.add(credential, "access_token", "protocol", where)
                elif scheme.lower() == "basic":
                    values.add(credential, "client credentials", "protocol", where)
            elif lname == "location":
                from_mapping({k: v[0] for k, v in parse_qs(urlsplit(value).query).items()}, where, value)

    for _, kind, e, anchor in ordered:
        if kind == "req":
            from_mapping({k: v[0] for k, v in parse_qs(urlsplit(e.url).query).items()}, anchor, e.url)
            from_mapping(form(e.req_body), anchor)
            from_headers(e.req_headers, anchor)
        elif kind == "resp":
            from_headers(e.resp_headers, anchor)
            from_json(json_body(e.resp_body), anchor)
        elif kind == "note":
            for key, value in e.values.items():
                values.add(value, key.replace("_", " ") if key == "session_id" else key, "bff", anchor)
        elif kind == "fwd":
            from_headers(e.headers, anchor)
    values.finalize()
    return values, source


# -- timeline ---------------------------------------------------------------------

def _ordered(rec) -> list:
    """[(t, kind, event, anchor)] in time order; kinds: phase, req, note, fwd, resp."""
    items = []
    for e in rec.events:
        if isinstance(e, Exchange):
            items += [(e.t_start, 1, "req", e), (e.t_end, 3, "resp", e)]
        elif isinstance(e, Note):
            items.append((e.t, 2, "note", e))
        elif isinstance(e, Forward):
            items.append((e.t, 2, "fwd", e))
        elif isinstance(e, Phase):
            items.append((e.t, 0, "phase", e))
    items.sort(key=lambda i: (i[0], i[1]))
    out, numbers, n = [], {}, 0
    for t, _, kind, e in items:
        if kind in ("req", "note", "fwd"):
            n += 1
            numbers[id(e)] = n
        anchor = f"m{numbers[id(e)]}" if id(e) in numbers else ""
        out.append((t, kind, e, anchor))
    # drop phases without traffic
    keep = []
    for i, entry in enumerate(out):
        if entry[1] == "phase":
            nxt = next((o for o in out[i + 1:] if o[1] == "phase"), None)
            span = out[i + 1: out.index(nxt) if nxt else len(out)]
            if not span:
                continue
        keep.append(entry)
    return keep


# -- HTML pieces ------------------------------------------------------------------

def _lane_x(name: str, lanes: list) -> float:
    return (lanes.index(name) + 0.5) * 100 / len(lanes)


def _used_lanes(ordered) -> list:
    used = {"browser", "gw"}
    for _, kind, e, _ in ordered:
        if kind == "req":
            used |= {e.src, e.dst}
        elif kind == "fwd":
            used.add(e.dst)
        elif kind == "note":
            used.add(e.lane)
    return [k for k, _ in LANES if k in used]


def _path(url: str) -> str:
    u = urlsplit(url)
    return u.path + (f"?{u.query}" if u.query else "")


def _readable(url: str) -> str:
    """Path and query, percent-decoded, for diagram labels."""
    return unquote(_path(url))


def _refs(refs) -> str:
    links = []
    for ref in refs:
        url = ref_url(ref)
        links.append(f'<a class="ref" href="{esc(url)}" target="_blank" rel="noopener">{esc(ref)}</a>'
                     if url else f'<span class="ref">{esc(ref)}</span>')
    return " ".join(links)


def _annotations(items) -> str:
    if not items:
        return ""
    return '<ul class="notes">' + "".join(f"<li>{esc(text)} {_refs(refs)}</li>" for text, refs in items) + "</ul>"


def _arrow_row(V, lanes, anchor, n, src, dst, label, chips, dashed=False, cls="") -> str:
    a, b = _lane_x(src, lanes), _lane_x(dst, lanes)
    left, width = min(a, b), abs(b - a)
    direction = "r" if b > a else "l"
    # the label may be wider than the arrow, centered on it and kept inside the diagram
    text_width = max(width, 60)
    text_left = min(max(left + width / 2 - text_width / 2, 0), 100 - text_width)
    chip_html = "".join(V.chip(v) for v in chips[:8])
    return (f'<a class="row msg {cls}" href="#{anchor}" title="{esc(label)}">'
            f'<span class="arrow {direction}{" dashed" if dashed else ""}" style="left:{left}%;width:{width}%"></span>'
            f'<span class="lbl" style="left:{text_left}%;width:{text_width}%">'
            f'{f"<b>#{n}</b> " if n else ""}{V.hl(label)}</span>'
            f'<span class="chips" style="left:{text_left}%;width:{text_width}%">{chip_html}</span></a>')


def _response_label(ex: Exchange) -> str:
    if ex.error:
        return f"✕ {ex.error}"
    label = f"{ex.status} {ex.reason}".strip()
    location = header(ex.resp_headers, "location")
    if location:
        label += f" → {_readable(location[0])}"
    if header(ex.resp_headers, "set-cookie"):
        label += " · Set-Cookie"
    return label


def _diagram(V, ordered) -> str:
    # requests to another origin than the test's usual one show their host
    hosts = [urlsplit(e.url).netloc for _, kind, e, _ in ordered if kind == "req" and e.src == "browser"]
    main_host = max(set(hosts), key=hosts.count) if hosts else ""
    lanes = _used_lanes(ordered)
    rows = []
    for _, kind, e, anchor in ordered:
        n = anchor[1:] if anchor else ""
        if kind == "phase":
            rows.append(f'<div class="row phase"><span>{esc(e.name)}</span></div>')
        elif kind == "req":
            host = urlsplit(e.url).netloc
            label = f"{e.method} {'//' + host if e.src == 'browser' and host != main_host else ''}{_readable(e.url)}"
            chips = V.present(*_request_texts(e))
            rows.append(_arrow_row(V, lanes, anchor, n, e.src, e.dst, label, chips))
        elif kind == "resp":
            chips = V.present(e.resp_body or "", *[v for _, v in e.resp_headers])
            rows.append(_arrow_row(V, lanes, anchor, "", e.dst, e.src, _response_label(e), chips, dashed=True,
                                   cls="err" if e.error or (e.status or 0) >= 400 else ""))
        elif kind == "fwd":
            chips = V.present(*[v for _, v in e.headers])
            rows.append(_arrow_row(V, lanes, anchor, n, "gw", e.dst,
                                   f"{e.method} {e.path} + Authorization: Bearer …", chips))
        elif kind == "note":
            x = min(max(_lane_x(e.lane, lanes) - 11, 0), 53)
            chips = "".join(V.chip(v) for v in V.present(*e.values.values()))
            rows.append(f'<a class="row note" href="#{anchor}"><span class="notebox" style="left:{x}%">'
                        f'<b>#{n}</b> {esc(e.text)}<span class="chips-inline">{chips}</span></span></a>')
    lifelines = ",".join("linear-gradient(var(--lifeline),var(--lifeline))" for _ in lanes)
    positions = ",".join(f"{_lane_x(k, lanes)}% 0" for k in lanes)
    head = "".join(f'<div class="lane">{esc(dict(LANES)[k])}</div>' for k in lanes)
    return (f'<div class="seq"><div class="lanes" style="grid-template-columns:repeat({len(lanes)},1fr)">{head}</div>'
            f'<div class="rows" style="background-image:{lifelines};background-position:{positions}">'
            f'{"".join(rows)}</div></div>')


def _headers_table(V, headers) -> str:
    if not headers:
        return '<p class="muted">no headers recorded</p>'
    rows = "".join(f"<tr><th>{esc(k)}</th><td>{V.hl(v)}</td></tr>" for k, v in headers)
    return f'<table class="headers">{rows}</table>'


def _body(V, body, headers) -> str:
    if body is None:
        return '<p class="muted">no body recorded (the browser keeps none for redirects)</p>'
    if body == "":
        return '<p class="muted">empty body</p>'
    parsed = json_body(body)
    if parsed is not None:
        return f"<pre>{V.hl(json.dumps(parsed, indent=2))}</pre>"
    content_type = " ".join(header(headers, "content-type")).lower()
    fields = form(body) if "form" in content_type or not content_type else {}
    if fields:
        rows = "".join(f"<tr><th>{esc(k)}</th><td>{V.hl(v)}</td></tr>" for k, v in fields.items())
        return (f'<table class="headers form">{rows}</table>'
                f'<details class="raw"><summary>raw</summary><pre>{V.hl(body)}</pre></details>')
    if len(body) > MAX_BODY:
        return (f"<pre>{V.hl(body[:MAX_BODY])}</pre>"
                f'<p class="muted">… {len(body) - MAX_BODY} more characters</p>')
    return f"<pre>{V.hl(body)}</pre>"


def _b64_json(part: str):
    try:
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except ValueError:
        return None


def _extras(V, texts, req_form, req_headers) -> str:
    """Decoded JWTs and Basic credentials, the PKCE check."""
    out = []
    for token in dict.fromkeys(m.group(0) for t in texts for m in JWT.finditer(t or "")):
        head, payload = (_b64_json(p) for p in token.split(".")[:2])
        if payload is None:
            continue
        v = V.get(token)
        name = v.label if v else "JWT"
        times = "".join(
            f"<li><code>{k}</code> = {datetime.fromtimestamp(payload[k], timezone.utc):%Y-%m-%d %H:%M:%S} UTC</li>"
            for k in ("iat", "exp") if isinstance(payload.get(k), (int, float)))
        what = ""
        if v and v.base == "id_token":
            what = ("<p>The BFF checks the signature (key from jwks_uri, alg from the allowlist), "
                    f"<code>iss</code>, <code>aud</code>, <code>exp</code>, <code>iat</code> and <code>nonce</code>. "
                    f"{_refs(['OIDC Core 3.1.3.7'])}</p>")
        out.append(f'<div class="extra"><h5>Decoded {esc(name)} (JWT) {_refs(["RFC 7519"])}</h5>{what}'
                   f'<div class="cols"><pre>{V.hl(json.dumps(head, indent=2))}</pre>'
                   f'<pre>{V.hl(json.dumps(payload, indent=2))}</pre></div>'
                   f'{f"<ul>{times}</ul>" if times else ""}</div>')
    for value in header(req_headers, "authorization"):
        scheme, _, credential = value.partition(" ")
        if scheme.lower() == "basic":
            try:
                decoded = base64.b64decode(credential).decode()
            except ValueError:
                continue
            client_id, _, secret = decoded.partition(":")
            out.append(f'<div class="extra"><h5>Client authentication: client_secret_basic '
                       f'{_refs(["RFC 6749 2.3.1"])}</h5><p>BASE64(urlencode(client_id) ":" urlencode(secret)) '
                       f'decodes to <code>{V.hl(unquote(client_id))}</code> : <code>{V.hl(unquote(secret))}</code>'
                       "</p></div>")
    verifier = req_form.get("code_verifier")
    if verifier:
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        sent = V.get(challenge)
        verdict = (f"equals the <code>code_challenge</code> of the authorization request "
                   f'(<a href="#{sent.first}">#{sent.first[1:]}</a>) ✓') if sent and sent.first else \
            "the server compares it with the code_challenge it got in the authorization request"
        out.append(f'<div class="extra"><h5>PKCE check, done by the authorization server {_refs(["RFC 7636 4.6"])}'
                   f'</h5><p><code>BASE64URL(SHA256({V.hl(verifier)}))</code> = <code>{V.hl(challenge)}</code>, '
                   f"which {verdict}</p></div>")
    return "".join(out)


def _exchange_detail(V, ex: Exchange, anchor: str) -> str:
    lanes = dict(LANES)
    status = "✕" if ex.error else str(ex.status)
    req_form = form(ex.req_body)
    texts = [ex.req_body, ex.resp_body] + [v for _, v in ex.req_headers + ex.resp_headers]
    via = {"test": "requests (test as browser)", "browser": "Chromium (Playwright)",
           "bff": "the BFF's back channel", "keycloak": "Keycloak's back channel, recorded by the BFF",
           "service-a": "Service A's back channel", "service-b": "Service B's back channel"}[ex.source]
    timing = f"{(ex.t_end - ex.t_start) * 1000:.0f} ms"
    return (f'<details class="ex" id="{anchor}"><summary><b>#{anchor[1:]}</b> '
            f'<span class="who">{esc(lanes[ex.src])} → {esc(lanes[ex.dst])}</span> '
            f'{esc(ex.method)} {V.hl(_path(ex.url))} → <span class="st">{esc(status)}</span></summary>'
            f'{_annotations(annotate(ex))}'
            f'<p class="meta">via {via} · {timing}</p>'
            f'<div class="cols"><section><h4>Request</h4><pre class="line">{esc(ex.method)} {V.hl(ex.url)}</pre>'
            f'{_headers_table(V, ex.req_headers)}{_body(V, ex.req_body, ex.req_headers) if ex.req_body else ""}'
            f'</section><section><h4>Response</h4>'
            f'<pre class="line">{esc(ex.error) if ex.error else esc(f"{ex.status} {ex.reason}")}</pre>'
            f'{_headers_table(V, ex.resp_headers)}{"" if ex.error else _body(V, ex.resp_body, ex.resp_headers)}'
            f'</section></div>{_extras(V, texts, req_form, ex.req_headers)}</details>')


def _note_detail(V, note: Note, anchor: str) -> str:
    rows = "".join(f"<tr><th>{esc(k)}</th><td>{V.hl(v)}</td></tr>" for k, v in note.values.items())
    return (f'<details class="ex note" id="{anchor}"><summary><b>#{anchor[1:]}</b> '
            f'<span class="who">{esc(dict(LANES)[note.lane])}</span> {esc(note.text)}</summary>'
            f'<ul class="notes"><li>{esc(note.text)} {_refs(note.refs)}</li></ul>'
            f'{f"<table class=headers>{rows}</table>" if rows else ""}</details>')


def _forward_detail(V, fwd: Forward, anchor: str) -> str:
    removed = ", ".join(f"<code>{esc(h)}</code>" for h in fwd.removed) or "none"
    return (f'<details class="ex" id="{anchor}"><summary><b>#{anchor[1:]}</b> '
            f'<span class="who">Gateway · BFF → {esc(dict(LANES)[fwd.dst])}</span> {esc(fwd.method)} '
            f'{esc(fwd.path)} (forwarded)</summary>{_annotations(annotate_forward(fwd))}'
            '<p class="meta">Headers as the BFF hands the request back to APISIX. The route then strips the '
            '<code>/api/…</code> prefix (proxy-rewrite); the service\'s answer goes back to the browser '
            'unchanged.</p>'
            f'<h4>Forwarded request</h4>{_headers_table(V, fwd.headers)}<p>Removed: {removed}</p>'
            f'{_extras(V, [v for _, v in fwd.headers], {}, [])}</details>')


# -- pages ------------------------------------------------------------------------

def _page(title: str, body: str, css: str) -> str:
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width, initial-scale=1">'
            f'<title>{esc(title)}</title><link rel="stylesheet" href="{css}report.css"></head>'
            f'<body>{body}<script src="{css}report.js"></script></body></html>')


def _slug(nodeid: str, i: int) -> str:
    return f"{i:03d}-" + re.sub(r"[^A-Za-z0-9_.-]+", "_", nodeid.split("/")[-1])[:90] + ".html"


def _test_page(rec, slug) -> str:
    ordered = _ordered(rec)
    V, source = _collect_values(rec, ordered)
    doc = inspect.getdoc(rec.item.obj) or ""
    legend = "".join(
        f'<tr><td>{V.chip(v)}</td><td class="muted">{V.ORIGINS[v.origin]}</td>'
        f'<td>{f"<a href=#{v.first}>#{v.first[1:]}</a>" if v.first else ""}</td>'
        f'<td class="val">{V.mark(v, v.value if len(v.value) <= 90 else v.value[:89] + "…")}</td></tr>'
        for v in V.items)
    details = []
    for _, kind, e, anchor in ordered:
        if kind == "req":
            details.append(_exchange_detail(V, e, anchor))
        elif kind == "note":
            details.append(_note_detail(V, e, anchor))
        elif kind == "fwd":
            details.append(_forward_detail(V, e, anchor))
    failure = f'<h2>Failure</h2><pre class="failure">{esc(rec.longrepr)}</pre>' if rec.longrepr else ""
    body = (f'<header><a href="../index.html">Traffic report</a> / {esc(rec.nodeid.split("::")[0])}'
            f'<h1>{esc(rec.item.name)} <span class="badge {rec.outcome}">{rec.outcome}</span></h1>'
            f'{f"<p>{esc(doc)}</p>" if doc else ""}</header>'
            f'<details class="source" open><summary>Test source</summary><pre>{V.hl(source)}</pre></details>'
            f'{failure}'
            f'<h2>Sequence</h2><p class="muted">Click a message for its full content, a highlighted value to '
            f'follow it through the flow. Dashed: responses. Boxes: decisions of the BFF.</p>'
            f'{_diagram(V, ordered)}'
            f'<h2>Values</h2><table class="legend"><tr><th>name</th><th>kind</th><th>first</th><th>value</th></tr>'
            f'{legend}</table>'
            f'<h2>Messages</h2>{"".join(details)}')
    return _page(rec.item.name, body, "../")


def render(out_dir: Path, recordings) -> Path:
    pages = out_dir / "tests"
    shutil.rmtree(pages, ignore_errors=True)
    pages.mkdir(parents=True)
    (out_dir / "report.css").write_text(CSS)
    (out_dir / "report.js").write_text(JS)
    groups: dict = {}
    for i, rec in enumerate(recordings, 1):
        exchanges = [e for e in rec.events if isinstance(e, Exchange)]
        if not exchanges:
            continue
        slug = _slug(rec.nodeid, i)
        (pages / slug).write_text(_test_page(rec, slug))
        notes = sum(isinstance(e, Note) for e in rec.events)
        doc = (inspect.getdoc(rec.item.obj) or "").split("\n")[0]
        groups.setdefault(rec.nodeid.split("::")[0], []).append(
            f'<tr><td><a href="tests/{slug}">{esc(rec.nodeid.split("::", 1)[1])}</a>'
            f'{f"<div class=muted>{esc(doc)}</div>" if doc else ""}</td>'
            f'<td><span class="badge {rec.outcome}">{rec.outcome}</span></td>'
            f'<td class="num">{len(exchanges)}</td><td class="num">{notes}</td></tr>')
    sections = "".join(
        f'<h2>{esc(module)}</h2><table class="index"><tr><th>test</th><th>outcome</th>'
        f'<th class="num">messages</th><th class="num">BFF notes</th></tr>{"".join(rows)}</table>'
        for module, rows in groups.items())
    body = (f'<header><h1>Traffic report</h1>'
            f'<p>The HTTP traffic of each test as a sequence diagram: browser (Chromium or <code>requests</code> '
            f'acting as one), gateway with the BFF, Keycloak, and the two services behind the BFF. Every message links to its '
            f'full headers and body and to the RFC / OWASP sections it is an example of; the best practices '
            f'themselves are listed in <a href="../docs/oauth-best-practices.md">docs/oauth-best-practices.md</a>.'
            f'</p><p class="warn">Contains the dev stack\'s real codes, tokens and client secret. '
            f'Generated {datetime.now():%Y-%m-%d %H:%M}.</p></header>{sections}')
    index = out_dir / "index.html"
    index.write_text(_page("Traffic report", body, ""))
    return index


CSS = """
:root {
  color-scheme: light dark;
  --fg: #1d1d1f; --muted: #6b6b70; --bg: #f7f7f9; --card: #fff; --border: #dcdce2;
  --accent: #2f5bd3; --lifeline: #c9c9d2; --arrow: #3a3a40; --err: #b42318; --ok: #1a7f37; --warn: #9a6700;
  --note-bg: #fff8e6; --note-border: #e8c766; --code-bg: #f1f1f4;
}
@media (prefers-color-scheme: dark) {
  :root {
    --fg: #ececf0; --muted: #a0a0a8; --bg: #16161a; --card: #1f1f25; --border: #34343c;
    --accent: #8aa6ff; --lifeline: #45454f; --arrow: #d0d0d8; --err: #ff8a80; --ok: #6fdc8c; --warn: #f2cc60;
    --note-bg: #2e2816; --note-border: #7a6420; --code-bg: #26262d;
  }
}
* { box-sizing: border-box; }
body { margin: 0 auto; max-width: 1200px; padding: 1.5rem 1rem 4rem; background: var(--bg); color: var(--fg);
  font: 15px/1.5 system-ui, sans-serif; }
a { color: var(--accent); }
h1 { margin: 0.25rem 0; font-size: 1.5rem; }
h2 { margin-top: 2rem; font-size: 1.15rem; }
h4 { margin: 0.5rem 0 0.25rem; }
h5 { margin: 0 0 0.25rem; font-size: 0.9rem; }
pre, code { font: 12.5px/1.45 ui-monospace, SFMono-Regular, Menlo, monospace; }
pre { background: var(--code-bg); border: 1px solid var(--border); border-radius: 6px; padding: 0.6rem;
  overflow-x: auto; white-space: pre-wrap; overflow-wrap: anywhere; margin: 0.25rem 0; }
.muted, .meta { color: var(--muted); font-size: 0.875rem; }
.warn { color: var(--warn); font-size: 0.875rem; }
.badge { font-size: 0.75rem; padding: 0.1rem 0.5rem; border-radius: 99px; border: 1px solid; vertical-align: middle; }
.badge.passed { color: var(--ok); } .badge.failed, .badge.error { color: var(--err); } .badge.skipped { color: var(--muted); }
table { border-collapse: collapse; width: 100%; font-size: 0.875rem; }
th, td { text-align: left; vertical-align: top; padding: 0.3rem 0.5rem; border-bottom: 1px solid var(--border); }
td.num, th.num { text-align: right; }
table.headers th { white-space: nowrap; color: var(--muted); font-weight: 500; width: 1%; }
table.headers td { font: 12.5px/1.45 ui-monospace, monospace; overflow-wrap: anywhere; }
table.legend td.val { font: 12px/1.4 ui-monospace, monospace; overflow-wrap: anywhere; }
.index td:first-child { width: 70%; }

/* values */
mark.v, .chip { border-radius: 3px; cursor: pointer; color: inherit; }
mark.v { padding: 0 1px; }
.chip { display: inline-block; font-size: 11px; line-height: 16px; padding: 0 5px; margin: 0 2px 2px 0;
  white-space: nowrap; }
.focus-on mark.v:not(.focus), .focus-on .chip:not(.focus) { opacity: 0.35; }
mark.v.focus, .chip.focus { outline: 2px solid var(--fg); }
""" + "".join(
    f".c{i} {{ background: hsl({h} 85% 84%); }}\n"
    f"@media (prefers-color-scheme: dark) {{ .c{i} {{ background: hsl({h} 45% 30%); }} }}\n"
    for i, h in enumerate([210, 40, 130, 330, 270, 180, 10, 90, 300, 160, 240, 60])) + """

/* sequence diagram */
.seq { background: var(--card); border: 1px solid var(--border); border-radius: 8px; }
.lanes { display: grid; position: sticky; top: 0; z-index: 2;
  background: var(--card); border-bottom: 1px solid var(--border); border-radius: 8px 8px 0 0; }
.lane { text-align: center; font-weight: 600; font-size: 0.85rem; padding: 0.6rem 0.25rem; }
.rows { position: relative; background-repeat: no-repeat; background-size: 1px 100%; padding: 0.5rem 0; }
.row { display: block; position: relative; text-decoration: none; color: inherit; }
.row.msg { height: 54px; }
.row.msg:hover, .row.note:hover .notebox { background-color: color-mix(in srgb, var(--accent) 7%, transparent); }
.arrow { position: absolute; top: 24px; height: 0; border-top: 2px solid var(--arrow); }
.arrow.dashed { border-top-style: dashed; }
.row.err .arrow { border-top-color: var(--err); }
.arrow::after { content: ""; position: absolute; top: -7px; border: 6px solid transparent; }
.arrow.r::after { right: -2px; border-left: 9px solid var(--arrow); border-right: 0; }
.arrow.l::after { left: -2px; border-right: 9px solid var(--arrow); border-left: 0; }
.row.err .arrow.r::after { border-left-color: var(--err); }
.row.err .arrow.l::after { border-right-color: var(--err); }
.lbl { position: absolute; top: 3px; padding: 0 8px; text-align: center; font: 12px/18px ui-monospace, monospace;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.lbl b { font-family: system-ui, sans-serif; color: var(--muted); }
.chips { position: absolute; top: 30px; padding: 0 8px; text-align: center; white-space: nowrap; overflow: hidden; }
.row.note { padding: 4px 0; }
.notebox { position: relative; display: block; width: 47%; padding: 0.35rem 0.6rem; font-size: 12.5px;
  background: var(--note-bg); border: 1px solid var(--note-border); border-radius: 6px; }
.notebox b { color: var(--muted); }
.chips-inline { display: block; margin-top: 2px; }
.row.phase { border-top: 1px dashed var(--border); margin: 6px 0; height: 0; }
.row.phase span { position: absolute; left: 6px; top: -9px; font-size: 11px; color: var(--muted);
  background: var(--card); padding: 0 4px; text-transform: uppercase; letter-spacing: 0.05em; }

/* messages */
details.ex { background: var(--card); border: 1px solid var(--border); border-radius: 8px; margin: 0.5rem 0;
  padding: 0.4rem 0.8rem; scroll-margin-top: 1rem; }
details.ex > summary { cursor: pointer; font: 13px/1.6 ui-monospace, monospace; overflow-wrap: anywhere; }
details.ex > summary .who { font-family: system-ui, sans-serif; color: var(--muted); }
details.ex.note > summary { font-family: system-ui, sans-serif; }
details.ex:target { outline: 2px solid var(--accent); }
.cols { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
.cols > * { min-width: 0; }
@media (max-width: 800px) { .cols { grid-template-columns: 1fr; } .lane { font-size: 0.7rem; } }
ul.notes { margin: 0.5rem 0; padding-left: 1.2rem; font-size: 0.9rem; }
.ref { display: inline-block; font-size: 11px; padding: 0 5px; border: 1px solid var(--border); border-radius: 4px;
  text-decoration: none; margin: 1px 0; white-space: nowrap; }
.extra { border-top: 1px solid var(--border); margin-top: 0.75rem; padding-top: 0.5rem; font-size: 0.9rem; }
details.raw summary { cursor: pointer; font-size: 0.8rem; color: var(--muted); }
details.source { margin-top: 1rem; }
details.source summary { cursor: pointer; font-weight: 600; }
pre.failure { color: var(--err); }
"""

JS = """
// Click a highlighted value: dim everything else, click again to clear.
document.addEventListener("click", (e) => {
  const el = e.target.closest("mark.v, .chip");
  if (!el) return;
  e.preventDefault();
  e.stopPropagation();
  const v = el.dataset.v;
  const on = !el.classList.contains("focus");
  document.querySelectorAll("mark.v, .chip").forEach((m) => m.classList.toggle("focus", on && m.dataset.v === v));
  document.body.classList.toggle("focus-on", on);
}, true);

// Open the message a diagram row links to.
function openTarget() {
  const el = location.hash && document.getElementById(location.hash.slice(1));
  if (el && el.tagName === "DETAILS") el.open = true;
}
window.addEventListener("hashchange", openTarget);
openTarget();
"""
