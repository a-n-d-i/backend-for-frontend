"""The traffic report's building blocks (tests/traffic), without a gateway."""
from tests.traffic.recorder import Exchange, Recording, _fix_redirect_timing
from tests.traffic.report import Values, _sent_values
from tests.traffic.specs import annotate, ref_url


def exchange(url, method="GET", req_headers=(), req_body=None, status=200, resp_headers=(), resp_body="",
             source="test", src="browser", dst="gw", t_start=0.0, t_end=1.0):
    return Exchange(source, src, dst, method, url, list(req_headers), req_body, status, "",
                    list(resp_headers), resp_body, t_start, t_end)


def test_values_are_highlighted_raw_and_url_encoded():
    values = Values()
    values.add("http://localhost:9080/bff/callback", "redirect_uri", "protocol")
    values.add("abc123", "state", "protocol")
    values.finalize()

    out = values.hl("redirect_uri=http%3A%2F%2Flocalhost%3A9080%2Fbff%2Fcallback&state=abc123")

    assert out.count("<mark") == 2
    assert 'title="redirect_uri · protocol value"' in out
    assert 'title="state · protocol value"' in out


def test_values_get_numbered_labels_per_name():
    values = Values()
    for v in ("first-state", "second-state"):
        values.add(v, "state", "protocol")
    values.add("only-nonce", "nonce", "protocol")
    values.finalize()

    assert [v.label for v in values.items] == ["state #1", "state #2", "nonce"]


def test_short_and_duplicate_values_are_ignored():
    values = Values()
    values.add("abc", "x", "test")
    values.add("abcd", "first", "test")
    values.add("abcd", "second", "protocol")
    values.finalize()

    assert [v.label for v in values.items] == ["first"]


def test_highlighting_escapes_html():
    values = Values()
    values.add("<b>v</b>", "x", "test")
    values.finalize()

    assert values.hl("a <b>v</b> <i>") == 'a <mark class="v c0" data-v="0" title="x · used by the test">' \
                                          "&lt;b&gt;v&lt;/b&gt;</mark> &lt;i&gt;"


def test_sent_values_are_whole_values_not_substrings():
    ex = exchange("http://h/bff/login?return_to=/somewhere%3Ftab%3D2",
                  req_headers=[("Cookie", "a=1; __Host-x=sid"), ("X-BFF-CSRF", "1")],
                  req_body="login=admin%40example.com&password=pw")

    sent = _sent_values(ex)

    assert {"/somewhere?tab=2", "/bff/login", "__Host-x", "sid", "admin@example.com", "pw"} <= sent
    assert "return_to" not in sent and "state" not in sent


def test_redirect_hop_ends_where_the_browser_follows_it():
    rec = Recording(item=None, trace_id="T1")
    first = exchange("http://h/bff/login", status=302, resp_headers=[("Location", "/dex/auth?x=1")],
                     source="browser", t_start=1.0, t_end=1.5)
    second = exchange("http://h/dex/auth?x=1", source="browser", t_start=1.4, t_end=2.0)
    rec.events += [first, second]

    _fix_redirect_timing(rec)

    assert first.t_end < second.t_start


def test_ref_urls():
    assert ref_url("RFC 7636 4.2") == "https://www.rfc-editor.org/rfc/rfc7636#section-4.2"
    assert ref_url("RFC 9207") == "https://www.rfc-editor.org/rfc/rfc9207"
    assert ref_url("BBA 6.1.3.2").endswith("draft-ietf-oauth-browser-based-apps-27#section-6.1.3.2")
    assert ref_url("OIDC Core 3.1.3.7").endswith("#IDTokenValidation")
    assert ref_url("OWASP CSRF").startswith("https://cheatsheetseries.owasp.org/")
    assert ref_url("OIDC BCL 2.6") == "https://openid.net/specs/openid-connect-backchannel-1_0.html"


def refs_of(ex):
    return {ref for _, refs in annotate(ex) for ref in refs}


def test_authorization_request_redirect_is_annotated():
    ex = exchange("http://h/bff/login", status=302, resp_headers=[
        ("Location", "http://h/dex/auth?response_type=code&state=s&nonce=n&code_challenge=c"),
        ("Set-Cookie", "__Host-Http-bff-session=x; Path=/; Secure; HttpOnly; SameSite=Lax")])

    refs = refs_of(ex)

    assert {"BBA 6.1.2.1", "RFC 7636 4.3", "RFC 6749 4.1.1", "BBA 6.1.3.2"} <= refs


def test_token_request_is_annotated():
    ex = exchange("https://auth.example.test/realms/demo/protocol/openid-connect/token", method="POST",
                  source="bff", src="gw", dst="keycloak",
                  req_body="grant_type=authorization_code&code=c&redirect_uri=r&code_verifier=v",
                  resp_body='{"access_token": "a", "token_type": "bearer"}')

    assert {"RFC 6749 4.1.3", "RFC 7636 4.5", "RFC 6749 2.3.1", "RFC 6749 5.1"} <= refs_of(ex)


def test_token_exchange_is_annotated():
    ex = exchange("https://auth.example.test/realms/demo/protocol/openid-connect/token", method="POST",
                  source="bff", src="gw", dst="keycloak",
                  req_body="grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&audience=service-a",
                  resp_body='{"access_token": "a", "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"}')

    assert {"RFC 8693 2.1", "RFC 8693 2.2.1", "RFC 9700 2.3"} <= refs_of(ex)


def test_service_rejection_is_annotated():
    ex = exchange("http://service-b:7002/whoami", src="gw", dst="service-b", status=401,
                  resp_headers=[("WWW-Authenticate", 'Bearer error="invalid_token"')])

    assert "RFC 6750 3.1" in refs_of(ex)


def test_back_channel_logout_is_annotated():
    ex = exchange("https://app.example.test/bff/backchannel-logout", method="POST", source="keycloak",
                  src="keycloak", dst="gw", req_body="logout_token=x")

    assert {"OIDC BCL 2.5", "OIDC BCL 2.6"} <= refs_of(ex)


def test_csrf_refusal_is_annotated():
    ex = exchange("http://h/api/headers", status=403, resp_body='{"error": "csrf_check_failed"}')

    assert "BBA 6.1.3.3" in refs_of(ex)
