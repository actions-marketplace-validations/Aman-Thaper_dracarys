"""Unit tests for the deterministic scanner oracles."""
from dracarys.scanner.oracles import (
    boolean_divergence,
    cors_permissive,
    find_secrets,
    reflects_unencoded,
    sql_error_signature,
    stack_trace_signature,
    template_evaluated,
    time_delayed,
    traversal_signature,
)
from dracarys.tools.base import HttpExchange, ToolStatus


def _ex(body="", status=200, ctype="text/html", elapsed=10):
    return HttpExchange(
        status=ToolStatus.OK, body_text=body,
        response={"status_code": status, "headers": {"content-type": ctype}},
        elapsed_ms=elapsed,
    )


def test_sql_error_signatures():
    assert sql_error_signature("near \"x\": syntax error")
    assert sql_error_signature("You have an error in your SQL syntax near MySQL")
    assert sql_error_signature("PostgreSQL query failed: ERROR")
    assert sql_error_signature("totally normal response") is None


def test_secret_detection():
    assert any("AWS" in lbl for lbl, _ in find_secrets("id=AKIAIOSFODNN7EXAMPLE"))
    assert any("JSON Web Token" in lbl for lbl, _ in find_secrets(
        "t=eyJhbGciOiJIUzI1NiJ9.eyJ1IjoiYSJ9.c2lnbmF0dXJlc2FtcGxlMTIzNDU2"))
    assert find_secrets("nothing to see") == []


def test_stack_trace():
    assert stack_trace_signature("Traceback (most recent call last): ...")
    assert stack_trace_signature("all good") is None


def test_reflects_unencoded_only_in_html():
    marker = "dcrsXYZ<svg/onload=1>"
    assert reflects_unencoded(marker, _ex(body=f"hello {marker} world"))
    # encoded reflection is NOT a finding
    assert not reflects_unencoded(marker, _ex(body="hello dcrsXYZ&lt;svg/onload=1&gt;"))
    # JSON reflection is not XSS
    assert not reflects_unencoded(marker, _ex(body=marker, ctype="application/json"))


def test_boolean_divergence():
    base = _ex(body="rows: apple, apricot")
    truthy = _ex(body="rows: apple, apricot")     # same as baseline
    falsy = _ex(body="rows:")                       # empty
    assert boolean_divergence(base, truthy, falsy)
    # no divergence when all identical
    assert not boolean_divergence(base, base, base)


def test_time_delayed():
    assert time_delayed(20, 3100, 3)       # ~3s delay over 20ms control
    assert not time_delayed(20, 60, 3)     # fast response, no delay


def test_traversal_signature():
    assert traversal_signature("root:x:0:0:root:/root:/bin/bash")
    assert traversal_signature("daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
    assert traversal_signature("[extensions]\nmci=\n")           # win.ini
    # A page that merely mentions the file is not proof it was read.
    assert traversal_signature("could not open /etc/passwd") is None
    assert traversal_signature("not found") is None


def test_template_evaluated_requires_server_side_evaluation():
    payload = "{{191*7}}"
    assert template_evaluated("1337", payload, _ex(body="<p>Hello, 1337!</p>"))
    # Reflected but NOT evaluated — the literal payload survives, so it is not SSTI.
    assert not template_evaluated("1337", payload, _ex(body=f"<p>Hello, {payload}!</p>"))
    # Neither evaluated nor reflected.
    assert not template_evaluated("1337", payload, _ex(body="<p>Hello, friend!</p>"))


def _cors_ex(**headers):
    return HttpExchange(
        status=ToolStatus.OK, body_text="{}",
        response={"status_code": 200, "headers": {"content-type": "application/json", **headers}},
        elapsed_ms=10,
    )


def test_cors_permissive():
    evil = "https://dcrs-evil.example"
    # Reflected origin + credentials: readable authenticated response.
    assert cors_permissive(evil, _cors_ex(**{
        "access-control-allow-origin": evil,
        "access-control-allow-credentials": "true"}))
    # 'null' origin with credentials is equally exploitable.
    assert cors_permissive(evil, _cors_ex(**{
        "access-control-allow-origin": "null",
        "access-control-allow-credentials": "true"}))
    # Wildcard WITHOUT credentials is normal for public APIs — never reported.
    assert cors_permissive(evil, _cors_ex(**{"access-control-allow-origin": "*"})) is None
    # A trusted origin that is not ours, even with credentials.
    assert cors_permissive(evil, _cors_ex(**{
        "access-control-allow-origin": "https://app.example.com",
        "access-control-allow-credentials": "true"})) is None
    # Reflected origin but no credentials: cannot read an authenticated response.
    assert cors_permissive(evil, _cors_ex(**{"access-control-allow-origin": evil})) is None
    # No CORS headers at all.
    assert cors_permissive(evil, _cors_ex()) is None
