from __future__ import annotations

import io
import json
from email.message import Message

import pytest

from hive_protocol.core import ProtocolError
from hive_protocol.product.shell_security import (
    BrowserSessionStore,
    expected_origin,
    read_bounded_json,
    security_headers,
    validate_bind_host,
    validate_host,
    validate_loopback_peer,
    validate_mutation_headers,
    validate_request_headers,
    validate_request_target,
)


SHA_A = "a" * 64


def test_bind_peer_and_host_require_exact_ip_loopback() -> None:
    assert validate_bind_host("127.0.0.1") == "127.0.0.1"
    assert validate_bind_host("::1") == "::1"
    for denied in ("localhost", "0.0.0.0", "::", "192.0.2.10", "example.test"):
        with pytest.raises(ProtocolError, match="WEB_BIND_DENIED"):
            validate_bind_host(denied)

    validate_loopback_peer("127.0.0.1")
    validate_loopback_peer("::1")
    for denied in ("192.0.2.10", "::ffff:192.0.2.10", "not-an-ip"):
        with pytest.raises(ProtocolError, match="WEB_PEER_DENIED"):
            validate_loopback_peer(denied)

    validate_host("127.0.0.1:8787", "127.0.0.1", 8787)
    validate_host("[::1]:8787", "::1", 8787)
    assert expected_origin("127.0.0.1", 8787) == "http://127.0.0.1:8787"
    assert expected_origin("::1", 8787) == "http://[::1]:8787"
    for denied in (
        "localhost:8787",
        "evil.example:8787",
        "127.0.0.1",
        "127.0.0.1:8788",
        "127.0.0.1:8787, evil.example",
    ):
        with pytest.raises(ProtocolError, match="WEB_HOST_DENIED"):
            validate_host(denied, "127.0.0.1", 8787)


def test_request_target_and_headers_are_bounded_and_rebinding_safe() -> None:
    validate_request_target("/api/search?q=bounded")
    for denied in (
        "http://evil.example/app",
        "//evil.example/app",
        "/app#fragment",
        "/app?token=secret-value",
        "/app?access_token=secret-value",
        "/" + ("x" * 2048),
    ):
        with pytest.raises(ProtocolError):
            validate_request_target(denied)

    headers = {"Host": "127.0.0.1:8787", "Sec-Fetch-Site": "same-origin"}
    validate_request_headers(
        headers,
        peer="127.0.0.1",
        bind_host="127.0.0.1",
        bind_port=8787,
        target="/app",
    )

    for site in ("cross-site", "same-site", "invalid"):
        changed = dict(headers, **{"Sec-Fetch-Site": site})
        with pytest.raises(ProtocolError, match="WEB_FETCH_SITE_DENIED"):
            validate_request_headers(
                changed,
                peer="127.0.0.1",
                bind_host="127.0.0.1",
                bind_port=8787,
                target="/app",
            )

    too_many = {f"X-Test-{index}": "value" for index in range(65)}
    too_many["Host"] = "127.0.0.1:8787"
    with pytest.raises(ProtocolError, match="WEB_HEADERS_LIMIT"):
        validate_request_headers(
            too_many,
            peer="127.0.0.1",
            bind_host="127.0.0.1",
            bind_port=8787,
            target="/app",
        )

    too_long = dict(headers, **{"X-Untrusted": "x" * ((8 * 1024) + 1)})
    with pytest.raises(ProtocolError, match="WEB_HEADERS_LIMIT"):
        validate_request_headers(
            too_long,
            peer="127.0.0.1",
            bind_host="127.0.0.1",
            bind_port=8787,
            target="/app",
        )

    duplicate_host = Message()
    duplicate_host["Host"] = "127.0.0.1:8787"
    duplicate_host["Host"] = "evil.example:8787"
    with pytest.raises(ProtocolError, match="WEB_HEADER_DUPLICATE"):
        validate_request_headers(
            duplicate_host,
            peer="127.0.0.1",
            bind_host="127.0.0.1",
            bind_port=8787,
            target="/app",
        )


def test_browser_sessions_are_opaque_bounded_expiring_and_memory_only() -> None:
    now = [100.0]
    sessions = BrowserSessionStore(
        ttl_seconds=30,
        max_sessions=2,
        clock=lambda: now[0],
    )
    first = sessions.create()
    cookie = sessions.cookie_header(first)
    assert cookie.startswith("HiveSession=")
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie
    assert "Path=/" in cookie
    assert "Secure" not in cookie
    assert "Max-Age" not in cookie
    assert first.session_id not in repr(sessions)
    assert sessions.authenticate(f"HiveSession={first.session_id}") == first

    with pytest.raises(ProtocolError, match="WEB_SESSION_INVALID"):
        sessions.authenticate("HiveSession=forged-session-value")

    sessions.create()
    with pytest.raises(ProtocolError, match="WEB_SESSION_LIMIT"):
        sessions.create()

    now[0] = 131.0
    with pytest.raises(ProtocolError, match="WEB_SESSION_EXPIRED"):
        sessions.authenticate(f"HiveSession={first.session_id}")
    assert sessions.count == 0
    sessions.clear()
    assert sessions.count == 0

    duplicate_cookie = Message()
    duplicate_cookie["Cookie"] = "HiveSession=first-session-value-that-is-long-enough"
    duplicate_cookie["Cookie"] = "HiveSession=second-session-value-that-is-long-enough"
    with pytest.raises(ProtocolError, match="WEB_HEADER_DUPLICATE"):
        sessions.authenticate_headers(duplicate_cookie)

    sessions.close()
    with pytest.raises(ProtocolError, match="WEB_SESSION_STORE_CLOSED"):
        sessions.create()


def _mutation_headers(session_id: str, csrf_token: str) -> dict[str, str]:
    return {
        "Host": "127.0.0.1:8787",
        "Cookie": f"HiveSession={session_id}",
        "Origin": "http://127.0.0.1:8787",
        "Sec-Fetch-Site": "same-origin",
        "Content-Type": "application/json",
        "X-Hive-CSRF": csrf_token,
        "X-Hive-Idempotency-Key": "operator-request-0001",
        "If-Match": SHA_A,
    }


def test_mutation_headers_require_session_origin_csrf_replay_and_version() -> None:
    sessions = BrowserSessionStore()
    session = sessions.create()
    headers = _mutation_headers(session.session_id, session.csrf_token)
    binding = validate_mutation_headers(
        headers,
        session=session,
        origin="http://127.0.0.1:8787",
    )
    assert binding.idempotency_key == "operator-request-0001"
    assert binding.expected_version == SHA_A

    mutations = {
        "Origin": "http://evil.example",
        "Sec-Fetch-Site": "cross-site",
        "Content-Type": "text/plain",
        "X-Hive-CSRF": "forged-csrf-token-value",
        "X-Hive-Idempotency-Key": "short",
        "If-Match": "*",
    }
    for name, value in mutations.items():
        changed = dict(headers)
        changed[name] = value
        with pytest.raises(ProtocolError):
            validate_mutation_headers(
                changed,
                session=session,
                origin="http://127.0.0.1:8787",
            )

    for name in (
        "Origin",
        "Sec-Fetch-Site",
        "Content-Type",
        "X-Hive-CSRF",
        "X-Hive-Idempotency-Key",
        "If-Match",
    ):
        changed = dict(headers)
        changed.pop(name)
        with pytest.raises(ProtocolError):
            validate_mutation_headers(
                changed,
                session=session,
                origin="http://127.0.0.1:8787",
            )

    with_bearer = dict(headers, Authorization="Bearer process-only-value")
    with pytest.raises(ProtocolError, match="WEB_MUTATION_BEARER_DENIED"):
        validate_mutation_headers(
            with_bearer,
            session=session,
            origin="http://127.0.0.1:8787",
        )


def test_json_reader_rejects_length_tricks_duplicates_nonfinite_and_depth() -> None:
    body = json.dumps({"safe": [1, 2, 3]}).encode("utf-8")
    assert read_bounded_json(
        io.BytesIO(body), {"Content-Length": str(len(body))}
    ) == {"safe": [1, 2, 3]}

    duplicate = b'{"same":1,"same":2}'
    invalid_cases = (
        (duplicate, {"Content-Length": str(len(duplicate))}),
        (b'{"value":NaN}', {"Content-Length": "13"}),
        (b"{}", {}),
        (b"{}", {"Content-Length": "invalid"}),
        (b"{}", {"Content-Length": "2", "Transfer-Encoding": "chunked"}),
        (b"{}", {"Content-Length": str((1024 * 1024) + 1)}),
    )
    for payload, headers in invalid_cases:
        with pytest.raises(ProtocolError):
            read_bounded_json(io.BytesIO(payload), headers)

    nested: dict[str, object] = {}
    current = nested
    for _ in range(14):
        child: dict[str, object] = {}
        current["child"] = child
        current = child
    deep = json.dumps(nested).encode("utf-8")
    with pytest.raises(ProtocolError, match="WEB_JSON_DEPTH"):
        read_bounded_json(
            io.BytesIO(deep), {"Content-Length": str(len(deep))}
        )


def test_every_response_header_is_fail_closed_without_inline_permissions() -> None:
    headers = security_headers()
    assert headers["Cache-Control"] == "no-store"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert headers["Cross-Origin-Resource-Policy"] == "same-origin"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Permissions-Policy"]
    assert "unsafe-inline" not in headers["Content-Security-Policy"]
    for directive in (
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
        "form-action 'self'",
    ):
        assert directive in headers["Content-Security-Policy"]
