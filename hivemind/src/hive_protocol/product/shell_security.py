"""Fail-closed loopback, browser-session, and request security for M4."""

from __future__ import annotations

import ipaddress
import json
import math
import re
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, BinaryIO, Callable, Mapping
from urllib.parse import parse_qsl, urlsplit

from hive_protocol.core import ProtocolError


SESSION_COOKIE_NAME = "HiveSession"
MAX_HEADER_COUNT = 64
MAX_HEADER_BYTES = 32 * 1024
MAX_HEADER_VALUE_BYTES = 8 * 1024
MAX_REQUEST_TARGET_BYTES = 2048
MAX_JSON_BODY_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 12
MAX_SESSIONS = 64
SESSION_TTL_SECONDS = 8 * 60 * 60

_OPAQUE_TOKEN = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9._:-]{16,128}$")
_OBJECT_VERSION = re.compile(r"^[a-f0-9]{64}$")
_CONTENT_LENGTH = re.compile(r"^(?:0|[1-9][0-9]*)$")
_SENSITIVE_QUERY_KEYS = frozenset(
    {"access_token", "authorization", "bearer", "csrf", "secret", "token"}
)


@dataclass(frozen=True)
class BrowserSession:
    session_id: str
    csrf_token: str
    created_at: float
    expires_at: float


@dataclass(frozen=True)
class MutationBinding:
    idempotency_key: str
    expected_version: str


def validate_bind_host(host: str) -> str:
    if host not in {"127.0.0.1", "::1"}:
        raise ProtocolError(
            "WEB_BIND_DENIED", "operator shell bind must be an explicit loopback IP"
        )
    return host


def validate_loopback_peer(peer: str) -> None:
    try:
        address = ipaddress.ip_address(peer)
    except ValueError as exc:
        raise ProtocolError(
            "WEB_PEER_DENIED", "request peer is not a loopback IP"
        ) from exc
    if not address.is_loopback:
        raise ProtocolError("WEB_PEER_DENIED", "request peer is not loopback")


def _host_port(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def expected_origin(host: str, port: int) -> str:
    validate_bind_host(host)
    return f"http://{_host_port(host, port)}"


def validate_host(value: str, bind_host: str, bind_port: int) -> None:
    if not secrets.compare_digest(value, _host_port(bind_host, bind_port)):
        raise ProtocolError(
            "WEB_HOST_DENIED", "Host must match the bound loopback listener"
        )


def _header_values(headers: Mapping[str, Any], name: str) -> list[str]:
    getter = getattr(headers, "get_all", None)
    if callable(getter):
        values = getter(name, [])
        return [str(value) for value in values]
    value = headers.get(name)
    if value is None:
        lowered = name.lower()
        for key, candidate in headers.items():
            if str(key).lower() == lowered:
                value = candidate
                break
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return [str(value)]


def _single_header(
    headers: Mapping[str, Any],
    name: str,
    *,
    required: bool = False,
    missing_code: str = "WEB_HEADER_REQUIRED",
) -> str:
    values = _header_values(headers, name)
    if len(values) > 1:
        raise ProtocolError("WEB_HEADER_DUPLICATE", f"duplicate {name} header")
    if not values or not values[0]:
        if required:
            raise ProtocolError(missing_code, f"{name} header is required")
        return ""
    return values[0]


def validate_request_target(target: str) -> None:
    try:
        encoded = target.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ProtocolError(
            "WEB_TARGET_INVALID", "request target must be ASCII"
        ) from exc
    if (
        not target.startswith("/")
        or target.startswith("//")
        or "\\" in target
        or any(ord(character) < 32 or ord(character) == 127 for character in target)
    ):
        raise ProtocolError("WEB_TARGET_INVALID", "request target is not origin-form")
    if len(encoded) > MAX_REQUEST_TARGET_BYTES:
        raise ProtocolError("WEB_TARGET_LIMIT", "request target is too long")
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        raise ProtocolError("WEB_TARGET_INVALID", "request target is not origin-form")
    try:
        query = parse_qsl(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=False,
            max_num_fields=64,
        )
    except ValueError as exc:
        raise ProtocolError("WEB_QUERY_INVALID", "query is invalid or excessive") from exc
    if any(name.lower() in _SENSITIVE_QUERY_KEYS for name, _ in query):
        raise ProtocolError(
            "WEB_QUERY_SECRET_DENIED", "credentials and tokens are forbidden in URLs"
        )


def validate_request_headers(
    headers: Mapping[str, Any],
    *,
    peer: str,
    bind_host: str,
    bind_port: int,
    target: str,
) -> None:
    validate_bind_host(bind_host)
    validate_loopback_peer(peer)
    validate_request_target(target)
    items = [(str(key), str(value)) for key, value in headers.items()]
    if len(items) > MAX_HEADER_COUNT:
        raise ProtocolError("WEB_HEADERS_LIMIT", "too many request headers")
    total = 0
    for name, value in items:
        try:
            name_bytes = name.encode("ascii")
            value_bytes = value.encode("latin-1")
        except UnicodeEncodeError as exc:
            raise ProtocolError(
                "WEB_HEADER_INVALID", "request headers contain invalid characters"
            ) from exc
        if (
            not name
            or any(byte < 33 or byte > 126 for byte in name_bytes)
            or any(byte < 32 and byte != 9 for byte in value_bytes)
            or 127 in value_bytes
        ):
            raise ProtocolError(
                "WEB_HEADER_INVALID", "request headers contain invalid characters"
            )
        if len(value_bytes) > MAX_HEADER_VALUE_BYTES:
            raise ProtocolError("WEB_HEADERS_LIMIT", "request header is too long")
        total += len(name_bytes) + len(value_bytes) + 4
    if total > MAX_HEADER_BYTES:
        raise ProtocolError("WEB_HEADERS_LIMIT", "request headers are too large")

    host = _single_header(headers, "Host", required=True)
    validate_host(host, bind_host, bind_port)
    fetch_site = _single_header(headers, "Sec-Fetch-Site")
    if fetch_site and fetch_site not in {"none", "same-origin"}:
        raise ProtocolError(
            "WEB_FETCH_SITE_DENIED", "cross-site and same-site requests are refused"
        )
    origin = _single_header(headers, "Origin")
    if origin and not secrets.compare_digest(
        origin, expected_origin(bind_host, bind_port)
    ):
        raise ProtocolError("WEB_ORIGIN_DENIED", "request origin is not exact")


class BrowserSessionStore:
    """A bounded, process-memory-only browser session collection."""

    def __init__(
        self,
        *,
        ttl_seconds: int = SESSION_TTL_SECONDS,
        max_sessions: int = MAX_SESSIONS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if ttl_seconds < 1 or max_sessions < 1:
            raise ValueError("session bounds must be positive")
        self._ttl_seconds = ttl_seconds
        self._max_sessions = max_sessions
        self._clock = clock
        self._sessions: dict[str, BrowserSession] = {}
        self._lock = threading.Lock()
        self._closed = False

    def __repr__(self) -> str:
        return f"BrowserSessionStore(count={self.count})"

    def _purge_expired_locked(self, now: float) -> None:
        expired = [
            session_id
            for session_id, session in self._sessions.items()
            if now >= session.expires_at
        ]
        for session_id in expired:
            self._sessions.pop(session_id, None)

    @property
    def count(self) -> int:
        with self._lock:
            self._purge_expired_locked(self._clock())
            return len(self._sessions)

    def create(self) -> BrowserSession:
        with self._lock:
            if self._closed:
                raise ProtocolError(
                    "WEB_SESSION_STORE_CLOSED", "browser session store is closed"
                )
            now = self._clock()
            self._purge_expired_locked(now)
            if len(self._sessions) >= self._max_sessions:
                raise ProtocolError(
                    "WEB_SESSION_LIMIT", "browser session limit reached"
                )
            for _ in range(8):
                session_id = secrets.token_urlsafe(32)
                if session_id not in self._sessions:
                    break
            else:  # pragma: no cover - cryptographic collision protection
                raise ProtocolError(
                    "WEB_SESSION_RANDOM_FAILURE", "could not allocate a browser session"
                )
            session = BrowserSession(
                session_id=session_id,
                csrf_token=secrets.token_urlsafe(32),
                created_at=now,
                expires_at=now + self._ttl_seconds,
            )
            self._sessions[session_id] = session
            return session

    def cookie_header(self, session: BrowserSession) -> str:
        return (
            f"{SESSION_COOKIE_NAME}={session.session_id}; "
            "HttpOnly; SameSite=Strict; Path=/"
        )

    def authenticate(self, cookie_header: str) -> BrowserSession:
        values = []
        for part in cookie_header.split(";"):
            name, separator, value = part.strip().partition("=")
            if separator and name == SESSION_COOKIE_NAME:
                values.append(value)
        if not values:
            raise ProtocolError("WEB_SESSION_REQUIRED", "browser session is required")
        if len(values) != 1 or _OPAQUE_TOKEN.fullmatch(values[0]) is None:
            raise ProtocolError("WEB_SESSION_INVALID", "browser session is invalid")
        supplied = values[0]
        with self._lock:
            if self._closed:
                raise ProtocolError(
                    "WEB_SESSION_STORE_CLOSED", "browser session store is closed"
                )
            now = self._clock()
            matched: BrowserSession | None = None
            for session_id, session in self._sessions.items():
                if secrets.compare_digest(session_id, supplied):
                    matched = session
            if matched is None:
                self._purge_expired_locked(now)
                raise ProtocolError("WEB_SESSION_INVALID", "browser session is invalid")
            if now >= matched.expires_at:
                self._sessions.pop(matched.session_id, None)
                self._purge_expired_locked(now)
                raise ProtocolError("WEB_SESSION_EXPIRED", "browser session expired")
            return matched

    def authenticate_headers(self, headers: Mapping[str, Any]) -> BrowserSession:
        return self.authenticate(
            _single_header(
                headers,
                "Cookie",
                required=True,
                missing_code="WEB_SESSION_REQUIRED",
            )
        )

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._sessions.clear()


class BrowserLaunchHandoff:
    """Issue one browser session from one process-memory launch secret."""

    _PATH_PREFIX = "/_hive/launch/"

    def __init__(self, token: str | None = None) -> None:
        launch_token = token or secrets.token_urlsafe(32)
        if _OPAQUE_TOKEN.fullmatch(launch_token) is None:
            raise ValueError("browser launch token is invalid")
        self._token: str | None = launch_token
        self._lock = threading.Lock()
        self._closed = False

    def __repr__(self) -> str:
        with self._lock:
            state = "closed" if self._closed else "available" if self._token else "consumed"
        return f"BrowserLaunchHandoff(state={state})"

    @property
    def path(self) -> str:
        with self._lock:
            if self._closed or self._token is None:
                raise ProtocolError(
                    "WEB_LAUNCH_INVALID", "browser launch handoff is unavailable"
                )
            return f"{self._PATH_PREFIX}{self._token}"

    def issue(
        self, path: str, sessions: BrowserSessionStore
    ) -> BrowserSession:
        candidate = path.removeprefix(self._PATH_PREFIX)
        if (
            not path.startswith(self._PATH_PREFIX)
            or not candidate
            or "/" in candidate
            or _OPAQUE_TOKEN.fullmatch(candidate) is None
        ):
            raise ProtocolError(
                "WEB_LAUNCH_INVALID", "browser launch handoff is invalid"
            )
        with self._lock:
            if (
                self._closed
                or self._token is None
                or not secrets.compare_digest(candidate, self._token)
            ):
                raise ProtocolError(
                    "WEB_LAUNCH_INVALID", "browser launch handoff is invalid"
                )
            session = sessions.create()
            self._token = None
            return session

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._token = None


def session_cookie_present(headers: Mapping[str, Any]) -> bool:
    cookie = _single_header(headers, "Cookie")
    return any(
        part.strip().partition("=")[0] == SESSION_COOKIE_NAME
        for part in cookie.split(";")
    )


def validate_mutation_headers(
    headers: Mapping[str, Any],
    *,
    session: BrowserSession,
    origin: str,
) -> MutationBinding:
    if _single_header(headers, "Authorization"):
        raise ProtocolError(
            "WEB_MUTATION_BEARER_DENIED",
            "process bearer authentication is read-only",
        )
    supplied_origin = _single_header(
        headers,
        "Origin",
        required=True,
        missing_code="WEB_ORIGIN_REQUIRED",
    )
    if not secrets.compare_digest(supplied_origin, origin):
        raise ProtocolError("WEB_ORIGIN_DENIED", "request origin is not exact")
    if _single_header(headers, "Sec-Fetch-Site", required=True) != "same-origin":
        raise ProtocolError(
            "WEB_FETCH_SITE_DENIED", "browser mutations must be same-origin"
        )
    if _single_header(headers, "Content-Type", required=True) != "application/json":
        raise ProtocolError(
            "WEB_MEDIA_TYPE_DENIED", "browser mutations require application/json"
        )
    csrf = _single_header(
        headers,
        "X-Hive-CSRF",
        required=True,
        missing_code="WEB_CSRF_REQUIRED",
    )
    if not secrets.compare_digest(csrf, session.csrf_token):
        raise ProtocolError("WEB_CSRF_DENIED", "CSRF token is invalid")
    idempotency_key = _single_header(
        headers,
        "X-Hive-Idempotency-Key",
        required=True,
        missing_code="WEB_IDEMPOTENCY_REQUIRED",
    )
    if _IDEMPOTENCY_KEY.fullmatch(idempotency_key) is None:
        raise ProtocolError(
            "WEB_IDEMPOTENCY_INVALID", "idempotency key is invalid"
        )
    expected_version = _single_header(
        headers,
        "If-Match",
        required=True,
        missing_code="WEB_PRECONDITION_REQUIRED",
    )
    if expected_version != "ABSENT" and _OBJECT_VERSION.fullmatch(
        expected_version
    ) is None:
        raise ProtocolError(
            "WEB_PRECONDITION_INVALID", "If-Match object version is invalid"
        )
    return MutationBinding(
        idempotency_key=idempotency_key,
        expected_version=expected_version,
    )


def is_bearer_authenticated(headers: Mapping[str, Any], access_token: str) -> bool:
    authorization = _single_header(headers, "Authorization")
    if not authorization.startswith("Bearer "):
        return False
    return secrets.compare_digest(authorization[7:], access_token)


def require_direct_navigation(headers: Mapping[str, Any]) -> None:
    if _single_header(headers, "Sec-Fetch-Site", required=True) not in {
        "none",
        "same-origin",
    }:
        raise ProtocolError(
            "WEB_FETCH_SITE_DENIED", "application navigation must be direct"
        )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("WEB_JSON_DUPLICATE_KEY", "JSON keys must be unique")
        result[key] = value
    return result


def _reject_json_constant(_: str) -> None:
    raise ProtocolError("WEB_JSON_NONFINITE", "JSON numbers must be finite")


def _validate_json_bounds(value: Any, *, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ProtocolError("WEB_JSON_DEPTH", "JSON nesting is excessive")
    if isinstance(value, Mapping):
        if len(value) > 128:
            raise ProtocolError("WEB_JSON_LIMIT", "JSON object has too many fields")
        for child in value.values():
            _validate_json_bounds(child, depth=depth + 1)
        return
    if isinstance(value, list):
        if len(value) > 1024:
            raise ProtocolError("WEB_JSON_LIMIT", "JSON array has too many items")
        for child in value:
            _validate_json_bounds(child, depth=depth + 1)
        return
    if isinstance(value, float) and not math.isfinite(value):
        raise ProtocolError("WEB_JSON_NONFINITE", "JSON numbers must be finite")


def read_bounded_json(
    stream: BinaryIO,
    headers: Mapping[str, Any],
    *,
    max_bytes: int = MAX_JSON_BODY_BYTES,
) -> dict[str, Any]:
    if _single_header(headers, "Transfer-Encoding"):
        raise ProtocolError(
            "WEB_TRANSFER_ENCODING_DENIED", "transfer encoding is not supported"
        )
    length_value = _single_header(
        headers,
        "Content-Length",
        required=True,
        missing_code="WEB_CONTENT_LENGTH_REQUIRED",
    )
    if _CONTENT_LENGTH.fullmatch(length_value) is None:
        raise ProtocolError("WEB_CONTENT_LENGTH_INVALID", "Content-Length is invalid")
    length = int(length_value)
    if length < 2 or length > max_bytes:
        raise ProtocolError("WEB_BODY_LIMIT", "JSON body length is outside bounds")
    payload = stream.read(length)
    if len(payload) != length:
        raise ProtocolError("WEB_BODY_TRUNCATED", "JSON body is truncated")
    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except ProtocolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("WEB_JSON_INVALID", "request body is not valid JSON") from exc
    if not isinstance(document, dict):
        raise ProtocolError("WEB_JSON_INVALID", "request body must be a JSON object")
    _validate_json_bounds(document)
    return document


def security_headers() -> dict[str, str]:
    return {
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "X-Frame-Options": "DENY",
        "Permissions-Policy": (
            "accelerometer=(), camera=(), geolocation=(), microphone=(), "
            "payment=(), usb=()"
        ),
        "Content-Security-Policy": (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self'; connect-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        ),
    }
