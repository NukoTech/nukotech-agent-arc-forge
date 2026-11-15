"""Bounded, read-compatible loopback application server for a local Hive."""

from __future__ import annotations

import hashlib
import json
import secrets
import socket
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Mapping
from urllib.parse import parse_qs, parse_qsl, urlparse
from uuid import uuid4

from hive_protocol.core import ProtocolError

from .api import OperatorAPI
from .shell_service import ShellService
from .shell_views import (
    PAGE_DEFINITIONS,
    read_static_asset,
    render_shell_page,
    resolve_app_page,
)
from .shell_contracts import OperatorResponse, route_for
from .shell_security import (
    BrowserLaunchHandoff,
    BrowserSession,
    BrowserSessionStore,
    MAX_JSON_BODY_BYTES,
    expected_origin,
    is_bearer_authenticated,
    read_bounded_json,
    require_direct_navigation,
    security_headers,
    session_cookie_present,
    validate_bind_host,
    validate_mutation_headers,
    validate_request_headers,
)
from .workspace import HiveWorkspace


def _json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _error_status(code: str) -> HTTPStatus:
    if code in {
        "WEB_AUTH_REQUIRED",
        "WEB_AUTH_INVALID",
        "WEB_LAUNCH_INVALID",
        "WEB_SESSION_REQUIRED",
        "WEB_SESSION_INVALID",
        "WEB_SESSION_EXPIRED",
    }:
        return HTTPStatus.UNAUTHORIZED
    if code in {
        "WEB_BIND_DENIED",
        "WEB_CORS_DENIED",
        "WEB_CSRF_DENIED",
        "WEB_FETCH_SITE_DENIED",
        "WEB_HOST_DENIED",
        "WEB_MUTATION_BEARER_DENIED",
        "WEB_ORIGIN_DENIED",
        "WEB_ORIGIN_REQUIRED",
        "WEB_PEER_DENIED",
        "WEB_QUERY_SECRET_DENIED",
        "OPERATOR_SCOPE_DENIED",
    }:
        return HTTPStatus.FORBIDDEN
    if code == "WEB_MEDIA_TYPE_DENIED":
        return HTTPStatus.UNSUPPORTED_MEDIA_TYPE
    if code == "WEB_CONTENT_LENGTH_REQUIRED":
        return HTTPStatus.LENGTH_REQUIRED
    if code in {"WEB_BODY_LIMIT", "WEB_JSON_LIMIT", "WEB_JSON_DEPTH"}:
        return HTTPStatus.REQUEST_ENTITY_TOO_LARGE
    if code == "WEB_TARGET_LIMIT":
        return HTTPStatus.REQUEST_URI_TOO_LONG
    if code == "WEB_HEADERS_LIMIT":
        return HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE
    if code in {"WEB_PRECONDITION_REQUIRED", "WEB_IDEMPOTENCY_REQUIRED"}:
        return HTTPStatus.PRECONDITION_REQUIRED
    if code == "WEB_SESSION_LIMIT":
        return HTTPStatus.SERVICE_UNAVAILABLE
    if code == "OPERATOR_ROUTE_UNKNOWN":
        return HTTPStatus.NOT_FOUND
    if code == "OPERATOR_API_NOT_IMPLEMENTED":
        return HTTPStatus.NOT_IMPLEMENTED
    return HTTPStatus.BAD_REQUEST


class HiveHTTPServer(HTTPServer):
    """One attended foreground listener with main-thread adapter deadlines."""

    allow_reuse_address = False

    def __init__(
        self,
        server_address: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        *,
        access_token: str,
        launch_handoff: BrowserLaunchHandoff,
        session_store: BrowserSessionStore,
        operator_api: OperatorAPI,
    ) -> None:
        self.access_token = access_token
        self.launch_handoff = launch_handoff
        self.session_store = session_store
        self.operator_api = operator_api
        super().__init__(server_address, handler)

    @property
    def launch_path(self) -> str:
        return self.launch_handoff.path

    def shutdown(self) -> None:
        self.launch_handoff.close()
        self.session_store.close()
        super().shutdown()

    def server_close(self) -> None:
        self.launch_handoff.close()
        self.session_store.close()
        super().server_close()


class HiveIPv6HTTPServer(HiveHTTPServer):
    address_family = socket.AF_INET6


def handler_for(workspace: HiveWorkspace) -> type[BaseHTTPRequestHandler]:
    class HiveHandler(BaseHTTPRequestHandler):
        server_version = "NukoTechHiveLocal"
        sys_version = ""

        @property
        def hive_server(self) -> HiveHTTPServer:
            return self.server  # type: ignore[return-value]

        def version_string(self) -> str:
            return "NukoTechHiveLocal"

        def log_message(self, format: str, *args: object) -> None:
            return

        def _send(
            self,
            status: HTTPStatus,
            body: bytes,
            content_type: str,
            *,
            extra_headers: Mapping[str, str] | None = None,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            headers = security_headers()
            headers.update(extra_headers or {})
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _send_error(self, error: ProtocolError) -> None:
            self.close_connection = True
            response = OperatorResponse.from_dict(
                {
                    "schema_version": "hive.operator-response.v1",
                    "request_id": str(uuid4()),
                    "outcome": "REFUSED",
                    "reason_code": error.code,
                    "object_version": "ABSENT",
                    "changed": False,
                    "data": {},
                    "technical_evidence": [],
                }
            )
            self._send(
                _error_status(error.code),
                _json_bytes(response.as_dict()),
                "application/json; charset=utf-8",
            )

        def send_error(
            self,
            code: int,
            message: str | None = None,
            explain: str | None = None,
        ) -> None:
            del message, explain
            self.close_connection = True
            status = HTTPStatus(code)
            response = OperatorResponse.from_dict(
                {
                    "schema_version": "hive.operator-response.v1",
                    "request_id": str(uuid4()),
                    "outcome": "REFUSED",
                    "reason_code": "WEB_HTTP_REFUSED",
                    "object_version": "ABSENT",
                    "changed": False,
                    "data": {},
                    "technical_evidence": [],
                }
            )
            self._send(
                status,
                _json_bytes(response.as_dict()),
                "application/json; charset=utf-8",
            )

        def _validate_common(self) -> None:
            bound_host = str(self.hive_server.server_address[0])
            bound_port = int(self.hive_server.server_address[1])
            validate_request_headers(
                self.headers,
                peer=str(self.client_address[0]),
                bind_host=bound_host,
                bind_port=bound_port,
                target=self.path,
            )

        def _browser_session(self) -> BrowserSession:
            return self.hive_server.session_store.authenticate_headers(self.headers)

        def _require_read_authentication(self) -> BrowserSession | None:
            authorization = self.headers.get("Authorization", "")
            if authorization:
                if is_bearer_authenticated(
                    self.headers, self.hive_server.access_token
                ):
                    return None
                raise ProtocolError("WEB_AUTH_INVALID", "authentication is invalid")
            return self._browser_session()

        def _serve_app(self, parsed: Any) -> None:
            if parsed.query:
                raise ProtocolError(
                    "WEB_QUERY_DENIED", "application navigation has no query inputs"
                )
            require_direct_navigation(self.headers)
            slug = resolve_app_page(parsed.path)
            if slug is None:
                raise ProtocolError(
                    "OPERATOR_ROUTE_UNKNOWN", "operator application page is not available"
                )
            has_session = session_cookie_present(self.headers)
            if not has_session:
                raise ProtocolError(
                    "WEB_SESSION_REQUIRED", "browser launch handoff is required"
                )
            self._browser_session()
            if len(self.hive_server.operator_api.project_ids) != 1:
                raise ProtocolError(
                    "OPERATOR_SCOPE_DENIED",
                    "operator application requires one exact current project",
                )
            page = PAGE_DEFINITIONS[slug]
            project_id = next(iter(self.hive_server.operator_api.project_ids))
            query = {} if slug == "projects" else {"project_id": project_id}
            result = self.hive_server.operator_api.dispatch_read(
                "GET",
                page.api_path,
                tenant_id=self.hive_server.operator_api.tenant_id,
                project_id=project_id,
                query=query,
            )
            if result.status != HTTPStatus.OK:
                raise ProtocolError(
                    result.response.reason_code or "OPERATOR_PAGE_PROJECTION_FAILED",
                    "operator application page could not be projected",
                )
            projection = dict(result.response.data)
            projection["technical_evidence"] = list(
                result.response.technical_evidence
            )
            self._send(
                HTTPStatus.OK,
                render_shell_page(
                    slug,
                    projection,
                    object_version=result.response.object_version,
                ),
                "text/html; charset=utf-8",
            )

        def _serve_launch(self, parsed: Any) -> None:
            if parsed.query:
                raise ProtocolError(
                    "WEB_QUERY_DENIED", "browser launch handoff has no query inputs"
                )
            require_direct_navigation(self.headers)
            if len(self.hive_server.operator_api.project_ids) != 1:
                raise ProtocolError(
                    "OPERATOR_SCOPE_DENIED",
                    "operator application requires one exact current project",
                )
            session = self.hive_server.launch_handoff.issue(
                parsed.path, self.hive_server.session_store
            )
            self._send(
                HTTPStatus.SEE_OTHER,
                b"",
                "text/plain; charset=utf-8",
                extra_headers={
                    "Location": "/app",
                    "Set-Cookie": self.hive_server.session_store.cookie_header(session),
                },
            )

        def _serve_static(self, parsed: Any) -> None:
            if parsed.query:
                raise ProtocolError(
                    "OPERATOR_ROUTE_UNKNOWN", "operator application resource is not available"
                )
            self._require_read_authentication()
            asset = read_static_asset(parsed.path)
            extra_headers = {
                "Cache-Control": "public, max-age=31536000, immutable",
                "ETag": asset.etag,
            }
            etags = self.headers.get_all("If-None-Match", [])
            if len(etags) > 1:
                raise ProtocolError(
                    "WEB_HEADER_DUPLICATE", "duplicate If-None-Match header"
                )
            if etags and etags[0] == asset.etag:
                self._send(
                    HTTPStatus.NOT_MODIFIED,
                    b"",
                    asset.content_type,
                    extra_headers=extra_headers,
                )
                return
            self._send(
                HTTPStatus.OK,
                asset.body,
                asset.content_type,
                extra_headers=extra_headers,
            )

        def _legacy_query(self, parsed: Any) -> str:
            try:
                query = parse_qs(
                    parsed.query,
                    keep_blank_values=True,
                    strict_parsing=False,
                    max_num_fields=4,
                )
            except ValueError as exc:
                raise ProtocolError(
                    "WEB_QUERY_INVALID", "query is invalid or excessive"
                ) from exc
            if set(query) - {"q"} or len(query.get("q", [])) > 1:
                raise ProtocolError("WEB_QUERY_INVALID", "query is not allowlisted")
            return query.get("q", [""])[0]

        def _versioned_query(self, parsed: Any) -> dict[str, str]:
            try:
                pairs = parse_qsl(
                    parsed.query,
                    keep_blank_values=True,
                    strict_parsing=False,
                    max_num_fields=16,
                )
            except ValueError as exc:
                raise ProtocolError(
                    "OPERATOR_QUERY_INVALID", "query is invalid or excessive"
                ) from exc
            if len({key for key, _ in pairs}) != len(pairs):
                raise ProtocolError(
                    "OPERATOR_QUERY_INVALID", "query keys must be unique"
                )
            return dict(pairs)

        def do_GET(self) -> None:  # noqa: N802
            try:
                self._validate_common()
                parsed = urlparse(self.path)
                if parsed.path.startswith(BrowserLaunchHandoff._PATH_PREFIX):
                    self._serve_launch(parsed)
                    return
                if resolve_app_page(parsed.path) is not None:
                    self._serve_app(parsed)
                    return
                if parsed.path.startswith("/static/"):
                    self._serve_static(parsed)
                    return
                if parsed.path == "/api/v1/session":
                    if parsed.query:
                        raise ProtocolError(
                            "WEB_QUERY_DENIED", "session endpoint has no query inputs"
                        )
                    session = self._browser_session()
                    response = OperatorResponse.from_dict(
                        {
                            "schema_version": "hive.operator-response.v1",
                            "request_id": str(uuid4()),
                            "outcome": "OK",
                            "reason_code": None,
                            "object_version": "ABSENT",
                            "changed": False,
                            "data": {
                                "authenticated": True,
                                "csrf_proof": session.csrf_token,
                            },
                            "technical_evidence": [],
                        }
                    )
                    self._send(
                        HTTPStatus.OK,
                        _json_bytes(response.as_dict()),
                        "application/json; charset=utf-8",
                    )
                    return

                if parsed.path.startswith("/api/v1/"):
                    self._require_read_authentication()
                    query = self._versioned_query(parsed)
                    project_id = query.get("project_id")
                    if project_id is None:
                        if len(self.hive_server.operator_api.project_ids) != 1:
                            raise ProtocolError(
                                "OPERATOR_SCOPE_DENIED",
                                "versioned read requires one exact project",
                            )
                        project_id = next(
                            iter(self.hive_server.operator_api.project_ids)
                        )
                    result = self.hive_server.operator_api.dispatch_read(
                        "GET",
                        parsed.path,
                        tenant_id=self.hive_server.operator_api.tenant_id,
                        project_id=project_id,
                        query=query,
                    )
                    self._send(
                        HTTPStatus(result.status),
                        _json_bytes(result.response.as_dict()),
                        "application/json; charset=utf-8",
                    )
                    return

                self._require_read_authentication()
                if parsed.path == "/api/status":
                    if parsed.query:
                        raise ProtocolError(
                            "WEB_QUERY_INVALID", "status endpoint has no query inputs"
                        )
                    value = workspace.status()
                elif parsed.path == "/api/search":
                    value = {"results": workspace.search_exact(self._legacy_query(parsed))}
                elif parsed.path == "/api/ask":
                    value = workspace.ask(self._legacy_query(parsed))
                elif parsed.path == "/api/graph":
                    if parsed.query:
                        raise ProtocolError(
                            "WEB_QUERY_INVALID", "graph endpoint has no query inputs"
                        )
                    value = workspace.graph()
                elif parsed.path == "/api/receipts":
                    if parsed.query:
                        raise ProtocolError(
                            "WEB_QUERY_INVALID", "receipts endpoint has no query inputs"
                        )
                    value = {"receipts": workspace.last_receipts()}
                else:
                    raise ProtocolError(
                        "OPERATOR_ROUTE_UNKNOWN", "operator API route is not available"
                    )
                self._send(
                    HTTPStatus.OK,
                    _json_bytes(value),
                    "application/json; charset=utf-8",
                )
            except ProtocolError as exc:
                self._send_error(exc)
            except (KeyError, OSError, TypeError, ValueError):
                self._send_error(
                    ProtocolError(
                        "WEB_REQUEST_FAILED", "request could not be completed"
                    )
                )

        def do_POST(self) -> None:  # noqa: N802
            try:
                self._validate_common()
                parsed = urlparse(self.path)
                if parsed.query:
                    raise ProtocolError(
                        "WEB_QUERY_DENIED", "mutation routes have no query inputs"
                    )
                route_for("POST", parsed.path)
                session = self._browser_session()
                binding = validate_mutation_headers(
                    self.headers,
                    session=session,
                    origin=expected_origin(
                        str(self.hive_server.server_address[0]),
                        int(self.hive_server.server_address[1]),
                    ),
                )
                # Loadout staging carries a bounded 16 MiB package set encoded as
                # base64. All other API routes keep their 1 MiB cap.
                body_limit = {"/api/v1/loadouts/stage": 23 * 1024 * 1024}.get(parsed.path, MAX_JSON_BODY_BYTES)
                document = read_bounded_json(self.rfile, self.headers, max_bytes=body_limit)
                result = self.hive_server.operator_api.dispatch_mutation(
                    "POST",
                    parsed.path,
                    document,
                    session_digest=hashlib.sha256(
                        session.session_id.encode("utf-8")
                    ).hexdigest(),
                    idempotency_key=binding.idempotency_key,
                    expected_version=binding.expected_version,
                )
                self._send(
                    HTTPStatus(result.status),
                    _json_bytes(result.response.as_dict()),
                    "application/json; charset=utf-8",
                )
            except ProtocolError as exc:
                self._send_error(exc)
            except (KeyError, OSError, TypeError, ValueError):
                self._send_error(
                    ProtocolError(
                        "WEB_REQUEST_FAILED", "request could not be completed"
                    )
                )

        def do_OPTIONS(self) -> None:  # noqa: N802
            try:
                self._validate_common()
                raise ProtocolError("WEB_CORS_DENIED", "CORS preflight is refused")
            except ProtocolError as exc:
                self._send_error(exc)

        def _method_denied(self) -> None:
            try:
                self._validate_common()
                raise ProtocolError("WEB_METHOD_DENIED", "HTTP method is not available")
            except ProtocolError as exc:
                self._send_error(exc)

        do_CONNECT = _method_denied  # noqa: N815
        do_DELETE = _method_denied  # noqa: N815
        do_HEAD = _method_denied  # noqa: N815
        do_PATCH = _method_denied  # noqa: N815
        do_PUT = _method_denied  # noqa: N815
        do_TRACE = _method_denied  # noqa: N815

    return HiveHandler


def make_server(
    workspace: HiveWorkspace,
    host: str,
    port: int,
    *,
    access_token: str | None = None,
    operator_api: OperatorAPI | None = None,
) -> HiveHTTPServer:
    bind_host = validate_bind_host(host)
    if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
        raise ProtocolError("WEB_PORT_INVALID", "listener port is invalid")
    token = access_token or secrets.token_urlsafe(32)
    normalized_token = token.replace("-", "").replace("_", "")
    if not 32 <= len(token) <= 128 or not normalized_token.isalnum():
        raise ProtocolError("WEB_TOKEN_INVALID", "process token is invalid")
    server_class = HiveIPv6HTTPServer if bind_host == "::1" else HiveHTTPServer
    api = operator_api or OperatorAPI(
        workspace.root,
        ShellService(
            workspace,
            tenant_id="local-user",
            project_ids={"HiveMind"},
        ),
        tenant_id="local-user",
        project_ids={"HiveMind"},
    )
    return server_class(
        (bind_host, port),
        handler_for(workspace),
        access_token=token,
        launch_handoff=BrowserLaunchHandoff(),
        session_store=BrowserSessionStore(),
        operator_api=api,
    )
