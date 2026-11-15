"""Versioned M4 operator API dispatch, optimistic concurrency, and replay."""

from __future__ import annotations

import copy
import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol
from uuid import UUID, uuid4

from hive_protocol.adapters.security import reject_credential_values
from hive_protocol.core import ProtocolError, document_digest
from hive_protocol.storage import (
    atomic_write_json,
    ensure_owned_directory,
    exclusive_lock,
    read_json,
    require_no_symlink_components,
    utc_now,
)

from .shell_contracts import OperatorRequest, OperatorResponse, RouteContract, route_for


_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_SAFE_SCOPE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SAFE_OBJECT_KEY = re.compile(r"^[A-Za-z0-9._:/-]{1,256}$")
_RECORD_SCHEMA = "hive.operator-api-replay.v1"
_RECORD_STATES = frozenset({"PREPARED", "INVOKING", "DOMAIN_RESULT", "COMPLETE"})
_RECORD_FIELDS = frozenset(
    {
        "schema_version",
        "record_id",
        "state",
        "session_digest",
        "idempotency_digest",
        "method",
        "path",
        "action",
        "tenant_id",
        "project_id",
        "request_id",
        "request_digest",
        "expected_version",
        "object_digest",
        "operation_key",
        "result_digest",
        "result_ref",
        "claimed_at",
        "completed_at",
    }
)
_READ_QUERY_FIELDS: dict[str, frozenset[str]] = {
    "/api/v1/session": frozenset(),
    "/api/v1/home": frozenset({"project_id"}),
    "/api/v1/projects": frozenset(),
    "/api/v1/inbox": frozenset({"project_id"}),
    "/api/v1/capture": frozenset({"project_id"}),
    "/api/v1/research": frozenset({"project_id"}),
    "/api/v1/memory": frozenset({"project_id"}),
    "/api/v1/knowledge": frozenset({"project_id"}),
    "/api/v1/workflows": frozenset(
        {"project_id", "workflow_id", "from_version", "to_version"}
    ),
    "/api/v1/agents": frozenset({"project_id"}),
    "/api/v1/receipts": frozenset(
        {
            "project_id",
            "lane",
            "action",
            "actor",
            "outcome",
            "from",
            "to",
            "limit",
        }
    ),
    "/api/v1/settings": frozenset({"project_id"}),
    "/api/v1/loadouts": frozenset({"project_id"}),
}


class OperatorDomainService(Protocol):
    def object_key(self, route: RouteContract, request: OperatorRequest) -> str: ...

    def current_version(
        self, route: RouteContract, request: OperatorRequest
    ) -> str: ...

    def mutate(
        self,
        route: RouteContract,
        request: OperatorRequest,
        *,
        operation_key: str,
    ) -> Mapping[str, Any]: ...

    def recover(
        self,
        route: RouteContract,
        request: OperatorRequest,
        *,
        operation_key: str,
    ) -> Mapping[str, Any] | None: ...

    def read(
        self,
        route: RouteContract,
        *,
        tenant_id: str,
        project_id: str,
        query: dict[str, str],
    ) -> Mapping[str, Any]: ...


class UnavailableOperatorService:
    """Closed transition seam until the M4 lane facade is installed."""

    def object_key(self, route: RouteContract, request: OperatorRequest) -> str:
        return f"{request.project_id}:{route.action}:unavailable"

    def current_version(
        self, route: RouteContract, request: OperatorRequest
    ) -> str:
        del route, request
        raise ProtocolError(
            "OPERATOR_DOMAIN_UNAVAILABLE",
            "operator domain facade is not installed",
        )

    def mutate(
        self,
        route: RouteContract,
        request: OperatorRequest,
        *,
        operation_key: str,
    ) -> Mapping[str, Any]:
        del route, request, operation_key
        raise ProtocolError(
            "OPERATOR_DOMAIN_UNAVAILABLE",
            "operator domain facade is not installed",
        )

    def recover(
        self,
        route: RouteContract,
        request: OperatorRequest,
        *,
        operation_key: str,
    ) -> Mapping[str, Any] | None:
        del route, request, operation_key
        return None

    def read(
        self,
        route: RouteContract,
        *,
        tenant_id: str,
        project_id: str,
        query: dict[str, str],
    ) -> Mapping[str, Any]:
        del route, tenant_id, project_id, query
        raise ProtocolError(
            "OPERATOR_DOMAIN_UNAVAILABLE",
            "operator domain facade is not installed",
        )


@dataclass(frozen=True)
class APIResult:
    status: int
    response: OperatorResponse


def _safe_request_id(document: Mapping[str, Any] | object) -> str:
    if isinstance(document, Mapping):
        value = document.get("request_id")
        if isinstance(value, str):
            try:
                UUID(value)
            except ValueError:
                pass
            else:
                return value
    return str(uuid4())


def _status_for(code: str) -> int:
    if code == "OPERATOR_ROUTE_UNKNOWN":
        return 404
    if code in {
        "OPERATOR_SCOPE_DENIED",
        "OPERATOR_RUNTIME_BOUNDARY",
    } or any(
        word in code
        for word in ("APPROVAL", "AUTHORITY", "UNAUTHORIZED", "PRIVACY", "SCOPE_DENIED")
    ):
        return 403
    if code == "OPERATOR_VERSION_STALE":
        return 412
    if code in {
        "OPERATOR_EFFECT_STATE_PENDING",
        "OPERATOR_REPLAY_CONFLICT",
        "OPERATOR_REPLAY_INVALID",
    }:
        return 409
    if code == "OPERATOR_DOMAIN_UNAVAILABLE":
        return 503
    if "LIMIT" in code:
        return 413
    return 400


def _error_result(request_id: str, error: ProtocolError) -> APIResult:
    reason_code = (
        error.code
        if re.fullmatch(r"[A-Z][A-Z0-9_]{1,127}", error.code)
        else "OPERATOR_PROTOCOL_ERROR"
    )
    response = OperatorResponse.from_dict(
        {
            "schema_version": "hive.operator-response.v1",
            "request_id": request_id,
            "outcome": "REFUSED",
            "reason_code": reason_code,
            "object_version": "ABSENT",
            "changed": False,
            "data": {},
            "technical_evidence": [],
        }
    )
    return APIResult(_status_for(reason_code), response)


def _internal_error_result(request_id: str) -> APIResult:
    response = OperatorResponse.from_dict(
        {
            "schema_version": "hive.operator-response.v1",
            "request_id": request_id,
            "outcome": "REFUSED",
            "reason_code": "OPERATOR_INTERNAL_ERROR",
            "object_version": "ABSENT",
            "changed": False,
            "data": {},
            "technical_evidence": [],
        }
    )
    return APIResult(500, response)


class OperatorAPI:
    """Closed dispatch over an injected, authority-bearing domain facade."""

    def __init__(
        self,
        workspace_root: Path,
        service: OperatorDomainService,
        *,
        tenant_id: str,
        project_ids: set[str] | frozenset[str],
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        frozen_projects = frozenset(project_ids)
        if (
            _SAFE_SCOPE_ID.fullmatch(tenant_id) is None
            or not frozen_projects
            or tenant_id in frozen_projects
            or any(_SAFE_SCOPE_ID.fullmatch(project) is None for project in frozen_projects)
        ):
            raise ValueError("operator API scope must contain distinct safe identities")
        self.workspace_root = workspace_root.expanduser().absolute()
        self.service = service
        self.tenant_id = tenant_id
        self.project_ids = frozen_projects
        self.fault_hook = fault_hook
        self.runtime_root = (
            self.workspace_root / ".hive" / "runtime" / "operator-shell" / "api-replay"
        )
        self.ledger_root = self.runtime_root / "ledger"
        self.locks_root = self.runtime_root / "locks"
        self.object_locks_root = self.runtime_root / "object-locks"
        self.results_root = self.runtime_root / "results"

    def _fault(self, stage: str) -> None:
        if self.fault_hook is not None:
            self.fault_hook(stage)

    def _require_scope(self, tenant_id: str, project_id: str) -> None:
        if tenant_id != self.tenant_id or project_id not in self.project_ids:
            raise ProtocolError(
                "OPERATOR_SCOPE_DENIED", "operator tenant or project is outside scope"
            )

    def _ensure_runtime(self) -> None:
        try:
            metadata = self.workspace_root.stat()
        except OSError as exc:
            raise ProtocolError(
                "OPERATOR_RUNTIME_BOUNDARY", "workspace root is unavailable"
            ) from exc
        if (
            self.workspace_root.is_symlink()
            or not self.workspace_root.is_dir()
            or metadata.st_uid != os.geteuid()
        ):
            raise ProtocolError(
                "OPERATOR_RUNTIME_BOUNDARY", "workspace root is not owned and canonical"
            )
        for directory in (
            self.runtime_root,
            self.ledger_root,
            self.locks_root,
            self.object_locks_root,
            self.results_root,
        ):
            ensure_owned_directory(
                self.workspace_root,
                directory,
                code="OPERATOR_RUNTIME_BOUNDARY",
                detail="operator replay directory is not owned and canonical",
            )

    def _require_paths(self, *paths: Path) -> None:
        for path in paths:
            require_no_symlink_components(
                self.workspace_root,
                path,
                code="OPERATOR_RUNTIME_BOUNDARY",
                detail="operator replay path may not contain symlinks",
            )
            if path.is_symlink():
                raise ProtocolError(
                    "OPERATOR_RUNTIME_BOUNDARY",
                    "operator replay path may not be a symlink",
                )

    @staticmethod
    def _validate_version(value: str, *, code: str) -> str:
        if not isinstance(value, str) or (
            value != "ABSENT" and _SHA256.fullmatch(value) is None
        ):
            raise ProtocolError(code, "object version is invalid")
        return value

    def _current_version(
        self, route: RouteContract, request: OperatorRequest
    ) -> str:
        return self._validate_version(
            self.service.current_version(route, request),
            code="OPERATOR_VERSION_INVALID",
        )

    @staticmethod
    def _record_id(idempotency_key: str) -> str:
        return hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()

    @staticmethod
    def _operation_key(binding: Mapping[str, Any]) -> str:
        return document_digest(
            {"schema_version": "hive.operator-operation.v1", **dict(binding)}
        )

    def _read_record(self, path: Path) -> dict[str, Any]:
        try:
            record = read_json(path)
        except ProtocolError as exc:
            raise ProtocolError(
                "OPERATOR_REPLAY_INVALID", "operator replay record is invalid"
            ) from exc
        self._validate_record(record)
        return record

    @staticmethod
    def _validate_record(record: Mapping[str, Any]) -> None:
        reject_credential_values(record, location="operator replay record")
        if set(record) != _RECORD_FIELDS or record.get("schema_version") != _RECORD_SCHEMA:
            raise ProtocolError(
                "OPERATOR_REPLAY_INVALID", "operator replay record shape is invalid"
            )
        hash_fields = (
            "record_id",
            "session_digest",
            "idempotency_digest",
            "request_digest",
            "object_digest",
            "operation_key",
        )
        if not all(
            isinstance(record.get(field), str)
            and _SHA256.fullmatch(str(record[field])) is not None
            for field in hash_fields
        ):
            raise ProtocolError(
                "OPERATOR_REPLAY_INVALID", "operator replay digests are invalid"
            )
        state = record.get("state")
        if state not in _RECORD_STATES:
            raise ProtocolError(
                "OPERATOR_REPLAY_INVALID", "operator replay state is invalid"
            )
        result_digest = record.get("result_digest")
        completed_at = record.get("completed_at")
        if state in {"PREPARED", "INVOKING"}:
            if result_digest is not None or completed_at is not None:
                raise ProtocolError(
                    "OPERATOR_REPLAY_INVALID", "pending replay result state is invalid"
                )
        elif (
            not isinstance(result_digest, str)
            or _SHA256.fullmatch(result_digest) is None
            or (state == "COMPLETE" and not isinstance(completed_at, str))
            or (state == "DOMAIN_RESULT" and completed_at is not None)
        ):
            raise ProtocolError(
                "OPERATOR_REPLAY_INVALID", "completed replay result state is invalid"
            )
        record_id = str(record["record_id"])
        if (
            record.get("idempotency_digest") != record_id
            or record.get("result_ref") != f"results/{record_id}.json"
            or record.get("method") != "POST"
            or not isinstance(record.get("claimed_at"), str)
            or not record.get("claimed_at")
        ):
            raise ProtocolError(
                "OPERATOR_REPLAY_INVALID", "operator replay bindings are invalid"
            )

    def _write_record(self, path: Path, record: Mapping[str, Any]) -> None:
        self._require_paths(path)
        self._validate_record(record)
        atomic_write_json(path, record, mode=0o600)

    def _validate_record_binding(
        self, record: Mapping[str, Any], binding: Mapping[str, Any]
    ) -> None:
        for field, expected in binding.items():
            if record.get(field) != expected:
                raise ProtocolError(
                    "OPERATOR_REPLAY_CONFLICT",
                    "idempotency key is bound to a different request",
                )

    @staticmethod
    def _response_from_domain(
        request_id: str,
        domain_result: Mapping[str, Any],
        *,
        operation_key: str,
        request_digest: str | None,
        mutation: bool,
    ) -> OperatorResponse:
        expected_fields = {
            "outcome",
            "reason_code",
            "object_version",
            "changed",
            "data",
            "technical_evidence",
        }
        if mutation:
            expected_fields |= {"operation_key", "request_digest"}
        if set(domain_result) != expected_fields:
            raise ProtocolError(
                "OPERATOR_DOMAIN_RESULT_INVALID", "domain result shape is invalid"
            )
        if mutation and (
            domain_result.get("operation_key") != operation_key
            or domain_result.get("request_digest") != request_digest
        ):
            raise ProtocolError(
                "OPERATOR_DOMAIN_RESULT_MISMATCH",
                "domain result does not bind the exact operation and request",
            )
        response = OperatorResponse.from_dict(
            {
                "schema_version": "hive.operator-response.v1",
                "request_id": request_id,
                "outcome": domain_result["outcome"],
                "reason_code": domain_result["reason_code"],
                "object_version": domain_result["object_version"],
                "changed": domain_result["changed"],
                "data": copy.deepcopy(domain_result["data"]),
                "technical_evidence": copy.deepcopy(
                    domain_result["technical_evidence"]
                ),
            }
        )
        if mutation:
            if response.changed is True and response.outcome != "APPLIED":
                raise ProtocolError(
                    "OPERATOR_DOMAIN_RESULT_INVALID",
                    "changed mutation result must be APPLIED",
                )
            if response.changed is True and not response.technical_evidence:
                raise ProtocolError(
                    "OPERATOR_DOMAIN_RESULT_INVALID",
                    "changed mutation result requires durable evidence",
                )
        elif response.changed or response.outcome == "APPLIED":
            raise ProtocolError(
                "OPERATOR_DOMAIN_RESULT_INVALID", "read result may not claim mutation"
            )
        return response

    def _read_result(
        self,
        path: Path,
        *,
        record: Mapping[str, Any],
    ) -> OperatorResponse:
        self._require_paths(path)
        try:
            response = OperatorResponse.from_dict(read_json(path))
        except ProtocolError as exc:
            raise ProtocolError(
                "OPERATOR_REPLAY_INVALID", "stored operator result is invalid"
            ) from exc
        if response.digest != record.get("result_digest"):
            raise ProtocolError(
                "OPERATOR_REPLAY_INVALID", "stored operator result digest changed"
            )
        return response

    @staticmethod
    def _as_replay(response: OperatorResponse) -> OperatorResponse:
        document = response.as_dict()
        document["changed"] = False
        return OperatorResponse.from_dict(document)

    def _persist_domain_result(
        self,
        record: dict[str, Any],
        record_path: Path,
        result_path: Path,
        response: OperatorResponse,
    ) -> None:
        self._require_paths(result_path)
        atomic_write_json(result_path, response.as_dict(), mode=0o600)
        record["state"] = "DOMAIN_RESULT"
        record["result_digest"] = response.digest
        self._write_record(record_path, record)

    def _require_domain_head(
        self,
        route: RouteContract,
        request: OperatorRequest,
        response: OperatorResponse,
    ) -> None:
        if self._current_version(route, request) != response.object_version:
            raise ProtocolError(
                "OPERATOR_DOMAIN_RESULT_MISMATCH",
                "domain result does not match the current object version",
            )

    def _complete_record(
        self, record: dict[str, Any], record_path: Path
    ) -> None:
        record["state"] = "COMPLETE"
        record["completed_at"] = utc_now()
        self._write_record(record_path, record)

    def _invoke_prepared(
        self,
        route: RouteContract,
        request: OperatorRequest,
        record: dict[str, Any],
        record_path: Path,
        result_path: Path,
    ) -> OperatorResponse:
        current = self._current_version(route, request)
        if current != request.expected_version:
            raise ProtocolError(
                "OPERATOR_VERSION_STALE", "object version does not match If-Match"
            )
        record["state"] = "INVOKING"
        self._write_record(record_path, record)
        domain_result = self.service.mutate(
            route,
            request,
            operation_key=str(record["operation_key"]),
        )
        response = self._response_from_domain(
            str(request.request_id),
            domain_result,
            operation_key=str(record["operation_key"]),
            request_digest=request.digest,
            mutation=True,
        )
        self._require_domain_head(route, request, response)
        self._fault("after_domain_result")
        self._persist_domain_result(record, record_path, result_path, response)
        self._fault("after_result_persist")
        self._complete_record(record, record_path)
        return response

    def _resume_record(
        self,
        route: RouteContract,
        request: OperatorRequest,
        record: dict[str, Any],
        record_path: Path,
        result_path: Path,
    ) -> OperatorResponse:
        state = record["state"]
        if state == "COMPLETE":
            return self._as_replay(self._read_result(result_path, record=record))
        if state == "DOMAIN_RESULT":
            response = self._read_result(result_path, record=record)
            self._complete_record(record, record_path)
            return self._as_replay(response)
        if state == "PREPARED":
            return self._invoke_prepared(
                route, request, record, record_path, result_path
            )
        recovered = self.service.recover(
            route,
            request,
            operation_key=str(record["operation_key"]),
        )
        if recovered is None:
            raise ProtocolError(
                "OPERATOR_EFFECT_STATE_PENDING",
                "domain effect lacks an exact durable recovery result",
            )
        response = self._response_from_domain(
            str(request.request_id),
            recovered,
            operation_key=str(record["operation_key"]),
            request_digest=request.digest,
            mutation=True,
        )
        self._require_domain_head(route, request, response)
        self._persist_domain_result(record, record_path, result_path, response)
        self._fault("after_result_persist")
        self._complete_record(record, record_path)
        return self._as_replay(response)

    def _execute_mutation(
        self,
        route: RouteContract,
        request: OperatorRequest,
        *,
        session_digest: str,
        idempotency_key: str,
    ) -> OperatorResponse:
        self._ensure_runtime()
        object_key = self.service.object_key(route, request)
        if not isinstance(object_key, str) or _SAFE_OBJECT_KEY.fullmatch(object_key) is None:
            raise ProtocolError(
                "OPERATOR_OBJECT_KEY_INVALID", "domain object key is invalid"
            )
        object_digest = hashlib.sha256(object_key.encode("utf-8")).hexdigest()
        record_id = self._record_id(idempotency_key)
        record_path = self.ledger_root / f"{record_id}.json"
        result_path = self.results_root / f"{record_id}.json"
        record_lock = self.locks_root / f"{record_id}.lock"
        object_lock = self.object_locks_root / f"{object_digest}.lock"
        self._require_paths(record_path, result_path, record_lock, object_lock)

        binding = {
            "record_id": record_id,
            "session_digest": session_digest,
            "idempotency_digest": record_id,
            "method": route.method,
            "path": route.path,
            "action": route.action,
            "tenant_id": str(request.tenant_id),
            "project_id": str(request.project_id),
            "request_id": str(request.request_id),
            "request_digest": request.digest,
            "expected_version": str(request.expected_version),
            "object_digest": object_digest,
        }
        operation_key = self._operation_key(binding)
        binding["operation_key"] = operation_key

        try:
            with exclusive_lock(object_lock):
                with exclusive_lock(record_lock):
                    self._require_paths(
                        record_path, result_path, record_lock, object_lock
                    )
                    if record_path.exists():
                        record = self._read_record(record_path)
                        self._validate_record_binding(record, binding)
                        return self._resume_record(
                            route, request, record, record_path, result_path
                        )
                    if result_path.exists():
                        raise ProtocolError(
                            "OPERATOR_REPLAY_INVALID",
                            "operator result exists without its replay record",
                        )
                    current = self._current_version(route, request)
                    if current != request.expected_version:
                        raise ProtocolError(
                            "OPERATOR_VERSION_STALE",
                            "object version does not match If-Match",
                        )
                    record = {
                        "schema_version": _RECORD_SCHEMA,
                        **binding,
                        "state": "PREPARED",
                        "result_digest": None,
                        "result_ref": f"results/{record_id}.json",
                        "claimed_at": utc_now(),
                        "completed_at": None,
                    }
                    self._write_record(record_path, record)
                    self._fault("after_prepare")
                    return self._invoke_prepared(
                        route, request, record, record_path, result_path
                    )
        except ProtocolError as exc:
            if exc.code == "LOCK_BOUNDARY":
                raise ProtocolError(
                    "OPERATOR_RUNTIME_BOUNDARY",
                    "operator replay lock is unsafe",
                ) from exc
            raise

    def dispatch_mutation(
        self,
        method: str,
        path: str,
        document: Mapping[str, Any] | object,
        *,
        session_digest: str,
        idempotency_key: str,
        expected_version: str,
    ) -> APIResult:
        request_id = _safe_request_id(document)
        try:
            begin_request = getattr(self.service, "begin_request", None)
            if callable(begin_request):
                begin_request()
            route = route_for(method, path)
            if not route.mutation:
                raise ProtocolError(
                    "OPERATOR_ROUTE_UNKNOWN", "operator mutation route is unavailable"
                )
            if not isinstance(document, Mapping):
                raise ProtocolError(
                    "OPERATOR_DOCUMENT_INVALID",
                    "operator request body must be an object",
                )
            if (
                not isinstance(session_digest, str)
                or _SHA256.fullmatch(session_digest) is None
            ):
                raise ProtocolError(
                    "OPERATOR_SESSION_BINDING_INVALID",
                    "session binding digest is invalid",
                )
            self._validate_version(
                expected_version, code="OPERATOR_PRECONDITION_INVALID"
            )
            if not isinstance(idempotency_key, str):
                raise ProtocolError(
                    "OPERATOR_IDEMPOTENCY_INVALID",
                    "idempotency key is invalid",
                )
            request = OperatorRequest.from_dict(document)
            request_id = str(request.request_id)
            if request.action != route.action:
                raise ProtocolError(
                    "OPERATOR_ACTION_ROUTE_MISMATCH",
                    "request action does not match its exact route",
                )
            if (
                request.idempotency_key != idempotency_key
                or request.expected_version != expected_version
            ):
                raise ProtocolError(
                    "OPERATOR_HEADER_BODY_MISMATCH",
                    "request replay headers do not match the body",
                )
            self._require_scope(str(request.tenant_id), str(request.project_id))
            response = self._execute_mutation(
                route,
                request,
                session_digest=session_digest,
                idempotency_key=idempotency_key,
            )
            return APIResult(200, response)
        except ProtocolError as exc:
            return _error_result(request_id, exc)
        except Exception:
            return _internal_error_result(request_id)

    def _validate_query(
        self,
        path: str,
        query: Mapping[str, Any],
        *,
        project_id: str,
    ) -> dict[str, str]:
        allowed = _READ_QUERY_FIELDS.get(path)
        if allowed is None or len(query) > 16 or set(query) - allowed:
            raise ProtocolError(
                "OPERATOR_QUERY_DENIED", "read query is not allowlisted"
            )
        normalized: dict[str, str] = {}
        for key, value in query.items():
            if (
                not isinstance(key, str)
                or not isinstance(value, str)
                or len(value) > 256
                or any(ord(character) < 32 for character in value)
            ):
                raise ProtocolError(
                    "OPERATOR_QUERY_INVALID", "read query value is invalid"
                )
            normalized[key] = value
        reject_credential_values(normalized, location="operator read query")
        if "project_id" in normalized and normalized["project_id"] != project_id:
            raise ProtocolError(
                "OPERATOR_SCOPE_DENIED", "query project is outside request scope"
            )
        return normalized

    def dispatch_read(
        self,
        method: str,
        path: str,
        *,
        tenant_id: str,
        project_id: str,
        query: Mapping[str, Any],
    ) -> APIResult:
        request_id = str(uuid4())
        try:
            begin_request = getattr(self.service, "begin_request", None)
            if callable(begin_request):
                begin_request()
            route = route_for(method, path)
            if route.mutation:
                raise ProtocolError(
                    "OPERATOR_ROUTE_UNKNOWN", "operator read route is unavailable"
                )
            self._require_scope(tenant_id, project_id)
            normalized = self._validate_query(
                path, query, project_id=project_id
            )
            result = self.service.read(
                route,
                tenant_id=tenant_id,
                project_id=project_id,
                query=normalized,
            )
            response = self._response_from_domain(
                request_id,
                result,
                operation_key="",
                request_digest=None,
                mutation=False,
            )
            return APIResult(200, response)
        except ProtocolError as exc:
            return _error_result(request_id, exc)
        except Exception:
            return _internal_error_result(request_id)
