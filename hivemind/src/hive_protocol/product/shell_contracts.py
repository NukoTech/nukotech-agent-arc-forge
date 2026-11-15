"""Closed M4 operator request, response, and route contracts."""

from __future__ import annotations

import copy
import json
import math
from dataclasses import dataclass
from importlib.resources import files
from pathlib import PurePosixPath
from typing import Any, ClassVar, Mapping

from jsonschema import Draft202012Validator, FormatChecker

from hive_protocol.adapters.security import reject_credential_values
from hive_protocol.core import ProtocolError, document_digest


OPERATIONAL_STATES = (
    "DOCUMENTED",
    "IMPLEMENTED",
    "RUNNING",
    "WORKING",
    "VERIFIED",
    "AUTHORIZED",
)
RELEASE_HOLDS = (
    "NOT_RELEASED",
    "NO_CUSTOMER_DEPLOYMENT",
    "NO_UNATTENDED_RUNNER",
    "NO_PERSISTENT_SERVICE",
    "WINDOWS_NATIVE_NOT_VERIFIED",
    "MACOS_NATIVE_NOT_VERIFIED",
)


@dataclass(frozen=True)
class RouteContract:
    method: str
    path: str
    action: str
    mutation: bool
    approval: str


def _route(
    method: str,
    path: str,
    action: str,
    *,
    approval: str = "NONE",
) -> RouteContract:
    return RouteContract(
        method=method,
        path=path,
        action=action,
        mutation=method == "POST",
        approval=approval,
    )


ROUTES = (
    _route("GET", "/api/v1/session", "session.read"),
    _route("GET", "/api/v1/home", "home.read"),
    _route("GET", "/api/v1/projects", "projects.read"),
    _route("GET", "/api/v1/inbox", "inbox.read"),
    _route("GET", "/api/v1/capture", "capture.read"),
    _route("GET", "/api/v1/research", "research.read"),
    _route("GET", "/api/v1/memory", "memory.read"),
    _route("GET", "/api/v1/knowledge", "knowledge.read"),
    _route("GET", "/api/v1/workflows", "workflows.read"),
    _route("GET", "/api/v1/agents", "agents.read"),
    _route("GET", "/api/v1/receipts", "receipts.read"),
    _route("GET", "/api/v1/settings", "settings.read"),
    _route("GET", "/api/v1/loadouts", "loadouts.read"),
    _route("POST", "/api/v1/loadouts/stage", "loadouts.stage"),
    _route("POST", "/api/v1/loadouts/plan", "loadouts.plan"),
    _route("POST", "/api/v1/loadouts/approve", "loadouts.approve", approval="DOMAIN_PREVIEW"),
    _route("POST", "/api/v1/loadouts/apply", "loadouts.apply", approval="DOMAIN_EXACT"),
    _route("POST", "/api/v1/capture/preview", "capture.preview"),
    _route(
        "POST",
        "/api/v1/capture/admit",
        "capture.admit",
        approval="DOMAIN_PREVIEW",
    ),
    _route("POST", "/api/v1/research/workspaces/create", "research.workspaces.create"),
    _route("POST", "/api/v1/research/sources/add", "research.sources.add"),
    _route("POST", "/api/v1/research/sources/remove", "research.sources.remove"),
    _route("POST", "/api/v1/research/search", "research.search"),
    _route("POST", "/api/v1/research/ask", "research.ask"),
    _route("POST", "/api/v1/research/artifacts/create", "research.artifacts.create"),
    _route(
        "POST",
        "/api/v1/research/export",
        "research.export",
        approval="DOMAIN_PREVIEW",
    ),
    _route("POST", "/api/v1/memory/propose", "memory.propose"),
    _route("POST", "/api/v1/memory/review", "memory.review", approval="DOMAIN_EXACT"),
    _route("POST", "/api/v1/memory/promote", "memory.promote", approval="DOMAIN_EXACT"),
    _route("POST", "/api/v1/memory/correct", "memory.correct", approval="DOMAIN_EXACT"),
    _route("POST", "/api/v1/memory/revoke", "memory.revoke", approval="DOMAIN_EXACT"),
    _route("POST", "/api/v1/memory/retention/scan", "memory.retention.scan"),
    _route("POST", "/api/v1/memory/deletion/preview", "memory.deletion.preview"),
    _route(
        "POST",
        "/api/v1/memory/deletion/approve",
        "memory.deletion.approve",
        approval="DOMAIN_PREVIEW",
    ),
    _route(
        "POST",
        "/api/v1/memory/deletion/apply",
        "memory.deletion.apply",
        approval="DOMAIN_EXACT",
    ),
    _route("POST", "/api/v1/knowledge/notes/preview", "knowledge.notes.preview"),
    _route(
        "POST",
        "/api/v1/knowledge/notes/approve",
        "knowledge.notes.approve",
        approval="DOMAIN_PREVIEW",
    ),
    _route(
        "POST",
        "/api/v1/knowledge/notes/apply",
        "knowledge.notes.apply",
        approval="DOMAIN_PREVIEW",
    ),
    _route("POST", "/api/v1/knowledge/graph/rebuild", "knowledge.graph.rebuild"),
    _route("POST", "/api/v1/workflows/definitions/preview", "workflows.definitions.preview"),
    _route(
        "POST",
        "/api/v1/workflows/definitions/publish",
        "workflows.definitions.publish",
        approval="DOMAIN_PREVIEW",
    ),
    _route("POST", "/api/v1/workflows/runs/launch", "workflows.runs.launch"),
    _route("POST", "/api/v1/workflows/readiness", "workflows.readiness"),
    _route("POST", "/api/v1/workflows/conflicts/record", "workflows.conflicts.record"),
    _route("POST", "/api/v1/workflows/approvals/preview", "workflows.approvals.preview"),
    _route(
        "POST",
        "/api/v1/workflows/approvals/approve",
        "workflows.approvals.approve",
        approval="DOMAIN_PREVIEW",
    ),
    _route(
        "POST",
        "/api/v1/workflows/claims/create",
        "workflows.claims.create",
        approval="DOMAIN_PREVIEW",
    ),
    _route("POST", "/api/v1/workflows/tasks/deliver", "workflows.tasks.deliver"),
    _route("POST", "/api/v1/workflows/sessions/start", "workflows.sessions.start"),
    _route("POST", "/api/v1/workflows/sessions/record", "workflows.sessions.record"),
    _route("POST", "/api/v1/workflows/stale/preview", "workflows.stale.preview"),
    _route(
        "POST",
        "/api/v1/workflows/stale/apply",
        "workflows.stale.apply",
        approval="DOMAIN_EXACT",
    ),
    _route("POST", "/api/v1/workflows/retries/create", "workflows.retries.create"),
    _route(
        "POST",
        "/api/v1/workflows/compensation/preview",
        "workflows.compensation.preview",
    ),
    _route(
        "POST",
        "/api/v1/workflows/compensation/authorize",
        "workflows.compensation.authorize",
        approval="DOMAIN_EXACT",
    ),
    _route("POST", "/api/v1/workflows/rollback/preview", "workflows.rollback.preview"),
    _route(
        "POST",
        "/api/v1/workflows/rollback/apply",
        "workflows.rollback.apply",
        approval="DOMAIN_EXACT",
    ),
    _route("POST", "/api/v1/workflows/runs/cancel", "workflows.runs.cancel"),
    _route("POST", "/api/v1/workflows/runs/complete", "workflows.runs.complete"),
    _route(
        "POST",
        "/api/v1/agents/capabilities/authorize",
        "agents.capabilities.authorize",
        approval="DOMAIN_EXACT",
    ),
    _route("POST", "/api/v1/agents/register", "agents.register"),
    _route("POST", "/api/v1/agents/tasks/submit", "agents.tasks.submit"),
    _route("POST", "/api/v1/settings/provider/preview", "settings.provider.preview"),
    _route(
        "POST",
        "/api/v1/settings/provider/apply",
        "settings.provider.apply",
        approval="DOMAIN_PREVIEW",
    ),
    _route("POST", "/api/v1/settings/adapters/plan", "settings.adapters.plan"),
    _route(
        "POST",
        "/api/v1/settings/adapters/invoke",
        "settings.adapters.invoke",
        approval="DOMAIN_PREVIEW",
    ),
    _route("POST", "/api/v1/settings/lifecycle/preview", "settings.lifecycle.preview"),
    _route(
        "POST",
        "/api/v1/settings/lifecycle/approve",
        "settings.lifecycle.approve",
        approval="DOMAIN_PREVIEW",
    ),
    _route(
        "POST",
        "/api/v1/settings/lifecycle/apply",
        "settings.lifecycle.apply",
        approval="DOMAIN_EXACT",
    ),
    _route("POST", "/api/v1/settings/snapshot", "settings.snapshot"),
    _route(
        "POST",
        "/api/v1/settings/export",
        "settings.export",
        approval="DOMAIN_PREVIEW",
    ),
    _route("POST", "/api/v1/settings/reopen", "settings.reopen", approval="DOMAIN_PREVIEW"),
    _route(
        "POST",
        "/api/v1/settings/rollback",
        "settings.rollback",
        approval="DOMAIN_EXACT",
    ),
)

MUTATION_ROUTES = tuple(route for route in ROUTES if route.mutation)
_ROUTE_INDEX = {(route.method, route.path): route for route in ROUTES}
_MUTATION_ACTIONS = frozenset(route.action for route in MUTATION_ROUTES)
_TRANSPORT_SECRET_KEYS = frozenset(
    {"authorization", "proxy_authorization", "cookie", "set_cookie"}
)
_RAW_DIAGNOSTIC_KEYS = frozenset(
    {"exception", "raw_exception", "stack", "stack_trace", "traceback"}
)


def route_for(method: str, path: str) -> RouteContract:
    route = _ROUTE_INDEX.get((method, path))
    if route is None:
        raise ProtocolError(
            "OPERATOR_ROUTE_UNKNOWN", "operator API route is not available"
        )
    return route


def _require_finite_and_bounded(value: Any, *, depth: int = 0) -> None:
    if depth > 12:
        raise ProtocolError(
            "OPERATOR_DOCUMENT_DEPTH", "operator document nesting is excessive"
        )
    if isinstance(value, Mapping):
        if len(value) > 128:
            raise ProtocolError(
                "OPERATOR_DOCUMENT_LIMIT", "operator object has too many fields"
            )
        for key, child in value.items():
            if isinstance(key, str):
                normalized = key.lower().replace("-", "_")
                if normalized in _TRANSPORT_SECRET_KEYS and child not in (
                    None,
                    "",
                    [],
                    {},
                ):
                    raise ProtocolError(
                        "OPERATOR_TRANSPORT_SECRET_DENIED",
                        "transport credentials are forbidden in operator documents",
                    )
            _require_finite_and_bounded(child, depth=depth + 1)
        return
    if isinstance(value, (list, tuple)):
        if len(value) > 1024:
            raise ProtocolError(
                "OPERATOR_DOCUMENT_LIMIT", "operator array has too many items"
            )
        for child in value:
            _require_finite_and_bounded(child, depth=depth + 1)
        return
    if isinstance(value, float) and not math.isfinite(value):
        raise ProtocolError(
            "OPERATOR_NUMBER_NONFINITE", "operator documents require finite numbers"
        )


def _reject_raw_diagnostics(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if isinstance(key, str):
                normalized = key.lower().replace("-", "_")
                if normalized in _RAW_DIAGNOSTIC_KEYS and child not in (
                    None,
                    "",
                    [],
                    {},
                ):
                    raise ProtocolError(
                        "OPERATOR_DIAGNOSTIC_DENIED",
                        "raw diagnostics are forbidden in operator responses",
                    )
            _reject_raw_diagnostics(child)
        return
    if isinstance(value, (list, tuple)):
        for child in value:
            _reject_raw_diagnostics(child)


def _validate(schema_name: str, document: Mapping[str, Any]) -> dict[str, Any]:
    candidate = copy.deepcopy(dict(document))
    reject_credential_values(candidate, location="operator document")
    _require_finite_and_bounded(candidate)
    schema = json.loads(
        files("hive_protocol.schemas")
        .joinpath(schema_name)
        .read_text(encoding="utf-8")
    )
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(
            candidate
        ),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        location = ".".join(str(part) for part in errors[0].absolute_path) or "$"
        raise ProtocolError(
            "OPERATOR_DOCUMENT_SCHEMA_INVALID",
            f"{location}: {errors[0].message}",
        )
    return candidate


@dataclass(frozen=True)
class _OperatorDocument:
    _document: dict[str, Any]

    schema_name: ClassVar[str]

    def __post_init__(self) -> None:
        object.__setattr__(self, "_document", copy.deepcopy(self._document))

    def as_dict(self) -> dict[str, Any]:
        return copy.deepcopy(self._document)

    @property
    def digest(self) -> str:
        return document_digest(self._document)

    def __getattr__(self, name: str) -> Any:
        document = object.__getattribute__(self, "_document")
        if name in document:
            return copy.deepcopy(document[name])
        raise AttributeError(name)


@dataclass(frozen=True)
class OperatorRequest(_OperatorDocument):
    schema_name: ClassVar[str] = "operator-request.v1.schema.json"

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "OperatorRequest":
        candidate = _validate(cls.schema_name, document)
        if candidate["tenant_id"] == candidate["project_id"]:
            raise ProtocolError(
                "OPERATOR_IDENTITY_COLLAPSE",
                "tenant and project identity dimensions must remain distinct",
            )
        if candidate["action"] not in _MUTATION_ACTIONS:
            raise ProtocolError(
                "OPERATOR_ACTION_UNKNOWN",
                "operator request action is not an available mutation",
            )
        return cls(candidate)


@dataclass(frozen=True)
class OperatorResponse(_OperatorDocument):
    schema_name: ClassVar[str] = "operator-response.v1.schema.json"

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "OperatorResponse":
        candidate = _validate(cls.schema_name, document)
        _reject_raw_diagnostics(candidate["data"])
        for item in candidate["technical_evidence"]:
            reference = item["ref"]
            path = PurePosixPath(reference)
            if (
                "\\" in reference
                or any(ord(character) < 32 for character in reference)
                or path.is_absolute()
                or ".." in path.parts
            ):
                raise ProtocolError(
                    "OPERATOR_EVIDENCE_REF_INVALID",
                    "technical evidence reference is unsafe",
                )
        return cls(candidate)
