"""Closed, immutable M3.3 workflow documents."""

from __future__ import annotations

import copy
import json
import math
from dataclasses import dataclass
from datetime import datetime
from importlib.resources import files
from typing import Any, ClassVar, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker

from hive_protocol.adapters.security import reject_credential_values
from hive_protocol.core import ProtocolError, document_digest


_SCHEMA_NAMES = frozenset(
    {
        "workflow-definition.v1.schema.json",
        "workflow-run.v1.schema.json",
        "workflow-event.v1.schema.json",
        "workflow-approval.v1.schema.json",
        "agent-session.v1.schema.json",
    }
)
_IDENTITY_FIELDS = (
    "actor_id",
    "persona_id",
    "surface_id",
    "machine_id",
    "project_id",
    "app_actor",
)
_RUN_EVENTS = frozenset({"RUN_STARTED", "RUN_COMPLETED", "RUN_CANCELLED"})
_ATTEMPT_EVENTS = frozenset(
    {
        "STEP_ASSIGNED",
        "STEP_CLAIMED",
        "SESSION_STARTED",
        "SESSION_HEARTBEAT",
        "STEP_ACKNOWLEDGED",
        "STEP_PROGRESS",
        "STEP_OUTPUT",
        "STEP_FAILED",
        "STEP_RETRY_CREATED",
        "SESSION_ABANDONED",
        "CLAIM_RELEASED",
        "COMPENSATION_STARTED",
        "COMPENSATION_COMPLETED",
        "ROLLBACK_STARTED",
        "ROLLBACK_COMPLETED",
        "STEP_COMPLETED",
    }
)


def validate_workflow_document(
    schema_name: str,
    document: Mapping[str, Any],
    *,
    verified_by: Mapping[str, Ed25519PublicKey] | None = None,
) -> None:
    if schema_name not in _SCHEMA_NAMES:
        raise ProtocolError(
            "WORKFLOW_DOCUMENT_SCHEMA_UNKNOWN",
            "unsupported workflow document schema",
        )
    candidate = copy.deepcopy(dict(document))
    reject_credential_values(
        candidate, location="workflow document", verified_by=verified_by
    )
    _require_finite(candidate)
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
        first = errors[0]
        location = ".".join(str(part) for part in first.absolute_path) or "$"
        raise ProtocolError(
            "WORKFLOW_DOCUMENT_SCHEMA_INVALID",
            f"{location}: {first.message}",
        )


def workflow_document_digest(document: Mapping[str, Any]) -> str:
    return document_digest(document)


def _require_finite(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            _require_finite(child, f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _require_finite(child, f"{path}[{index}]")
        return
    if isinstance(value, float) and not math.isfinite(value):
        raise ProtocolError(
            "WORKFLOW_NUMBER_NONFINITE", f"non-finite number at {path}"
        )


def _parse_time(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ProtocolError("WORKFLOW_TIME_INVALID", f"invalid {label}") from exc
    if parsed.tzinfo is None:
        raise ProtocolError(
            "WORKFLOW_TIME_INVALID", f"{label} must include a timezone"
        )
    return parsed


def _require_unique_strings(
    values: list[str], *, code: str, detail: str, sorted_values: bool = True
) -> None:
    if len(values) != len(set(values)) or (
        sorted_values and values != sorted(values)
    ):
        raise ProtocolError(code, detail)


def _require_unique_names(values: list[Mapping[str, Any]], *, label: str) -> None:
    names = [str(value["name"]) for value in values]
    if len(names) != len(set(names)):
        raise ProtocolError(
            "WORKFLOW_NAME_DUPLICATE", f"{label} names must be unique"
        )


def _require_identity(
    identity: Mapping[str, Any],
    *,
    signature: Mapping[str, Any],
    project_id: str,
    label: str,
) -> None:
    dimensions = [str(identity[field]) for field in _IDENTITY_FIELDS]
    if len(dimensions) != len(set(dimensions)):
        raise ProtocolError(
            "WORKFLOW_IDENTITY_COLLAPSE",
            f"{label} identity dimensions must remain distinct",
        )
    if identity["project_id"] != project_id:
        raise ProtocolError(
            "WORKFLOW_IDENTITY_PROJECT_MISMATCH",
            f"{label} project does not match the workflow document",
        )
    if identity["key_id"] != signature["key_id"]:
        raise ProtocolError(
            "WORKFLOW_SIGNER_MISMATCH",
            f"{label} key does not match the document signature",
        )


@dataclass(frozen=True)
class _CanonicalWorkflowDocument:
    _document: dict[str, Any]

    schema_name: ClassVar[str]

    def __post_init__(self) -> None:
        object.__setattr__(self, "_document", copy.deepcopy(self._document))

    def as_dict(self) -> dict[str, Any]:
        return copy.deepcopy(self._document)

    @property
    def digest(self) -> str:
        return workflow_document_digest(self._document)

    def __getattr__(self, name: str) -> Any:
        document = object.__getattribute__(self, "_document")
        if name in document:
            return copy.deepcopy(document[name])
        raise AttributeError(name)


@dataclass(frozen=True)
class WorkflowDefinition(_CanonicalWorkflowDocument):
    schema_name: ClassVar[str] = "workflow-definition.v1.schema.json"

    @classmethod
    def from_dict(
        cls,
        document: Mapping[str, Any],
        *,
        verified_by: Mapping[str, Ed25519PublicKey] | None = None,
    ) -> "WorkflowDefinition":
        validate_workflow_document(cls.schema_name, document, verified_by=verified_by)
        candidate = copy.deepcopy(dict(document))
        _require_identity(
            candidate["publisher"],
            signature=candidate["signature"],
            project_id=candidate["project_id"],
            label="publisher",
        )
        step_ids = [str(step["step_id"]) for step in candidate["steps"]]
        if len(step_ids) != len(set(step_ids)):
            raise ProtocolError(
                "WORKFLOW_STEP_DUPLICATE", "workflow step IDs must be unique"
            )
        for step in candidate["steps"]:
            for name in ("dependencies", "required_capabilities"):
                _require_unique_strings(
                    step[name],
                    code="WORKFLOW_LIST_NONCANONICAL",
                    detail=f"step {name} must be unique and sorted",
                )
            for name in ("branches", "files"):
                _require_unique_strings(
                    step["ownership"][name],
                    code="WORKFLOW_OWNERSHIP_NONCANONICAL",
                    detail=f"owned {name} must be unique and sorted",
                )
            _require_unique_names(step["inputs"], label="input")
            _require_unique_names(step["outputs"], label="output")
            if step["target"]["project_id"] != candidate["project_id"]:
                raise ProtocolError(
                    "WORKFLOW_STEP_PROJECT_MISMATCH",
                    "step target project does not match definition project",
                )
        _require_unique_strings(
            candidate["metadata"]["tags"],
            code="WORKFLOW_TAGS_NONCANONICAL",
            detail="workflow tags must be unique and sorted",
        )
        _parse_time(candidate["created_at"], "created_at")
        return cls(candidate)


@dataclass(frozen=True)
class WorkflowRun(_CanonicalWorkflowDocument):
    schema_name: ClassVar[str] = "workflow-run.v1.schema.json"

    @classmethod
    def from_dict(
        cls,
        document: Mapping[str, Any],
        *,
        verified_by: Mapping[str, Ed25519PublicKey] | None = None,
    ) -> "WorkflowRun":
        validate_workflow_document(cls.schema_name, document, verified_by=verified_by)
        candidate = copy.deepcopy(dict(document))
        _require_identity(
            candidate["launched_by"],
            signature=candidate["signature"],
            project_id=candidate["project_id"],
            label="launcher",
        )
        if candidate["policy"]["mode"] != "ATTENDED":
            raise ProtocolError(
                "WORKFLOW_UNATTENDED_FORBIDDEN", "workflow runs must remain attended"
            )
        _parse_time(candidate["started_at"], "started_at")
        return cls(candidate)


@dataclass(frozen=True)
class WorkflowEvent(_CanonicalWorkflowDocument):
    schema_name: ClassVar[str] = "workflow-event.v1.schema.json"

    @classmethod
    def from_dict(
        cls,
        document: Mapping[str, Any],
        *,
        verified_by: Mapping[str, Ed25519PublicKey] | None = None,
    ) -> "WorkflowEvent":
        validate_workflow_document(cls.schema_name, document, verified_by=verified_by)
        candidate = copy.deepcopy(dict(document))
        _require_identity(
            candidate["actor"],
            signature=candidate["signature"],
            project_id=candidate["project_id"],
            label="event actor",
        )
        if document_digest(candidate["payload"]) != candidate["payload_sha256"]:
            raise ProtocolError(
                "WORKFLOW_EVENT_PAYLOAD_TAMPERED",
                "workflow event payload digest does not match payload",
            )
        event_type = candidate["event_type"]
        step_id = candidate["step_id"]
        attempt = candidate["attempt"]
        if event_type in _RUN_EVENTS and (step_id is not None or attempt is not None):
            raise ProtocolError(
                "WORKFLOW_EVENT_SCOPE_INVALID",
                "run-level events may not name a step or attempt",
            )
        if event_type in _ATTEMPT_EVENTS and (
            step_id is None or attempt is None
        ):
            raise ProtocolError(
                "WORKFLOW_EVENT_SCOPE_INVALID",
                "attempt events require both step and attempt",
            )
        if (step_id is None) != (attempt is None):
            raise ProtocolError(
                "WORKFLOW_EVENT_SCOPE_INVALID",
                "step and attempt must both be present or absent",
            )
        _parse_time(candidate["recorded_at"], "recorded_at")
        return cls(candidate)


@dataclass(frozen=True)
class WorkflowApproval(_CanonicalWorkflowDocument):
    schema_name: ClassVar[str] = "workflow-approval.v1.schema.json"

    @classmethod
    def from_dict(
        cls,
        document: Mapping[str, Any],
        *,
        verified_by: Mapping[str, Ed25519PublicKey] | None = None,
    ) -> "WorkflowApproval":
        validate_workflow_document(cls.schema_name, document, verified_by=verified_by)
        candidate = copy.deepcopy(dict(document))
        _require_identity(
            candidate["approver"],
            signature=candidate["signature"],
            project_id=candidate["project_id"],
            label="approver",
        )
        if (candidate["step_id"] is None) != (candidate["attempt"] is None):
            raise ProtocolError(
                "WORKFLOW_APPROVAL_SCOPE_INVALID",
                "approval step and attempt must both be present or absent",
            )
        decided = _parse_time(candidate["decided_at"], "decided_at")
        expires = _parse_time(candidate["expires_at"], "expires_at")
        if expires <= decided:
            raise ProtocolError(
                "WORKFLOW_APPROVAL_EXPIRY_INVALID",
                "workflow approval must expire after its decision time",
            )
        return cls(candidate)


@dataclass(frozen=True)
class AgentSession(_CanonicalWorkflowDocument):
    schema_name: ClassVar[str] = "agent-session.v1.schema.json"

    @classmethod
    def from_dict(
        cls,
        document: Mapping[str, Any],
        *,
        verified_by: Mapping[str, Ed25519PublicKey] | None = None,
    ) -> "AgentSession":
        validate_workflow_document(cls.schema_name, document, verified_by=verified_by)
        candidate = copy.deepcopy(dict(document))
        _require_identity(
            candidate["agent"],
            signature=candidate["signature"],
            project_id=candidate["project_id"],
            label="session agent",
        )
        progress = candidate["progress"]
        if progress["completed_units"] > progress["total_units"]:
            raise ProtocolError(
                "WORKFLOW_SESSION_PROGRESS_INVALID",
                "completed session units exceed total units",
            )
        _require_unique_names(candidate["outputs"], label="session output")
        _parse_time(candidate["heartbeat_at"], "heartbeat_at")
        _parse_time(candidate["recorded_at"], "recorded_at")
        return cls(candidate)
