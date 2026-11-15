"""Closed, immutable M3.2 cognition and knowledge documents."""

from __future__ import annotations

import copy
import json
import math
from dataclasses import dataclass
from datetime import datetime
from importlib.resources import files
from pathlib import PurePosixPath
from typing import Any, ClassVar, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker

from hive_protocol.adapters.security import reject_credential_values
from hive_protocol.core import ProtocolError, document_digest


_SCHEMA_NAMES = frozenset(
    {
        "cognition-event.v1.schema.json",
        "memory-candidate.v1.schema.json",
        "memory-review-decision.v1.schema.json",
        "knowledge-node.v1.schema.json",
        "knowledge-edge.v1.schema.json",
        "memory-deletion-plan.v1.schema.json",
    }
)
_SCORE_KEYS = (
    "evidence_quality",
    "repetition",
    "recency",
    "project_relevance",
    "source_trust",
    "contradiction",
    "sensitivity",
)


def validate_cognition_document(
    schema_name: str,
    document: Mapping[str, Any],
    *,
    verified_by: Mapping[str, Ed25519PublicKey] | None = None,
) -> None:
    if schema_name not in _SCHEMA_NAMES:
        raise ProtocolError(
            "COGNITION_DOCUMENT_SCHEMA_UNKNOWN",
            "unsupported cognition document schema",
        )
    candidate = copy.deepcopy(dict(document))
    reject_credential_values(
        candidate, location="cognition document", verified_by=verified_by
    )
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
            "COGNITION_DOCUMENT_SCHEMA_INVALID",
            f"{location}: {first.message}",
        )


def cognition_document_digest(document: Mapping[str, Any]) -> str:
    return document_digest(document)


def _identity(document: Mapping[str, Any], prefix: str, fields: tuple[str, ...]) -> str:
    body = {name: copy.deepcopy(document.get(name)) for name in fields}
    return f"{prefix}:{document_digest(body)}"


def _require_unique(items: list[Any], *, code: str, detail: str) -> None:
    canonical = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in items]
    if len(canonical) != len(set(canonical)):
        raise ProtocolError(code, detail)


def _parse_time(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ProtocolError("COGNITION_TIME_INVALID", f"invalid {label}") from exc
    if parsed.tzinfo is None:
        raise ProtocolError("COGNITION_TIME_INVALID", f"{label} must include a timezone")
    return parsed


def _require_exact_identity(
    document: Mapping[str, Any], actual_field: str, expected: str
) -> None:
    if document.get(actual_field) != expected:
        raise ProtocolError(
            "COGNITION_IDENTITY_MISMATCH",
            f"{actual_field} does not bind the canonical document identity",
        )


@dataclass(frozen=True)
class _CanonicalDocument:
    _document: dict[str, Any]

    schema_name: ClassVar[str]

    def __post_init__(self) -> None:
        object.__setattr__(self, "_document", copy.deepcopy(self._document))

    def as_dict(self) -> dict[str, Any]:
        return copy.deepcopy(self._document)

    @property
    def digest(self) -> str:
        return cognition_document_digest(self._document)

    def __getattr__(self, name: str) -> Any:
        document = object.__getattribute__(self, "_document")
        if name in document:
            return copy.deepcopy(document[name])
        raise AttributeError(name)


@dataclass(frozen=True)
class CognitionEvent(_CanonicalDocument):
    schema_name: ClassVar[str] = "cognition-event.v1.schema.json"

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "CognitionEvent":
        validate_cognition_document(cls.schema_name, document)
        candidate = copy.deepcopy(dict(document))
        _require_unique(
            candidate["evidence"],
            code="COGNITION_EVIDENCE_DUPLICATE",
            detail="event evidence anchors must be unique",
        )
        _require_unique(
            candidate["structured_claims"],
            code="COGNITION_CLAIM_DUPLICATE",
            detail="structured event claims must be unique",
        )
        _parse_time(candidate["occurred_at"], "occurred_at")
        _parse_time(candidate["recorded_at"], "recorded_at")
        return cls(candidate)


@dataclass(frozen=True)
class MemoryCandidate(_CanonicalDocument):
    schema_name: ClassVar[str] = "memory-candidate.v1.schema.json"
    _identity_fields: ClassVar[tuple[str, ...]] = (
        "tenant_id",
        "project_id",
        "candidate_type",
        "proposed_action",
        "experience_scope",
        "subject_id",
        "claim",
        "supersedes",
        "revokes",
    )

    @classmethod
    def identity_for(cls, document: Mapping[str, Any]) -> str:
        return _identity(document, "memory", cls._identity_fields)

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "MemoryCandidate":
        validate_cognition_document(cls.schema_name, document)
        candidate = copy.deepcopy(dict(document))
        _require_exact_identity(candidate, "candidate_id", cls.identity_for(candidate))
        _require_unique(
            candidate["evidence"],
            code="COGNITION_EVIDENCE_DUPLICATE",
            detail="candidate evidence anchors must be unique",
        )
        event_ids = candidate["source_event_ids"]
        if event_ids != sorted(event_ids) or len(event_ids) != len(set(event_ids)):
            raise ProtocolError(
                "COGNITION_EVENT_SET_NONCANONICAL",
                "source event IDs must be unique and sorted",
            )
        action = candidate["proposed_action"]
        supersedes = candidate["supersedes"]
        revokes = candidate["revokes"]
        if (
            (action == "CREATE" and (supersedes is not None or revokes is not None))
            or (action == "CORRECT" and (supersedes is None or revokes is not None))
            or (action == "REVOKE" and (revokes is None or supersedes is not None))
        ):
            raise ProtocolError(
                "COGNITION_ACTION_TARGET_INVALID",
                "candidate action and correction/revocation targets disagree",
            )
        score = candidate["score"]
        features = score["features"]
        weights = score["weights"]
        total = score["total"]
        if (
            set(features) != set(_SCORE_KEYS)
            or set(weights) != set(_SCORE_KEYS)
            or not isinstance(total, (int, float))
            or isinstance(total, bool)
            or not math.isfinite(total)
        ):
            raise ProtocolError(
                "COGNITION_SCORE_INVALID", "candidate score is not canonical"
            )
        expected_total = round(
            sum(float(features[name]) * float(weights[name]) for name in _SCORE_KEYS),
            6,
        )
        if abs(float(total) - expected_total) > 0.000001:
            raise ProtocolError(
                "COGNITION_SCORE_INVALID",
                "candidate score does not match its explainable features and weights",
            )
        _parse_time(candidate["created_at"], "created_at")
        if candidate["retention_until"] is not None:
            _parse_time(candidate["retention_until"], "retention_until")
        return cls(candidate)


@dataclass(frozen=True)
class MemoryReviewDecision(_CanonicalDocument):
    schema_name: ClassVar[str] = "memory-review-decision.v1.schema.json"
    _identity_fields: ClassVar[tuple[str, ...]] = (
        "candidate_id",
        "candidate_sha256",
        "tenant_id",
        "project_id",
        "experience_scope",
        "outcome",
        "corrections",
        "reviewer",
        "reviewed_at",
        "expires_at",
    )

    @classmethod
    def identity_for(cls, document: Mapping[str, Any]) -> str:
        return _identity(document, "review", cls._identity_fields)

    @classmethod
    def from_dict(
        cls,
        document: Mapping[str, Any],
        *,
        verified_by: Mapping[str, Ed25519PublicKey] | None = None,
    ) -> "MemoryReviewDecision":
        validate_cognition_document(cls.schema_name, document, verified_by=verified_by)
        candidate = copy.deepcopy(dict(document))
        _require_exact_identity(candidate, "decision_id", cls.identity_for(candidate))
        reviewed = _parse_time(candidate["reviewed_at"], "reviewed_at")
        expires = _parse_time(candidate["expires_at"], "expires_at")
        if expires <= reviewed:
            raise ProtocolError(
                "COGNITION_REVIEW_EXPIRY_INVALID",
                "review decision must expire after review time",
            )
        if candidate["reviewer"]["key_id"] != candidate["signature"]["key_id"]:
            raise ProtocolError(
                "COGNITION_REVIEW_SIGNER_MISMATCH",
                "reviewer key does not match the decision signature",
            )
        return cls(candidate)


@dataclass(frozen=True)
class KnowledgeNode(_CanonicalDocument):
    schema_name: ClassVar[str] = "knowledge-node.v1.schema.json"
    _identity_fields: ClassVar[tuple[str, ...]] = (
        "tenant_id",
        "project_id",
        "experience_scope",
        "node_type",
        "title",
        "relative_path",
        "markdown_sha256",
        "claim",
        "evidence",
        "trust_state",
        "source_candidate_id",
        "review_decision_id",
        "supersedes",
        "revokes",
        "retention_until",
        "created_at",
    )

    @classmethod
    def identity_for(cls, document: Mapping[str, Any]) -> str:
        return _identity(document, "node", cls._identity_fields)

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "KnowledgeNode":
        validate_cognition_document(cls.schema_name, document)
        candidate = copy.deepcopy(dict(document))
        _require_exact_identity(candidate, "node_id", cls.identity_for(candidate))
        _require_unique(
            candidate["evidence"],
            code="COGNITION_EVIDENCE_DUPLICATE",
            detail="knowledge evidence anchors must be unique",
        )
        path = PurePosixPath(candidate["relative_path"])
        if (
            path.is_absolute()
            or not path.parts
            or any(part in {"", ".", ".."} for part in path.parts)
            or path.parts[0] != "prime"
            or path.suffix.lower() != ".md"
        ):
            raise ProtocolError(
                "KNOWLEDGE_PATH_INVALID", "knowledge node path is not a safe PRIME Markdown path"
            )
        _parse_time(candidate["created_at"], "created_at")
        if candidate["retention_until"] is not None:
            _parse_time(candidate["retention_until"], "retention_until")
        return cls(candidate)


@dataclass(frozen=True)
class KnowledgeEdge(_CanonicalDocument):
    schema_name: ClassVar[str] = "knowledge-edge.v1.schema.json"
    _identity_fields: ClassVar[tuple[str, ...]] = (
        "tenant_id",
        "project_id",
        "source_node_id",
        "target_node_id",
        "relation",
        "evidence_anchor_ids",
        "created_at",
    )

    @classmethod
    def identity_for(cls, document: Mapping[str, Any]) -> str:
        return _identity(document, "edge", cls._identity_fields)

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "KnowledgeEdge":
        validate_cognition_document(cls.schema_name, document)
        candidate = copy.deepcopy(dict(document))
        _require_exact_identity(candidate, "edge_id", cls.identity_for(candidate))
        anchors = candidate["evidence_anchor_ids"]
        if anchors != sorted(anchors) or len(anchors) != len(set(anchors)):
            raise ProtocolError(
                "KNOWLEDGE_EDGE_NONCANONICAL",
                "edge evidence anchor IDs must be unique and sorted",
            )
        _parse_time(candidate["created_at"], "created_at")
        return cls(candidate)


@dataclass(frozen=True)
class MemoryDeletionPlan(_CanonicalDocument):
    schema_name: ClassVar[str] = "memory-deletion-plan.v1.schema.json"
    _identity_fields: ClassVar[tuple[str, ...]] = (
        "node_id",
        "node_sha256",
        "tenant_id",
        "project_id",
        "experience_scope",
        "owned_paths",
        "risk_class",
        "checkpoint_required",
        "created_at",
        "expires_at",
    )

    @classmethod
    def identity_for(cls, document: Mapping[str, Any]) -> str:
        return _identity(document, "delete", cls._identity_fields)

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "MemoryDeletionPlan":
        validate_cognition_document(cls.schema_name, document)
        candidate = copy.deepcopy(dict(document))
        _require_exact_identity(candidate, "plan_id", cls.identity_for(candidate))
        paths = candidate["owned_paths"]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ProtocolError(
                "MEMORY_DELETION_PATH_INVALID",
                "deletion paths must be unique and sorted",
            )
        for value in paths:
            path = PurePosixPath(value)
            if (
                path.is_absolute()
                or not path.parts
                or any(part in {"", ".", ".."} for part in path.parts)
                or path.parts[0] != "prime"
                or path.suffix.lower() not in {".md", ".json"}
            ):
                raise ProtocolError(
                    "MEMORY_DELETION_PATH_INVALID",
                    "deletion plans may own only safe PRIME Markdown and JSON paths",
                )
        created = _parse_time(candidate["created_at"], "created_at")
        expires = _parse_time(candidate["expires_at"], "expires_at")
        if expires <= created:
            raise ProtocolError(
                "MEMORY_DELETION_EXPIRY_INVALID",
                "deletion plan must expire after creation",
            )
        return cls(candidate)
