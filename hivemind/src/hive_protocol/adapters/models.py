"""Immutable domain objects for the HiveMind application adapter contract."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from enum import Enum
from importlib.resources import files
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker

from hive_protocol.core import ProtocolError, document_digest


_SCHEMA_NAMES = frozenset(
    {
        "application-adapter-manifest.v1.schema.json",
        "adapter-request.v1.schema.json",
        "adapter-plan.v1.schema.json",
        "adapter-approval.v1.schema.json",
        "adapter-result.v1.schema.json",
        "adapter-ownership-manifest.v1.schema.json",
    }
)


class AdapterOutcome(str, Enum):
    APPLIED = "APPLIED"
    NO_OP = "NO_OP"
    REFUSED = "REFUSED"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"


def validate_adapter_document(schema_name: str, document: Mapping[str, Any]) -> None:
    if schema_name not in _SCHEMA_NAMES:
        raise ProtocolError("ADAPTER_DOCUMENT_SCHEMA_UNKNOWN", "unsupported adapter document schema")
    schema = json.loads(
        files("hive_protocol.schemas").joinpath(schema_name).read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.absolute_path))
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.absolute_path) or "$"
        raise ProtocolError(
            "ADAPTER_DOCUMENT_SCHEMA_INVALID",
            f"{location}: {first.message}",
        )


def adapter_document_digest(document: Mapping[str, Any]) -> str:
    return document_digest(document)


def _document_body(document: Mapping[str, Any], expected_version: str) -> dict[str, Any]:
    if document.get("schema_version") != expected_version:
        raise ProtocolError(
            "ADAPTER_DOCUMENT_VERSION",
            "unsupported adapter document version",
        )
    body = copy.deepcopy(dict(document))
    body.pop("schema_version")
    body.pop("signature", None)
    return body


@dataclass(frozen=True)
class AdapterRequest:
    request_id: str
    adapter_id: str
    adapter_version: str
    sender: dict[str, str]
    project_id: str
    capability_id: str
    data_classification: str
    authorization_ref: str
    evidence_sha256: list[str]
    payload: dict[str, Any]
    nonce: str
    expires_at: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "hive.adapter-request.v1",
            "request_id": self.request_id,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "sender": copy.deepcopy(self.sender),
            "project_id": self.project_id,
            "capability_id": self.capability_id,
            "data_classification": self.data_classification,
            "authorization_ref": self.authorization_ref,
            "evidence_sha256": list(self.evidence_sha256),
            "payload": copy.deepcopy(self.payload),
            "nonce": self.nonce,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "AdapterRequest":
        return cls(**_document_body(document, "hive.adapter-request.v1"))


@dataclass(frozen=True)
class AdapterPlan:
    plan_id: str
    request_digest: str
    manifest_digest: str
    policy_digest: str
    adapter_id: str
    adapter_version: str
    capability_id: str
    project_id: str
    side_effects: list[str]
    network_destinations: list[str]
    requires_approval: bool
    expires_at: str
    payload: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "hive.adapter-plan.v1",
            "plan_id": self.plan_id,
            "request_digest": self.request_digest,
            "manifest_digest": self.manifest_digest,
            "policy_digest": self.policy_digest,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "capability_id": self.capability_id,
            "project_id": self.project_id,
            "side_effects": list(self.side_effects),
            "network_destinations": list(self.network_destinations),
            "requires_approval": self.requires_approval,
            "expires_at": self.expires_at,
            "payload": copy.deepcopy(self.payload),
        }

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "AdapterPlan":
        return cls(**_document_body(document, "hive.adapter-plan.v1"))


@dataclass(frozen=True)
class AdapterApproval:
    approval_id: str
    plan_digest: str
    approver: dict[str, str]
    decision: str
    expires_at: str
    nonce: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "hive.adapter-approval.v1",
            "approval_id": self.approval_id,
            "plan_digest": self.plan_digest,
            "approver": copy.deepcopy(self.approver),
            "decision": self.decision,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
        }

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "AdapterApproval":
        return cls(**_document_body(document, "hive.adapter-approval.v1"))


@dataclass(frozen=True)
class AdapterResult:
    result_id: str
    request_digest: str
    plan_digest: str
    adapter_id: str
    adapter_version: str
    project_id: str
    outcome: str
    evidence_refs: list[dict[str, Any]]
    side_effects: list[str]
    resource_use: dict[str, Any]
    rollback_ref: str | None
    detail: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "hive.adapter-result.v1",
            "result_id": self.result_id,
            "request_digest": self.request_digest,
            "plan_digest": self.plan_digest,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "project_id": self.project_id,
            "outcome": self.outcome,
            "evidence_refs": copy.deepcopy(self.evidence_refs),
            "side_effects": list(self.side_effects),
            "resource_use": copy.deepcopy(self.resource_use),
            "rollback_ref": self.rollback_ref,
            "detail": copy.deepcopy(self.detail),
        }

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "AdapterResult":
        return cls(**_document_body(document, "hive.adapter-result.v1"))
