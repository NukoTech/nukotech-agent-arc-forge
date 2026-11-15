"""Immutable canonical objects for bounded research workspaces and artifacts."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from importlib.resources import files
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker

from hive_protocol.adapters.security import reject_credential_values
from hive_protocol.core import ProtocolError, document_digest


_SCHEMA_NAMES = frozenset(
    {
        "research-workspace.v1.schema.json",
        "research-source-set.v1.schema.json",
        "research-artifact.v1.schema.json",
    }
)


def validate_research_document(
    schema_name: str, document: Mapping[str, Any]
) -> None:
    if schema_name not in _SCHEMA_NAMES:
        raise ProtocolError(
            "RESEARCH_DOCUMENT_SCHEMA_UNKNOWN",
            "unsupported research document schema",
        )
    candidate = copy.deepcopy(dict(document))
    reject_credential_values(candidate, location="research document")
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
            "RESEARCH_DOCUMENT_SCHEMA_INVALID",
            f"{location}: {first.message}",
        )


def research_document_digest(document: Mapping[str, Any]) -> str:
    return document_digest(document)


def _body(document: Mapping[str, Any], version: str) -> dict[str, Any]:
    if document.get("schema_version") != version:
        raise ProtocolError(
            "RESEARCH_DOCUMENT_VERSION", "unsupported research document version"
        )
    body = copy.deepcopy(dict(document))
    body.pop("schema_version")
    return body


@dataclass(frozen=True)
class ResearchWorkspace:
    workspace_id: str
    tenant_id: str
    project_id: str
    name: str
    privacy_class: str
    created_at: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "hive.research-workspace.v1",
            "workspace_id": self.workspace_id,
            "tenant_id": self.tenant_id,
            "project_id": self.project_id,
            "name": self.name,
            "privacy_class": self.privacy_class,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "ResearchWorkspace":
        validate_research_document("research-workspace.v1.schema.json", document)
        return cls(**_body(document, "hive.research-workspace.v1"))


@dataclass(frozen=True)
class ResearchSourceSet:
    source_set_id: str
    workspace_id: str
    tenant_id: str
    project_id: str
    parent_digest: str | None
    sources: list[dict[str, str]]
    retrieval_policy: dict[str, Any]
    created_at: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "sources", copy.deepcopy(self.sources))
        object.__setattr__(
            self, "retrieval_policy", copy.deepcopy(self.retrieval_policy)
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "hive.research-source-set.v1",
            "source_set_id": self.source_set_id,
            "workspace_id": self.workspace_id,
            "tenant_id": self.tenant_id,
            "project_id": self.project_id,
            "parent_digest": self.parent_digest,
            "sources": copy.deepcopy(self.sources),
            "retrieval_policy": copy.deepcopy(self.retrieval_policy),
            "created_at": self.created_at,
        }

    def digest(self) -> str:
        return research_document_digest(self.as_dict())

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "ResearchSourceSet":
        raw_sources = document.get("sources")
        if isinstance(raw_sources, list) and all(
            isinstance(item, Mapping) and isinstance(item.get("source_id"), str)
            for item in raw_sources
        ):
            raw_ids = [str(item["source_id"]) for item in raw_sources]
            if raw_ids != sorted(raw_ids) or len(raw_ids) != len(set(raw_ids)):
                raise ProtocolError(
                    "RESEARCH_SOURCE_SET_NONCANONICAL",
                    "research sources must be unique and sorted by source ID",
                )
        validate_research_document("research-source-set.v1.schema.json", document)
        body = _body(document, "hive.research-source-set.v1")
        source_ids = [item["source_id"] for item in body["sources"]]
        if source_ids != sorted(source_ids) or len(source_ids) != len(set(source_ids)):
            raise ProtocolError(
                "RESEARCH_SOURCE_SET_NONCANONICAL",
                "research sources must be unique and sorted by source ID",
            )
        return cls(**body)


@dataclass(frozen=True)
class ResearchArtifact:
    artifact_id: str
    workspace_id: str
    tenant_id: str
    project_id: str
    source_set_digest: str
    artifact_type: str
    status: str
    markdown_path: str
    markdown_sha256: str
    generator: dict[str, Any]
    provider_state: dict[str, Any]
    claims: list[dict[str, Any]]
    contradictions: list[dict[str, Any]]
    uncertainties: list[dict[str, Any]]
    verification_state: str
    created_at: str

    def __post_init__(self) -> None:
        for name in (
            "generator",
            "provider_state",
            "claims",
            "contradictions",
            "uncertainties",
        ):
            object.__setattr__(self, name, copy.deepcopy(getattr(self, name)))

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "hive.research-artifact.v1",
            "artifact_id": self.artifact_id,
            "workspace_id": self.workspace_id,
            "tenant_id": self.tenant_id,
            "project_id": self.project_id,
            "source_set_digest": self.source_set_digest,
            "artifact_type": self.artifact_type,
            "status": self.status,
            "markdown_path": self.markdown_path,
            "markdown_sha256": self.markdown_sha256,
            "generator": copy.deepcopy(self.generator),
            "provider_state": copy.deepcopy(self.provider_state),
            "claims": copy.deepcopy(self.claims),
            "contradictions": copy.deepcopy(self.contradictions),
            "uncertainties": copy.deepcopy(self.uncertainties),
            "verification_state": self.verification_state,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "ResearchArtifact":
        validate_research_document("research-artifact.v1.schema.json", document)
        body = _body(document, "hive.research-artifact.v1")
        if body["status"] == "ANSWERED" and (
            not body["claims"]
            or any(not claim["citation_anchor_ids"] for claim in body["claims"])
        ):
            raise ProtocolError(
                "RESEARCH_ARTIFACT_INVALID",
                "answered research artifacts require cited claims",
            )
        return cls(**body)
