from __future__ import annotations

import copy

import pytest

from hive_protocol.core import ProtocolError
from hive_protocol.research.models import (
    ResearchArtifact,
    ResearchSourceSet,
    ResearchWorkspace,
    research_document_digest,
    validate_research_document,
)


SOURCE_A = {
    "source_id": "source:alpha",
    "source_record_digest": "a" * 64,
}
SOURCE_B = {
    "source_id": "source:beta",
    "source_record_digest": "b" * 64,
}


def workspace_document() -> dict:
    return {
        "schema_version": "hive.research-workspace.v1",
        "workspace_id": "research:alpha",
        "tenant_id": "tenant:local",
        "project_id": "HiveMind",
        "name": "Alpha Research",
        "privacy_class": "PROJECT_PRIVATE",
        "created_at": "2026-08-31T22:00:00-05:00",
    }


def source_set_document() -> dict:
    return {
        "schema_version": "hive.research-source-set.v1",
        "source_set_id": "source-set:alpha-v1",
        "workspace_id": "research:alpha",
        "tenant_id": "tenant:local",
        "project_id": "HiveMind",
        "parent_digest": None,
        "sources": [copy.deepcopy(SOURCE_A), copy.deepcopy(SOURCE_B)],
        "retrieval_policy": {
            "exact_first": True,
            "semantic_allowed": False,
            "max_results": 10,
            "max_quote_bytes": 2048,
        },
        "created_at": "2026-08-31T22:00:01-05:00",
    }


def artifact_document() -> dict:
    return {
        "schema_version": "hive.research-artifact.v1",
        "artifact_id": "artifact:alpha-answer",
        "workspace_id": "research:alpha",
        "tenant_id": "tenant:local",
        "project_id": "HiveMind",
        "source_set_digest": research_document_digest(source_set_document()),
        "artifact_type": "CITED_ANSWER",
        "status": "ANSWERED",
        "markdown_path": "research/workspaces/research-alpha/artifacts/answer.md",
        "markdown_sha256": "c" * 64,
        "generator": {"kind": "LOCAL_PROVIDER", "id": "test-provider"},
        "provider_state": {"available": True, "reason": "AVAILABLE"},
        "claims": [
            {
                "text": "The frozen parent is the rollback target.",
                "citation_anchor_ids": ["anchor:alpha"],
                "uncertainty": None,
            }
        ],
        "contradictions": [],
        "uncertainties": [],
        "verification_state": "VERIFIED",
        "created_at": "2026-08-31T22:00:02-05:00",
    }


def test_research_workspace_round_trip_is_immutable() -> None:
    document = workspace_document()
    model = ResearchWorkspace.from_dict(document)
    document["name"] = "mutated"
    assert model.as_dict() == workspace_document()
    validate_research_document("research-workspace.v1.schema.json", model.as_dict())


def test_source_set_is_canonical_and_has_stable_digest() -> None:
    document = source_set_document()
    model = ResearchSourceSet.from_dict(document)
    document["sources"][0]["source_id"] = "mutated"

    restored = model.as_dict()
    assert restored == source_set_document()
    assert model.digest() == research_document_digest(restored)
    assert model.digest() == ResearchSourceSet.from_dict(restored).digest()


def test_source_set_rejects_noncanonical_order_and_duplicate_sources() -> None:
    reordered = source_set_document()
    reordered["sources"].reverse()
    with pytest.raises(ProtocolError, match="RESEARCH_SOURCE_SET_NONCANONICAL"):
        ResearchSourceSet.from_dict(reordered)

    duplicate = source_set_document()
    duplicate["sources"] = [copy.deepcopy(SOURCE_A), copy.deepcopy(SOURCE_A)]
    with pytest.raises(ProtocolError, match="RESEARCH_SOURCE_SET_NONCANONICAL"):
        ResearchSourceSet.from_dict(duplicate)


def test_artifact_round_trip_retains_exact_source_set_and_citations() -> None:
    document = artifact_document()
    artifact = ResearchArtifact.from_dict(document)
    document["claims"][0]["citation_anchor_ids"].append("anchor:mutated")
    assert artifact.as_dict() == artifact_document()
    validate_research_document("research-artifact.v1.schema.json", artifact.as_dict())


@pytest.mark.parametrize(
    ("schema_name", "document"),
    [
        ("research-workspace.v1.schema.json", workspace_document()),
        ("research-source-set.v1.schema.json", source_set_document()),
        ("research-artifact.v1.schema.json", artifact_document()),
    ],
)
def test_research_schemas_reject_unknown_fields(schema_name: str, document: dict) -> None:
    document["authority_override"] = "admin"
    with pytest.raises(ProtocolError, match="RESEARCH_DOCUMENT_SCHEMA_INVALID"):
        validate_research_document(schema_name, document)


def test_research_documents_reject_credential_shaped_metadata() -> None:
    document = artifact_document()
    document["generator"]["id"] = "token=not-a-real-secret-value"
    with pytest.raises(ProtocolError, match="ADAPTER_CREDENTIAL_VALUE_DENIED"):
        ResearchArtifact.from_dict(document)


def test_artifact_rejects_claims_without_citations_when_answered() -> None:
    document = artifact_document()
    document["claims"][0]["citation_anchor_ids"] = []
    with pytest.raises(ProtocolError, match="RESEARCH_ARTIFACT_INVALID"):
        ResearchArtifact.from_dict(document)


def test_retrieval_only_artifact_may_have_no_claims() -> None:
    document = artifact_document()
    document["status"] = "RETRIEVAL_ONLY"
    document["claims"] = []
    document["verification_state"] = "RETRIEVAL_VERIFIED"
    validate_research_document("research-artifact.v1.schema.json", document)
    assert ResearchArtifact.from_dict(document).as_dict() == document
