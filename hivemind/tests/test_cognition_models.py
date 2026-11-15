from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from hive_protocol.cognition.models import (
    CognitionEvent,
    KnowledgeEdge,
    KnowledgeNode,
    MemoryCandidate,
    MemoryDeletionPlan,
    MemoryReviewDecision,
    cognition_document_digest,
)
from hive_protocol.core import ProtocolError, generate_keypair, load_private_key, sign_document


SHA_A = "a" * 64
SHA_B = "b" * 64
NOW = datetime(2026, 9, 1, 5, 30, tzinfo=timezone.utc)


def _evidence() -> list[dict[str, str]]:
    return [
        {
            "source_id": "source:alpha",
            "anchor_id": "anchor:alpha",
            "source_sha256": SHA_A,
            "normalized_sha256": SHA_B,
        }
    ]


def _event_document() -> dict[str, object]:
    return {
        "schema_version": "hive.cognition-event.v1",
        "event_id": str(uuid4()),
        "tenant_id": "local-user",
        "project_id": "HiveMind",
        "event_type": "PROJECT_EVENT",
        "privacy_class": "PROJECT_PRIVATE",
        "experience_scope": {"kind": "DOMAIN", "owner_id": "HiveMind"},
        "title": "Architecture decision",
        "text": "Decision: keep portable Markdown canonical.",
        "structured_claims": [
            {
                "candidate_type": "DECISION",
                "subject_id": "project:HiveMind",
                "key": "storage.canonical",
                "value": "portable Markdown",
                "narrative": "Portable Markdown remains canonical.",
                "proposed_action": "CREATE",
                "supersedes": None,
                "revokes": None,
            }
        ],
        "evidence": _evidence(),
        "source_ref": "project-event:architecture-1",
        "source_sha256": SHA_A,
        "occurred_at": NOW.isoformat().replace("+00:00", "Z"),
        "recorded_at": NOW.isoformat().replace("+00:00", "Z"),
    }


def _candidate_document(*, scope: str = "DOMAIN") -> dict[str, object]:
    document = {
        "schema_version": "hive.memory-candidate.v1",
        "candidate_id": "memory:placeholder",
        "tenant_id": "local-user",
        "project_id": "HiveMind",
        "candidate_type": "DECISION",
        "proposed_action": "CREATE",
        "experience_scope": {"kind": scope, "owner_id": "HiveMind"},
        "subject_id": "project:HiveMind",
        "claim": {
            "key": "storage.canonical",
            "value": "portable Markdown",
            "narrative": "Portable Markdown remains canonical.",
        },
        "evidence": _evidence(),
        "score": {
            "features": {
                "evidence_quality": 1.0,
                "repetition": 0.5,
                "recency": 1.0,
                "project_relevance": 1.0,
                "source_trust": 0.8,
                "contradiction": 0.0,
                "sensitivity": 0.2,
            },
            "weights": {
                "evidence_quality": 0.25,
                "repetition": 0.15,
                "recency": 0.15,
                "project_relevance": 0.15,
                "source_trust": 0.15,
                "contradiction": -0.1,
                "sensitivity": -0.05,
            },
            "total": 0.735,
        },
        "sensitivity": "INTERNAL",
        "contradictions": [],
        "status": "PROPOSED",
        "source_event_ids": [str(uuid4())],
        "extractor": {
            "id": "nukotech.hive.deterministic-extractor",
            "version": "1.0.0",
            "mode": "LOCAL_DETERMINISTIC",
        },
        "supersedes": None,
        "revokes": None,
        "retention_until": None,
        "created_at": NOW.isoformat().replace("+00:00", "Z"),
    }
    document["candidate_id"] = MemoryCandidate.identity_for(document)
    return document


def _signed_review_document(tmp_path) -> dict[str, object]:
    candidate = _candidate_document()
    _, _, key_id = generate_keypair(tmp_path, "reviewer")
    unsigned = {
        "schema_version": "hive.memory-review-decision.v1",
        "decision_id": "review:placeholder",
        "candidate_id": candidate["candidate_id"],
        "candidate_sha256": cognition_document_digest(candidate),
        "tenant_id": "local-user",
        "project_id": "HiveMind",
        "experience_scope": {"kind": "DOMAIN", "owner_id": "HiveMind"},
        "outcome": "APPROVED",
        "corrections": [],
        "reviewer": {
            "actor_id": "Owner",
            "authorization_ref": "attended-review:m32",
            "key_id": key_id,
        },
        "reviewed_at": NOW.isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(minutes=15)).isoformat().replace("+00:00", "Z"),
    }
    unsigned["decision_id"] = MemoryReviewDecision.identity_for(unsigned)
    return sign_document(unsigned, load_private_key(tmp_path / "reviewer.private.pem"))


def _node_document() -> dict[str, object]:
    candidate = _candidate_document()
    document = {
        "schema_version": "hive.knowledge-node.v1",
        "node_id": "node:placeholder",
        "tenant_id": "local-user",
        "project_id": "HiveMind",
        "experience_scope": {"kind": "DOMAIN", "owner_id": "HiveMind"},
        "node_type": "DECISION",
        "title": "Canonical storage decision",
        "relative_path": "prime/domain/HiveMind/storage.canonical.md",
        "markdown_sha256": SHA_A,
        "claim": copy.deepcopy(candidate["claim"]),
        "evidence": _evidence(),
        "trust_state": "REVIEWED",
        "source_candidate_id": candidate["candidate_id"],
        "review_decision_id": "review:" + "c" * 64,
        "supersedes": None,
        "revokes": None,
        "retention_until": None,
        "created_at": NOW.isoformat().replace("+00:00", "Z"),
    }
    document["node_id"] = KnowledgeNode.identity_for(document)
    return document


@pytest.mark.parametrize(
    ("model", "document"),
    [
        (CognitionEvent, _event_document()),
        (MemoryCandidate, _candidate_document()),
        (KnowledgeNode, _node_document()),
    ],
)
def test_cognition_models_round_trip_without_aliasing(model, document) -> None:
    value = model.from_dict(document)
    assert value.as_dict() == document
    returned = value.as_dict()
    if "evidence" in returned:
        returned["evidence"][0]["source_id"] = "source:changed"
        assert value.as_dict() == document


def test_review_decision_and_deletion_plan_round_trip(tmp_path) -> None:
    review = _signed_review_document(tmp_path)
    assert MemoryReviewDecision.from_dict(review).as_dict() == review

    node = _node_document()
    plan_document = {
        "schema_version": "hive.memory-deletion-plan.v1",
        "plan_id": "delete:placeholder",
        "node_id": node["node_id"],
        "node_sha256": cognition_document_digest(node),
        "tenant_id": "local-user",
        "project_id": "HiveMind",
        "experience_scope": {"kind": "DOMAIN", "owner_id": "HiveMind"},
        "owned_paths": [
            "prime/domain/HiveMind/storage.canonical.json",
            "prime/domain/HiveMind/storage.canonical.md",
        ],
        "risk_class": "HIGH",
        "checkpoint_required": True,
        "created_at": NOW.isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
    }
    plan_document["plan_id"] = MemoryDeletionPlan.identity_for(plan_document)
    assert MemoryDeletionPlan.from_dict(plan_document).as_dict() == plan_document


def test_knowledge_edge_has_stable_identity() -> None:
    node = _node_document()
    edge_document = {
        "schema_version": "hive.knowledge-edge.v1",
        "edge_id": "edge:placeholder",
        "tenant_id": "local-user",
        "project_id": "HiveMind",
        "source_node_id": node["node_id"],
        "target_node_id": "node:" + "d" * 64,
        "relation": "SUPERSEDES",
        "evidence_anchor_ids": ["anchor:alpha"],
        "created_at": NOW.isoformat().replace("+00:00", "Z"),
    }
    edge_document["edge_id"] = KnowledgeEdge.identity_for(edge_document)
    edge = KnowledgeEdge.from_dict(edge_document)
    assert edge.as_dict() == edge_document
    assert KnowledgeEdge.from_dict(edge.as_dict()).edge_id == edge.edge_id


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(schema_version="hive.memory-candidate.v2"),
        lambda value: value.update(project_id="../escape"),
        lambda value: value["experience_scope"].update(kind="UNKNOWN"),
        lambda value: value["score"].update(total=float("nan")),
        lambda value: value["evidence"].append(copy.deepcopy(value["evidence"][0])),
        lambda value: value.update(candidate_id="memory:" + "0" * 64),
        lambda value: value.update(revokes="node:" + "d" * 64),
    ],
)
def test_memory_candidate_rejects_noncanonical_or_scope_broadening(mutation) -> None:
    document = _candidate_document()
    mutation(document)
    with pytest.raises(ProtocolError):
        MemoryCandidate.from_dict(document)


def test_scope_is_part_of_candidate_identity() -> None:
    domain = _candidate_document(scope="DOMAIN")
    shared = _candidate_document(scope="SHARED")
    assert domain["candidate_id"] != shared["candidate_id"]


def test_review_decision_rejects_scope_or_candidate_digest_drift(tmp_path) -> None:
    document = _signed_review_document(tmp_path)
    document["experience_scope"]["kind"] = "SHARED"
    with pytest.raises(ProtocolError):
        MemoryReviewDecision.from_dict(document)


def test_deletion_plan_requires_sorted_unique_owned_regular_paths() -> None:
    node = _node_document()
    document = {
        "schema_version": "hive.memory-deletion-plan.v1",
        "plan_id": "delete:placeholder",
        "node_id": node["node_id"],
        "node_sha256": cognition_document_digest(node),
        "tenant_id": "local-user",
        "project_id": "HiveMind",
        "experience_scope": {"kind": "DOMAIN", "owner_id": "HiveMind"},
        "owned_paths": ["prime/domain/HiveMind/note.md", "../escape"],
        "risk_class": "HIGH",
        "checkpoint_required": True,
        "created_at": NOW.isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
    }
    document["plan_id"] = MemoryDeletionPlan.identity_for(document)
    with pytest.raises(ProtocolError):
        MemoryDeletionPlan.from_dict(document)
