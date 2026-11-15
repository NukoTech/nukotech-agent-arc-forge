from __future__ import annotations

from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import pytest

from hive_protocol.cognition.authority import CognitionAuthority
from hive_protocol.cognition.extraction import DeterministicCognitionExtractor
from hive_protocol.cognition.models import CognitionEvent, KnowledgeNode
from hive_protocol.cognition.promotion import CognitionPromotionService
from hive_protocol.cognition.store import CognitionStore
from hive_protocol.core import ProtocolError, verify_document
from hive_protocol.storage import read_json


NOW = datetime(2026, 9, 1, 8, 0, tzinfo=timezone.utc)


def _event(
    *,
    key: str = "storage.canonical",
    value="portable Markdown",
    narrative: str = "Portable Markdown remains canonical.",
    action: str = "CREATE",
    supersedes: str | None = None,
    revokes: str | None = None,
    scope: dict | None = None,
) -> CognitionEvent:
    return CognitionEvent.from_dict(
        {
            "schema_version": "hive.cognition-event.v1",
            "event_id": str(uuid4()),
            "tenant_id": "local-user",
            "project_id": "HiveMind",
            "event_type": "PROJECT_EVENT",
            "privacy_class": "PROJECT_PRIVATE",
            "experience_scope": scope or {"kind": "DOMAIN", "owner_id": "HiveMind"},
            "title": "Memory event",
            "text": "",
            "structured_claims": [
                {
                    "candidate_type": "CORRECTION" if action != "CREATE" else "DECISION",
                    "subject_id": "project:HiveMind",
                    "key": key,
                    "value": value,
                    "narrative": narrative,
                    "proposed_action": action,
                    "supersedes": supersedes,
                    "revokes": revokes,
                }
            ],
            "evidence": [
                {
                    "source_id": "source:alpha",
                    "anchor_id": "anchor:" + uuid4().hex,
                    "source_sha256": "a" * 64,
                    "normalized_sha256": "b" * 64,
                }
            ],
            "source_ref": "project-event:" + uuid4().hex,
            "source_sha256": "a" * 64,
            "occurred_at": NOW.isoformat().replace("+00:00", "Z"),
            "recorded_at": NOW.isoformat().replace("+00:00", "Z"),
        }
    )


def _stage_review(
    root: Path,
    authority: CognitionAuthority,
    event: CognitionEvent,
    *,
    outcome: str = "APPROVED",
):
    store = CognitionStore(root, authority)
    candidate = DeterministicCognitionExtractor().extract(event, now=NOW).candidates[0]
    store.stage(event, candidate)
    decision = authority.create_review(
        candidate,
        outcome=outcome,
        actor_id="Owner",
        authorization_ref="attended:m32",
        corrections=[] if outcome == "APPROVED" else ["Needs more evidence"],
        now=NOW,
    )
    store.record_review(decision, now=NOW)
    return store, candidate, decision


def test_approved_candidate_promotes_into_exact_scope_with_signed_receipt(tmp_path: Path) -> None:
    authority = CognitionAuthority(tmp_path, trusted_reviewer_actors={"Owner"})
    store, candidate, decision = _stage_review(tmp_path, authority, _event())
    result = CognitionPromotionService(tmp_path, store, authority).promote(
        candidate.candidate_id, now=NOW
    )

    assert result["outcome"] == "PROMOTED"
    node = KnowledgeNode.from_dict(result["node"])
    assert node.experience_scope == {"kind": "DOMAIN", "owner_id": "HiveMind"}
    assert node.relative_path.startswith("prime/domain/HiveMind/")
    assert (tmp_path / node.relative_path).is_file()
    assert (tmp_path / result["sidecar_path"]).is_file()
    assert not (tmp_path / "prime" / "shared").exists()
    receipt = read_json(tmp_path / result["receipt_path"])
    verify_document(receipt, {authority.promoter_key_id: authority.promoter_public_key})
    assert receipt["candidate_sha256"] == candidate.digest
    assert receipt["review_decision_id"] == decision.decision_id
    assert receipt["node_sha256"] == node.digest


def test_promotion_requires_approved_authenticated_review(tmp_path: Path) -> None:
    authority = CognitionAuthority(tmp_path, trusted_reviewer_actors={"Owner"})
    store = CognitionStore(tmp_path, authority)
    event = _event()
    candidate = DeterministicCognitionExtractor().extract(event, now=NOW).candidates[0]
    store.stage(event, candidate)
    with pytest.raises(ProtocolError):
        CognitionPromotionService(tmp_path, store, authority).promote(
            candidate.candidate_id, now=NOW
        )

    store, candidate, _ = _stage_review(
        tmp_path / "rejected",
        CognitionAuthority(
            tmp_path / "rejected", trusted_reviewer_actors={"Owner"}
        ),
        _event(),
        outcome="REJECTED",
    )
    with pytest.raises(ProtocolError, match="approved"):
        CognitionPromotionService(
            tmp_path / "rejected", store, store.authority
        ).promote(candidate.candidate_id, now=NOW)


def test_correction_creates_new_node_and_preserves_target(tmp_path: Path) -> None:
    authority = CognitionAuthority(tmp_path, trusted_reviewer_actors={"Owner"})
    store, original_candidate, _ = _stage_review(tmp_path, authority, _event())
    service = CognitionPromotionService(tmp_path, store, authority)
    original = KnowledgeNode.from_dict(
        service.promote(original_candidate.candidate_id, now=NOW)["node"]
    )
    original_bytes = (tmp_path / original.relative_path).read_bytes()

    correction_event = _event(
        value="portable Markdown plus JSON sidecars",
        narrative="Portable Markdown and canonical sidecars remain authoritative.",
        action="CORRECT",
        supersedes=original.node_id,
    )
    _, correction_candidate, _ = _stage_review(
        tmp_path, authority, correction_event
    )
    corrected_result = service.promote(correction_candidate.candidate_id, now=NOW)
    corrected = KnowledgeNode.from_dict(corrected_result["node"])

    assert corrected.supersedes == original.node_id
    assert corrected.revokes is None
    assert (tmp_path / original.relative_path).read_bytes() == original_bytes
    assert corrected_result["edge"]["relation"] == "SUPERSEDES"
    assert (tmp_path / corrected_result["edge_path"]).is_file()


def test_revocation_is_a_new_audit_node_and_preserves_target(tmp_path: Path) -> None:
    authority = CognitionAuthority(tmp_path, trusted_reviewer_actors={"Owner"})
    store, original_candidate, _ = _stage_review(tmp_path, authority, _event())
    service = CognitionPromotionService(tmp_path, store, authority)
    original = KnowledgeNode.from_dict(
        service.promote(original_candidate.candidate_id, now=NOW)["node"]
    )
    original_bytes = (tmp_path / original.relative_path).read_bytes()
    revoke_event = _event(
        value=False,
        narrative="This claim is revoked from current retrieval.",
        action="REVOKE",
        revokes=original.node_id,
    )
    _, revoke_candidate, _ = _stage_review(tmp_path, authority, revoke_event)
    revoked_result = service.promote(revoke_candidate.candidate_id, now=NOW)
    revoked = KnowledgeNode.from_dict(revoked_result["node"])
    assert revoked.node_type == "REVOCATION"
    assert revoked.revokes == original.node_id
    assert revoked_result["edge"]["relation"] == "REVOKES"
    assert (tmp_path / original.relative_path).read_bytes() == original_bytes


def test_correction_cannot_cross_project_or_scope(tmp_path: Path) -> None:
    authority = CognitionAuthority(tmp_path, trusted_reviewer_actors={"Owner"})
    store, candidate, _ = _stage_review(tmp_path, authority, _event())
    service = CognitionPromotionService(tmp_path, store, authority)
    original = KnowledgeNode.from_dict(service.promote(candidate.candidate_id, now=NOW)["node"])
    event = _event(
        action="CORRECT",
        supersedes=original.node_id,
        scope={"kind": "SHARED", "owner_id": "HiveMind"},
    )
    _, correction, _ = _stage_review(tmp_path, authority, event)
    with pytest.raises(ProtocolError, match="scope"):
        service.promote(correction.candidate_id, now=NOW)


@pytest.mark.parametrize(
    "fault_point",
    ["journal-written", "markdown-written", "sidecar-written", "edge-written", "receipt-written"],
)
def test_promotion_recovers_every_crash_window_without_duplicate_effects(
    tmp_path: Path, fault_point: str
) -> None:
    authority = CognitionAuthority(tmp_path, trusted_reviewer_actors={"Owner"})
    store, candidate, _ = _stage_review(tmp_path, authority, _event())
    fired = False

    def fault(point: str) -> None:
        nonlocal fired
        if point == fault_point and not fired:
            fired = True
            raise RuntimeError("simulated crash")

    with pytest.raises(RuntimeError, match="simulated crash"):
        CognitionPromotionService(
            tmp_path, store, authority, fault_hook=fault
        ).promote(candidate.candidate_id, now=NOW)
    recovered = CognitionPromotionService(tmp_path, store, authority).promote(
        candidate.candidate_id, now=NOW
    )
    replayed = CognitionPromotionService(tmp_path, store, authority).promote(
        candidate.candidate_id, now=NOW
    )
    assert recovered == replayed
    assert len(list((tmp_path / "prime").rglob("*.md"))) == 1
    assert len(list((tmp_path / "prime").rglob("*.json"))) == 1


@pytest.mark.parametrize(
    "fault_point",
    ["journal-written", "markdown-written", "sidecar-written", "edge-written", "receipt-written"],
)
def test_correction_recovers_with_pending_sidecar_excluded_from_current_projection(
    tmp_path: Path, fault_point: str
) -> None:
    authority = CognitionAuthority(tmp_path, trusted_reviewer_actors={"Owner"})
    store, original_candidate, _ = _stage_review(tmp_path, authority, _event())
    original_service = CognitionPromotionService(tmp_path, store, authority)
    original = KnowledgeNode.from_dict(
        original_service.promote(original_candidate.candidate_id, now=NOW)["node"]
    )
    _, correction_candidate, _ = _stage_review(
        tmp_path,
        authority,
        _event(
            action="CORRECT",
            supersedes=original.node_id,
            value="portable Markdown and sidecars",
            narrative="Portable Markdown and sidecars are canonical.",
        ),
    )
    fired = False

    def fault(point: str) -> None:
        nonlocal fired
        if point == fault_point and not fired:
            fired = True
            raise RuntimeError("simulated crash")

    with pytest.raises(RuntimeError, match="simulated crash"):
        CognitionPromotionService(
            tmp_path, store, authority, fault_hook=fault
        ).promote(correction_candidate.candidate_id, now=NOW)
    recovered = CognitionPromotionService(tmp_path, store, authority).promote(
        correction_candidate.candidate_id, now=NOW
    )
    assert recovered["node"]["supersedes"] == original.node_id
    assert len(list((tmp_path / "prime").rglob("*.md"))) == 2


def test_promotion_refuses_changed_candidate_after_review(tmp_path: Path) -> None:
    authority = CognitionAuthority(tmp_path, trusted_reviewer_actors={"Owner"})
    store, candidate, _ = _stage_review(tmp_path, authority, _event())
    candidate_path = next((tmp_path / "staging" / "memory" / "candidates").glob("*.json"))
    document = read_json(candidate_path)
    document["claim"]["narrative"] = "tampered"
    candidate_path.write_text(__import__("json").dumps(document), encoding="utf-8")
    with pytest.raises(ProtocolError):
        CognitionPromotionService(tmp_path, store, authority).promote(
            candidate.candidate_id, now=NOW
        )


def test_concurrent_promotion_converges_on_one_receipted_node(tmp_path: Path) -> None:
    authority = CognitionAuthority(tmp_path, trusted_reviewer_actors={"Owner"})
    store, candidate, _ = _stage_review(tmp_path, authority, _event())

    def apply_once(_index: int):
        return CognitionPromotionService(tmp_path, store, authority).promote(
            candidate.candidate_id, now=NOW
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(apply_once, range(16)))
    assert all(result == results[0] for result in results)
    assert len(list((tmp_path / "prime").rglob("*.md"))) == 1
    assert len(list((tmp_path / ".hive" / "receipts").glob("cognition-promotion-*.json"))) == 1
