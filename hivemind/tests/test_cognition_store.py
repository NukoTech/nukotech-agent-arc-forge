from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from hive_protocol.cognition.authority import CognitionAuthority
from hive_protocol.cognition.extraction import DeterministicCognitionExtractor
from hive_protocol.cognition.models import CognitionEvent
from hive_protocol.cognition.store import CognitionStore
from hive_protocol.core import ProtocolError, verify_document
from hive_protocol.storage import read_json


NOW = datetime(2026, 9, 1, 7, 30, tzinfo=timezone.utc)


def _event(*, event_id: str | None = None) -> CognitionEvent:
    return CognitionEvent.from_dict(
        {
            "schema_version": "hive.cognition-event.v1",
            "event_id": event_id or str(uuid4()),
            "tenant_id": "local-user",
            "project_id": "HiveMind",
            "event_type": "PROJECT_EVENT",
            "privacy_class": "PROJECT_PRIVATE",
            "experience_scope": {"kind": "DOMAIN", "owner_id": "HiveMind"},
            "title": "Decision",
            "text": "Decision: keep memory reviewed.",
            "structured_claims": [],
            "evidence": [
                {
                    "source_id": "source:alpha",
                    "anchor_id": "anchor:alpha",
                    "source_sha256": "a" * 64,
                    "normalized_sha256": "b" * 64,
                }
            ],
            "source_ref": "project-event:alpha",
            "source_sha256": "a" * 64,
            "occurred_at": NOW.isoformat().replace("+00:00", "Z"),
            "recorded_at": NOW.isoformat().replace("+00:00", "Z"),
        }
    )


def _candidate(event: CognitionEvent):
    return DeterministicCognitionExtractor().extract(event, now=NOW).candidates[0]


def test_stage_writes_candidate_markdown_provenance_and_signed_receipt_only(tmp_path: Path) -> None:
    authority = CognitionAuthority(tmp_path)
    store = CognitionStore(tmp_path, authority)
    event = _event()
    candidate = _candidate(event)
    result = store.stage(event, candidate)

    assert result["outcome"] == "STAGED"
    assert not (tmp_path / "prime").exists()
    candidate_path = tmp_path / result["candidate_path"]
    markdown_path = tmp_path / result["markdown_path"]
    provenance_path = tmp_path / result["provenance_path"]
    receipt_path = tmp_path / result["receipt_path"]
    assert candidate_path.is_file() and markdown_path.is_file()
    assert provenance_path.is_file() and receipt_path.is_file()
    assert store.load_candidate(candidate.candidate_id).as_dict() == candidate.as_dict()
    receipt = read_json(receipt_path)
    verify_document(receipt, {authority.proposer_key_id: authority.proposer_public_key})
    assert receipt["prime_write"] is False
    assert receipt["candidate_sha256"] == candidate.digest


def test_duplicate_claim_preserves_distinct_event_provenance_without_rewrite(tmp_path: Path) -> None:
    authority = CognitionAuthority(tmp_path)
    store = CognitionStore(tmp_path, authority)
    first_event = _event()
    first_candidate = _candidate(first_event)
    first = store.stage(first_event, first_candidate)
    before = (tmp_path / first["candidate_path"]).read_bytes()

    second_event = _event()
    second_candidate = _candidate(second_event)
    assert first_candidate.candidate_id == second_candidate.candidate_id
    second = store.stage(second_event, second_candidate)

    assert second["outcome"] == "DUPLICATE_PROVENANCE"
    assert (tmp_path / first["candidate_path"]).read_bytes() == before
    assert len(store.proposal_receipts(first_candidate.candidate_id)) == 2
    event_paths = sorted(
        (tmp_path / ".hive" / "provenance" / "memory" / first_candidate.candidate_id.split(":", 1)[1] / "events").glob("*.json")
    )
    assert len(event_paths) == 2


@pytest.mark.parametrize(
    "fault_point",
    ["journal-written", "candidate-written", "markdown-written", "provenance-written", "receipt-written"],
)
def test_stage_recovers_every_multifile_crash_window(tmp_path: Path, fault_point: str) -> None:
    authority = CognitionAuthority(tmp_path)
    event = _event()
    candidate = _candidate(event)
    fired = False

    def fault(point: str) -> None:
        nonlocal fired
        if point == fault_point and not fired:
            fired = True
            raise RuntimeError("simulated crash")

    with pytest.raises(RuntimeError, match="simulated crash"):
        CognitionStore(tmp_path, authority, fault_hook=fault).stage(event, candidate)
    result = CognitionStore(tmp_path, authority).stage(event, candidate)
    assert result["outcome"] == "STAGED"
    assert len(CognitionStore(tmp_path, authority).proposal_receipts(candidate.candidate_id)) == 1
    assert not (tmp_path / "prime").exists()


def test_stage_refuses_event_binding_drift_and_symlink_lane(tmp_path: Path) -> None:
    authority = CognitionAuthority(tmp_path)
    store = CognitionStore(tmp_path, authority)
    event = _event()
    candidate = _candidate(event)
    another = _event()
    with pytest.raises(ProtocolError):
        store.stage(another, candidate)

    staging = tmp_path / "staging"
    staging.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (staging / "memory").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ProtocolError):
        store.stage(event, candidate)


def test_review_record_is_replay_safe_and_conflicting_second_decision_refuses(tmp_path: Path) -> None:
    authority = CognitionAuthority(tmp_path, trusted_reviewer_actors={"Owner"})
    store = CognitionStore(tmp_path, authority)
    event = _event()
    candidate = _candidate(event)
    store.stage(event, candidate)
    decision = authority.create_review(
        candidate,
        outcome="APPROVED",
        actor_id="Owner",
        authorization_ref="attended:m32",
        corrections=[],
        now=NOW,
    )
    assert store.record_review(decision, now=NOW)["outcome"] == "RECORDED"
    assert store.record_review(decision, now=NOW)["outcome"] == "REPLAYED"

    rejected = authority.create_review(
        candidate,
        outcome="REJECTED",
        actor_id="Owner",
        authorization_ref="attended:m32",
        corrections=["Insufficient evidence"],
        now=NOW + timedelta(seconds=1),
    )
    with pytest.raises(ProtocolError, match="already"):
        store.record_review(rejected, now=NOW + timedelta(seconds=1))


def test_tampered_candidate_and_receipt_refuse_review(tmp_path: Path) -> None:
    authority = CognitionAuthority(tmp_path, trusted_reviewer_actors={"Owner"})
    store = CognitionStore(tmp_path, authority)
    event = _event()
    candidate = _candidate(event)
    staged = store.stage(event, candidate)
    decision = authority.create_review(
        candidate,
        outcome="APPROVED",
        actor_id="Owner",
        authorization_ref="attended:m32",
        corrections=[],
        now=NOW,
    )
    receipt_path = tmp_path / staged["receipt_path"]
    receipt = read_json(receipt_path)
    receipt["prime_write"] = True
    receipt_path.write_text(__import__("json").dumps(receipt), encoding="utf-8")
    with pytest.raises(ProtocolError):
        store.record_review(decision, now=NOW)
