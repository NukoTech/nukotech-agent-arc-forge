from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from hive_protocol.cognition.authority import CognitionAuthority
from hive_protocol.cognition.extraction import DeterministicCognitionExtractor
from hive_protocol.cognition.models import MemoryCandidate
from hive_protocol.cognition.promotion import CognitionPromotionService
from hive_protocol.cognition.retention import CognitionRetentionService
from hive_protocol.cognition.store import CognitionStore
from hive_protocol.core import verify_document
from hive_protocol.storage import read_json

from test_cognition_promotion import NOW, _event


def _retained_node(root: Path, retention_until: datetime):
    authority = CognitionAuthority(root, trusted_reviewer_actors={"Owner"})
    store = CognitionStore(root, authority)
    event = _event()
    extracted = DeterministicCognitionExtractor().extract(event, now=NOW).candidates[0]
    document = extracted.as_dict()
    document["retention_until"] = retention_until.isoformat().replace("+00:00", "Z")
    candidate = MemoryCandidate.from_dict(document)
    store.stage(event, candidate)
    decision = authority.create_review(
        candidate,
        outcome="APPROVED",
        actor_id="Owner",
        authorization_ref="attended:m32",
        corrections=[],
        now=NOW,
    )
    store.record_review(decision, now=NOW)
    result = CognitionPromotionService(root, store, authority).promote(
        candidate.candidate_id, now=NOW
    )
    return authority, result["node"]


def test_retention_expiry_creates_signed_review_request_without_deletion(tmp_path: Path) -> None:
    authority, node = _retained_node(tmp_path, NOW - timedelta(days=1))
    markdown = tmp_path / node["relative_path"]
    before = markdown.read_bytes()
    requests = CognitionRetentionService(tmp_path, authority).scan(
        now=NOW, project_id="HiveMind"
    )
    assert len(requests) == 1
    request = requests[0]
    assert request["action"] == "REVIEW_REQUIRED"
    assert request["automatic_delete"] is False
    assert request["node_id"] == node["node_id"]
    assert markdown.read_bytes() == before
    stored = read_json(tmp_path / request["request_path"])
    verify_document(stored, {authority.proposer_key_id: authority.proposer_public_key})


def test_future_retention_is_ignored_and_expired_scan_replays_one_request(tmp_path: Path) -> None:
    authority, _ = _retained_node(tmp_path, NOW + timedelta(days=30))
    service = CognitionRetentionService(tmp_path, authority)
    assert service.scan(now=NOW, project_id="HiveMind") == []
    first = service.scan(now=NOW + timedelta(days=31), project_id="HiveMind")
    second = service.scan(now=NOW + timedelta(days=32), project_id="HiveMind")
    assert first == second
    assert len(list((tmp_path / "staging" / "memory" / "reviews" / "retention").glob("*.json"))) == 1
