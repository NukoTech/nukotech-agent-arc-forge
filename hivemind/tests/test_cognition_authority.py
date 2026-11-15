from __future__ import annotations

import copy
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from hive_protocol.cognition.authority import CognitionAuthority
from hive_protocol.cognition.extraction import DeterministicCognitionExtractor
from hive_protocol.cognition.models import CognitionEvent, MemoryReviewDecision
from hive_protocol.core import ProtocolError, sign_document


NOW = datetime(2026, 9, 1, 7, 0, tzinfo=timezone.utc)


def _candidate():
    event = CognitionEvent.from_dict(
        {
            "schema_version": "hive.cognition-event.v1",
            "event_id": str(uuid4()),
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
    return DeterministicCognitionExtractor().extract(event, now=NOW).candidates[0]


def _proposal_receipt(authority: CognitionAuthority, candidate) -> dict:
    return authority.sign_proposal(
        {
            "schema_version": "hive.memory-candidate-receipt.v1",
            "operation_id": "c" * 64,
            "candidate_id": candidate.candidate_id,
            "candidate_sha256": candidate.digest,
            "proposed_candidate_sha256": candidate.digest,
            "event_id": candidate.source_event_ids[0],
            "event_sha256": "d" * 64,
            "outcome": "STAGED",
            "owned_paths": ["staging/memory/candidates/example.json"],
            "prime_write": False,
            "recorded_at": NOW.isoformat().replace("+00:00", "Z"),
        }
    )


def test_authority_bootstraps_three_distinct_private_roles(tmp_path: Path) -> None:
    authority = CognitionAuthority(tmp_path)
    assert len(
        {
            authority.proposer_key_id,
            authority.reviewer_key_id,
            authority.promoter_key_id,
        }
    ) == 3
    for label in ("proposer", "reviewer", "promoter"):
        path = tmp_path / ".hive" / "keys" / "cognition" / f"{label}.private.pem"
        assert path.is_file()
        assert path.stat().st_mode & 0o777 == 0o600


def test_review_is_exact_signed_and_separate_from_proposer(tmp_path: Path) -> None:
    authority = CognitionAuthority(tmp_path, trusted_reviewer_actors={"Owner"})
    candidate = _candidate()
    proposal = _proposal_receipt(authority, candidate)
    decision = authority.create_review(
        candidate,
        outcome="APPROVED",
        actor_id="Owner",
        authorization_ref="attended:m32",
        corrections=[],
        now=NOW,
    )
    verified = authority.verify_review(candidate, decision, proposal, now=NOW)
    assert verified.decision_id == decision.decision_id
    assert decision.signature["key_id"] == authority.reviewer_key_id
    assert proposal["signature"]["key_id"] == authority.proposer_key_id


@pytest.mark.parametrize("field", ["candidate_sha256", "project_id", "experience_scope"])
def test_review_refuses_candidate_project_or_scope_drift(tmp_path: Path, field: str) -> None:
    authority = CognitionAuthority(tmp_path, trusted_reviewer_actors={"Owner"})
    candidate = _candidate()
    proposal = _proposal_receipt(authority, candidate)
    document = authority.create_review(
        candidate,
        outcome="APPROVED",
        actor_id="Owner",
        authorization_ref="attended:m32",
        corrections=[],
        now=NOW,
    ).as_dict()
    if field == "experience_scope":
        document[field] = {"kind": "SHARED", "owner_id": "HiveMind"}
    elif field == "candidate_sha256":
        document[field] = "0" * 64
    else:
        document[field] = "AnotherProject"
    unsigned = copy.deepcopy(document)
    unsigned.pop("signature")
    unsigned["decision_id"] = MemoryReviewDecision.identity_for(unsigned)
    document = sign_document(unsigned, authority.reviewer_private_key)
    with pytest.raises(ProtocolError):
        authority.verify_review(candidate, document, proposal, now=NOW)


def test_review_refuses_tamper_expiry_untrusted_actor_and_role_reuse(tmp_path: Path) -> None:
    authority = CognitionAuthority(tmp_path, trusted_reviewer_actors={"Owner"})
    candidate = _candidate()
    proposal = _proposal_receipt(authority, candidate)
    decision = authority.create_review(
        candidate,
        outcome="APPROVED",
        actor_id="Owner",
        authorization_ref="attended:m32",
        corrections=[],
        now=NOW,
        ttl=timedelta(minutes=1),
    )
    with pytest.raises(ProtocolError, match="expired"):
        authority.verify_review(
            candidate, decision, proposal, now=NOW + timedelta(minutes=2)
        )

    tampered = decision.as_dict()
    tampered["outcome"] = "REJECTED"
    with pytest.raises(ProtocolError):
        authority.verify_review(candidate, tampered, proposal, now=NOW)

    with pytest.raises(ProtocolError):
        authority.create_review(
            candidate,
            outcome="APPROVED",
            actor_id="Untrusted",
            authorization_ref="attended:m32",
            corrections=[],
            now=NOW,
        )

    reused_unsigned = decision.as_dict()
    reused_unsigned.pop("signature")
    reused_unsigned["reviewer"]["key_id"] = authority.proposer_key_id
    reused_unsigned["decision_id"] = MemoryReviewDecision.identity_for(reused_unsigned)
    reused = sign_document(reused_unsigned, authority.proposer_private_key)
    with pytest.raises(ProtocolError):
        authority.verify_review(candidate, reused, proposal, now=NOW)

    mismatched_unsigned = decision.as_dict()
    mismatched_unsigned.pop("signature")
    mismatched_unsigned["reviewer"]["key_id"] = authority.proposer_key_id
    mismatched_unsigned["decision_id"] = MemoryReviewDecision.identity_for(
        mismatched_unsigned
    )
    mismatched = sign_document(mismatched_unsigned, authority.reviewer_private_key)
    with pytest.raises(ProtocolError, match="reviewer key"):
        authority.verify_review(candidate, mismatched, proposal, now=NOW)


def test_historical_public_role_reassignment_is_refused(tmp_path: Path) -> None:
    authority = CognitionAuthority(tmp_path)
    trust_root = tmp_path / ".hive" / "provenance" / "cognition-public-keys"
    source = authority._public_role_path("proposer", authority.proposer_key_id)
    reassigned = trust_root / (
        "promoter-" + authority.proposer_key_id.replace(":", "-") + ".public.pem"
    )
    reassigned.write_bytes(source.read_bytes())
    with pytest.raises(ProtocolError, match="trust sets"):
        CognitionAuthority(tmp_path)


def test_key_root_symlink_is_refused(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    metadata = tmp_path / ".hive"
    metadata.mkdir()
    (metadata / "keys").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ProtocolError):
        CognitionAuthority(tmp_path)
