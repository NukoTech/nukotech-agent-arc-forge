from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from hive_protocol.cognition.authority import CognitionAuthority
from hive_protocol.cognition.models import KnowledgeNode
from hive_protocol.cognition.promotion import CognitionPromotionService
from hive_protocol.cognition.retrieval import CognitionRetrieval
from hive_protocol.core import ProtocolError

from test_cognition_promotion import NOW, _event, _stage_review


def _lifecycle(root: Path):
    authority = CognitionAuthority(root, trusted_reviewer_actors={"Owner"})
    store, original_candidate, _ = _stage_review(root, authority, _event())
    promotion = CognitionPromotionService(root, store, authority)
    original = KnowledgeNode.from_dict(
        promotion.promote(original_candidate.candidate_id, now=NOW)["node"]
    )
    _, correction_candidate, _ = _stage_review(
        root,
        authority,
        _event(
            value="portable Markdown plus JSON sidecars",
            narrative="Portable Markdown and sidecars remain canonical.",
            action="CORRECT",
            supersedes=original.node_id,
        ),
    )
    corrected = KnowledgeNode.from_dict(
        promotion.promote(correction_candidate.candidate_id, now=NOW)["node"]
    )
    return authority, store, promotion, original, corrected


def test_default_retrieval_excludes_superseded_claim_and_history_retains_it(tmp_path: Path) -> None:
    authority, _, _, original, corrected = _lifecycle(tmp_path)
    retrieval = CognitionRetrieval(tmp_path, authority)
    current = retrieval.list_nodes(project_id="HiveMind")
    history = retrieval.list_nodes(project_id="HiveMind", include_historical=True)
    assert [item["node_id"] for item in current] == [corrected.node_id]
    states = {item["node_id"]: item["derived_state"] for item in history}
    assert states[original.node_id] == "SUPERSEDED"
    assert states[corrected.node_id] == "CURRENT"


def test_revoked_claim_leaves_default_retrieval_but_history_and_audit_remain(tmp_path: Path) -> None:
    authority, store, promotion, original, corrected = _lifecycle(tmp_path)
    _, revoke_candidate, _ = _stage_review(
        tmp_path,
        authority,
        _event(
            value=False,
            narrative="The corrected storage claim is revoked.",
            action="REVOKE",
            revokes=corrected.node_id,
        ),
    )
    revocation = KnowledgeNode.from_dict(
        promotion.promote(revoke_candidate.candidate_id, now=NOW)["node"]
    )
    retrieval = CognitionRetrieval(tmp_path, authority)
    assert retrieval.list_nodes(project_id="HiveMind") == []
    history = retrieval.list_nodes(project_id="HiveMind", include_historical=True)
    states = {item["node_id"]: item["derived_state"] for item in history}
    assert states[original.node_id] == "SUPERSEDED"
    assert states[corrected.node_id] == "REVOKED"
    assert states[revocation.node_id] == "AUDIT"


def test_search_is_scope_bound_and_uses_only_current_reviewed_nodes(tmp_path: Path) -> None:
    authority, _, _, original, corrected = _lifecycle(tmp_path)
    retrieval = CognitionRetrieval(tmp_path, authority)
    assert [item["node_id"] for item in retrieval.search("sidecars", project_id="HiveMind")] == [
        corrected.node_id
    ]
    assert retrieval.search("Markdown", project_id="AnotherProject") == []
    assert retrieval.list_nodes(
        project_id="HiveMind", scope_kind="SHARED", scope_owner="HiveMind"
    ) == []


def test_retrieval_refuses_markdown_or_sidecar_tamper(tmp_path: Path) -> None:
    authority, _, _, _, corrected = _lifecycle(tmp_path)
    markdown = tmp_path / corrected.relative_path
    markdown.write_text(markdown.read_text(encoding="utf-8") + "tamper", encoding="utf-8")
    with pytest.raises(ProtocolError):
        CognitionRetrieval(tmp_path, authority).list_nodes(project_id="HiveMind")
