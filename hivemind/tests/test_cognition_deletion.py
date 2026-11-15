from __future__ import annotations

import copy
import shutil
from datetime import timedelta
from pathlib import Path

import pytest

from hive_protocol.cognition.authority import CognitionAuthority
from hive_protocol.cognition.deletion import CognitionDeletionService
from hive_protocol.cognition.models import KnowledgeNode
from hive_protocol.cognition.promotion import CognitionPromotionService
from hive_protocol.cognition.retrieval import CognitionRetrieval
from hive_protocol.cognition.store import CognitionStore
from hive_protocol.core import ProtocolError, verify_document
from hive_protocol.product.workspace import HiveWorkspace
from hive_protocol.storage import read_json

from test_cognition_promotion import NOW, _event, _stage_review


def _setup(root: Path):
    workspace = HiveWorkspace.create(root)
    sentinel = root / "sources" / "sentinel.md"
    sentinel.write_bytes(b"# unrelated\n")
    authority = CognitionAuthority(root, trusted_reviewer_actors={"Owner"})
    store, candidate, _ = _stage_review(root, authority, _event())
    promoted = CognitionPromotionService(root, store, authority).promote(
        candidate.candidate_id, now=NOW
    )
    node = KnowledgeNode.from_dict(promoted["node"])
    return workspace, sentinel, authority, node


def test_deletion_requires_exact_separate_confirmation_and_preserves_unrelated_data(tmp_path: Path) -> None:
    workspace, sentinel, authority, node = _setup(tmp_path)
    service = CognitionDeletionService(tmp_path, authority)
    plan = service.create_plan(node.node_id, now=NOW)
    assert plan.owned_paths == sorted(
        [node.relative_path, str(Path(node.relative_path).with_suffix(".json"))]
    )
    assert (tmp_path / node.relative_path).is_file()

    with pytest.raises(ProtocolError):
        service.approve(
            plan.plan_id,
            actor_id="Owner",
            authorization_ref="attended:m32-delete",
            confirmation="DELETE something-else",
            now=NOW,
        )
    approval = service.approve(
        plan.plan_id,
        actor_id="Owner",
        authorization_ref="attended:m32-delete",
        confirmation=f"DELETE {node.node_id}",
        now=NOW,
    )
    result = service.apply(plan.plan_id, approval, now=NOW)
    assert result["outcome"] == "DELETED"
    assert not (tmp_path / node.relative_path).exists()
    assert sentinel.read_bytes() == b"# unrelated\n"
    receipt = read_json(tmp_path / result["receipt_path"])
    verify_document(receipt, {authority.promoter_key_id: authority.promoter_public_key})
    assert receipt["node_id"] == node.node_id
    assert CognitionRetrieval(tmp_path, authority).list_nodes(project_id="HiveMind") == []

    workspace.rollback(result["checkpoint"])
    assert (tmp_path / node.relative_path).is_file()
    assert sentinel.read_bytes() == b"# unrelated\n"


def test_deletion_refuses_missing_expired_tampered_or_wrong_actor_approval(tmp_path: Path) -> None:
    _, _, authority, node = _setup(tmp_path)
    service = CognitionDeletionService(tmp_path, authority)
    plan = service.create_plan(node.node_id, now=NOW, ttl=timedelta(minutes=2))
    approval = service.approve(
        plan.plan_id,
        actor_id="Owner",
        authorization_ref="attended:m32-delete",
        confirmation=f"DELETE {node.node_id}",
        now=NOW,
        ttl=timedelta(minutes=1),
    )
    with pytest.raises(ProtocolError, match="expired"):
        service.apply(plan.plan_id, approval, now=NOW + timedelta(minutes=2))
    tampered = approval.copy()
    tampered["node_id"] = "node:" + "0" * 64
    with pytest.raises(ProtocolError):
        service.apply(plan.plan_id, tampered, now=NOW)
    with pytest.raises(ProtocolError):
        service.approve(
            plan.plan_id,
            actor_id="Untrusted",
            authorization_ref="attended:m32-delete",
            confirmation=f"DELETE {node.node_id}",
            now=NOW,
        )


def test_exact_deletion_approval_survives_private_key_rotation(tmp_path: Path) -> None:
    _, sentinel, authority, node = _setup(tmp_path)
    service = CognitionDeletionService(tmp_path, authority)
    plan = service.create_plan(node.node_id, now=NOW)
    approval = service.approve(
        plan.plan_id,
        actor_id="Owner",
        authorization_ref="attended:m32-delete",
        confirmation=f"DELETE {node.node_id}",
        now=NOW,
    )
    old_reviewer_key_id = authority.reviewer_key_id
    shutil.rmtree(tmp_path / ".hive" / "keys" / "cognition")
    rotated = CognitionAuthority(
        tmp_path, trusted_reviewer_actors={"Owner"}
    )
    assert rotated.reviewer_key_id != old_reviewer_key_id
    assert old_reviewer_key_id in rotated.reviewer_public_keys
    result = CognitionDeletionService(tmp_path, rotated).apply(
        plan.plan_id, approval, now=NOW
    )
    assert result["outcome"] == "DELETED"
    assert sentinel.read_bytes() == b"# unrelated\n"


def test_changed_or_linked_owned_path_refuses_before_deletion(tmp_path: Path) -> None:
    _, sentinel, authority, node = _setup(tmp_path)
    service = CognitionDeletionService(tmp_path, authority)
    plan = service.create_plan(node.node_id, now=NOW)
    approval = service.approve(
        plan.plan_id,
        actor_id="Owner",
        authorization_ref="attended:m32-delete",
        confirmation=f"DELETE {node.node_id}",
        now=NOW,
    )
    markdown = tmp_path / node.relative_path
    markdown.unlink()
    markdown.symlink_to(sentinel)
    with pytest.raises(ProtocolError):
        service.apply(plan.plan_id, approval, now=NOW)
    assert sentinel.read_bytes() == b"# unrelated\n"


@pytest.mark.parametrize(
    "fault_point",
    ["journal-written", "checkpoint-created", "first-path-deleted", "paths-deleted", "receipt-written"],
)
def test_deletion_recovers_every_crash_window_and_replays_exactly(
    tmp_path: Path, fault_point: str
) -> None:
    _, sentinel, authority, node = _setup(tmp_path)
    plan_service = CognitionDeletionService(tmp_path, authority)
    plan = plan_service.create_plan(node.node_id, now=NOW)
    approval = plan_service.approve(
        plan.plan_id,
        actor_id="Owner",
        authorization_ref="attended:m32-delete",
        confirmation=f"DELETE {node.node_id}",
        now=NOW,
    )
    fired = False

    def fault(point: str) -> None:
        nonlocal fired
        if point == fault_point and not fired:
            fired = True
            raise RuntimeError("simulated crash")

    with pytest.raises(RuntimeError, match="simulated crash"):
        CognitionDeletionService(
            tmp_path, authority, fault_hook=fault
        ).apply(plan.plan_id, approval, now=NOW)
    recovered = CognitionDeletionService(tmp_path, authority).apply(
        plan.plan_id, approval, now=NOW
    )
    replayed = CognitionDeletionService(tmp_path, authority).apply(
        plan.plan_id, approval, now=NOW
    )
    assert recovered == replayed
    assert sentinel.read_bytes() == b"# unrelated\n"
    assert len(list((tmp_path / ".hive" / "receipts").glob("cognition-deletion-*.json"))) == 1


def test_deletion_recovers_an_exact_started_journal_after_approval_expiry(
    tmp_path: Path,
) -> None:
    _, sentinel, authority, node = _setup(tmp_path)
    service = CognitionDeletionService(tmp_path, authority)
    plan = service.create_plan(node.node_id, now=NOW)
    approval = service.approve(
        plan.plan_id,
        actor_id="Owner",
        authorization_ref="attended:m32-delete",
        confirmation=f"DELETE {node.node_id}",
        now=NOW,
        ttl=timedelta(minutes=1),
    )
    fired = False

    def fault(point: str) -> None:
        nonlocal fired
        if point == "first-path-deleted" and not fired:
            fired = True
            raise RuntimeError("simulated crash")

    with pytest.raises(RuntimeError, match="simulated crash"):
        CognitionDeletionService(
            tmp_path, authority, fault_hook=fault
        ).apply(plan.plan_id, approval, now=NOW)

    recovered = CognitionDeletionService(tmp_path, authority).apply(
        plan.plan_id,
        approval,
        now=NOW + timedelta(minutes=2),
    )
    assert recovered["outcome"] == "DELETED"
    assert sentinel.read_bytes() == b"# unrelated\n"
    assert len(list((tmp_path / ".hive" / "receipts").glob("cognition-deletion-*.json"))) == 1
