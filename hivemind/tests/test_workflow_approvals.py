from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.core import ProtocolError, public_key_id
from hive_protocol.workflows.approvals import (
    WorkflowApprovalAuthority,
    build_approval_preview,
)


NOW = datetime(2026, 9, 1, 7, 45, tzinfo=timezone.utc)
SHA_A = "a" * 64
SHA_B = "b" * 64


def _identity(key: Ed25519PrivateKey, actor_id: str = "agent:approver") -> dict[str, str]:
    return {
        "actor_id": actor_id,
        "persona_id": "persona:owner",
        "surface_id": "surface:attended-human",
        "machine_id": "machine:hive-lab-host",
        "project_id": "HiveMind",
        "app_actor": "app:hive-local-attended",
        "key_id": public_key_id(key.public_key()),
    }


def _preview(**overrides) -> dict[str, object]:
    arguments = {
        "approval_kind": "STEP_APPROVAL",
        "run_id": "11111111-1111-4111-8111-111111111111",
        "workflow_sha256": SHA_A,
        "step_id": "research",
        "attempt": 1,
        "tenant_id": "local-user",
        "project_id": "HiveMind",
        "action": "record attended result",
        "destination": "research/report.md",
        "data_classes": ["PROJECT_PRIVATE"],
        "side_effects": ["canonical-markdown-write"],
        "evidence_refs": ["evidence:brief"],
        "rollback": {"mode": "GIT_CHECKPOINT", "checkpoint": SHA_B},
        "risk_class": "HIGH",
        "input_sha256": SHA_B,
        "conflict_ids": [],
        "existing_capabilities": ["vault:search", "workflow:report"],
        "requested_capabilities": ["workflow:report"],
        "created_at": NOW,
        "expires_at": NOW + timedelta(minutes=10),
    }
    arguments.update(overrides)
    return build_approval_preview(**arguments)


def _authority(
    tmp_path: Path, key: Ed25519PrivateKey
) -> WorkflowApprovalAuthority:
    return WorkflowApprovalAuthority(
        tmp_path / "hive", {public_key_id(key.public_key()): key.public_key()}
    )


def test_exact_approval_records_and_verifies_idempotently(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    authority = _authority(tmp_path, key)
    preview = _preview()
    decision = authority.decide(
        preview,
        decision="APPROVED",
        approver=_identity(key),
        authorization_ref="owner-attended-alpha",
        private_key=key,
        approval_id="22222222-2222-4222-8222-222222222222",
        idempotency_key="approval-alpha",
        decided_at=NOW,
    )
    assert decision["changed"] is True
    assert authority.verify(decision["approval"], preview, now=NOW) is True
    replay = authority.decide(
        preview,
        decision="APPROVED",
        approver=_identity(key),
        authorization_ref="owner-attended-alpha",
        private_key=key,
        approval_id="22222222-2222-4222-8222-222222222222",
        idempotency_key="approval-alpha",
        decided_at=NOW,
    )
    assert replay["changed"] is False


def test_changed_preview_input_expiry_wrong_scope_and_self_approval_refuse(
    tmp_path: Path,
) -> None:
    key = Ed25519PrivateKey.generate()
    authority = _authority(tmp_path, key)
    preview = _preview()
    result = authority.decide(
        preview,
        decision="APPROVED",
        approver=_identity(key),
        authorization_ref="owner-attended-alpha",
        private_key=key,
        approval_id="33333333-3333-4333-8333-333333333333",
        idempotency_key="approval-exact",
        decided_at=NOW,
    )
    changed = copy.deepcopy(preview)
    changed["action"] = "different mutation"
    with pytest.raises(ProtocolError):
        authority.verify(result["approval"], changed, now=NOW)
    with pytest.raises(ProtocolError):
        authority.verify(
            result["approval"], preview, now=NOW + timedelta(minutes=11)
        )

    with pytest.raises(ProtocolError):
        authority.decide(
            preview,
            decision="APPROVED",
            approver=_identity(key),
            authorization_ref="owner-attended-alpha",
            private_key=key,
            approval_id="44444444-4444-4444-8444-444444444444",
            idempotency_key="self-approval",
            decided_at=NOW,
            disallowed_agent_key_ids={public_key_id(key.public_key())},
        )


def test_conflict_exception_cannot_broaden_capability(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    preview = _preview(
        approval_kind="CONFLICT_EXCEPTION",
        conflict_ids=["conflict:" + "c" * 64],
        requested_capabilities=["admin:all"],
    )
    with pytest.raises(ProtocolError, match="capability"):
        _authority(tmp_path, key).decide(
            preview,
            decision="APPROVED",
            approver=_identity(key),
            authorization_ref="owner-attended-alpha",
            private_key=key,
            approval_id="55555555-5555-4555-8555-555555555555",
            idempotency_key="broadening-exception",
            decided_at=NOW,
        )


def test_approval_crash_after_write_is_adopted_exactly_once(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    authority = _authority(tmp_path, key)
    preview = _preview()
    arguments = {
        "decision": "APPROVED",
        "approver": _identity(key),
        "authorization_ref": "owner-attended-alpha",
        "private_key": key,
        "approval_id": "66666666-6666-4666-8666-666666666666",
        "idempotency_key": "approval-crash",
        "decided_at": NOW,
    }
    with pytest.raises(SystemExit, match="approval crash"):
        authority.decide(
            preview,
            **arguments,
            after_approval_write=lambda: (_ for _ in ()).throw(
                SystemExit("approval crash")
            ),
        )

    recovered = _authority(tmp_path, key).decide(preview, **arguments)
    assert recovered["changed"] is True
    assert recovered["outcome"] == "RECORDED"
    approval_files = list(
        (tmp_path / "hive" / ".hive" / "receipts" / "workflows").rglob(
            "*.json"
        )
    )
    assert len(approval_files) == 1


def test_signed_but_absent_approval_receipt_is_not_authority(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    authority = _authority(tmp_path, key)
    preview = _preview()
    decision = authority.decide(
        preview,
        decision="APPROVED",
        approver=_identity(key),
        authorization_ref="owner-attended-alpha",
        private_key=key,
        approval_id="88888888-8888-4888-8888-888888888888",
        idempotency_key="approval-must-remain-durable",
        decided_at=NOW,
    )
    authority._path(
        decision["approval"]["run_id"], decision["approval"]["approval_id"]
    ).unlink()

    with pytest.raises(ProtocolError, match="WORKFLOW_APPROVAL_NOT_RECORDED"):
        authority.verify(decision["approval"], preview, now=NOW)


def test_credential_shaped_preview_is_refused_before_persistence(tmp_path: Path) -> None:
    with pytest.raises(ProtocolError):
        _preview(action="api_" + "key=" + "examplevalue12345")
    assert not (tmp_path / "hive").exists()


def test_nested_run_symlink_cannot_redirect_approval_receipt(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    run_root = (
        tmp_path
        / "hive"
        / ".hive"
        / "receipts"
        / "workflows"
        / "11111111-1111-4111-8111-111111111111"
    )
    run_root.parent.mkdir(parents=True)
    outside = tmp_path / "outside-approvals"
    outside.mkdir()
    run_root.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ProtocolError, match="WORKFLOW_APPROVAL_BOUNDARY"):
        _authority(tmp_path, key).decide(
            _preview(),
            decision="APPROVED",
            approver=_identity(key),
            authorization_ref="owner-attended-alpha",
            private_key=key,
            approval_id="77777777-7777-4777-8777-777777777777",
            idempotency_key="nested-symlink-approval",
            decided_at=NOW,
        )
    assert list(outside.iterdir()) == []
