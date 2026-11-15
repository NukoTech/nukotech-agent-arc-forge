"""Exact protected workflow approvals and conflict exceptions."""

from __future__ import annotations

import copy
import re
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from hive_protocol.adapters.security import reject_credential_values
from hive_protocol.core import (
    ProtocolError,
    document_digest,
    public_key_id,
    sign_document,
    verify_document,
)
from hive_protocol.storage import (
    ReplayLedger,
    atomic_write_json,
    exclusive_lock,
    read_json,
    require_no_symlink_components,
)
from hive_protocol.workflows.models import WorkflowApproval


_SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_PREVIEW_KEYS = frozenset(
    {
        "schema_version",
        "approval_kind",
        "run_id",
        "workflow_sha256",
        "step_id",
        "attempt",
        "tenant_id",
        "project_id",
        "action",
        "destination",
        "data_classes",
        "side_effects",
        "evidence_refs",
        "rollback",
        "risk_class",
        "input_sha256",
        "conflict_ids",
        "existing_capabilities",
        "requested_capabilities",
        "created_at",
        "expires_at",
    }
)


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        raise ProtocolError(
            "WORKFLOW_APPROVAL_TIME_INVALID", "approval time requires timezone"
        )
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ProtocolError(
            "WORKFLOW_APPROVAL_TIME_INVALID", "approval time is invalid"
        ) from exc
    if parsed.tzinfo is None:
        raise ProtocolError(
            "WORKFLOW_APPROVAL_TIME_INVALID", "approval time requires timezone"
        )
    return parsed


def _sorted_unique(values: Sequence[str], label: str) -> list[str]:
    result = sorted(set(values))
    if len(result) != len(values) or any(
        not isinstance(value, str) or not value for value in values
    ):
        raise ProtocolError(
            "WORKFLOW_APPROVAL_PREVIEW_INVALID", f"{label} must be unique strings"
        )
    return result


def build_approval_preview(
    *,
    approval_kind: str,
    run_id: str,
    workflow_sha256: str,
    step_id: str | None,
    attempt: int | None,
    tenant_id: str,
    project_id: str,
    action: str,
    destination: str,
    data_classes: Sequence[str],
    side_effects: Sequence[str],
    evidence_refs: Sequence[str],
    rollback: Mapping[str, Any],
    risk_class: str,
    input_sha256: str,
    conflict_ids: Sequence[str],
    existing_capabilities: Sequence[str],
    requested_capabilities: Sequence[str],
    created_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    preview = {
        "schema_version": "hive.workflow-approval-preview.v1",
        "approval_kind": approval_kind,
        "run_id": run_id,
        "workflow_sha256": workflow_sha256,
        "step_id": step_id,
        "attempt": attempt,
        "tenant_id": tenant_id,
        "project_id": project_id,
        "action": action,
        "destination": destination,
        "data_classes": _sorted_unique(data_classes, "data classes"),
        "side_effects": _sorted_unique(side_effects, "side effects"),
        "evidence_refs": _sorted_unique(evidence_refs, "evidence references"),
        "rollback": copy.deepcopy(dict(rollback)),
        "risk_class": risk_class,
        "input_sha256": input_sha256,
        "conflict_ids": _sorted_unique(conflict_ids, "conflict IDs"),
        "existing_capabilities": _sorted_unique(
            existing_capabilities, "existing capabilities"
        ),
        "requested_capabilities": _sorted_unique(
            requested_capabilities, "requested capabilities"
        ),
        "created_at": _iso(created_at),
        "expires_at": _iso(expires_at),
    }
    _validate_preview(preview)
    return preview


def _validate_preview(preview: Mapping[str, Any]) -> None:
    if set(preview) != _PREVIEW_KEYS:
        raise ProtocolError(
            "WORKFLOW_APPROVAL_PREVIEW_INVALID", "approval preview fields are not closed"
        )
    reject_credential_values(preview, location="workflow approval preview")
    if preview["schema_version"] != "hive.workflow-approval-preview.v1":
        raise ProtocolError(
            "WORKFLOW_APPROVAL_PREVIEW_INVALID", "approval preview version is unknown"
        )
    for field in ("tenant_id", "project_id"):
        if not isinstance(preview[field], str) or not _SAFE_ID.fullmatch(preview[field]):
            raise ProtocolError(
                "WORKFLOW_APPROVAL_PREVIEW_INVALID", f"unsafe {field}"
            )
    if (preview["step_id"] is None) != (preview["attempt"] is None):
        raise ProtocolError(
            "WORKFLOW_APPROVAL_PREVIEW_INVALID",
            "preview step and attempt must both be present or absent",
        )
    destination = PurePosixPath(str(preview["destination"]))
    if destination.is_absolute() or any(
        part in {"", ".", ".."} for part in destination.parts
    ):
        raise ProtocolError(
            "WORKFLOW_APPROVAL_DESTINATION_INVALID", "approval destination is unsafe"
        )
    created = _time(preview["created_at"])
    expires = _time(preview["expires_at"])
    if expires <= created:
        raise ProtocolError(
            "WORKFLOW_APPROVAL_EXPIRY_INVALID",
            "approval preview must expire after creation",
        )
    if preview["approval_kind"] == "CONFLICT_EXCEPTION" and not preview[
        "conflict_ids"
    ]:
        raise ProtocolError(
            "WORKFLOW_APPROVAL_PREVIEW_INVALID",
            "conflict exceptions must name exact conflicts",
        )


class WorkflowApprovalAuthority:
    """Record exact attended approvals without granting new capabilities."""

    def __init__(
        self,
        hive_root: Path,
        trusted_approver_keys: Mapping[str, Ed25519PublicKey],
    ) -> None:
        self.hive_root = hive_root.expanduser()
        self.trusted_keys = dict(trusted_approver_keys)
        self.receipts = self.hive_root / ".hive" / "receipts" / "workflows"
        self.runtime = self.hive_root / ".hive" / "runtime" / "workflows"
        self.lock = self.runtime / ".approval-record.lock"
        self.replay = ReplayLedger(self.runtime / "approval-record.json", mode=0o600)
        for path in (self.hive_root, self.hive_root / ".hive", self.receipts, self.runtime):
            if path.exists() and path.is_symlink():
                raise ProtocolError(
                    "WORKFLOW_APPROVAL_BOUNDARY", "approval paths may not be symlinks"
                )

    def _path(self, run_id: str, approval_id: str) -> Path:
        target = self.receipts / run_id / "approvals" / f"{approval_id}.json"
        require_no_symlink_components(
            self.hive_root,
            target,
            code="WORKFLOW_APPROVAL_BOUNDARY",
            detail="workflow approval path contains a symlink",
        )
        return target

    def decide(
        self,
        preview: Mapping[str, Any],
        *,
        decision: str,
        approver: Mapping[str, Any],
        authorization_ref: str,
        private_key: Ed25519PrivateKey,
        approval_id: str,
        idempotency_key: str,
        decided_at: datetime,
        disallowed_agent_key_ids: set[str] | None = None,
        after_approval_write: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        _validate_preview(preview)
        key_id = public_key_id(private_key.public_key())
        if key_id not in self.trusted_keys or approver.get("key_id") != key_id:
            raise ProtocolError(
                "WORKFLOW_APPROVER_UNAUTHORIZED",
                "approval signer is not an authorized exact approver",
            )
        if key_id in (disallowed_agent_key_ids or set()):
            raise ProtocolError(
                "WORKFLOW_SELF_APPROVAL_FORBIDDEN",
                "assigned or claiming agents may not approve their own action",
            )
        requested = set(preview["requested_capabilities"])
        existing = set(preview["existing_capabilities"])
        if decision == "APPROVED" and not requested.issubset(existing):
            raise ProtocolError(
                "WORKFLOW_CAPABILITY_BROADENING",
                "approval or exception may not broaden capability",
            )
        decided = decided_at.astimezone(timezone.utc)
        if decided < _time(preview["created_at"]) or decided >= _time(
            preview["expires_at"]
        ):
            raise ProtocolError(
                "WORKFLOW_APPROVAL_STALE", "approval decision is outside preview validity"
            )
        document = sign_document(
            {
                "schema_version": "hive.workflow-approval.v1",
                "approval_id": approval_id,
                "approval_kind": preview["approval_kind"],
                "run_id": preview["run_id"],
                "workflow_sha256": preview["workflow_sha256"],
                "step_id": preview["step_id"],
                "attempt": preview["attempt"],
                "tenant_id": preview["tenant_id"],
                "project_id": preview["project_id"],
                "preview_sha256": document_digest(preview),
                "input_sha256": preview["input_sha256"],
                "decision": decision,
                "risk_class": preview["risk_class"],
                "approver": copy.deepcopy(dict(approver)),
                "authorization_ref": authorization_ref,
                "decided_at": _iso(decided_at),
                "expires_at": preview["expires_at"],
            },
            private_key,
        )
        approval = WorkflowApproval.from_dict(document, verified_by=self.trusted_keys)
        verify_document(approval.as_dict(), self.trusted_keys)
        target = self._path(approval.run_id, approval.approval_id)
        if target.is_symlink():
            raise ProtocolError(
                "WORKFLOW_APPROVAL_BOUNDARY", "approval target may not be a symlink"
            )
        self.runtime.mkdir(parents=True, exist_ok=True)
        if self.runtime.is_symlink():
            raise ProtocolError(
                "WORKFLOW_APPROVAL_BOUNDARY", "approval runtime may not be a symlink"
            )
        with exclusive_lock(self.lock):
            if target.exists():
                existing_document = read_json(target)
                existing = WorkflowApproval.from_dict(existing_document)
                if existing.digest != approval.digest:
                    raise ProtocolError(
                        "WORKFLOW_APPROVAL_CONFLICT",
                        "approval ID is already bound to different bytes",
                    )
                state = self._replay_state(idempotency_key, approval.digest)
                if state == "COMPLETE":
                    return {
                        "outcome": "RECORDED",
                        "changed": False,
                        "approval": existing.as_dict(),
                    }
            claim = self.replay.begin(idempotency_key, approval.digest)
            if claim == "RESUME" and not target.exists():
                raise ProtocolError(
                    "WORKFLOW_APPROVAL_RECOVERY_MISSING",
                    "pending approval has no exact durable decision",
                )
            if claim == "NEW":
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.parent.is_symlink():
                    raise ProtocolError(
                        "WORKFLOW_APPROVAL_BOUNDARY",
                        "approval receipt directory may not be a symlink",
                    )
                atomic_write_json(target, approval.as_dict())
                if after_approval_write is not None:
                    after_approval_write()
            self.replay.complete(idempotency_key, approval.digest)
        return {
            "outcome": "RECORDED",
            "changed": True,
            "approval": approval.as_dict(),
        }

    def _replay_state(self, idempotency_key: str, digest: str) -> str | None:
        if not self.replay.ledger_path.exists():
            return None
        ledger = read_json(self.replay.ledger_path)
        record = ledger.get("messages", {}).get(idempotency_key)
        if not isinstance(record, Mapping):
            return None
        if record.get("nonce") != digest:
            raise ProtocolError(
                "WORKFLOW_APPROVAL_REPLAY_CONFLICT",
                "approval idempotency key is bound to different bytes",
            )
        state = record.get("state")
        if state not in {"PENDING", "COMPLETE"}:
            raise ProtocolError(
                "WORKFLOW_APPROVAL_REPLAY_CONFLICT", "approval replay state is invalid"
            )
        return str(state)

    def verify(
        self,
        approval_document: Mapping[str, Any],
        preview: Mapping[str, Any],
        *,
        now: datetime,
    ) -> bool:
        _validate_preview(preview)
        approval = WorkflowApproval.from_dict(
            approval_document, verified_by=self.trusted_keys
        )
        verify_document(approval.as_dict(), self.trusted_keys)
        receipt_path = self._path(approval.run_id, approval.approval_id)
        if receipt_path.is_symlink() or not receipt_path.is_file():
            raise ProtocolError(
                "WORKFLOW_APPROVAL_NOT_RECORDED",
                "workflow approval has no durable exact receipt",
            )
        recorded = WorkflowApproval.from_dict(
            read_json(receipt_path), verified_by=self.trusted_keys
        )
        verify_document(recorded.as_dict(), self.trusted_keys)
        if recorded.digest != approval.digest:
            raise ProtocolError(
                "WORKFLOW_APPROVAL_CONFLICT",
                "durable workflow approval differs from supplied authority",
            )
        bindings = {
            "approval_kind": preview["approval_kind"],
            "run_id": preview["run_id"],
            "workflow_sha256": preview["workflow_sha256"],
            "step_id": preview["step_id"],
            "attempt": preview["attempt"],
            "tenant_id": preview["tenant_id"],
            "project_id": preview["project_id"],
            "preview_sha256": document_digest(preview),
            "input_sha256": preview["input_sha256"],
            "risk_class": preview["risk_class"],
            "expires_at": preview["expires_at"],
        }
        if any(approval.as_dict()[key] != value for key, value in bindings.items()):
            raise ProtocolError(
                "WORKFLOW_APPROVAL_BINDING_MISMATCH",
                "approval does not bind the exact preview and input",
            )
        if approval.decision != "APPROVED":
            raise ProtocolError(
                "WORKFLOW_APPROVAL_REJECTED", "workflow action was not approved"
            )
        if now.tzinfo is None or now >= _time(approval.expires_at):
            raise ProtocolError(
                "WORKFLOW_APPROVAL_EXPIRED", "workflow approval has expired"
            )
        if not set(preview["requested_capabilities"]).issubset(
            preview["existing_capabilities"]
        ):
            raise ProtocolError(
                "WORKFLOW_CAPABILITY_BROADENING",
                "approval may not broaden capability",
            )
        return True
