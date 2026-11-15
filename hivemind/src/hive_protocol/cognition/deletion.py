"""Separately approved, manifest-bounded physical memory deletion."""

from __future__ import annotations

import copy
import hashlib
import re
import shutil
import subprocess  # nosec B404
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

from hive_protocol.core import ProtocolError, canonical_bytes, document_digest, sign_document, verify_document
from hive_protocol.product.workspace import HiveWorkspace
from hive_protocol.storage import atomic_write_json, exclusive_lock, read_json

from .authority import CognitionAuthority
from .models import MemoryDeletionPlan
from .promotion import load_verified_nodes, verify_deletion_receipt
from .store import _ensure_directory, _token, _write_exact


_APPROVAL_ID = re.compile(r"^delete-approval:[0-9a-f]{64}$")


def _time(value) -> str:
    if value.tzinfo is None:
        raise ProtocolError("COGNITION_DELETION_TIME_INVALID", "deletion time lacks timezone")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _approval_identity(document: Mapping[str, Any]) -> str:
    body = {key: copy.deepcopy(value) for key, value in document.items() if key not in {"approval_id", "signature"}}
    return "delete-approval:" + document_digest(body)


def _owned_path(root: Path, relative: str) -> Path:
    pure = PurePosixPath(relative)
    if (
        pure.is_absolute()
        or not pure.parts
        or any(part in {"", ".", ".."} for part in pure.parts)
        or pure.parts[0] != "prime"
        or pure.as_posix() != relative
    ):
        raise ProtocolError(
            "COGNITION_DELETION_PATH_INVALID", "owned deletion path is unsafe"
        )
    current = root
    for part in pure.parts:
        current /= part
        if current.is_symlink():
            raise ProtocolError(
                "COGNITION_DELETION_PATH_INVALID",
                "owned deletion path contains a symlink",
            )
    resolved_parent = current.parent.resolve(strict=True)
    if resolved_parent != root and root not in resolved_parent.parents:
        raise ProtocolError(
            "COGNITION_DELETION_PATH_INVALID", "owned deletion path escapes Hive"
        )
    return current


class CognitionDeletionService:
    def __init__(
        self,
        root: Path,
        authority: CognitionAuthority,
        *,
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        self.root = root.expanduser().resolve(strict=True)
        if self.root != authority.root:
            raise ProtocolError("COGNITION_DELETION_BOUNDARY", "authority belongs to another Hive")
        self.authority = authority
        self.fault_hook = fault_hook
        self.plans = self.root / "staging" / "memory" / "reviews" / "deletion-plans"
        self.receipts = self.root / ".hive" / "receipts"
        self.journals = self.root / ".hive" / "runtime" / "cognition-journals"
        self.locks = self.root / ".hive" / "runtime" / "locks"

    def _prepare(self) -> None:
        for path in (self.plans, self.receipts, self.journals, self.locks):
            _ensure_directory(path, self.root)

    def _fault(self, point: str) -> None:
        if self.fault_hook is not None:
            self.fault_hook(point)

    def create_plan(
        self, node_id: str, *, now, ttl: timedelta = timedelta(minutes=10)
    ) -> MemoryDeletionPlan:
        if ttl <= timedelta(0) or ttl > timedelta(hours=1):
            raise ProtocolError("COGNITION_DELETION_EXPIRY_INVALID", "deletion TTL is invalid")
        node = load_verified_nodes(self.root, self.authority).get(node_id)
        if node is None:
            raise ProtocolError("COGNITION_NODE_MISSING", "deletion target is absent")
        sidecar = str(Path(node.relative_path).with_suffix(".json"))
        document: dict[str, Any] = {
            "schema_version": "hive.memory-deletion-plan.v1",
            "plan_id": "delete:placeholder",
            "node_id": node.node_id,
            "node_sha256": node.digest,
            "tenant_id": node.tenant_id,
            "project_id": node.project_id,
            "experience_scope": node.experience_scope,
            "owned_paths": sorted([node.relative_path, sidecar]),
            "risk_class": "HIGH",
            "checkpoint_required": True,
            "created_at": _time(now),
            "expires_at": _time(now + ttl),
        }
        document["plan_id"] = MemoryDeletionPlan.identity_for(document)
        plan = MemoryDeletionPlan.from_dict(document)
        self._prepare()
        path = self.plans / f"{_token(plan.plan_id, 'delete')}.json"
        _write_exact(path, canonical_bytes(plan.as_dict()) + b"\n")
        return plan

    def _load_plan(self, plan_id: str) -> MemoryDeletionPlan:
        self._prepare()
        return MemoryDeletionPlan.from_dict(
            read_json(self.plans / f"{_token(plan_id, 'delete')}.json")
        )

    def approve(
        self,
        plan_id: str,
        *,
        actor_id: str,
        authorization_ref: str,
        confirmation: str,
        now,
        ttl: timedelta = timedelta(minutes=5),
    ) -> dict[str, Any]:
        plan = self._load_plan(plan_id)
        if actor_id not in self.authority.trusted_reviewer_actors:
            raise ProtocolError("COGNITION_REVIEWER_UNTRUSTED", "deletion reviewer is not trusted")
        if confirmation != f"DELETE {plan.node_id}":
            raise ProtocolError("COGNITION_DELETION_CONFIRMATION_INVALID", "typed deletion confirmation is not exact")
        if ttl <= timedelta(0) or ttl > timedelta(minutes=15):
            raise ProtocolError("COGNITION_DELETION_EXPIRY_INVALID", "approval TTL is invalid")
        if now >= datetime.fromisoformat(plan.expires_at.replace("Z", "+00:00")):
            raise ProtocolError("COGNITION_DELETION_PLAN_EXPIRED", "deletion plan expired")
        node = load_verified_nodes(self.root, self.authority).get(plan.node_id)
        if node is None or node.digest != plan.node_sha256:
            raise ProtocolError("COGNITION_DELETION_TARGET_DRIFT", "deletion target changed")
        unsigned: dict[str, Any] = {
            "schema_version": "hive.memory-deletion-approval.v1",
            "approval_id": "delete-approval:placeholder",
            "plan_id": plan.plan_id,
            "plan_sha256": plan.digest,
            "node_id": plan.node_id,
            "node_sha256": plan.node_sha256,
            "actor_id": actor_id,
            "authorization_ref": authorization_ref,
            "key_id": self.authority.reviewer_key_id,
            "confirmation": confirmation,
            "approved_at": _time(now),
            "expires_at": _time(now + ttl),
        }
        unsigned["approval_id"] = _approval_identity(unsigned)
        approval = sign_document(unsigned, self.authority.reviewer_private_key)
        self._verify_approval(plan, approval, now=now)
        path = self.receipts / f"cognition-approval-deletion-{_token(plan.plan_id, 'delete')}.json"
        _write_exact(path, canonical_bytes(approval) + b"\n")
        return approval

    def _verify_approval(
        self,
        plan: MemoryDeletionPlan,
        approval: Mapping[str, Any],
        *,
        now,
        enforce_expiry: bool = True,
    ) -> dict[str, Any]:
        document = copy.deepcopy(dict(approval))
        expected = {
            "schema_version", "approval_id", "plan_id", "plan_sha256", "node_id",
            "node_sha256", "actor_id", "authorization_ref", "key_id", "confirmation",
            "approved_at", "expires_at", "signature",
        }
        if (
            set(document) != expected
            or document.get("schema_version") != "hive.memory-deletion-approval.v1"
            or _APPROVAL_ID.fullmatch(str(document.get("approval_id", ""))) is None
            or document.get("approval_id") != _approval_identity(document)
            or document.get("plan_id") != plan.plan_id
            or document.get("plan_sha256") != plan.digest
            or document.get("node_id") != plan.node_id
            or document.get("node_sha256") != plan.node_sha256
            or document.get("actor_id") not in self.authority.trusted_reviewer_actors
            or document.get("key_id") != document.get("signature", {}).get("key_id")
            or document.get("key_id") not in self.authority.reviewer_public_keys
            or document.get("confirmation") != f"DELETE {plan.node_id}"
        ):
            raise ProtocolError("COGNITION_DELETION_APPROVAL_INVALID", "deletion approval binding is invalid")
        verify_document(document, self.authority.reviewer_public_keys)
        if enforce_expiry and now >= datetime.fromisoformat(
            document["expires_at"].replace("Z", "+00:00")
        ):
            raise ProtocolError("COGNITION_DELETION_APPROVAL_EXPIRED", "deletion approval expired")
        return document

    def _checkpoint_from_history(self, message: str) -> str | None:
        git = shutil.which("git")
        if git is None or not (self.root / ".git").exists():
            return None
        result = subprocess.run(  # nosec B603
            [git, "-C", str(self.root), "log", "--all", "--fixed-strings", f"--grep={message}", "-n", "1", "--format=%H"],
            check=False,
            capture_output=True,
            text=True,
        )
        value = result.stdout.strip()
        return value if re.fullmatch(r"[0-9a-f]{40}", value) else None

    def _write_journal(self, path: Path, document: dict[str, Any]) -> None:
        atomic_write_json(path, sign_document(document, self.authority.promoter_private_key), mode=0o600)

    def _read_journal(self, path: Path) -> dict[str, Any]:
        document = read_json(path)
        verify_document(document, {self.authority.promoter_key_id: self.authority.promoter_public_key})
        return document

    @staticmethod
    def _operation_id(
        plan: MemoryDeletionPlan, approval_document: Mapping[str, Any]
    ) -> str:
        return document_digest(
            {
                "plan_id": plan.plan_id,
                "approval_id": approval_document["approval_id"],
            }
        )

    @staticmethod
    def _require_journal_binding(
        journal: Mapping[str, Any],
        *,
        operation_id: str,
        plan: MemoryDeletionPlan,
        approval_document: Mapping[str, Any],
    ) -> None:
        if (
            journal.get("operation_id") != operation_id
            or journal.get("plan") != plan.as_dict()
            or journal.get("approval") != approval_document
        ):
            raise ProtocolError(
                "COGNITION_DELETION_JOURNAL_INVALID",
                "deletion journal binding changed",
            )

    def has_started_journal(
        self,
        plan: MemoryDeletionPlan,
        approval: Mapping[str, Any],
        *,
        now,
    ) -> bool:
        approval_document = self._verify_approval(
            plan, approval, now=now, enforce_expiry=False
        )
        operation_id = self._operation_id(plan, approval_document)
        journal_path = self.journals / f"delete-{operation_id}.json"
        if not journal_path.exists():
            return False
        journal = self._read_journal(journal_path)
        self._require_journal_binding(
            journal,
            operation_id=operation_id,
            plan=plan,
            approval_document=approval_document,
        )
        return True

    def apply(self, plan_id: str, approval: Mapping[str, Any], *, now) -> dict[str, Any]:
        plan = self._load_plan(plan_id)
        approval_document = self._verify_approval(
            plan, approval, now=now, enforce_expiry=False
        )
        operation_id = self._operation_id(plan, approval_document)
        journal_path = self.journals / f"delete-{operation_id}.json"
        with exclusive_lock(self.locks / "cognition-deletion.lock"):
            is_new = not journal_path.exists()
            if is_new:
                self._verify_approval(plan, approval_document, now=now)
                node = load_verified_nodes(self.root, self.authority).get(plan.node_id)
                if node is None or node.digest != plan.node_sha256:
                    raise ProtocolError("COGNITION_DELETION_TARGET_DRIFT", "deletion target changed")
                expected_paths = sorted([node.relative_path, str(Path(node.relative_path).with_suffix(".json"))])
                if expected_paths != plan.owned_paths:
                    raise ProtocolError("COGNITION_DELETION_PATH_INVALID", "deletion ownership changed")
                deleted_paths = []
                for relative in plan.owned_paths:
                    path = _owned_path(self.root, relative)
                    if path.is_symlink() or not path.is_file():
                        raise ProtocolError("COGNITION_DELETION_PATH_INVALID", "owned deletion path is unsafe")
                    deleted_paths.append({"path": relative, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
                journal = {
                    "schema_version": "hive.cognition-deletion-journal.v1",
                    "operation_id": operation_id,
                    "state": "PREPARED",
                    "plan": plan.as_dict(),
                    "approval": approval_document,
                    "deleted_paths": deleted_paths,
                    "checkpoint": None,
                    "result": None,
                }
                self._write_journal(journal_path, journal)
            else:
                journal = self._read_journal(journal_path)
                self._require_journal_binding(
                    journal,
                    operation_id=operation_id,
                    plan=plan,
                    approval_document=approval_document,
                )
                if journal.get("state") == "TERMINAL":
                    return copy.deepcopy(journal["result"])
            self._fault("journal-written")
            checkpoint = journal.get("checkpoint")
            if checkpoint is None:
                message = f"pre-deletion {operation_id}"
                checkpoint = self._checkpoint_from_history(message)
                if checkpoint is None:
                    checkpoint = HiveWorkspace.open(self.root).snapshot(message)["commit"]
                journal["checkpoint"] = checkpoint
                self._write_journal(journal_path, journal)
            self._fault("checkpoint-created")

            for index, entry in enumerate(journal["deleted_paths"]):
                relative = entry["path"]
                path = _owned_path(self.root, relative)
                if path.exists() or path.is_symlink():
                    if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
                        raise ProtocolError("COGNITION_DELETION_TARGET_DRIFT", "owned deletion path changed")
                    path.unlink()
                if index == 0:
                    self._fault("first-path-deleted")
            self._fault("paths-deleted")
            receipt_path = self.receipts / f"cognition-deletion-{operation_id}.json"
            receipt = sign_document(
                {
                    "schema_version": "hive.memory-deletion-receipt.v1",
                    "operation_id": operation_id,
                    "plan_id": plan.plan_id,
                    "plan_sha256": plan.digest,
                    "approval_id": approval_document["approval_id"],
                    "approval_sha256": document_digest(approval_document),
                    "node_id": plan.node_id,
                    "node_sha256": plan.node_sha256,
                    "deleted_paths": copy.deepcopy(journal["deleted_paths"]),
                    "checkpoint": checkpoint,
                    "outcome": "DELETED",
                    "deleted_at": _time(now),
                },
                self.authority.promoter_private_key,
            )
            verify_deletion_receipt(receipt, self.authority)
            _write_exact(receipt_path, canonical_bytes(receipt) + b"\n")
            self._fault("receipt-written")
            result = {"outcome": "DELETED", "node_id": plan.node_id, "checkpoint": checkpoint, "receipt_path": receipt_path.relative_to(self.root).as_posix()}
            terminal = copy.deepcopy(journal)
            terminal["state"] = "TERMINAL"
            terminal["result"] = result
            self._write_journal(journal_path, terminal)
            return result
