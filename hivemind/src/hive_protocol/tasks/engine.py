"""Small, signed, replay-safe task engine for a local Node Hive."""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from importlib.resources import files
from pathlib import Path
from typing import Any, Mapping
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker

from ..core import ProtocolError, document_digest, sign_document, verify_document
from ..receipts.core import build_receipt, verify_receipt
from ..storage import ReplayLedger, atomic_write_json, exclusive_lock, read_json, utc_now


_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_STATES = {"CREATED", "ASSIGNED", "ACCEPTED", "ACKNOWLEDGED", "PROGRESS", "COMPLETED", "REJECTED", "CANCELLED"}
_TRANSITIONS = {
    "CREATED": {"ASSIGNED", "CANCELLED"},
    "ASSIGNED": {"ACCEPTED", "REJECTED", "CANCELLED"},
    "ACCEPTED": {"ACKNOWLEDGED", "PROGRESS", "REJECTED", "CANCELLED"},
    "ACKNOWLEDGED": {"PROGRESS", "COMPLETED", "REJECTED", "CANCELLED"},
    "PROGRESS": {"PROGRESS", "COMPLETED", "REJECTED", "CANCELLED"},
    "COMPLETED": set(),
    "REJECTED": set(),
    "CANCELLED": set(),
}
_OWNER_TRANSITIONS = {"ACCEPTED", "ACKNOWLEDGED", "PROGRESS", "COMPLETED", "REJECTED"}


class TaskError(ProtocolError):
    """Stable task operation failure."""


class TaskIdentity(dict[str, str]):
    """Persona, surface, machine, project, and App actor are separate fields."""

    KEYS = ("persona_id", "surface_id", "machine_id", "project_id", "app_actor")

    def __init__(self, *, persona_id: str, surface_id: str, machine_id: str, project_id: str, app_actor: str):
        super().__init__(
            persona_id=persona_id,
            surface_id=surface_id,
            machine_id=machine_id,
            project_id=project_id,
            app_actor=app_actor,
        )
        if any(not isinstance(self[key], str) or not _ID.fullmatch(self[key]) for key in self.KEYS):
            raise TaskError("TASK_IDENTITY_INVALID", "identity dimensions must be safe identifiers")
        if len({self[key] for key in self.KEYS}) != len(self.KEYS):
            raise TaskError("TASK_IDENTITY_COLLAPSE", "persona, surface, machine, project, and App actor must differ")


def _schema() -> dict[str, Any]:
    return json.loads(files("hive_protocol.schemas").joinpath("cycle2-task.v1.schema.json").read_text())


def _validate(task: Mapping[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(_schema(), format_checker=FormatChecker()).iter_errors(task),
        key=lambda error: list(error.path),
    )
    if errors:
        error = errors[0]
        where = ".".join(str(part) for part in error.absolute_path) or "$"
        raise TaskError("TASK_SCHEMA_INVALID", f"{where}: {error.message}")


def _time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TaskError("TASK_TIME_INVALID", "timestamp must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise TaskError("TASK_TIME_INVALID", "timestamp requires timezone")
    return parsed


def _identity(value: Mapping[str, str]) -> TaskIdentity:
    return TaskIdentity(**{key: str(value[key]) for key in TaskIdentity.KEYS})


class TaskEngine:
    """Durable task engine. Only its root is mutable; user project material is never removed."""

    def __init__(self, root: Path, trusted_keys: Mapping[str, Ed25519PublicKey] | None = None):
        if root.exists() and root.is_symlink():
            raise TaskError("TASK_ROOT_BOUNDARY", "task root may not be a symlink")
        self.root = root
        self.tasks = root / "tasks"
        self.receipts = root / "receipts"
        self.queue = root / "queue" / "offline"
        self.replay = ReplayLedger(root / "replay" / "task-events.json")
        self.lock = root / ".tasks.lock"
        self.trusted_keys = dict(trusted_keys or {})
        for path in (self.tasks, self.receipts, self.queue):
            path.mkdir(parents=True, exist_ok=True)

    def _path(self, task_id: str) -> Path:
        if not _ID.fullmatch(task_id):
            raise TaskError("TASK_ID_INVALID", "task identifier is unsafe")
        return self.tasks / f"{task_id}.json"

    def _load(self, task_id: str) -> dict[str, Any]:
        task = read_json(self._path(task_id))
        _validate(task)
        if task["task_id"] != task_id:
            raise TaskError("TASK_ID_MISMATCH", "filename and task ID differ")
        if self.trusted_keys:
            verify_document(task, self.trusted_keys)
        return task

    def create(
        self,
        *,
        identity: TaskIdentity,
        assignee: TaskIdentity,
        operation: str,
        payload: Mapping[str, Any],
        capability: str,
        source_refs: list[Mapping[str, str]],
        private_key: Ed25519PrivateKey,
        task_id: str | None = None,
        expires_at: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        identity = _identity(identity)
        assignee = _identity(assignee)
        if identity["project_id"] != assignee["project_id"]:
            raise TaskError("TASK_PROJECT_MISMATCH", "creator and assignee projects differ")
        if not isinstance(operation, str) or not _ID.fullmatch(operation) or not isinstance(capability, str) or not _ID.fullmatch(capability):
            raise TaskError("TASK_OPERATION_INVALID", "operation and capability are unsafe")
        if not isinstance(payload, Mapping):
            raise TaskError("TASK_PAYLOAD_INVALID", "payload must be an object")
        for ref in source_refs:
            if not _SHA256.fullmatch(str(ref.get("sha256", ""))):
                raise TaskError("TASK_REFERENCE_INVALID", "source references require immutable SHA-256")
        observed_at = now if now is not None else datetime.now(timezone.utc)
        if not isinstance(observed_at, datetime) or observed_at.tzinfo is None:
            raise TaskError("TASK_TIME_INVALID", "task creation time requires timezone")
        created_at = observed_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        task_id = task_id or str(uuid4())
        expires_at = expires_at or (observed_at + timedelta(hours=1)).replace(microsecond=0).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        if _time(expires_at) <= observed_at:
            raise TaskError("TASK_TIME_INVALID", "task expiry must follow creation time")
        task: dict[str, Any] = {
            "schema_version": "hive.cycle2.task.v1",
            "task_id": task_id,
            "state": "CREATED",
            "version": 1,
            "created_at": created_at,
            "updated_at": created_at,
            "expires_at": expires_at,
            "creator": dict(identity),
            "assignee": dict(assignee),
            "operation": operation,
            "capability": capability,
            "payload": dict(payload),
            "source_refs": [dict(ref) for ref in source_refs],
            "nonce": uuid4().hex,
        }
        signed = sign_document(task, private_key)
        _validate(signed)
        with exclusive_lock(self.lock):
            if self._path(task_id).exists():
                raise TaskError("TASK_REPLAY", "task ID already exists", 3)
            atomic_write_json(self._path(task_id), signed)
            atomic_write_json(self.queue / f"{task_id}.json", signed)
        self.trusted_keys.setdefault(signed["signature"]["key_id"], private_key.public_key())
        return signed

    def transition(
        self,
        task_id: str,
        *,
        target: str,
        actor: TaskIdentity,
        private_key: Ed25519PrivateKey,
        expected_version: int,
        result: Mapping[str, Any] | None = None,
        artifact_refs: list[Mapping[str, str]] | None = None,
        event_id: str | None = None,
        nonce: str | None = None,
    ) -> dict[str, Any]:
        if target not in _STATES:
            raise TaskError("TASK_STATE_INVALID", "unknown target state")
        actor = _identity(actor)
        event_id = event_id or str(uuid4())
        nonce = nonce or uuid4().hex
        with exclusive_lock(self.lock):
            task = self._load(task_id)
            if task["version"] != expected_version:
                raise TaskError("TASK_STALE", "expected task version is not current")
            if _time(task["expires_at"]) <= datetime.now(timezone.utc) and target not in {"CANCELLED", "REJECTED"}:
                raise TaskError("TASK_STALE", "task has expired")
            if target not in _TRANSITIONS[task["state"]]:
                raise TaskError("TASK_TRANSITION_INVALID", f"{task['state']} cannot transition to {target}")
            if target == "ASSIGNED" and actor != task["creator"]:
                raise TaskError("TASK_UNAUTHORIZED", "only the creator may assign a task")
            if target in _OWNER_TRANSITIONS and actor != task["assignee"]:
                raise TaskError("TASK_WRONG_RECIPIENT", "only the assigned identity may perform this transition")
            if target == "CANCELLED" and actor != task["creator"] and actor != task["assignee"]:
                raise TaskError("TASK_UNAUTHORIZED", "only creator or assignee may cancel")
            try:
                claim = self.replay.begin(event_id, nonce)
            except ProtocolError as exc:
                if exc.code.startswith("REPLAY_"):
                    raise TaskError("TASK_REPLAY", "event has already been claimed", 3) from exc
                raise
            if claim == "RESUME":
                raise TaskError("TASK_REPLAY", "event is already pending", 3)
            updated = dict(task)
            updated["state"] = target
            updated["version"] = task["version"] + 1
            updated["updated_at"] = utc_now()
            updated = sign_document(updated, private_key)
            _validate(updated)
            atomic_write_json(self._path(task_id), updated)
            receipt = build_receipt(
                receipt_id=event_id,
                task_id=task_id,
                event=target.lower(),
                actor=actor,
                recipient=TaskIdentity(**task["assignee"]),
                state_before=task["state"],
                state_after=target,
                version=updated["version"],
                nonce=nonce,
                artifact_refs=list(artifact_refs or []),
                result=result,
                private_key=private_key,
            )
            atomic_write_json(self.receipts / f"{event_id}.json", receipt)
            self.trusted_keys.setdefault(receipt["signature"]["key_id"], private_key.public_key())
            self.replay.complete(event_id, nonce)
            self.queue.joinpath(f"{task_id}.json").unlink(missing_ok=True)
            return receipt

    def recover(self) -> list[str]:
        """Rebuild the offline queue deterministically from durable task files."""
        recovered: list[str] = []
        with exclusive_lock(self.lock):
            for path in sorted(self.tasks.glob("*.json")):
                task = read_json(path)
                _validate(task)
                if task["state"] not in {"COMPLETED", "REJECTED", "CANCELLED"}:
                    target = self.queue / path.name
                    if target.exists() and document_digest(read_json(target)) != document_digest(task):
                        raise TaskError("TASK_RECOVERY_CONFLICT", f"queue differs for {path.stem}")
                    if not target.exists():
                        atomic_write_json(target, task)
                    recovered.append(path.stem)
        return recovered

    def list_tasks(self) -> list[dict[str, Any]]:
        return [self._load(path.stem) for path in sorted(self.tasks.glob("*.json"))]

    def list_receipts(self) -> list[dict[str, Any]]:
        return [read_json(path) for path in sorted(self.receipts.glob("*.json"))]

    def verify_all_receipts(self) -> None:
        for receipt in self.list_receipts():
            verify_receipt(receipt, self.trusted_keys)
