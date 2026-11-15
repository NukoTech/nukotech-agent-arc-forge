"""Append-only signed workflow run journal with exact crash adoption."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

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
from hive_protocol.workflows.models import (
    WorkflowDefinition,
    WorkflowEvent,
    WorkflowRun,
)


_LAUNCHER_CONTROL_EVENTS = frozenset(
    {
        "RUN_STARTED",
        "RUN_COMPLETED",
        "RUN_CANCELLED",
        "STEP_ASSIGNED",
        "STEP_RETRY_CREATED",
        "SESSION_ABANDONED",
        "CLAIM_RELEASED",
        "COMPENSATION_STARTED",
        "COMPENSATION_COMPLETED",
        "ROLLBACK_STARTED",
        "ROLLBACK_COMPLETED",
        "CONFLICT_DETECTED",
    }
)


class WorkflowRunJournal:
    """Store immutable run bindings and append-only signed workflow events."""

    def __init__(
        self,
        hive_root: Path,
        trusted_keys: Mapping[str, Ed25519PublicKey],
    ) -> None:
        self.hive_root = hive_root.expanduser()
        self.trusted_keys = dict(trusted_keys)
        self.runs = self.hive_root / "workflows" / "runs"
        self.receipts = self.hive_root / ".hive" / "receipts" / "workflows"
        self.runtime = self.hive_root / ".hive" / "runtime" / "workflows"
        self.lock = self.runtime / ".run-journal.lock"
        self.replay = ReplayLedger(self.runtime / "workflow-events.json", mode=0o600)
        for path in (
            self.hive_root,
            self.hive_root / "workflows",
            self.runs,
            self.hive_root / ".hive",
            self.receipts,
            self.runtime,
        ):
            if path.exists() and path.is_symlink():
                raise ProtocolError(
                    "WORKFLOW_JOURNAL_BOUNDARY", "workflow journal paths may not be symlinks"
                )

    @staticmethod
    def _run_id(value: str) -> str:
        try:
            return str(UUID(value))
        except (TypeError, ValueError) as exc:
            raise ProtocolError(
                "WORKFLOW_RUN_ID_INVALID", "workflow run ID must be a canonical UUID"
            ) from exc

    def run_path(self, run_id: str) -> Path:
        canonical = self._run_id(run_id)
        directory = self.runs / canonical
        target = directory / "run.json"
        require_no_symlink_components(
            self.hive_root,
            target,
            code="WORKFLOW_JOURNAL_BOUNDARY",
            detail="workflow run path contains a symlink",
        )
        return target

    def _events_root(self, run_id: str) -> Path:
        target = self.receipts / self._run_id(run_id) / "events"
        require_no_symlink_components(
            self.hive_root,
            target,
            code="WORKFLOW_JOURNAL_BOUNDARY",
            detail="workflow event path contains a symlink",
        )
        return target

    def load_run(self, run_id: str) -> WorkflowRun:
        path = self.run_path(run_id)
        if path.is_symlink() or not path.is_file():
            raise ProtocolError(
                "WORKFLOW_RUN_MISSING", "workflow run is absent or unsafe"
            )
        run = WorkflowRun.from_dict(read_json(path), verified_by=self.trusted_keys)
        verify_document(run.as_dict(), self.trusted_keys)
        if run.run_id != self._run_id(run_id):
            raise ProtocolError(
                "WORKFLOW_RUN_ID_MISMATCH", "run path and document ID differ"
            )
        return run

    def start(
        self,
        definition_document: Mapping[str, Any],
        run_document: Mapping[str, Any],
        *,
        private_key: Ed25519PrivateKey,
        event_id: str,
        idempotency_key: str,
        after_run_write: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        definition = WorkflowDefinition.from_dict(
            definition_document, verified_by=self.trusted_keys
        )
        run = WorkflowRun.from_dict(run_document, verified_by=self.trusted_keys)
        verify_document(definition.as_dict(), self.trusted_keys)
        verify_document(run.as_dict(), self.trusted_keys)
        if (
            run.workflow_id != definition.workflow_id
            or run.workflow_version != definition.version
            or run.workflow_sha256 != definition.digest
            or run.tenant_id != definition.tenant_id
            or run.project_id != definition.project_id
        ):
            raise ProtocolError(
                "WORKFLOW_RUN_BINDING_MISMATCH",
                "workflow run does not bind the exact definition and scope",
            )
        if public_key_id(private_key.public_key()) != run.launched_by["key_id"]:
            raise ProtocolError(
                "WORKFLOW_RUN_SIGNER_MISMATCH",
                "run-start event signer is not the launcher",
            )
        path = self.run_path(run.run_id)
        if path.is_symlink():
            raise ProtocolError(
                "WORKFLOW_JOURNAL_BOUNDARY", "workflow run target may not be a symlink"
            )
        self._ensure_write_roots()
        run_changed = False
        with exclusive_lock(self.lock):
            if path.exists():
                existing = self.load_run(run.run_id)
                if existing.digest != run.digest:
                    raise ProtocolError(
                        "WORKFLOW_RUN_IMMUTABLE",
                        "workflow run ID is already bound to different bytes",
                    )
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                if path.parent.is_symlink():
                    raise ProtocolError(
                        "WORKFLOW_JOURNAL_BOUNDARY", "workflow run directory is unsafe"
                    )
                atomic_write_json(path, run.as_dict())
                run_changed = True
                if after_run_write is not None:
                    after_run_write()
        started = datetime.fromisoformat(run.started_at.replace("Z", "+00:00"))
        event_result = self.append(
            run.run_id,
            event_type="RUN_STARTED",
            actor=run.launched_by,
            payload={
                "workflow_id": run.workflow_id,
                "workflow_version": run.workflow_version,
                "definition_verified": True,
                "source_commit": run.source_commit,
                "input_manifest_sha256": run.input_manifest_sha256,
            },
            private_key=private_key,
            event_id=event_id,
            idempotency_key=idempotency_key,
            recorded_at=started,
            step_id=None,
            attempt=None,
        )
        return {
            "outcome": "RUN_STARTED",
            "changed": run_changed or event_result["changed"],
            "run": run.as_dict(),
            "event": event_result["event"],
        }

    def append(
        self,
        run_id: str,
        *,
        event_type: str,
        actor: Mapping[str, Any],
        payload: Mapping[str, Any],
        private_key: Ed25519PrivateKey,
        event_id: str,
        idempotency_key: str,
        recorded_at: datetime,
        step_id: str | None,
        attempt: int | None,
        after_event_write: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        run = self.load_run(run_id)
        key_id = public_key_id(private_key.public_key())
        if key_id not in self.trusted_keys or actor.get("key_id") != key_id:
            raise ProtocolError(
                "WORKFLOW_EVENT_SIGNER_UNTRUSTED",
                "workflow event signer is not trusted for its actor identity",
            )
        if event_type in _LAUNCHER_CONTROL_EVENTS and (
            key_id != run.launched_by["key_id"]
        ):
            raise ProtocolError(
                "WORKFLOW_EVENT_ROLE_MISMATCH",
                "workflow control events must be signed by the bound launcher",
            )
        if recorded_at.tzinfo is None:
            raise ProtocolError(
                "WORKFLOW_EVENT_TIME_INVALID", "event time requires timezone"
            )
        self._ensure_write_roots()
        with exclusive_lock(self.lock):
            existing_events = self.events(run_id)
            for existing in existing_events:
                if existing.event_id == event_id:
                    expected = self._build_event(
                        run,
                        sequence=existing.sequence,
                        previous_event_sha256=existing.previous_event_sha256,
                        event_type=event_type,
                        actor=actor,
                        payload=payload,
                        private_key=private_key,
                        event_id=event_id,
                        recorded_at=recorded_at,
                        step_id=step_id,
                        attempt=attempt,
                    )
                    if expected.digest != existing.digest:
                        raise ProtocolError(
                            "WORKFLOW_EVENT_ID_CONFLICT",
                            "workflow event ID is bound to different bytes",
                        )
                    state = self._replay_state(idempotency_key, existing.digest)
                    if state == "COMPLETE":
                        return {
                            "outcome": "EVENT_APPENDED",
                            "changed": False,
                            "event": existing.as_dict(),
                        }
                    claim = self.replay.begin(idempotency_key, existing.digest)
                    if claim != "RESUME":
                        raise ProtocolError(
                            "WORKFLOW_EVENT_RECOVERY_CONFLICT",
                            "durable event does not have a pending exact claim",
                        )
                    self.replay.complete(idempotency_key, existing.digest)
                    return {
                        "outcome": "EVENT_APPENDED",
                        "changed": True,
                        "event": existing.as_dict(),
                    }

            self._validate_event_authority(
                run,
                existing_events,
                event_type=event_type,
                actor=actor,
                step_id=step_id,
                attempt=attempt,
            )

            previous = existing_events[-1] if existing_events else None
            event = self._build_event(
                run,
                sequence=len(existing_events) + 1,
                previous_event_sha256=previous.digest if previous else None,
                event_type=event_type,
                actor=actor,
                payload=payload,
                private_key=private_key,
                event_id=event_id,
                recorded_at=recorded_at,
                step_id=step_id,
                attempt=attempt,
            )
            claim = self.replay.begin(idempotency_key, event.digest)
            if claim == "RESUME":
                raise ProtocolError(
                    "WORKFLOW_EVENT_RECOVERY_MISSING",
                    "pending event claim has no exact durable event",
                )
            target = self._events_root(run_id) / (
                f"{event.sequence:09d}-{event.event_id}.json"
            )
            require_no_symlink_components(
                self.hive_root,
                target,
                code="WORKFLOW_JOURNAL_BOUNDARY",
                detail="workflow event target contains a symlink",
            )
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.parent.is_symlink():
                raise ProtocolError(
                    "WORKFLOW_JOURNAL_BOUNDARY", "event directory may not be a symlink"
                )
            atomic_write_json(target, event.as_dict())
            if after_event_write is not None:
                after_event_write()
            self.replay.complete(idempotency_key, event.digest)
            return {
                "outcome": "EVENT_APPENDED",
                "changed": True,
                "event": event.as_dict(),
            }

    @staticmethod
    def _validate_event_authority(
        run: WorkflowRun,
        prior_events: list[WorkflowEvent],
        *,
        event_type: str,
        actor: Mapping[str, Any],
        step_id: str | None,
        attempt: int | None,
    ) -> None:
        if event_type in {"RUN_COMPLETED", "RUN_CANCELLED"} and any(
            event.event_type in {"RUN_COMPLETED", "RUN_CANCELLED"}
            for event in prior_events
        ):
            raise ProtocolError(
                "WORKFLOW_RUN_TERMINAL",
                "workflow run already has one immutable terminal event",
            )
        if event_type in _LAUNCHER_CONTROL_EVENTS and actor.get("key_id") != run.launched_by[
            "key_id"
        ]:
            raise ProtocolError(
                "WORKFLOW_EVENT_ROLE_MISMATCH",
                "workflow control event is not signed by the bound launcher",
            )
        if event_type not in {"STEP_COMPLETED", "STEP_FAILED"}:
            return
        active_claim: WorkflowEvent | None = None
        for event in prior_events:
            if event.step_id != step_id or event.attempt != attempt:
                continue
            if event.event_type == "STEP_CLAIMED":
                active_claim = event
            elif event.event_type in {
                "STEP_COMPLETED",
                "STEP_FAILED",
                "SESSION_ABANDONED",
                "CLAIM_RELEASED",
                "RUN_CANCELLED",
            }:
                active_claim = None
        if active_claim is None or any(
            actor.get(field) != active_claim.actor.get(field)
            for field in ("actor_id", "key_id")
        ):
            raise ProtocolError(
                "WORKFLOW_EVENT_AUTHORITY_INVALID",
                "terminal step event requires the active claim signer",
            )

    def _build_event(
        self,
        run: WorkflowRun,
        *,
        sequence: int,
        previous_event_sha256: str | None,
        event_type: str,
        actor: Mapping[str, Any],
        payload: Mapping[str, Any],
        private_key: Ed25519PrivateKey,
        event_id: str,
        recorded_at: datetime,
        step_id: str | None,
        attempt: int | None,
    ) -> WorkflowEvent:
        document = sign_document(
            {
                "schema_version": "hive.workflow-event.v1",
                "event_id": event_id,
                "run_id": run.run_id,
                "workflow_sha256": run.workflow_sha256,
                "tenant_id": run.tenant_id,
                "project_id": run.project_id,
                "sequence": sequence,
                "event_type": event_type,
                "step_id": step_id,
                "attempt": attempt,
                "actor": copy.deepcopy(dict(actor)),
                "payload": copy.deepcopy(dict(payload)),
                "payload_sha256": document_digest(payload),
                "previous_event_sha256": previous_event_sha256,
                "recorded_at": recorded_at.astimezone(timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
            },
            private_key,
        )
        event = WorkflowEvent.from_dict(document, verified_by=self.trusted_keys)
        verify_document(event.as_dict(), self.trusted_keys)
        return event

    def event_paths(self, run_id: str) -> list[Path]:
        root = self._events_root(run_id)
        if not root.exists():
            return []
        if root.is_symlink() or not root.is_dir():
            raise ProtocolError(
                "WORKFLOW_JOURNAL_BOUNDARY", "event directory is unsafe"
            )
        paths = sorted(root.glob("*.json"))
        if any(path.is_symlink() or not path.is_file() for path in paths):
            raise ProtocolError(
                "WORKFLOW_JOURNAL_BOUNDARY", "event file is unsafe"
            )
        return paths

    def events(self, run_id: str) -> list[WorkflowEvent]:
        run = self.load_run(run_id)
        results: list[WorkflowEvent] = []
        previous: WorkflowEvent | None = None
        event_ids: set[str] = set()
        for expected_sequence, path in enumerate(self.event_paths(run_id), start=1):
            event = WorkflowEvent.from_dict(read_json(path), verified_by=self.trusted_keys)
            verify_document(event.as_dict(), self.trusted_keys)
            if (
                event.run_id != run.run_id
                or event.workflow_sha256 != run.workflow_sha256
                or event.tenant_id != run.tenant_id
                or event.project_id != run.project_id
                or event.sequence != expected_sequence
                or path.name
                != f"{expected_sequence:09d}-{event.event_id}.json"
                or event.event_id in event_ids
                or event.previous_event_sha256
                != (previous.digest if previous is not None else None)
            ):
                raise ProtocolError(
                    "WORKFLOW_EVENT_CHAIN_INVALID",
                    "workflow event chain is gapped, forked, or outside run scope",
                )
            if expected_sequence == 1 and event.event_type != "RUN_STARTED":
                raise ProtocolError(
                    "WORKFLOW_EVENT_CHAIN_INVALID",
                    "workflow event chain must begin with RUN_STARTED",
                )
            self._validate_event_authority(
                run,
                results,
                event_type=event.event_type,
                actor=event.actor,
                step_id=event.step_id,
                attempt=event.attempt,
            )
            if previous is not None and datetime.fromisoformat(
                event.recorded_at.replace("Z", "+00:00")
            ) < datetime.fromisoformat(
                previous.recorded_at.replace("Z", "+00:00")
            ):
                raise ProtocolError(
                    "WORKFLOW_EVENT_CHAIN_INVALID",
                    "workflow event time regressed",
                )
            results.append(event)
            event_ids.add(event.event_id)
            previous = event
        return results

    def _replay_state(self, idempotency_key: str, digest: str) -> str | None:
        if not self.replay.ledger_path.exists():
            return None
        ledger = read_json(self.replay.ledger_path)
        record = ledger.get("messages", {}).get(idempotency_key)
        if not isinstance(record, Mapping):
            return None
        if record.get("nonce") != digest:
            raise ProtocolError(
                "WORKFLOW_EVENT_REPLAY_CONFLICT",
                "event idempotency key is bound to different bytes",
            )
        state = record.get("state")
        if state not in {"PENDING", "COMPLETE"}:
            raise ProtocolError(
                "WORKFLOW_EVENT_REPLAY_CONFLICT", "event replay state is invalid"
            )
        return str(state)

    def _ensure_write_roots(self) -> None:
        for path in (self.runs, self.receipts, self.runtime):
            path.mkdir(parents=True, exist_ok=True)
            if path.is_symlink() or not path.is_dir():
                raise ProtocolError(
                    "WORKFLOW_JOURNAL_BOUNDARY", "workflow journal root is unsafe"
                )
