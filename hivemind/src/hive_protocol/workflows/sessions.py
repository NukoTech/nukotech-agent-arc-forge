"""Durable, attended workflow sessions, stale release, and retry control."""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.core import (
    ProtocolError,
    document_digest,
    public_key_id,
    sign_document,
    verify_document,
)
from hive_protocol.storage import (
    atomic_write_json,
    exclusive_lock,
    read_json,
    require_no_symlink_components,
)
from hive_protocol.workflows.approvals import (
    WorkflowApprovalAuthority,
    build_approval_preview,
)
from hive_protocol.workflows.events import WorkflowRunJournal
from hive_protocol.workflows.models import AgentSession, WorkflowDefinition, WorkflowRun


_SESSION_EVENT_STATES = {
    "SESSION_HEARTBEAT": "ACTIVE",
    "STEP_ACKNOWLEDGED": "ACTIVE",
    "STEP_PROGRESS": "ACTIVE",
    "STEP_OUTPUT": "ACTIVE",
    "STEP_COMPLETED": "COMPLETED",
    "STEP_FAILED": "FAILED",
}
_TERMINAL_SESSION_STATES = {"COMPLETED", "FAILED", "ABANDONED", "CANCELLED"}


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        raise ProtocolError(
            "WORKFLOW_SESSION_TIME_INVALID", "session time requires timezone"
        )
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ProtocolError(
            "WORKFLOW_SESSION_TIME_INVALID", "session time is invalid"
        ) from exc
    if parsed.tzinfo is None:
        raise ProtocolError(
            "WORKFLOW_SESSION_TIME_INVALID", "session time requires timezone"
        )
    return parsed


class WorkflowSessionManager:
    """Persist signed attempt snapshots without executing or polling for work."""

    def __init__(
        self,
        hive_root: Path,
        definition_document: Mapping[str, Any],
        run_document: Mapping[str, Any],
        *,
        journal: WorkflowRunJournal,
        approval_authority: WorkflowApprovalAuthority | None = None,
    ) -> None:
        self.hive_root = hive_root.expanduser()
        self.definition = WorkflowDefinition.from_dict(
            definition_document, verified_by=journal.trusted_keys
        )
        self.run = WorkflowRun.from_dict(run_document, verified_by=journal.trusted_keys)
        self.journal = journal
        self.approval_authority = approval_authority
        verify_document(self.definition.as_dict(), journal.trusted_keys)
        verify_document(self.run.as_dict(), journal.trusted_keys)
        if (
            self.run.workflow_id != self.definition.workflow_id
            or self.run.workflow_version != self.definition.version
            or self.run.workflow_sha256 != self.definition.digest
            or self.run.tenant_id != self.definition.tenant_id
            or self.run.project_id != self.definition.project_id
        ):
            raise ProtocolError(
                "WORKFLOW_SESSION_BINDING_MISMATCH",
                "session manager run and definition do not bind",
            )
        self.steps = {step["step_id"]: step for step in self.definition.steps}
        self.root = (
            self.hive_root
            / ".hive"
            / "receipts"
            / "workflows"
            / self.run.run_id
            / "sessions"
        )
        self.runtime = self.hive_root / ".hive" / "runtime" / "workflows"
        self.lock = self.runtime / ".session-record.lock"
        require_no_symlink_components(
            self.hive_root,
            self.root,
            code="WORKFLOW_SESSION_BOUNDARY",
            detail="workflow session path contains a symlink",
        )
        require_no_symlink_components(
            self.hive_root,
            self.lock,
            code="WORKFLOW_SESSION_BOUNDARY",
            detail="workflow session runtime contains a symlink",
        )
        for path in (self.hive_root, self.hive_root / ".hive", self.root, self.runtime):
            if path.exists() and path.is_symlink():
                raise ProtocolError(
                    "WORKFLOW_SESSION_BOUNDARY", "session paths may not be symlinks"
                )

    def _events(self):
        return self.journal.events(self.run.run_id)

    def _claim_event(self, claim_event_id: str):
        matches = [
            event
            for event in self._events()
            if event.event_id == claim_event_id and event.event_type == "STEP_CLAIMED"
        ]
        if len(matches) != 1:
            raise ProtocolError(
                "WORKFLOW_SESSION_CLAIM_INVALID",
                "session requires one exact durable step claim",
            )
        return matches[0]

    def _session_paths(self, session_id: str) -> list[Path]:
        directory = self.root / session_id
        require_no_symlink_components(
            self.hive_root,
            directory,
            code="WORKFLOW_SESSION_BOUNDARY",
            detail="workflow session directory contains a symlink",
        )
        if not directory.exists():
            return []
        if directory.is_symlink() or not directory.is_dir():
            raise ProtocolError(
                "WORKFLOW_SESSION_BOUNDARY", "session directory is unsafe"
            )
        paths = sorted(directory.glob("*.json"))
        if any(path.is_symlink() or not path.is_file() for path in paths):
            raise ProtocolError(
                "WORKFLOW_SESSION_BOUNDARY", "session snapshot is unsafe"
            )
        return paths

    def history(self, session_id: str) -> list[AgentSession]:
        events = {event.sequence: event for event in self._events()}
        history: list[AgentSession] = []
        prior_recorded_at: datetime | None = None
        for path in self._session_paths(session_id):
            try:
                sequence = int(path.name.split("-", 1)[0])
            except ValueError as exc:
                raise ProtocolError(
                    "WORKFLOW_SESSION_CHAIN_INVALID",
                    "session snapshot sequence is invalid",
                ) from exc
            session = AgentSession.from_dict(
                read_json(path), verified_by=self.journal.trusted_keys
            )
            verify_document(session.as_dict(), self.journal.trusted_keys)
            event = events.get(sequence)
            if (
                session.session_id != session_id
                or event is None
                or event.payload.get("session_id") != session_id
                or event.payload.get("session_sha256") != session.digest
                or event.step_id != session.step_id
                or event.attempt != session.attempt
                or session.run_id != self.run.run_id
                or session.workflow_sha256 != self.run.workflow_sha256
                or session.tenant_id != self.run.tenant_id
                or session.project_id != self.run.project_id
                or path.name != f"{sequence:09d}-{event.event_id}.json"
            ):
                raise ProtocolError(
                    "WORKFLOW_SESSION_CHAIN_INVALID",
                    "session snapshot and workflow event do not bind",
                )
            recorded_at = _time(session.recorded_at)
            if prior_recorded_at is not None and recorded_at < prior_recorded_at:
                raise ProtocolError(
                    "WORKFLOW_SESSION_CHAIN_INVALID",
                    "session recorded time regressed",
                )
            history.append(session)
            prior_recorded_at = recorded_at
        return history

    def _candidate(
        self,
        *,
        session_id: str,
        claim_event_id: str,
        step_id: str,
        attempt: int,
        agent: Mapping[str, Any],
        private_key: Ed25519PrivateKey,
        state: str,
        progress: Mapping[str, Any],
        resources: Mapping[str, Any],
        outputs: Sequence[Mapping[str, Any]],
        recorded_at: datetime,
    ) -> AgentSession:
        document = sign_document(
            {
                "schema_version": "hive.agent-session.v1",
                "session_id": session_id,
                "run_id": self.run.run_id,
                "workflow_sha256": self.run.workflow_sha256,
                "step_id": step_id,
                "attempt": attempt,
                "claim_event_id": claim_event_id,
                "tenant_id": self.run.tenant_id,
                "project_id": self.run.project_id,
                "agent": copy.deepcopy(dict(agent)),
                "state": state,
                "heartbeat_at": _iso(recorded_at),
                "progress": copy.deepcopy(dict(progress)),
                "resources": copy.deepcopy(dict(resources)),
                "outputs": [copy.deepcopy(dict(output)) for output in outputs],
                "recorded_at": _iso(recorded_at),
            },
            private_key,
        )
        session = AgentSession.from_dict(document, verified_by=self.journal.trusted_keys)
        verify_document(session.as_dict(), self.journal.trusted_keys)
        return session

    def _validate_agent(
        self,
        claim_event,
        agent: Mapping[str, Any],
        private_key: Ed25519PrivateKey,
    ) -> None:
        claim = claim_event.payload
        key_id = public_key_id(private_key.public_key())
        expected = {
            "actor_id": claim["agent_id"],
            "persona_id": claim_event.actor["persona_id"],
            "surface_id": claim["surface_id"],
            "machine_id": claim["machine_id"],
            "project_id": self.run.project_id,
            "app_actor": claim_event.actor["app_actor"],
            "key_id": claim["agent_key_id"],
        }
        if key_id != claim["agent_key_id"] or any(
            agent.get(field) != value for field, value in expected.items()
        ):
            raise ProtocolError(
                "WORKFLOW_SESSION_SIGNER_MISMATCH",
                "session signer does not bind the exact claimed agent",
            )

    def _write_snapshot(self, session: AgentSession, event: Mapping[str, Any]) -> bool:
        target = (
            self.root
            / session.session_id
            / f"{event['sequence']:09d}-{event['event_id']}.json"
        )
        require_no_symlink_components(
            self.hive_root,
            target,
            code="WORKFLOW_SESSION_BOUNDARY",
            detail="workflow session target contains a symlink",
        )
        if target.exists():
            existing = AgentSession.from_dict(read_json(target))
            if existing.digest != session.digest:
                raise ProtocolError(
                    "WORKFLOW_SESSION_IMMUTABLE",
                    "session event is already bound to different snapshot bytes",
                )
            return False
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.parent.is_symlink():
            raise ProtocolError(
                "WORKFLOW_SESSION_BOUNDARY", "session directory is unsafe"
            )
        atomic_write_json(target, session.as_dict())
        return True

    def _commit_snapshot(
        self,
        session: AgentSession,
        *,
        event_type: str,
        actor: Mapping[str, Any],
        private_key: Ed25519PrivateKey,
        event_id: str,
        idempotency_key: str,
        recorded_at: datetime,
        after_event_write: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        payload = {
            "session_id": session.session_id,
            "claim_event_id": session.claim_event_id,
            "session_sha256": session.digest,
            "state": session.state,
            "progress": session.progress,
            "resources": session.resources,
            "outputs": session.outputs,
            "execution_started": False,
        }
        event_result = self.journal.append(
            self.run.run_id,
            event_type=event_type,
            actor=actor,
            payload=payload,
            private_key=private_key,
            event_id=event_id,
            idempotency_key=idempotency_key,
            recorded_at=recorded_at,
            step_id=session.step_id,
            attempt=session.attempt,
            after_event_write=after_event_write,
        )
        snapshot_changed = self._write_snapshot(session, event_result["event"])
        return {
            "outcome": event_type,
            "changed": event_result["changed"] or snapshot_changed,
            "session": session.as_dict(),
            "event": event_result["event"],
            "execution_started": False,
        }

    def start(
        self,
        *,
        claim_event_id: str,
        session_id: str,
        agent: Mapping[str, Any],
        private_key: Ed25519PrivateKey,
        total_units: int,
        current_source_commit: str,
        current_input_sha256: str,
        event_id: str,
        idempotency_key: str,
        recorded_at: datetime,
        after_event_write: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        claim_event = self._claim_event(claim_event_id)
        claim = claim_event.payload
        self._validate_agent(claim_event, agent, private_key)
        if (
            current_source_commit != self.run.source_commit
            or current_source_commit != claim["source_commit"]
            or current_input_sha256 != claim["input_sha256"]
        ):
            raise ProtocolError(
                "WORKFLOW_SESSION_INPUT_STALE",
                "session source commit or input digest is stale",
            )
        if recorded_at.tzinfo is None or recorded_at >= _time(claim["expires_at"]):
            raise ProtocolError(
                "WORKFLOW_SESSION_CLAIM_EXPIRED",
                "session must start before its exact claim expires",
            )
        session = self._candidate(
            session_id=session_id,
            claim_event_id=claim_event_id,
            step_id=claim_event.step_id,
            attempt=claim_event.attempt,
            agent=agent,
            private_key=private_key,
            state="ACTIVE",
            progress={"completed_units": 0, "total_units": total_units},
            resources={
                "tokens_used": 0,
                "cost_microunits": 0,
                "peak_memory_mb": 0,
            },
            outputs=[],
            recorded_at=recorded_at,
        )
        self.runtime.mkdir(parents=True, exist_ok=True)
        if self.runtime.is_symlink():
            raise ProtocolError(
                "WORKFLOW_SESSION_BOUNDARY", "session runtime is unsafe"
            )
        with exclusive_lock(self.lock):
            starts = [
                event
                for event in self._events()
                if event.event_type == "SESSION_STARTED"
                and (
                    event.payload.get("claim_event_id") == claim_event_id
                    or (
                        event.step_id == claim_event.step_id
                        and event.attempt == claim_event.attempt
                    )
                )
            ]
            if starts and not (
                len(starts) == 1
                and starts[0].event_id == event_id
                and starts[0].payload.get("session_id") == session_id
                and starts[0].payload.get("session_sha256") == session.digest
            ):
                raise ProtocolError(
                    "WORKFLOW_SESSION_FORK",
                    "claim or attempt is already bound to another session fork",
                )
            return self._commit_snapshot(
                session,
                event_type="SESSION_STARTED",
                actor=agent,
                private_key=private_key,
                event_id=event_id,
                idempotency_key=idempotency_key,
                recorded_at=recorded_at,
                after_event_write=after_event_write,
            )

    def status(self, session_id: str) -> dict[str, Any]:
        history = self.history(session_id)
        if not history:
            raise ProtocolError(
                "WORKFLOW_SESSION_MISSING", "session has no durable snapshots"
            )
        latest = history[-1]
        claim = self._claim_event(latest.claim_event_id).payload
        abandoned = any(
            event.event_type == "SESSION_ABANDONED"
            and event.payload.get("session_id") == session_id
            for event in self._events()
        )
        released = any(
            event.event_type == "CLAIM_RELEASED"
            and event.payload.get("session_id") == session_id
            for event in self._events()
        )
        return {
            "session_id": session_id,
            "effective_state": "ABANDONED" if abandoned else latest.state,
            "claim_active": latest.state == "ACTIVE" and not released,
            "latest": latest.as_dict(),
            "claim": copy.deepcopy(dict(claim)),
            "snapshot_count": len(history),
        }

    def _validate_transition(
        self,
        previous: AgentSession,
        candidate: AgentSession,
        step: Mapping[str, Any],
        event_type: str,
    ) -> None:
        if previous.state in _TERMINAL_SESSION_STATES:
            raise ProtocolError(
                "WORKFLOW_SESSION_TERMINAL", "terminal session cannot be mutated"
            )
        if candidate.state != _SESSION_EVENT_STATES[event_type]:
            raise ProtocolError(
                "WORKFLOW_SESSION_STATE_INVALID",
                "session state does not match its event type",
            )
        if (
            candidate.progress["total_units"]
            != previous.progress["total_units"]
            or candidate.progress["completed_units"]
            < previous.progress["completed_units"]
        ):
            raise ProtocolError(
                "WORKFLOW_SESSION_COUNTER_REGRESSION",
                "session progress counters may not regress",
            )
        for name in ("tokens_used", "cost_microunits", "peak_memory_mb"):
            if candidate.resources[name] < previous.resources[name]:
                raise ProtocolError(
                    "WORKFLOW_SESSION_COUNTER_REGRESSION",
                    "session resource counters may not regress",
                )
        limits = {
            "tokens_used": step["resources"]["max_tokens"],
            "cost_microunits": step["resources"]["max_cost_microunits"],
            "peak_memory_mb": step["resources"]["max_memory_mb"],
        }
        if any(candidate.resources[name] > limit for name, limit in limits.items()):
            raise ProtocolError(
                "WORKFLOW_SESSION_RESOURCE_LIMIT",
                "session resource use exceeds the immutable step limit",
            )
        previous_outputs = {output["name"]: output for output in previous.outputs}
        candidate_outputs = {output["name"]: output for output in candidate.outputs}
        if any(
            name not in candidate_outputs or candidate_outputs[name] != output
            for name, output in previous_outputs.items()
        ):
            raise ProtocolError(
                "WORKFLOW_SESSION_OUTPUT_REGRESSION",
                "session outputs are append-only and immutable",
            )
        declared = {output["name"]: output["type"] for output in step["outputs"]}
        if any(
            name not in declared or output["type"] != declared[name]
            for name, output in candidate_outputs.items()
        ):
            raise ProtocolError(
                "WORKFLOW_SESSION_OUTPUT_INVALID",
                "session output is not declared by the workflow step",
            )
        if any(
            output["evidence_refs"] != sorted(output["evidence_refs"])
            for output in candidate.outputs
        ):
            raise ProtocolError(
                "WORKFLOW_SESSION_OUTPUT_INVALID",
                "session evidence references must be canonical",
            )
        if event_type == "STEP_COMPLETED" and (
            candidate.progress["completed_units"]
            != candidate.progress["total_units"]
            or set(candidate_outputs) != set(declared)
        ):
            raise ProtocolError(
                "WORKFLOW_SESSION_COMPLETION_INVALID",
                "completed session must finish all units and declared outputs",
            )

    def record(
        self,
        session_id: str,
        *,
        event_type: str,
        agent: Mapping[str, Any],
        private_key: Ed25519PrivateKey,
        state: str,
        progress: Mapping[str, Any],
        resources: Mapping[str, Any],
        outputs: Sequence[Mapping[str, Any]],
        current_source_commit: str,
        current_input_sha256: str,
        event_id: str,
        idempotency_key: str,
        recorded_at: datetime,
        after_event_write: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        if event_type not in _SESSION_EVENT_STATES:
            raise ProtocolError(
                "WORKFLOW_SESSION_EVENT_INVALID", "unsupported session event type"
            )
        self.runtime.mkdir(parents=True, exist_ok=True)
        with exclusive_lock(self.lock):
            history = self.history(session_id)
            if not history:
                raise ProtocolError(
                    "WORKFLOW_SESSION_MISSING", "session has no durable start"
                )
            previous = history[-1]
            claim_event = self._claim_event(previous.claim_event_id)
            self._validate_agent(claim_event, agent, private_key)
            claim = claim_event.payload
            if (
                current_source_commit != self.run.source_commit
                or current_source_commit != claim["source_commit"]
                or current_input_sha256 != claim["input_sha256"]
            ):
                raise ProtocolError(
                    "WORKFLOW_SESSION_INPUT_STALE",
                    "session source commit or input digest is stale",
                )
            candidate = self._candidate(
                session_id=session_id,
                claim_event_id=previous.claim_event_id,
                step_id=previous.step_id,
                attempt=previous.attempt,
                agent=agent,
                private_key=private_key,
                state=state,
                progress=progress,
                resources=resources,
                outputs=outputs,
                recorded_at=recorded_at,
            )
            existing = next(
                (event for event in self._events() if event.event_id == event_id), None
            )
            if existing is None:
                if recorded_at.tzinfo is None or recorded_at < _time(previous.recorded_at):
                    raise ProtocolError(
                        "WORKFLOW_SESSION_TIME_INVALID",
                        "session recorded time may not regress",
                    )
                self._validate_transition(
                    previous, candidate, self.steps[previous.step_id], event_type
                )
            return self._commit_snapshot(
                candidate,
                event_type=event_type,
                actor=agent,
                private_key=private_key,
                event_id=event_id,
                idempotency_key=idempotency_key,
                recorded_at=recorded_at,
                after_event_write=after_event_write,
            )

    def stale_preview(
        self, session_id: str, *, now: datetime, expires_at: datetime
    ) -> dict[str, Any]:
        status = self.status(session_id)
        latest = AgentSession.from_dict(status["latest"])
        if status["effective_state"] != "ACTIVE":
            raise ProtocolError(
                "WORKFLOW_SESSION_TERMINAL", "only an active session may become stale"
            )
        stale_at = _time(latest.heartbeat_at) + timedelta(
            seconds=self.run.policy["stale_after_seconds"]
        )
        if now.tzinfo is None or now < stale_at:
            raise ProtocolError(
                "WORKFLOW_SESSION_NOT_STALE", "session has not crossed its stale bound"
            )
        return self._stale_preview_document(
            status, latest, created_at=now, expires_at=expires_at
        )

    def _stale_preview_document(
        self,
        status: Mapping[str, Any],
        latest: AgentSession,
        *,
        created_at: datetime,
        expires_at: datetime,
    ) -> dict[str, Any]:
        step = self.steps[latest.step_id]
        return build_approval_preview(
            approval_kind="STALE_RELEASE",
            run_id=self.run.run_id,
            workflow_sha256=self.run.workflow_sha256,
            step_id=latest.step_id,
            attempt=latest.attempt,
            tenant_id=self.run.tenant_id,
            project_id=self.run.project_id,
            action=(
                f"abandon stale session {latest.session_id} and release its exact claim"
            ),
            destination=(
                f"workflows/runs/{self.run.run_id}/sessions/{latest.session_id}"
            ),
            data_classes=["WORKFLOW_RECEIPT"],
            side_effects=["CLAIM_RELEASE", "SESSION_ABANDONMENT"],
            evidence_refs=[f"session:{latest.digest}"],
            rollback=step["rollback"],
            risk_class="HIGH",
            input_sha256=status["claim"]["input_sha256"],
            conflict_ids=[],
            existing_capabilities=status["claim"]["capabilities"],
            requested_capabilities=status["claim"]["capabilities"],
            created_at=created_at,
            expires_at=expires_at,
        )

    def _validate_launcher(
        self, actor: Mapping[str, Any], private_key: Ed25519PrivateKey
    ) -> None:
        key_id = public_key_id(private_key.public_key())
        if key_id != self.run.launched_by["key_id"] or dict(actor) != dict(
            self.run.launched_by
        ):
            raise ProtocolError(
                "WORKFLOW_SESSION_OPERATOR_MISMATCH",
                "attended recovery must be signed by the bound launcher",
            )

    def release_stale(
        self,
        session_id: str,
        *,
        preview: Mapping[str, Any],
        approval: Mapping[str, Any],
        actor: Mapping[str, Any],
        private_key: Ed25519PrivateKey,
        now: datetime,
        abandonment_event_id: str,
        release_event_id: str,
        idempotency_key: str,
        after_abandonment_event: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        if (
            self.run.policy["mode"] != "ATTENDED"
            or not self.run.policy["allow_claim_release"]
            or self.approval_authority is None
        ):
            raise ProtocolError(
                "WORKFLOW_STALE_RELEASE_FORBIDDEN",
                "run policy does not permit attended claim release",
            )
        self._validate_launcher(actor, private_key)
        status = self.status(session_id)
        latest = AgentSession.from_dict(status["latest"])
        created_at = _time(str(preview.get("created_at", "")))
        expires_at = _time(str(preview.get("expires_at", "")))
        stale_at = _time(latest.heartbeat_at) + timedelta(
            seconds=self.run.policy["stale_after_seconds"]
        )
        existing_abandonment = next(
            (
                event
                for event in self._events()
                if event.event_id == abandonment_event_id
                and event.event_type == "SESSION_ABANDONED"
            ),
            None,
        )
        if created_at < stale_at:
            raise ProtocolError(
                "WORKFLOW_SESSION_NOT_STALE", "session was not stale at preview time"
            )
        if status["effective_state"] != "ACTIVE" and existing_abandonment is None:
            raise ProtocolError(
                "WORKFLOW_SESSION_TERMINAL", "session is already terminal"
            )
        expected = self._stale_preview_document(
            status, latest, created_at=created_at, expires_at=expires_at
        )
        if dict(preview) != expected:
            raise ProtocolError(
                "WORKFLOW_STALE_RELEASE_BINDING_MISMATCH",
                "stale release does not bind the exact current session preview",
            )
        self.approval_authority.verify(approval, preview, now=now)
        payload = {
            "session_id": session_id,
            "claim_event_id": latest.claim_event_id,
            "session_sha256": latest.digest,
            "preview_sha256": document_digest(preview),
            "approval_sha256": document_digest(approval),
            "reason": "ATTENDED_STALE_RELEASE",
            "execution_started": False,
        }
        with exclusive_lock(self.lock):
            abandoned = self.journal.append(
                self.run.run_id,
                event_type="SESSION_ABANDONED",
                actor=actor,
                payload=payload,
                private_key=private_key,
                event_id=abandonment_event_id,
                idempotency_key=f"{idempotency_key}:abandon",
                recorded_at=now,
                step_id=latest.step_id,
                attempt=latest.attempt,
                after_event_write=after_abandonment_event,
            )
            released = self.journal.append(
                self.run.run_id,
                event_type="CLAIM_RELEASED",
                actor=actor,
                payload=payload,
                private_key=private_key,
                event_id=release_event_id,
                idempotency_key=f"{idempotency_key}:release",
                recorded_at=now,
                step_id=latest.step_id,
                attempt=latest.attempt,
            )
        return {
            "outcome": "CLAIM_RELEASED",
            "changed": abandoned["changed"] or released["changed"],
            "abandonment_event": abandoned["event"],
            "release_event": released["event"],
            "execution_started": False,
        }

    def create_retry(
        self,
        step_id: str,
        *,
        failed_attempt: int,
        actor: Mapping[str, Any],
        private_key: Ed25519PrivateKey,
        event_id: str,
        idempotency_key: str,
        recorded_at: datetime,
        attended_confirmation: bool,
    ) -> dict[str, Any]:
        if not attended_confirmation or self.run.policy["mode"] != "ATTENDED":
            raise ProtocolError(
                "WORKFLOW_RETRY_ATTENDANCE_REQUIRED",
                "retry creation requires an attended confirmation",
            )
        self._validate_launcher(actor, private_key)
        if step_id not in self.steps or failed_attempt < 1:
            raise ProtocolError(
                "WORKFLOW_RETRY_SCOPE_INVALID", "retry step or attempt is invalid"
            )
        step = self.steps[step_id]
        new_attempt = failed_attempt + 1
        if new_attempt > step["retry"]["max_attempts"]:
            raise ProtocolError(
                "WORKFLOW_RETRY_EXHAUSTED", "workflow retry limit is exhausted"
            )
        with exclusive_lock(self.lock):
            events = self._events()
            causes = [
                event
                for event in events
                if event.step_id == step_id
                and event.attempt == failed_attempt
                and event.event_type in {"STEP_FAILED", "SESSION_ABANDONED"}
            ]
            if len(causes) != 1:
                raise ProtocolError(
                    "WORKFLOW_RETRY_CAUSE_INVALID",
                    "retry requires one exact failed or abandoned prior attempt",
                )
            existing_retries = [
                event
                for event in events
                if event.event_type == "STEP_RETRY_CREATED"
                and event.step_id == step_id
                and event.attempt == new_attempt
                and event.payload.get("failed_attempt") == failed_attempt
                and event.payload.get("new_attempt") == new_attempt
            ]
            if existing_retries and not (
                len(existing_retries) == 1
                and existing_retries[0].event_id == event_id
            ):
                raise ProtocolError(
                    "WORKFLOW_RETRY_ALREADY_AUTHORIZED",
                    "failed attempt already has one immutable retry authorization",
                )
            if any(
                event.step_id == step_id
                and event.attempt == failed_attempt
                and event.event_type == "STEP_COMPLETED"
                for event in events
            ):
                raise ProtocolError(
                    "WORKFLOW_RETRY_CAUSE_INVALID",
                    "a completed attempt may not be retried",
                )
            payload = {
                "failed_attempt": failed_attempt,
                "new_attempt": new_attempt,
                "cause_event_sha256": causes[0].digest,
                "attended_confirmation": True,
                "execution_started": False,
            }
            result = self.journal.append(
                self.run.run_id,
                event_type="STEP_RETRY_CREATED",
                actor=actor,
                payload=payload,
                private_key=private_key,
                event_id=event_id,
                idempotency_key=idempotency_key,
                recorded_at=recorded_at,
                step_id=step_id,
                attempt=new_attempt,
            )
        return {
            "outcome": "RETRY_CREATED",
            "changed": result["changed"],
            "new_attempt": new_attempt,
            "event": result["event"],
            "execution_started": False,
        }

    def _compensation_binding(
        self, failed_step_id: str, failed_attempt: int
    ) -> tuple[Mapping[str, Any], Mapping[str, Any], Any]:
        failed_step = self.steps.get(failed_step_id)
        if not isinstance(failed_step, Mapping) or failed_attempt < 1:
            raise ProtocolError(
                "WORKFLOW_COMPENSATION_UNDECLARED",
                "compensation source step is invalid",
            )
        compensation_step_id = failed_step["rollback"]["compensation_step_id"]
        compensation_step = self.steps.get(compensation_step_id)
        if (
            failed_step["rollback"]["mode"] != "COMPENSATION"
            or not isinstance(compensation_step, Mapping)
            or compensation_step["kind"] != "COMPENSATION"
        ):
            raise ProtocolError(
                "WORKFLOW_COMPENSATION_UNDECLARED",
                "recovery step is not declared by the bound workflow version",
            )
        causes = [
            event
            for event in self._events()
            if event.step_id == failed_step_id
            and event.attempt == failed_attempt
            and event.event_type in {"STEP_FAILED", "SESSION_ABANDONED"}
        ]
        if len(causes) != 1:
            raise ProtocolError(
                "WORKFLOW_COMPENSATION_CAUSE_INVALID",
                "compensation requires one exact failed or abandoned attempt",
            )
        return failed_step, compensation_step, causes[0]

    def compensation_preview(
        self,
        failed_step_id: str,
        *,
        failed_attempt: int,
        now: datetime,
        expires_at: datetime,
    ) -> dict[str, Any]:
        _, compensation_step, cause = self._compensation_binding(
            failed_step_id, failed_attempt
        )
        destination = (
            compensation_step["ownership"]["files"][0]
            if compensation_step["ownership"]["files"]
            else f"workflows/runs/{self.run.run_id}/compensation"
        )
        return build_approval_preview(
            approval_kind="COMPENSATION",
            run_id=self.run.run_id,
            workflow_sha256=self.run.workflow_sha256,
            step_id=compensation_step["step_id"],
            attempt=1,
            tenant_id=self.run.tenant_id,
            project_id=self.run.project_id,
            action=(
                f"authorize declared compensation {compensation_step['step_id']} "
                f"for {failed_step_id} attempt {failed_attempt}"
            ),
            destination=destination,
            data_classes=["WORKFLOW_RECEIPT"],
            side_effects=["DECLARED_COMPENSATION"],
            evidence_refs=[f"event:{cause.digest}"],
            rollback=compensation_step["rollback"],
            risk_class=compensation_step["approval"]["risk_class"],
            input_sha256=cause.digest,
            conflict_ids=[],
            existing_capabilities=compensation_step["required_capabilities"],
            requested_capabilities=compensation_step["required_capabilities"],
            created_at=now,
            expires_at=expires_at,
        )

    def authorize_compensation(
        self,
        failed_step_id: str,
        *,
        failed_attempt: int,
        preview: Mapping[str, Any],
        approval: Mapping[str, Any] | None,
        actor: Mapping[str, Any],
        private_key: Ed25519PrivateKey,
        event_id: str,
        idempotency_key: str,
        recorded_at: datetime,
        attended_confirmation: bool,
    ) -> dict[str, Any]:
        if not attended_confirmation or self.run.policy["mode"] != "ATTENDED":
            raise ProtocolError(
                "WORKFLOW_COMPENSATION_ATTENDANCE_REQUIRED",
                "compensation requires attended confirmation",
            )
        self._validate_launcher(actor, private_key)
        _, compensation_step, cause = self._compensation_binding(
            failed_step_id, failed_attempt
        )
        expected = self.compensation_preview(
            failed_step_id,
            failed_attempt=failed_attempt,
            now=_time(str(preview.get("created_at", ""))),
            expires_at=_time(str(preview.get("expires_at", ""))),
        )
        if dict(preview) != expected:
            raise ProtocolError(
                "WORKFLOW_COMPENSATION_BINDING_MISMATCH",
                "compensation does not bind the exact declared recovery preview",
            )
        if compensation_step["approval"]["required"]:
            if self.approval_authority is None or not isinstance(approval, Mapping):
                raise ProtocolError(
                    "WORKFLOW_COMPENSATION_APPROVAL_REQUIRED",
                    "protected compensation requires exact attended approval",
                )
            self.approval_authority.verify(approval, preview, now=recorded_at)
        payload = {
            "failed_step_id": failed_step_id,
            "failed_attempt": failed_attempt,
            "cause_event_sha256": cause.digest,
            "compensation_step_id": compensation_step["step_id"],
            "preview_sha256": document_digest(preview),
            "approval_sha256": (
                document_digest(approval) if isinstance(approval, Mapping) else None
            ),
            "attended_confirmation": True,
            "execution_started": False,
        }
        with exclusive_lock(self.lock):
            existing = [
                event
                for event in self._events()
                if event.event_type == "COMPENSATION_STARTED"
                and event.payload.get("cause_event_sha256") == cause.digest
            ]
            if existing and not (
                len(existing) == 1 and existing[0].event_id == event_id
            ):
                raise ProtocolError(
                    "WORKFLOW_COMPENSATION_ALREADY_AUTHORIZED",
                    "failed attempt already has a compensation authorization",
                )
            result = self.journal.append(
                self.run.run_id,
                event_type="COMPENSATION_STARTED",
                actor=actor,
                payload=payload,
                private_key=private_key,
                event_id=event_id,
                idempotency_key=idempotency_key,
                recorded_at=recorded_at,
                step_id=compensation_step["step_id"],
                attempt=1,
            )
        return {
            "outcome": "COMPENSATION_AUTHORIZED",
            "changed": result["changed"],
            "step_id": compensation_step["step_id"],
            "event": result["event"],
            "execution_started": False,
        }
