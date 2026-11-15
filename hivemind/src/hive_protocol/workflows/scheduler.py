"""Deterministic attended workflow readiness and signed step claims."""

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
    verify_document,
)
from hive_protocol.storage import exclusive_lock, require_no_symlink_components
from hive_protocol.workflows.approvals import WorkflowApprovalAuthority
from hive_protocol.workflows.conflicts import analyze_step_conflicts
from hive_protocol.workflows.events import WorkflowRunJournal
from hive_protocol.workflows.matching import match_agents
from hive_protocol.workflows.models import WorkflowDefinition, WorkflowRun


def _claim_expiry(value: Any) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError(
            "WORKFLOW_CLAIM_TIME_INVALID", "claim expiry must be ISO-8601"
        ) from exc
    if parsed.tzinfo is None:
        raise ProtocolError(
            "WORKFLOW_CLAIM_TIME_INVALID", "claim expiry requires a timezone"
        )
    return parsed


class WorkflowScheduler:
    """Compute readiness and record claims; never start a process or adapter."""

    def __init__(
        self,
        hive_root: Path,
        definition_document: Mapping[str, Any],
        run_document: Mapping[str, Any],
        *,
        journal: WorkflowRunJournal,
        registry: Mapping[str, Any],
        approval_authority: WorkflowApprovalAuthority | None = None,
        workspace_id: str = "local-hive",
    ) -> None:
        self.hive_root = hive_root.expanduser()
        self.definition = WorkflowDefinition.from_dict(
            definition_document, verified_by=journal.trusted_keys
        )
        self.run = WorkflowRun.from_dict(run_document, verified_by=journal.trusted_keys)
        self.journal = journal
        self.registry = copy.deepcopy(dict(registry))
        self.approval_authority = approval_authority
        self.workspace_id = workspace_id
        verify_document(self.definition.as_dict(), journal.trusted_keys)
        verify_document(self.run.as_dict(), journal.trusted_keys)
        if (
            self.run.workflow_id != self.definition.workflow_id
            or self.run.workflow_version != self.definition.version
            or self.run.workflow_sha256 != self.definition.digest
            or self.run.project_id != self.definition.project_id
            or self.run.tenant_id != self.definition.tenant_id
        ):
            raise ProtocolError(
                "WORKFLOW_SCHEDULER_BINDING_MISMATCH",
                "scheduler run and definition do not bind",
            )
        self.steps = {step["step_id"]: step for step in self.definition.steps}
        self.lock = self.hive_root / ".hive" / "runtime" / "workflows" / ".scheduler.lock"
        require_no_symlink_components(
            self.hive_root,
            self.lock,
            code="WORKFLOW_SCHEDULER_BOUNDARY",
            detail="workflow scheduler path contains a symlink",
        )

    def _validated_claim(self, event: Any) -> dict[str, Any]:
        payload = event.payload
        expected_fields = {
            "claim_id",
            "run_id",
            "workflow_sha256",
            "step_id",
            "attempt",
            "agent_id",
            "agent_key_id",
            "capabilities",
            "machine_id",
            "surface_id",
            "source_commit",
            "input_sha256",
            "readiness_sha256",
            "owned_branches",
            "owned_files",
            "expires_at",
        }
        step = self.steps.get(event.step_id)
        agents = self.registry.get("agents")
        record = (
            agents.get(payload.get("agent_id"))
            if isinstance(agents, Mapping)
            else None
        )
        claim_body = dict(payload)
        claim_id = claim_body.pop("claim_id", None)
        matches = (
            match_agents(
                self.registry,
                step,
                tenant_id=self.run.tenant_id,
                workspace_id=self.workspace_id,
                project_id=self.run.project_id,
            )
            if isinstance(step, Mapping)
            else []
        )
        matched_ids = {item["agent_id"] for item in matches}
        expected_actor = (
            {
                "actor_id": record["agent_id"],
                "persona_id": record["persona_id"],
                "surface_id": record["surface_id"],
                "machine_id": record.get("machine_id"),
                "project_id": self.run.project_id,
                "app_actor": record.get("app_actor"),
                "key_id": record["key_id"],
            }
            if isinstance(record, Mapping)
            else None
        )
        if (
            set(payload) != expected_fields
            or not isinstance(step, Mapping)
            or not isinstance(record, Mapping)
            or payload.get("agent_id") not in matched_ids
            or dict(event.actor) != expected_actor
            or event.step_id != payload.get("step_id")
            or event.attempt != payload.get("attempt")
            or payload.get("run_id") != self.run.run_id
            or payload.get("workflow_sha256") != self.run.workflow_sha256
            or payload.get("agent_key_id") != record.get("key_id")
            or payload.get("capabilities") != step["required_capabilities"]
            or payload.get("machine_id") != record.get("machine_id")
            or payload.get("surface_id") != record.get("surface_id")
            or payload.get("owned_branches") != step["ownership"]["branches"]
            or payload.get("owned_files") != step["ownership"]["files"]
            or claim_id != f"claim:{document_digest(claim_body)}"
        ):
            raise ProtocolError(
                "WORKFLOW_EVENT_AUTHORITY_INVALID",
                "step claim does not bind one eligible registered agent and immutable step",
            )
        _claim_expiry(payload["expires_at"])
        return copy.deepcopy(dict(payload))

    def _state(self) -> dict[str, Any]:
        completed: dict[str, dict[str, Any]] = {}
        claims: dict[tuple[str, int], dict[str, Any]] = {}
        terminal_attempts: set[tuple[str, int]] = set()
        authorized_retries: set[tuple[str, int]] = set()
        authorized_compensations: dict[tuple[str, int], dict[str, Any]] = {}
        run_terminal: str | None = None
        events = self.journal.events(self.run.run_id)
        terminal = {
            "STEP_COMPLETED",
            "STEP_FAILED",
            "SESSION_ABANDONED",
            "CLAIM_RELEASED",
            "RUN_CANCELLED",
        }
        for event in events:
            marker = (
                (event.step_id, event.attempt)
                if event.step_id is not None and event.attempt is not None
                else None
            )
            if event.event_type == "STEP_CLAIMED" and marker is not None:
                payload = self._validated_claim(event)
                claims[marker] = {
                    "claim_id": payload["claim_id"],
                    "step_id": event.step_id,
                    "attempt": event.attempt,
                    "project_id": event.project_id,
                    "machine_id": payload["machine_id"],
                    "branches": payload["owned_branches"],
                    "files": payload["owned_files"],
                    "expires_at": payload["expires_at"],
                    "agent_id": payload["agent_id"],
                    "agent_key_id": payload["agent_key_id"],
                }
            if event.event_type in terminal and marker is not None:
                claim = claims.get(marker)
                if event.event_type in {"STEP_COMPLETED", "STEP_FAILED"} and (
                    claim is None
                    or event.actor.get("actor_id") != claim["agent_id"]
                    or event.actor.get("key_id") != claim["agent_key_id"]
                ):
                    raise ProtocolError(
                        "WORKFLOW_EVENT_AUTHORITY_INVALID",
                        "terminal step event does not bind the active signed claim",
                    )
                claims.pop(marker, None)
                terminal_attempts.add(marker)
            if event.event_type == "STEP_RETRY_CREATED" and marker is not None:
                if event.payload.get("new_attempt") == event.attempt:
                    authorized_retries.add(marker)
            if event.event_type == "COMPENSATION_STARTED" and marker is not None:
                authorized_compensations[marker] = event.payload
            if event.event_type == "STEP_COMPLETED" and marker is not None:
                completed[event.step_id] = {
                    "attempt": event.attempt,
                    "outputs": copy.deepcopy(event.payload.get("outputs", [])),
                    "event_sha256": event.digest,
                }
            if event.event_type == "RUN_CANCELLED":
                claims.clear()
                run_terminal = "CANCELLED"
            elif event.event_type == "RUN_COMPLETED":
                run_terminal = "COMPLETED"
        return {
            "events": events,
            "event_head_sha256": events[-1].digest if events else None,
            "completed": completed,
            "active_claims": list(claims.values()),
            "terminal_attempts": terminal_attempts,
            "authorized_retries": authorized_retries,
            "authorized_compensations": authorized_compensations,
            "run_terminal": run_terminal,
        }

    @staticmethod
    def _blocker(code: str, detail: Mapping[str, Any]) -> dict[str, Any]:
        return {"code": code, "blocking": True, "detail": dict(detail)}

    def evaluate(
        self,
        step_id: str,
        *,
        attempt: int,
        current_source_commit: str,
        current_machine_id: str,
        task_sha256: str,
        existing_task_sha256s: Sequence[str],
        required_evidence_refs: Sequence[str],
        available_evidence_refs: Sequence[str],
        approvals: Sequence[Mapping[str, Any]],
        now: datetime,
        explicit_agent_id: str | None = None,
    ) -> dict[str, Any]:
        if step_id not in self.steps or attempt < 1 or now.tzinfo is None:
            raise ProtocolError(
                "WORKFLOW_READINESS_INPUT_INVALID", "readiness input is invalid"
            )
        step = self.steps[step_id]
        state = self._state()
        active_claims = [
            claim
            for claim in state["active_claims"]
            if _claim_expiry(claim["expires_at"]) > now
        ]
        blockers: list[dict[str, Any]] = []
        marker = (step_id, attempt)
        if state["run_terminal"] is not None:
            blockers.append(
                self._blocker(
                    "RUN_TERMINAL", {"state": state["run_terminal"]}
                )
            )
        if attempt > step["retry"]["max_attempts"]:
            blockers.append(
                self._blocker(
                    "RETRY_LIMIT_EXCEEDED",
                    {"max_attempts": step["retry"]["max_attempts"]},
                )
            )
        elif attempt > 1 and marker not in state["authorized_retries"]:
            blockers.append(
                self._blocker(
                    "RETRY_NOT_AUTHORIZED", {"attempt": attempt}
                )
            )
        if marker in state["terminal_attempts"]:
            blockers.append(
                self._blocker(
                    "ATTEMPT_TERMINAL", {"attempt": attempt}
                )
            )
        if (
            step["kind"] == "COMPENSATION"
            and marker not in state["authorized_compensations"]
        ):
            blockers.append(
                self._blocker(
                    "COMPENSATION_NOT_AUTHORIZED", {"attempt": attempt}
                )
            )
        inputs: list[dict[str, Any]] = []
        for dependency in step["dependencies"]:
            if dependency not in state["completed"]:
                blockers.append(
                    self._blocker(
                        "DEPENDENCY_NOT_SUCCEEDED", {"dependency": dependency}
                    )
                )
        for input_spec in step["inputs"]:
            source = state["completed"].get(input_spec["source_step_id"])
            output = None
            if source is not None:
                output = next(
                    (
                        item
                        for item in source["outputs"]
                        if item.get("name") == input_spec["source_output"]
                        and item.get("type") == input_spec["type"]
                    ),
                    None,
                )
            if output is None:
                if input_spec["required"]:
                    blockers.append(
                        self._blocker(
                            "INPUT_MISSING",
                            {
                                "name": input_spec["name"],
                                "source_step_id": input_spec["source_step_id"],
                                "source_output": input_spec["source_output"],
                                "type": input_spec["type"],
                            },
                        )
                    )
                continue
            inputs.append(
                {
                    "name": input_spec["name"],
                    "type": output["type"],
                    "sha256": output["sha256"],
                    "source_step_id": input_spec["source_step_id"],
                    "source_output": input_spec["source_output"],
                    "evidence_refs": sorted(output.get("evidence_refs", [])),
                }
            )
        inputs.sort(key=lambda item: item["name"])
        input_sha256 = document_digest(
            {
                "run_id": self.run.run_id,
                "step_id": step_id,
                "attempt": attempt,
                "inputs": inputs,
            }
        )
        matches = match_agents(
            self.registry,
            step,
            tenant_id=self.run.tenant_id,
            workspace_id=self.workspace_id,
            project_id=self.run.project_id,
        )
        if explicit_agent_id is not None:
            matches = [item for item in matches if item["agent_id"] == explicit_agent_id]
        if not matches:
            blockers.append(
                self._blocker(
                    "AGENT_MATCH_MISSING",
                    {"explicit_agent_id": explicit_agent_id},
                )
            )
        available_capabilities = sorted(
            {
                capability
                for match in matches
                for capability in match["capabilities"]
            }
        )
        conflicts = analyze_step_conflicts(
            step,
            run_id=self.run.run_id,
            workflow_sha256=self.run.workflow_sha256,
            project_id=self.run.project_id,
            machine_id=current_machine_id,
            run_source_commit=self.run.source_commit,
            current_source_commit=current_source_commit,
            active_claims=active_claims,
            task_sha256=task_sha256,
            existing_task_sha256s=existing_task_sha256s,
            required_evidence_refs=required_evidence_refs,
            available_evidence_refs=available_evidence_refs,
            agent_capabilities=available_capabilities,
            now=now,
        )
        approved_conflict_ids: set[str] = set()
        actual_conflict_ids = {item["conflict_id"] for item in conflicts}
        if self.approval_authority is not None:
            for pair in approvals:
                preview = pair.get("preview")
                approval = pair.get("approval")
                if not isinstance(preview, Mapping) or not isinstance(
                    approval, Mapping
                ):
                    continue
                preview_conflicts = set(preview.get("conflict_ids", []))
                if (
                    preview.get("approval_kind") != "CONFLICT_EXCEPTION"
                    or preview.get("run_id") != self.run.run_id
                    or preview.get("workflow_sha256") != self.run.workflow_sha256
                    or preview.get("step_id") != step_id
                    or preview.get("attempt") != attempt
                    or preview.get("input_sha256") != input_sha256
                    or not preview_conflicts
                    or not preview_conflicts.issubset(actual_conflict_ids)
                ):
                    continue
                try:
                    verified = self.approval_authority.verify(
                        approval, preview, now=now
                    )
                except ProtocolError:
                    continue
                if verified:
                    approved_conflict_ids.update(preview_conflicts)
        blockers.extend(
            conflict
            for conflict in conflicts
            if conflict["conflict_id"] not in approved_conflict_ids
        )
        if len(active_claims) >= self.run.policy["max_concurrent_claims"]:
            blockers.append(
                self._blocker(
                    "CLAIM_LIMIT_REACHED",
                    {"active_claims": len(active_claims)},
                )
            )
        if step["approval"]["required"]:
            approved = False
            if self.approval_authority is not None:
                for pair in approvals:
                    preview = pair.get("preview")
                    approval = pair.get("approval")
                    if not isinstance(preview, Mapping) or not isinstance(
                        approval, Mapping
                    ):
                        continue
                    compensation = state["authorized_compensations"].get(marker)
                    compensation_pair = (
                        step["kind"] == "COMPENSATION"
                        and compensation is not None
                        and preview.get("approval_kind") == "COMPENSATION"
                        and compensation.get("preview_sha256")
                        == document_digest(preview)
                        and compensation.get("approval_sha256")
                        == document_digest(approval)
                    )
                    if (
                        preview.get("run_id") != self.run.run_id
                        or preview.get("step_id") != step_id
                        or preview.get("attempt") != attempt
                        or (
                            preview.get("approval_kind") != "STEP_APPROVAL"
                            and not compensation_pair
                        )
                        or (
                            preview.get("input_sha256") != input_sha256
                            and not compensation_pair
                        )
                    ):
                        continue
                    try:
                        approved = self.approval_authority.verify(
                            approval, preview, now=now
                        )
                    except ProtocolError:
                        continue
                    if approved:
                        break
            if not approved:
                blockers.append(
                    self._blocker(
                        "APPROVAL_REQUIRED",
                        {"risk_class": step["approval"]["risk_class"]},
                    )
                )
        blockers.sort(key=lambda item: (item["code"], document_digest(item)))
        body = {
            "schema_version": "hive.workflow-readiness.v1",
            "run_id": self.run.run_id,
            "workflow_sha256": self.run.workflow_sha256,
            "step_id": step_id,
            "attempt": attempt,
            "project_id": self.run.project_id,
            "source_commit": current_source_commit,
            "input_sha256": input_sha256,
            "inputs": inputs,
            "event_head_sha256": state["event_head_sha256"],
            "eligible_agents": [item["agent_id"] for item in matches],
            "assigned_agent_id": matches[0]["agent_id"] if matches else None,
            "current_machine_id": current_machine_id,
            "task_sha256": task_sha256,
            "existing_task_sha256s": sorted(existing_task_sha256s),
            "required_evidence_refs": sorted(required_evidence_refs),
            "available_evidence_refs": sorted(available_evidence_refs),
            "explicit_agent_id": explicit_agent_id,
            "approved_conflict_ids": sorted(approved_conflict_ids),
            "blockers": blockers,
            "ready": not blockers,
            "execution_started": False,
        }
        return {**body, "readiness_sha256": document_digest(body)}

    def claim(
        self,
        readiness: Mapping[str, Any],
        *,
        agent_id: str,
        actor: Mapping[str, Any],
        private_key: Ed25519PrivateKey,
        expires_at: datetime,
        event_id: str,
        idempotency_key: str,
        now: datetime,
        approvals: Sequence[Mapping[str, Any]] = (),
        after_event_write: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        body = copy.deepcopy(dict(readiness))
        readiness_sha256 = body.pop("readiness_sha256", None)
        expected_fields = {
            "schema_version",
            "run_id",
            "workflow_sha256",
            "step_id",
            "attempt",
            "project_id",
            "source_commit",
            "input_sha256",
            "inputs",
            "event_head_sha256",
            "eligible_agents",
            "assigned_agent_id",
            "current_machine_id",
            "task_sha256",
            "existing_task_sha256s",
            "required_evidence_refs",
            "available_evidence_refs",
            "explicit_agent_id",
            "approved_conflict_ids",
            "blockers",
            "ready",
            "execution_started",
        }
        if (
            set(body) != expected_fields
            or readiness_sha256 != document_digest(body)
            or not readiness.get("ready")
            or readiness.get("schema_version") != "hive.workflow-readiness.v1"
            or readiness.get("run_id") != self.run.run_id
            or readiness.get("workflow_sha256") != self.run.workflow_sha256
            or readiness.get("project_id") != self.run.project_id
            or agent_id != readiness.get("assigned_agent_id")
            or readiness.get("execution_started") is not False
        ):
            raise ProtocolError(
                "WORKFLOW_READINESS_INVALID",
                "claim requires one exact ready scheduler result",
            )
        if now.tzinfo is None or expires_at.tzinfo is None or expires_at <= now:
            raise ProtocolError(
                "WORKFLOW_CLAIM_EXPIRY_INVALID", "claim expiry must be in the future"
            )
        step_id = readiness.get("step_id")
        if step_id not in self.steps:
            raise ProtocolError(
                "WORKFLOW_READINESS_INVALID", "readiness step does not exist"
            )
        step = self.steps[step_id]
        if expires_at > now + timedelta(seconds=step["retry"]["timeout_seconds"]):
            raise ProtocolError(
                "WORKFLOW_CLAIM_EXPIRY_INVALID", "claim exceeds the step timeout"
            )
        record = self.registry["agents"].get(agent_id)
        key_id = public_key_id(private_key.public_key())
        if not isinstance(record, Mapping) or key_id != record.get("key_id"):
            raise ProtocolError(
                "WORKFLOW_CLAIM_SIGNER_MISMATCH", "claim signer is not the matched agent"
            )
        identity_bindings = {
            "actor_id": agent_id,
            "persona_id": record["persona_id"],
            "surface_id": record["surface_id"],
            "machine_id": record.get("machine_id"),
            "project_id": self.run.project_id,
            "app_actor": record.get("app_actor"),
            "key_id": record["key_id"],
        }
        if any(actor.get(name) != value for name, value in identity_bindings.items()):
            raise ProtocolError(
                "WORKFLOW_CLAIM_IDENTITY_MISMATCH",
                "claim actor does not bind the matched agent identity",
            )
        claim_body = {
            "run_id": self.run.run_id,
            "workflow_sha256": self.run.workflow_sha256,
            "step_id": readiness["step_id"],
            "attempt": readiness["attempt"],
            "agent_id": agent_id,
            "agent_key_id": key_id,
            "capabilities": sorted(step["required_capabilities"]),
            "machine_id": record.get("machine_id"),
            "surface_id": record["surface_id"],
            "source_commit": readiness["source_commit"],
            "input_sha256": readiness["input_sha256"],
            "readiness_sha256": readiness_sha256,
            "owned_branches": sorted(step["ownership"]["branches"]),
            "owned_files": sorted(step["ownership"]["files"]),
            "expires_at": expires_at.astimezone(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        claim = {"claim_id": f"claim:{document_digest(claim_body)}", **claim_body}
        self.lock.parent.mkdir(parents=True, exist_ok=True)
        if self.lock.parent.is_symlink():
            raise ProtocolError(
                "WORKFLOW_SCHEDULER_BOUNDARY", "scheduler runtime is unsafe"
            )
        with exclusive_lock(self.lock):
            current_events = self.journal.events(self.run.run_id)
            existing = next(
                (event for event in current_events if event.event_id == event_id), None
            )
            if existing is None:
                refreshed = self.evaluate(
                    step_id,
                    attempt=readiness["attempt"],
                    current_source_commit=readiness["source_commit"],
                    current_machine_id=readiness["current_machine_id"],
                    task_sha256=readiness["task_sha256"],
                    existing_task_sha256s=readiness["existing_task_sha256s"],
                    required_evidence_refs=readiness["required_evidence_refs"],
                    available_evidence_refs=readiness["available_evidence_refs"],
                    approvals=approvals,
                    now=now,
                    explicit_agent_id=readiness["explicit_agent_id"],
                )
                if refreshed != dict(readiness):
                    raise ProtocolError(
                        "WORKFLOW_READINESS_STALE",
                        "readiness is stale or was not produced by the current scheduler state",
                    )
            result = self.journal.append(
                self.run.run_id,
                event_type="STEP_CLAIMED",
                actor=actor,
                payload=claim,
                private_key=private_key,
                event_id=event_id,
                idempotency_key=idempotency_key,
                recorded_at=now,
                step_id=readiness["step_id"],
                attempt=readiness["attempt"],
                after_event_write=after_event_write,
            )
        return {
            "outcome": "CLAIMED",
            "changed": result["changed"],
            "claim": claim,
            "event": result["event"],
            "execution_started": False,
        }
