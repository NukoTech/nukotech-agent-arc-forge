"""Read-only reconstruction of workflow runs from canonical signed events."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from hive_protocol.workflows.events import WorkflowRunJournal


class WorkflowReplay:
    """Rebuild a workflow view without invoking any task, adapter, or mutation."""

    def __init__(
        self,
        hive_root: Path,
        trusted_keys: Mapping[str, Ed25519PublicKey],
    ) -> None:
        self.journal = WorkflowRunJournal(hive_root, trusted_keys)

    def reconstruct(self, run_id: str) -> dict[str, Any]:
        run = self.journal.load_run(run_id)
        events = self.journal.events(run_id)
        state = "RUNNING"
        steps: dict[str, dict[str, Any]] = {}
        conflicts: list[str] = []
        approvals: list[str] = []
        github_refs: list[str] = []
        resource_use = {
            "tokens_used": 0,
            "cost_microunits": 0,
            "peak_memory_mb": 0,
        }
        session_resources: dict[str, dict[str, int]] = {}
        timeline: list[dict[str, Any]] = []
        state_by_event = {
            "STEP_ASSIGNED": "ASSIGNED",
            "STEP_CLAIMED": "CLAIMED",
            "SESSION_STARTED": "ACTIVE",
            "SESSION_HEARTBEAT": "ACTIVE",
            "STEP_ACKNOWLEDGED": "ACKNOWLEDGED",
            "STEP_PROGRESS": "PROGRESS",
            "STEP_OUTPUT": "OUTPUT_RECORDED",
            "STEP_FAILED": "FAILED",
            "STEP_RETRY_CREATED": "RETRY_CREATED",
            "SESSION_ABANDONED": "ABANDONED",
            "CLAIM_RELEASED": "CLAIM_RELEASED",
            "COMPENSATION_STARTED": "COMPENSATING",
            "COMPENSATION_COMPLETED": "COMPENSATED",
            "ROLLBACK_STARTED": "ROLLING_BACK",
            "ROLLBACK_COMPLETED": "ROLLED_BACK",
            "STEP_COMPLETED": "COMPLETED",
        }
        for event in events:
            payload = event.payload
            timeline.append(
                {
                    "sequence": event.sequence,
                    "event_id": event.event_id,
                    "event_type": event.event_type,
                    "step_id": event.step_id,
                    "attempt": event.attempt,
                    "event_sha256": event.digest,
                    "recorded_at": event.recorded_at,
                }
            )
            if event.step_id is not None and event.attempt is not None:
                step = steps.setdefault(event.step_id, {"attempts": {}})
                attempt = step["attempts"].setdefault(
                    str(event.attempt), {"state": "PENDING", "events": []}
                )
                attempt["events"].append(event.event_id)
                if event.event_type in state_by_event:
                    attempt["state"] = state_by_event[event.event_type]
                if event.event_type == "STEP_ASSIGNED":
                    attempt["agent_id"] = payload.get("agent_id")
                if event.event_type == "STEP_OUTPUT":
                    attempt["output"] = payload
            if event.event_type == "CONFLICT_DETECTED":
                conflicts.extend(payload.get("conflict_ids", []))
            if event.event_type == "APPROVAL_RECORDED":
                approval_id = payload.get("approval_id")
                if isinstance(approval_id, str):
                    approvals.append(approval_id)
            resources = payload.get("resources")
            session_id = payload.get("session_id")
            if isinstance(session_id, str) and isinstance(resources, Mapping):
                normalized = {
                    name: resources.get(name)
                    for name in resource_use
                }
                if all(
                    isinstance(value, int)
                    and not isinstance(value, bool)
                    and value >= 0
                    for value in normalized.values()
                ):
                    session_resources[session_id] = normalized
            for name in resource_use:
                value = payload.get(name)
                if isinstance(value, int) and not isinstance(value, bool):
                    if name == "peak_memory_mb":
                        resource_use[name] = max(resource_use[name], value)
                    else:
                        resource_use[name] += value
            github_ref = payload.get("github_ref")
            if isinstance(github_ref, str):
                github_refs.append(github_ref)
            if event.event_type == "RUN_COMPLETED":
                state = "COMPLETED"
            elif event.event_type == "RUN_CANCELLED":
                state = "CANCELLED"
        resource_use["tokens_used"] += sum(
            resources["tokens_used"] for resources in session_resources.values()
        )
        resource_use["cost_microunits"] += sum(
            resources["cost_microunits"] for resources in session_resources.values()
        )
        resource_use["peak_memory_mb"] = max(
            [
                resource_use["peak_memory_mb"],
                *(resources["peak_memory_mb"] for resources in session_resources.values()),
            ]
        )
        return {
            "schema_version": "hive.workflow-replay.v1",
            "run_id": run.run_id,
            "workflow_id": run.workflow_id,
            "workflow_version": run.workflow_version,
            "workflow_sha256": run.workflow_sha256,
            "source_commit": run.source_commit,
            "input_manifest_sha256": run.input_manifest_sha256,
            "state": state,
            "steps": steps,
            "conflicts": sorted(set(conflicts)),
            "approvals": sorted(set(approvals)),
            "resource_use": resource_use,
            "github_refs": sorted(set(github_refs)),
            "timeline": timeline,
            "execution_performed": False,
            "mutation_performed": False,
        }
