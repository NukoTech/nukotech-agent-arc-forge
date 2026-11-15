"""Deterministic, read-only workflow conflict analysis."""

from __future__ import annotations

from datetime import datetime
from pathlib import PurePosixPath
from typing import Any, Mapping, Sequence

from hive_protocol.core import ProtocolError, document_digest


def _time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ProtocolError(
            "WORKFLOW_CLAIM_TIME_INVALID", "claim expiry must be ISO-8601"
        ) from exc
    if parsed.tzinfo is None:
        raise ProtocolError(
            "WORKFLOW_CLAIM_TIME_INVALID", "claim expiry requires timezone"
        )
    return parsed


def _path_overlaps(left: str, right: str) -> bool:
    left_parts = PurePosixPath(left).parts
    right_parts = PurePosixPath(right).parts
    shortest = min(len(left_parts), len(right_parts))
    return left_parts[:shortest] == right_parts[:shortest]


def _conflict(
    code: str,
    *,
    run_id: str,
    workflow_sha256: str,
    step_id: str,
    detail: Mapping[str, Any],
) -> dict[str, Any]:
    body = {
        "code": code,
        "run_id": run_id,
        "workflow_sha256": workflow_sha256,
        "step_id": step_id,
        "detail": dict(detail),
    }
    return {
        "schema_version": "hive.workflow-conflict.v1",
        "conflict_id": f"conflict:{document_digest(body)}",
        **body,
        "blocking": True,
        "exception_required": True,
        "authority_granted": False,
    }


def analyze_step_conflicts(
    step: Mapping[str, Any],
    *,
    run_id: str,
    workflow_sha256: str,
    project_id: str,
    machine_id: str,
    run_source_commit: str,
    current_source_commit: str,
    active_claims: Sequence[Mapping[str, Any]],
    task_sha256: str,
    existing_task_sha256s: Sequence[str],
    required_evidence_refs: Sequence[str],
    available_evidence_refs: Sequence[str],
    agent_capabilities: Sequence[str],
    now: datetime,
) -> list[dict[str, Any]]:
    """Return stable blocking warnings without applying an exception or mutation."""

    step_id = step.get("step_id")
    target = step.get("target")
    ownership = step.get("ownership")
    required_capabilities = step.get("required_capabilities")
    if (
        not isinstance(step_id, str)
        or not isinstance(target, Mapping)
        or not isinstance(ownership, Mapping)
        or not isinstance(required_capabilities, list)
        or now.tzinfo is None
    ):
        raise ProtocolError(
            "WORKFLOW_CONFLICT_INPUT_INVALID", "conflict input is malformed"
        )

    conflicts: list[dict[str, Any]] = []

    def add(code: str, detail: Mapping[str, Any]) -> None:
        conflicts.append(
            _conflict(
                code,
                run_id=run_id,
                workflow_sha256=workflow_sha256,
                step_id=step_id,
                detail=detail,
            )
        )

    if target.get("project_id") != project_id:
        add(
            "PROJECT_TARGET_MISMATCH",
            {"expected": target.get("project_id"), "actual": project_id},
        )
    if target.get("machine_id") is not None and target.get("machine_id") != machine_id:
        add(
            "MACHINE_TARGET_MISMATCH",
            {"expected": target.get("machine_id"), "actual": machine_id},
        )
    if current_source_commit != run_source_commit:
        add(
            "STALE_SOURCE_COMMIT",
            {"run": run_source_commit, "current": current_source_commit},
        )
    if task_sha256 in set(existing_task_sha256s):
        add("DUPLICATE_TASK", {"task_sha256": task_sha256})
    missing_evidence = sorted(
        set(required_evidence_refs).difference(available_evidence_refs)
    )
    if missing_evidence:
        add("MISSING_EVIDENCE", {"missing": missing_evidence})
    missing_capabilities = sorted(
        set(required_capabilities).difference(agent_capabilities)
    )
    if missing_capabilities:
        add("CAPABILITY_ESCALATION", {"missing": missing_capabilities})

    owned_branches = set(ownership.get("branches", []))
    owned_files = list(ownership.get("files", []))
    for claim in active_claims:
        if claim.get("project_id") != target.get("project_id"):
            continue
        if _time(str(claim.get("expires_at", ""))) <= now:
            continue
        branch_overlap = sorted(owned_branches.intersection(claim.get("branches", [])))
        if branch_overlap:
            add(
                "ACTIVE_BRANCH_CLAIM",
                {"claim_id": claim.get("claim_id"), "branches": branch_overlap},
            )
        file_overlap = sorted(
            {
                current
                for current in owned_files
                for claimed in claim.get("files", [])
                if _path_overlaps(current, str(claimed))
            }
        )
        if file_overlap:
            add(
                "ACTIVE_FILE_CLAIM",
                {"claim_id": claim.get("claim_id"), "files": file_overlap},
            )
    return sorted(conflicts, key=lambda item: (item["code"], item["conflict_id"]))
