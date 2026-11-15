"""Read-only projection of local Node Hive operations."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..core import ProtocolError, document_digest
from ..storage import read_json
from ..tasks.engine import _validate as validate_task_document


class OperatorProjection:
    """Never writes: all values are rebuilt from durable task/state/receipt files."""

    def __init__(self, root: Path, *, machine_status: dict[str, Any] | None = None):
        self.root = root
        self.machine_status = dict(machine_status or {})

    def read(self) -> dict[str, Any]:
        tasks = []
        receipts = []
        task_root = self.root / "tasks"
        receipt_root = self.root / "receipts"
        if task_root.is_dir() and not task_root.is_symlink():
            for path in sorted(task_root.glob("*.json")):
                if path.is_file() and not path.is_symlink():
                    task = read_json(path)
                    tasks.append({
                        "task_id": task["task_id"],
                        "state": task["state"],
                        "version": task["version"],
                        "project_id": task["creator"]["project_id"],
                        "assignee": task["assignee"],
                        "blocker": task.get("blocker"),
                    })
        if receipt_root.is_dir() and not receipt_root.is_symlink():
            for path in sorted(receipt_root.glob("*.json")):
                if path.is_file() and not path.is_symlink():
                    receipt = read_json(path)
                    receipts.append({"receipt_id": receipt["receipt_id"], "task_id": receipt["task_id"], "event": receipt["event"], "state_after": receipt["state_after"]})
        states = []
        state_root = self.root / "project_state" / "projects"
        if state_root.is_dir() and not state_root.is_symlink():
            for path in sorted(state_root.glob("*/state.json")):
                if path.is_file() and not path.is_symlink():
                    state = read_json(path)
                    states.append({"project_id": state["project_id"], "version": state["version"], "digest": document_digest(state)})
        agents = sorted({task["assignee"]["app_actor"] for task in tasks})
        blockers = [task for task in tasks if task.get("blocker")]
        return {"agents": agents, "tasks": tasks, "project_state": states, "blockers": blockers, "receipts": receipts, "machine_status": self.machine_status}

    def governed_tasks(self, *, project_ids: frozenset[str]) -> list[dict[str, Any]]:
        """Validate and summarize canonical Cycle 2 tasks without mutating queues."""

        task_root = self.root / "tasks"
        if not task_root.exists():
            return []
        if task_root.is_symlink() or not task_root.is_dir():
            raise ProtocolError(
                "OPERATOR_CANONICAL_RECORD_INVALID",
                "governed task root is unsafe",
            )
        tasks: list[dict[str, Any]] = []
        for path in sorted(task_root.glob("*.json")):
            if path.is_symlink() or not path.is_file():
                raise ProtocolError(
                    "OPERATOR_CANONICAL_RECORD_INVALID",
                    "governed task record is unsafe",
                )
            try:
                task = read_json(path)
                validate_task_document(task)
            except (KeyError, TypeError, ProtocolError) as exc:
                raise ProtocolError(
                    "OPERATOR_CANONICAL_RECORD_INVALID",
                    "governed task record is malformed",
                ) from exc
            creator_project = task["creator"]["project_id"]
            assignee_project = task["assignee"]["project_id"]
            if (
                path.name != f"{task['task_id']}.json"
                or creator_project != assignee_project
            ):
                raise ProtocolError(
                    "OPERATOR_CANONICAL_RECORD_INVALID",
                    "governed task record binding changed",
                )
            if creator_project not in project_ids:
                raise ProtocolError(
                    "OPERATOR_CANONICAL_SCOPE_MISMATCH",
                    "governed task project is outside the operator scope",
                )
            tasks.append(
                {
                    "task_id": task["task_id"],
                    "project_id": creator_project,
                    "state": task["state"],
                    "version": task["version"],
                    "operation": task["operation"],
                    "capability": task["capability"],
                    "creator": task["creator"]["app_actor"],
                    "assignee": task["assignee"]["app_actor"],
                    "updated_at": task["updated_at"],
                    "expires_at": task["expires_at"],
                    "sha256": document_digest(task),
                }
            )
        return tasks
