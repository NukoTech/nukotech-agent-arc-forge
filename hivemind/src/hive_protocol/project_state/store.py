"""Versioned project state with snapshots, deterministic recovery, and safe rollback."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping

from ..core import ProtocolError, document_digest
from ..storage import atomic_write_json, exclusive_lock, read_json, utc_now


_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class ProjectStateStore:
    def __init__(self, root: Path):
        if root.exists() and root.is_symlink():
            raise ProtocolError("PROJECT_ROOT_BOUNDARY", "project state root may not be a symlink")
        self.root = root.resolve()
        self.projects = root / "projects"
        self.snapshots = root / "snapshots"
        self.lock = root / ".project-state.lock"
        self.projects.mkdir(parents=True, exist_ok=True)
        self.snapshots.mkdir(parents=True, exist_ok=True)

    def _project(self, project_id: str) -> Path:
        if not _ID.fullmatch(project_id):
            raise ProtocolError("PROJECT_ID_INVALID", "project ID is unsafe")
        return self.projects / project_id

    def initialize(self, project_id: str, identity: Mapping[str, str]) -> dict[str, Any]:
        path = self._project(project_id) / "state.json"
        if path.exists():
            return read_json(path)
        state = {
            "schema_version": "hive.cycle2.project-state.v1",
            "project_id": project_id,
            "version": 1,
            "updated_at": utc_now(),
            "identity": dict(identity),
            "values": {},
            "task_status": {},
        }
        with exclusive_lock(self.lock):
            if not path.exists():
                atomic_write_json(path, state)
        return state

    def read(self, project_id: str) -> dict[str, Any]:
        path = self._project(project_id) / "state.json"
        if not path.exists():
            raise ProtocolError("PROJECT_STATE_MISSING", "project state is not initialized")
        state = read_json(path)
        if state.get("project_id") != project_id:
            raise ProtocolError("PROJECT_STATE_MISMATCH", "state filename and project differ")
        return state

    def apply(self, project_id: str, *, expected_version: int, task_id: str, patch: Mapping[str, Any]) -> dict[str, Any]:
        state = self.read(project_id)
        if state["version"] != expected_version:
            raise ProtocolError("PROJECT_STATE_STALE", "expected project version is not current")
        if not _ID.fullmatch(task_id):
            raise ProtocolError("TASK_ID_INVALID", "task ID is unsafe")
        if not isinstance(patch, Mapping) or any(not isinstance(key, str) or key.startswith("_") for key in patch):
            raise ProtocolError("PROJECT_PATCH_INVALID", "patch keys must be public strings")
        updated = json.loads(json.dumps(state))
        updated["version"] += 1
        updated["updated_at"] = utc_now()
        updated["values"].update(dict(patch))
        updated["task_status"][task_id] = {"state": "COMPLETED", "version": updated["version"]}
        with exclusive_lock(self.lock):
            if self.read(project_id)["version"] != expected_version:
                raise ProtocolError("PROJECT_STATE_STALE", "state changed during update")
            atomic_write_json(self._project(project_id) / "state.json", updated)
        return updated

    def snapshot(self, project_id: str, label: str) -> tuple[Path, str]:
        if not _ID.fullmatch(label):
            raise ProtocolError("SNAPSHOT_LABEL_INVALID", "snapshot label is unsafe")
        state = self.read(project_id)
        payload = document_digest(state)
        path = self.snapshots / f"{project_id}.{label}.json"
        atomic_write_json(path, state)
        return path, payload

    def rollback(self, project_id: str, snapshot: Path) -> dict[str, Any]:
        if snapshot.is_symlink():
            raise ProtocolError("SNAPSHOT_BOUNDARY", "rollback snapshot may not be a symlink")
        snapshot = snapshot.resolve()
        if self.snapshots not in snapshot.parents:
            raise ProtocolError("SNAPSHOT_BOUNDARY", "rollback snapshot must be inside the snapshot root")
        state = read_json(snapshot)
        if state.get("project_id") != project_id:
            raise ProtocolError("SNAPSHOT_PROJECT_MISMATCH", "snapshot belongs to another project")
        atomic_write_json(self._project(project_id) / "state.json", state)
        return state

    def digest(self, project_id: str) -> str:
        return document_digest(self.read(project_id))
