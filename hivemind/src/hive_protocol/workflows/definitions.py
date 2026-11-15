"""Immutable, signed workflow-definition publishing and DAG validation."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from hive_protocol.core import ProtocolError, document_digest, verify_document
from hive_protocol.storage import (
    ReplayLedger,
    atomic_write_json,
    exclusive_lock,
    read_json,
    require_no_symlink_components,
    utc_now,
)
from hive_protocol.workflows.models import WorkflowDefinition


_SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SAFE_OPERATION = re.compile(r"^[A-Za-z0-9._/-]{1,512}$")


class WorkflowDefinitionStore:
    """Publish immutable workflow versions without creating an execution path."""

    def __init__(
        self,
        hive_root: Path,
        trusted_keys: Mapping[str, Ed25519PublicKey],
    ) -> None:
        self.hive_root = hive_root.expanduser()
        self.trusted_keys = dict(trusted_keys)
        self.definitions = self.hive_root / "workflows" / "definitions"
        self.receipts = (
            self.hive_root / ".hive" / "receipts" / "workflows" / "definitions"
        )
        self.runtime = self.hive_root / ".hive" / "runtime" / "workflows"
        self.lock = self.runtime / ".definition-publish.lock"
        self.replay = ReplayLedger(self.runtime / "definition-publish.json", mode=0o600)
        for candidate in (
            self.hive_root,
            self.hive_root / "workflows",
            self.definitions,
            self.hive_root / ".hive",
            self.receipts,
            self.runtime,
        ):
            if candidate.exists() and candidate.is_symlink():
                raise ProtocolError(
                    "WORKFLOW_DEFINITION_BOUNDARY",
                    "workflow definition paths may not be symlinks",
                )

    def definition_path(self, workflow_id: str, version: int) -> Path:
        if not isinstance(workflow_id, str) or not _SAFE_ID.fullmatch(workflow_id):
            raise ProtocolError(
                "WORKFLOW_ID_INVALID", "workflow identifier is not path-safe"
            )
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise ProtocolError(
                "WORKFLOW_VERSION_INVALID", "workflow version must be positive"
            )
        directory = self.definitions / workflow_id
        target = directory / f"{version:06d}.json"
        require_no_symlink_components(
            self.hive_root,
            target,
            code="WORKFLOW_DEFINITION_BOUNDARY",
            detail="workflow definition path contains a symlink",
        )
        return target

    def _receipt_path(self, workflow_id: str, version: int) -> Path:
        target = self.receipts / workflow_id / f"{version:06d}.json"
        require_no_symlink_components(
            self.hive_root,
            target,
            code="WORKFLOW_DEFINITION_BOUNDARY",
            detail="workflow definition receipt path contains a symlink",
        )
        return target

    def _validated(self, document: Mapping[str, Any]) -> WorkflowDefinition:
        definition = WorkflowDefinition.from_dict(document, verified_by=self.trusted_keys)
        verify_document(definition.as_dict(), self.trusted_keys)
        self._validate_semantics(definition.as_dict())
        return definition

    def preview(self, document: Mapping[str, Any]) -> dict[str, Any]:
        definition = self._validated(document)
        return {
            "schema_version": "hive.workflow-definition-preview.v1",
            "workflow_id": definition.workflow_id,
            "version": definition.version,
            "workflow_sha256": definition.digest,
            "project_id": definition.project_id,
            "steps": len(definition.steps),
            "target_path": str(
                Path("workflows")
                / "definitions"
                / definition.workflow_id
                / f"{definition.version:06d}.json"
            ),
            "mutation": "PUBLISH_IMMUTABLE_VERSION",
            "side_effects": ["canonical-workflow-definition", "publish-receipt"],
            "execution_authorized": False,
        }

    def load(self, workflow_id: str, version: int) -> WorkflowDefinition:
        path = self.definition_path(workflow_id, version)
        if path.is_symlink() or not path.is_file():
            raise ProtocolError(
                "WORKFLOW_DEFINITION_MISSING",
                "workflow definition version is absent or unsafe",
            )
        return self._validated(read_json(path))

    def list_versions(self, workflow_id: str) -> list[int]:
        directory = self.definition_path(workflow_id, 1).parent
        if not directory.exists():
            return []
        if directory.is_symlink() or not directory.is_dir():
            raise ProtocolError(
                "WORKFLOW_DEFINITION_BOUNDARY",
                "workflow definition directory is unsafe",
            )
        versions: list[int] = []
        for path in sorted(directory.glob("*.json")):
            if path.is_symlink() or not path.is_file():
                raise ProtocolError(
                    "WORKFLOW_DEFINITION_BOUNDARY",
                    "workflow definition version is unsafe",
                )
            if not re.fullmatch(r"[0-9]{6}", path.stem):
                raise ProtocolError(
                    "WORKFLOW_VERSION_INVALID",
                    "workflow version filename is noncanonical",
                )
            versions.append(int(path.stem))
        return versions

    def publish(
        self,
        document: Mapping[str, Any],
        *,
        idempotency_key: str,
        after_definition_write: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        if not isinstance(idempotency_key, str) or not _SAFE_ID.fullmatch(
            idempotency_key
        ):
            raise ProtocolError(
                "WORKFLOW_IDEMPOTENCY_INVALID",
                "definition publish idempotency key is unsafe",
            )
        definition = self._validated(document)
        target = self.definition_path(definition.workflow_id, definition.version)
        receipt_path = self._receipt_path(
            definition.workflow_id, definition.version
        )
        if target.is_symlink() or receipt_path.is_symlink():
            raise ProtocolError(
                "WORKFLOW_DEFINITION_BOUNDARY",
                "workflow definition or receipt target may not be a symlink",
            )

        self._ensure_publish_roots()
        with exclusive_lock(self.lock):
            existing_exact = False
            if target.exists():
                if target.is_symlink() or not target.is_file():
                    raise ProtocolError(
                        "WORKFLOW_DEFINITION_BOUNDARY",
                        "workflow version target is unsafe",
                    )
                existing = self._validated(read_json(target))
                if existing.digest != definition.digest:
                    raise ProtocolError(
                        "WORKFLOW_VERSION_CONFLICT",
                        "published workflow version bytes are immutable",
                    )
                existing_exact = True
                if receipt_path.is_file() and not receipt_path.is_symlink():
                    receipt = read_json(receipt_path)
                    if receipt.get("workflow_sha256") != definition.digest:
                        raise ProtocolError(
                            "WORKFLOW_RECEIPT_CONFLICT",
                            "definition receipt does not bind published bytes",
                        )
                    return {**receipt, "changed": False}
            else:
                self._validate_lineage(definition)

            claim = self.replay.begin(idempotency_key, definition.digest)
            if claim == "RESUME" and not existing_exact:
                raise ProtocolError(
                    "WORKFLOW_PUBLISH_RECOVERY_MISSING",
                    "pending definition publish has no exact durable definition",
                )
            if claim == "NEW":
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.parent.is_symlink():
                    raise ProtocolError(
                        "WORKFLOW_DEFINITION_BOUNDARY",
                        "workflow definition directory may not be a symlink",
                    )
                atomic_write_json(target, definition.as_dict())
                if after_definition_write is not None:
                    after_definition_write()

            receipt = {
                "schema_version": "hive.workflow-definition-receipt.v1",
                "outcome": "PUBLISHED",
                "workflow_id": definition.workflow_id,
                "version": definition.version,
                "workflow_sha256": definition.digest,
                "project_id": definition.project_id,
                "publisher_key_id": definition.publisher["key_id"],
                "definition_path": str(target.relative_to(self.hive_root)),
                "recorded_at": utc_now(),
            }
            receipt_path.parent.mkdir(parents=True, exist_ok=True)
            if receipt_path.parent.is_symlink():
                raise ProtocolError(
                    "WORKFLOW_DEFINITION_BOUNDARY",
                    "workflow receipt directory may not be a symlink",
                )
            atomic_write_json(receipt_path, receipt)
            self.replay.complete(idempotency_key, definition.digest)
            return {**receipt, "changed": True}

    def _ensure_publish_roots(self) -> None:
        for path in (self.definitions, self.receipts, self.runtime):
            path.mkdir(parents=True, exist_ok=True)
            if path.is_symlink() or not path.is_dir():
                raise ProtocolError(
                    "WORKFLOW_DEFINITION_BOUNDARY",
                    "workflow publish root is unsafe",
                )

    def _validate_lineage(self, definition: WorkflowDefinition) -> None:
        versions = self.list_versions(definition.workflow_id)
        if not versions:
            if definition.version != 1 or definition.parent_digest is not None:
                raise ProtocolError(
                    "WORKFLOW_VERSION_LINEAGE_INVALID",
                    "first workflow version must be version 1 without a parent",
                )
            return
        latest_version = versions[-1]
        if definition.version != latest_version + 1:
            raise ProtocolError(
                "WORKFLOW_VERSION_LINEAGE_INVALID",
                "new workflow version must directly follow the latest version",
            )
        latest = self.load(definition.workflow_id, latest_version)
        if definition.parent_digest != latest.digest:
            raise ProtocolError(
                "WORKFLOW_VERSION_LINEAGE_INVALID",
                "new workflow version does not bind the latest immutable digest",
            )

    def _validate_semantics(self, document: Mapping[str, Any]) -> None:
        steps = {str(step["step_id"]): step for step in document["steps"]}
        for step_id, step in steps.items():
            dependencies = set(step["dependencies"])
            if step_id in dependencies:
                raise ProtocolError(
                    "WORKFLOW_DEPENDENCY_SELF",
                    "a workflow step may not depend on itself",
                )
            missing = dependencies.difference(steps)
            if missing:
                raise ProtocolError(
                    "WORKFLOW_DEPENDENCY_MISSING",
                    "workflow dependency does not exist",
                )
            for item in step["inputs"]:
                source_id = item["source_step_id"]
                if source_id not in dependencies:
                    raise ProtocolError(
                        "WORKFLOW_INPUT_DEPENDENCY_INVALID",
                        "typed input source must be a direct dependency",
                    )
                outputs = {
                    output["name"]: output["type"]
                    for output in steps[source_id]["outputs"]
                }
                if outputs.get(item["source_output"]) != item["type"]:
                    raise ProtocolError(
                        "WORKFLOW_INPUT_TYPE_MISMATCH",
                        "typed workflow input does not match its source output",
                    )
            if step["kind"] == "APPROVAL" and not step["approval"]["required"]:
                raise ProtocolError(
                    "WORKFLOW_APPROVAL_PLACEMENT_INVALID",
                    "approval steps must require protected approval",
                )
            rollback = step["rollback"]
            compensation_id = rollback["compensation_step_id"]
            if rollback["mode"] == "COMPENSATION":
                if (
                    compensation_id is None
                    or compensation_id == step_id
                    or compensation_id not in steps
                    or steps[compensation_id]["kind"] != "COMPENSATION"
                ):
                    raise ProtocolError(
                        "WORKFLOW_COMPENSATION_INVALID",
                        "compensation mode requires a distinct compensation step",
                    )
            elif compensation_id is not None:
                raise ProtocolError(
                    "WORKFLOW_COMPENSATION_INVALID",
                    "non-compensation rollback may not name a compensation step",
                )
            for value in step["ownership"]["files"]:
                self._validate_owned_file(value)
            for value in step["ownership"]["branches"]:
                self._validate_owned_branch(value)
        self._require_acyclic(steps)

    @staticmethod
    def _validate_owned_file(value: str) -> None:
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or not path.parts
            or any(part in {"", ".", ".."} for part in path.parts)
            or path.parts[0] in {".git", ".hive", "workflows"}
        ):
            raise ProtocolError(
                "WORKFLOW_OWNED_PATH_INVALID",
                "workflow file ownership path is unsafe or protected",
            )

    @staticmethod
    def _validate_owned_branch(value: str) -> None:
        if (
            not _SAFE_OPERATION.fullmatch(value)
            or value.startswith(("/", "-", "."))
            or value.endswith(("/", "."))
            or ".." in value
            or "//" in value
            or "@{" in value
        ):
            raise ProtocolError(
                "WORKFLOW_OWNED_BRANCH_INVALID",
                "workflow branch ownership value is unsafe",
            )

    @staticmethod
    def _require_acyclic(steps: Mapping[str, Mapping[str, Any]]) -> None:
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(step_id: str) -> None:
            if step_id in visiting:
                raise ProtocolError(
                    "WORKFLOW_DAG_CYCLE", "workflow dependencies must be acyclic"
                )
            if step_id in visited:
                return
            visiting.add(step_id)
            for dependency in steps[step_id]["dependencies"]:
                visit(str(dependency))
            visiting.remove(step_id)
            visited.add(step_id)

        for step_id in steps:
            visit(step_id)
