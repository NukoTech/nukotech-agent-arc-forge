"""Read-only M4 operator projections over existing Hive authority stores."""

from __future__ import annotations

import copy
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from hive_protocol.adapters.security import reject_credential_values
from hive_protocol.agents import validate_agent_registry
from hive_protocol.capture.models import CaptureEnvelope, SourceRecord
from hive_protocol.cognition.models import (
    KnowledgeNode,
    MemoryCandidate,
    MemoryDeletionPlan,
    MemoryReviewDecision,
)
from hive_protocol.core import (
    ProtocolError,
    document_digest,
    public_key_id,
    verify_document,
)
from hive_protocol.operator.projection import OperatorProjection
from hive_protocol.receipts.core import _validate as validate_cycle2_receipt
from hive_protocol.research.models import ResearchArtifact, ResearchWorkspace
from hive_protocol.research.workspace import BoundedResearchWorkspaceStore
from hive_protocol.storage import read_json, require_no_symlink_components
from hive_protocol.workflows.definitions import WorkflowDefinitionStore
from hive_protocol.workflows.models import (
    AgentSession,
    WorkflowApproval,
    WorkflowEvent,
    WorkflowRun,
)
from hive_protocol.workflows.replay import WorkflowReplay

from .agent_adapter import adapter_status, list_tasks
from .shell_contracts import RELEASE_HOLDS, OperatorRequest, RouteContract
from .shell_lanes import (
    CaptureResearchLane,
    CognitionKnowledgeLane,
    SettingsLifecycleLane,
    WorkflowAgentsLane,
)
from .workflow_adapter import diff_workflow_documents
from .workspace import HiveWorkspace
from .shell_lanes.loadouts import LoadoutLane


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_CANONICAL_JSON_BYTES = 16 * 1024 * 1024
_TERMINAL_TASK_STATES = frozenset({"COMPLETED", "REJECTED", "CANCELLED"})
_READ_ACTIONS = frozenset(
    {
        "home.read",
        "projects.read",
        "inbox.read",
        "capture.read",
        "research.read",
        "memory.read",
        "knowledge.read",
        "workflows.read",
        "agents.read",
        "receipts.read",
        "settings.read",
        "loadouts.read",
    }
)
_COGNITION_RECEIPTS = frozenset(
    {
        "hive.memory-candidate-receipt.v1",
        "hive.memory-promotion-receipt.v1",
        "hive.memory-deletion-approval.v1",
        "hive.memory-deletion-receipt.v1",
        "hive.knowledge-edit-approval.v1",
        "hive.knowledge-edit-receipt.v1",
    }
)
_WORKFLOW_RECEIPTS = frozenset(
    {
        "hive.workflow-approval.v1",
        "hive.workflow-event.v1",
    }
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _time(value: str, *, code: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ProtocolError(code, "receipt time filter is invalid") from exc
    if parsed.tzinfo is None:
        raise ProtocolError(code, "receipt time filter requires a timezone")
    return parsed


def _public_key(value: str) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(value.encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise ProtocolError(
            "OPERATOR_CANONICAL_RECORD_INVALID",
            "public verification material is malformed",
        ) from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ProtocolError(
            "OPERATOR_CANONICAL_RECORD_INVALID",
            "verification material is not Ed25519",
        )
    return key


class ShellService:
    """Deterministically summarize canonical files without inventing authority."""

    def __init__(
        self,
        workspace: HiveWorkspace,
        *,
        tenant_id: str,
        project_ids: set[str] | frozenset[str],
        trusted_receipt_keys: Mapping[str, Ed25519PublicKey] | None = None,
        now: datetime | None = None,
        capture_research_fault_hook: Any | None = None,
        cognition_knowledge_fault_hook: Any | None = None,
        workflow_agents_fault_hook: Any | None = None,
        settings_lifecycle_fault_hook: Any | None = None,
    ) -> None:
        scope = workspace.scope()
        projects = frozenset(project_ids)
        if tenant_id != scope["tenant_id"] or scope["project_id"] not in projects:
            raise ProtocolError(
                "OPERATOR_SCOPE_DENIED",
                "operator shell does not match the canonical Hive scope",
            )
        self.workspace = workspace
        self.root = workspace.root
        self.tenant_id = tenant_id
        self.project_ids = projects
        self.default_project_id = scope["project_id"]
        self.trusted_receipt_keys = dict(trusted_receipt_keys or {})
        if now is None:
            self._clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
        else:
            self._clock = lambda: now
        self.now = self._clock()
        if not isinstance(self.now, datetime) or self.now.tzinfo is None:
            raise ProtocolError(
                "OPERATOR_TIME_INVALID", "operator projection time requires a timezone"
            )
        self.now = self.now.astimezone(timezone.utc)
        self.capture_research = CaptureResearchLane(
            workspace,
            tenant_id=tenant_id,
            project_ids=projects,
            now=self.now,
            fault_hook=capture_research_fault_hook,
        )
        self.cognition_knowledge = CognitionKnowledgeLane(
            workspace,
            tenant_id=tenant_id,
            project_ids=projects,
            now=self.now,
            fault_hook=cognition_knowledge_fault_hook,
        )
        self.workflow_agents = WorkflowAgentsLane(
            workspace,
            tenant_id=tenant_id,
            project_ids=projects,
            now=self.now,
            fault_hook=workflow_agents_fault_hook,
        )
        self.settings_lifecycle = SettingsLifecycleLane(
            workspace,
            tenant_id=tenant_id,
            project_ids=projects,
            now=self.now,
            fault_hook=settings_lifecycle_fault_hook,
        )
        self.loadouts = LoadoutLane(workspace, tenant_id=tenant_id, project_ids=projects, now=self.now)

    def _refresh_now(self) -> None:
        current = self._clock()
        if not isinstance(current, datetime) or current.tzinfo is None:
            raise ProtocolError(
                "OPERATOR_TIME_INVALID", "operator projection time requires a timezone"
            )
        self.now = current.astimezone(timezone.utc)
        self.capture_research.now = self.now
        self.cognition_knowledge.now = self.now
        self.workflow_agents.now = self.now
        self.settings_lifecycle.now = self.now
        self.loadouts.now = self.now

    def begin_request(self) -> None:
        """Bind one clock value across every phase of an API request."""

        self._refresh_now()

    def _application_lane(self, action: str):
        for lane in (
            self.capture_research,
            self.cognition_knowledge,
            self.workflow_agents,
            self.settings_lifecycle,
            self.loadouts,
        ):
            if lane.supports(action):
                return lane
        return None

    def object_key(self, route: RouteContract, request: OperatorRequest) -> str:
        lane = self._application_lane(route.action)
        if lane is not None:
            return lane.object_key(route, request)
        return f"{request.project_id}:{route.action}:pending-lane"

    def current_version(
        self, route: RouteContract, request: OperatorRequest
    ) -> str:
        lane = self._application_lane(route.action)
        if lane is not None:
            return lane.current_version(route, request)
        raise ProtocolError(
            "OPERATOR_DOMAIN_UNAVAILABLE",
            "operator mutation lane is not installed yet",
        )

    def mutate(
        self,
        route: RouteContract,
        request: OperatorRequest,
        *,
        operation_key: str,
    ) -> Mapping[str, Any]:
        lane = self._application_lane(route.action)
        if lane is not None:
            return lane.mutate(route, request, operation_key=operation_key)
        raise ProtocolError(
            "OPERATOR_DOMAIN_UNAVAILABLE",
            "operator mutation lane is not installed yet",
        )

    def recover(
        self,
        route: RouteContract,
        request: OperatorRequest,
        *,
        operation_key: str,
    ) -> Mapping[str, Any] | None:
        lane = self._application_lane(route.action)
        if lane is not None:
            return lane.recover(route, request, operation_key=operation_key)
        return None

    def _regular_json(self, root: Path, *, recursive: bool = False) -> list[Path]:
        if not root.exists():
            return []
        if root.is_symlink() or not root.is_dir():
            raise ProtocolError(
                "OPERATOR_CANONICAL_RECORD_INVALID",
                "canonical projection root is unsafe",
            )
        entries = sorted(root.rglob("*")) if recursive else sorted(root.iterdir())
        if any(path.is_symlink() for path in entries):
            raise ProtocolError(
                "OPERATOR_CANONICAL_RECORD_INVALID",
                "canonical projection record is unsafe",
            )
        paths = [path for path in entries if path.suffix == ".json"]
        if any(
            not path.is_file() or path.stat().st_size > _MAX_CANONICAL_JSON_BYTES
            for path in paths
        ):
            raise ProtocolError(
                "OPERATOR_CANONICAL_RECORD_INVALID",
                "canonical projection record is unsafe or excessive",
            )
        return paths

    def _owned_file(
        self,
        relative: str,
        *,
        roots: frozenset[str],
        sha256: str,
    ) -> Path:
        path = PurePosixPath(relative)
        if (
            not isinstance(relative, str)
            or not relative
            or "\\" in relative
            or path.is_absolute()
            or path.as_posix() != relative
            or any(part in {"", ".", ".."} for part in path.parts)
            or path.parts[0] not in roots
            or _SHA256.fullmatch(sha256) is None
        ):
            raise ProtocolError(
                "OPERATOR_CANONICAL_RECORD_INVALID",
                "canonical content path or digest is invalid",
            )
        target = self.root.joinpath(*path.parts)
        require_no_symlink_components(
            self.root,
            target,
            code="OPERATOR_CANONICAL_RECORD_INVALID",
            detail="canonical content path contains a symlink",
        )
        if (
            target.is_symlink()
            or not target.is_file()
            or _sha256_file(target) != sha256
        ):
            raise ProtocolError(
                "OPERATOR_CANONICAL_RECORD_INVALID",
                "canonical content bytes changed",
            )
        return target

    def _require_scope(self, tenant_id: str, project_id: str) -> None:
        if tenant_id != self.tenant_id or project_id not in self.project_ids:
            raise ProtocolError(
                "OPERATOR_CANONICAL_SCOPE_MISMATCH",
                "canonical record is outside the operator scope",
            )

    @staticmethod
    def _canonical_invalid(exc: Exception, detail: str) -> ProtocolError:
        if isinstance(exc, ProtocolError) and exc.code.startswith(
            "OPERATOR_CANONICAL_"
        ):
            return exc
        return ProtocolError("OPERATOR_CANONICAL_RECORD_INVALID", detail)

    def _sources_and_captures(
        self,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        sources: list[dict[str, Any]] = []
        for path in self._regular_json(self.workspace.provenance):
            document = read_json(path)
            if document.get("schema_version") == "nukotech.hive-local.provenance.v1":
                if document.get("kind") != "document":
                    continue
                try:
                    required = {
                        "stable_id",
                        "source_sha256",
                        "imported_relative_path",
                        "imported_at",
                    }
                    if (
                        not required.issubset(document)
                        or not str(document["stable_id"]).startswith("doc:")
                        or _SHA256.fullmatch(str(document["source_sha256"])) is None
                    ):
                        raise ProtocolError(
                            "OPERATOR_CANONICAL_RECORD_INVALID",
                            "imported source provenance is malformed",
                        )
                    self._owned_file(
                        str(document["imported_relative_path"]),
                        roots=frozenset({"sources"}),
                        sha256=str(document["source_sha256"]),
                    )
                except (KeyError, TypeError, ProtocolError) as exc:
                    raise self._canonical_invalid(
                        exc, "imported source provenance is malformed"
                    ) from exc
                sources.append(
                    {
                        "source_id": document["stable_id"],
                        "project_id": self.default_project_id,
                        "created_at": document["imported_at"],
                        "sha256": document_digest(document),
                    }
                )
                continue
            if document.get("schema_version") != "hive.source-record.v1":
                continue
            try:
                record = SourceRecord.from_dict(document)
                self._require_scope(record.tenant_id, record.project_id)
                if path.name != f"source-{record.source_id.removeprefix('source:')}.json":
                    raise ProtocolError(
                        "OPERATOR_CANONICAL_RECORD_INVALID",
                        "source record path binding changed",
                    )
                self._owned_file(
                    record.original_asset_path,
                    roots=frozenset({"assets"}),
                    sha256=record.original_sha256,
                )
                if record.normalized_text_path is not None:
                    self._owned_file(
                        record.normalized_text_path,
                        roots=frozenset({"sources"}),
                        sha256=str(record.normalized_sha256),
                    )
            except (KeyError, TypeError, ProtocolError) as exc:
                raise self._canonical_invalid(exc, "source record is malformed") from exc
            sources.append(
                {
                    "source_id": record.source_id,
                    "project_id": record.project_id,
                    "created_at": record.created_at,
                    "sha256": document_digest(document),
                }
            )

        captures: list[dict[str, Any]] = []
        capture_root = self.workspace.staging / "captures"
        for path in self._regular_json(capture_root):
            try:
                envelope = CaptureEnvelope.from_dict(read_json(path))
                self._require_scope(envelope.tenant_id, envelope.project_id)
                operation_key = envelope.capture_id.removeprefix("capture:")
                if path.name != f"capture-{operation_key}.json":
                    raise ProtocolError(
                        "OPERATOR_CANONICAL_RECORD_INVALID",
                        "capture envelope path binding changed",
                    )
            except (KeyError, TypeError, ProtocolError) as exc:
                raise self._canonical_invalid(exc, "capture envelope is malformed") from exc
            captures.append(envelope.as_dict())
        return sources, captures

    def _research(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        workspaces: list[dict[str, Any]] = []
        artifacts: list[dict[str, Any]] = []
        store = BoundedResearchWorkspaceStore(self.workspace)
        root = self.workspace.research / "workspaces"
        if not root.exists():
            return workspaces, artifacts
        if root.is_symlink() or not root.is_dir():
            raise ProtocolError(
                "OPERATOR_CANONICAL_RECORD_INVALID", "research root is unsafe"
            )
        for path in sorted(root.glob("*/workspace.json")):
            try:
                model = ResearchWorkspace.from_dict(read_json(path))
                self._require_scope(model.tenant_id, model.project_id)
                verified = store.open_workspace(model.workspace_id)
                if verified.as_dict() != model.as_dict():
                    raise ProtocolError(
                        "OPERATOR_CANONICAL_RECORD_INVALID",
                        "research workspace binding changed",
                    )
                artifact_root = path.parent / "artifacts"
                for artifact_path in self._regular_json(artifact_root):
                    artifact = ResearchArtifact.from_dict(read_json(artifact_path))
                    self._require_scope(artifact.tenant_id, artifact.project_id)
                    if artifact.workspace_id != model.workspace_id:
                        raise ProtocolError(
                            "OPERATOR_CANONICAL_RECORD_INVALID",
                            "research artifact crosses workspaces",
                        )
                    self._owned_file(
                        artifact.markdown_path,
                        roots=frozenset({"research"}),
                        sha256=artifact.markdown_sha256,
                    )
                    artifacts.append(artifact.as_dict())
            except (KeyError, TypeError, ProtocolError) as exc:
                raise self._canonical_invalid(
                    exc, "research canonical record is malformed"
                ) from exc
            workspaces.append(model.as_dict())
        return workspaces, artifacts

    def _memory(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        candidates: list[dict[str, Any]] = []
        review_root = self.workspace.staging / "memory" / "reviews"
        for path in self._regular_json(
            self.workspace.staging / "memory" / "candidates"
        ):
            try:
                candidate = MemoryCandidate.from_dict(read_json(path))
                self._require_scope(candidate.tenant_id, candidate.project_id)
                review_path = review_root / path.name
                review = None
                if review_path.exists() or review_path.is_symlink():
                    review = MemoryReviewDecision.from_dict(read_json(review_path))
                    self._require_scope(review.tenant_id, review.project_id)
                    if (
                        review.candidate_id != candidate.candidate_id
                        or review.candidate_sha256 != candidate.digest
                    ):
                        raise ProtocolError(
                            "OPERATOR_CANONICAL_RECORD_INVALID",
                            "memory review no longer binds its candidate",
                        )
            except (KeyError, TypeError, ProtocolError) as exc:
                raise self._canonical_invalid(
                    exc, "memory candidate or review is malformed"
                ) from exc
            candidates.append(
                {
                    "candidate": candidate.as_dict(),
                    "review": None if review is None else review.as_dict(),
                }
            )

        knowledge: list[dict[str, Any]] = []
        for path in self._regular_json(self.workspace.prime, recursive=True):
            try:
                node = KnowledgeNode.from_dict(read_json(path))
                self._require_scope(node.tenant_id, node.project_id)
                markdown = self._owned_file(
                    node.relative_path,
                    roots=frozenset({"prime"}),
                    sha256=node.markdown_sha256,
                )
                if path != markdown.with_suffix(".json"):
                    raise ProtocolError(
                        "OPERATOR_CANONICAL_RECORD_INVALID",
                        "knowledge node bytes or path changed",
                    )
            except (KeyError, TypeError, ProtocolError) as exc:
                raise self._canonical_invalid(exc, "knowledge node is malformed") from exc
            knowledge.append(node.as_dict())
        return candidates, knowledge

    def _workflow_keys(self) -> dict[str, Ed25519PublicKey]:
        trusted: dict[str, Ed25519PublicKey] = {}
        path = self.workspace.workflow_keys / "public-keys.json"
        if path.exists() or path.is_symlink():
            document = read_json(path)
            if (
                document.get("schema_version") != "hive.workflow-public-keys.v1"
                or not isinstance(document.get("keys"), dict)
            ):
                raise ProtocolError(
                    "OPERATOR_CANONICAL_RECORD_INVALID",
                    "workflow verification registry is malformed",
                )
            for key_id, record in sorted(document["keys"].items()):
                key = _public_key(str(record.get("public_key_pem", "")))
                if public_key_id(key) != key_id:
                    raise ProtocolError(
                        "OPERATOR_CANONICAL_RECORD_INVALID",
                        "workflow verification key binding changed",
                    )
                trusted[key_id] = key
        registry_path = self.workspace.meta / "agent-operations" / "registry.json"
        if registry_path.exists() or registry_path.is_symlink():
            registry = read_json(registry_path)
            validate_agent_registry(registry)
            for record in registry["agents"].values():
                key = _public_key(str(record["public_key_pem"]))
                if public_key_id(key) != record["key_id"]:
                    raise ProtocolError(
                        "OPERATOR_CANONICAL_RECORD_INVALID",
                        "agent verification key binding changed",
                    )
                trusted[record["key_id"]] = key
        return trusted

    def _workflows(self) -> list[dict[str, Any]]:
        run_root = self.workspace.workflows / "runs"
        run_paths = (
            sorted(run_root.glob("*/run.json"))
            if run_root.exists() and not run_root.is_symlink()
            else []
        )
        if run_root.exists() and (run_root.is_symlink() or not run_root.is_dir()):
            raise ProtocolError(
                "OPERATOR_CANONICAL_RECORD_INVALID", "workflow run root is unsafe"
            )
        if not run_paths:
            return []
        keys = self._workflow_keys()
        if not keys:
            raise ProtocolError(
                "OPERATOR_CANONICAL_RECORD_INVALID",
                "workflow runs have no verification trust root",
            )
        definitions = WorkflowDefinitionStore(self.root, keys)
        replay = WorkflowReplay(self.root, keys)
        results: list[dict[str, Any]] = []
        for path in run_paths:
            try:
                run = WorkflowRun.from_dict(read_json(path), verified_by=keys)
                verify_document(run.as_dict(), keys)
                self._require_scope(run.tenant_id, run.project_id)
                if path.parent.name != run.run_id:
                    raise ProtocolError(
                        "OPERATOR_CANONICAL_RECORD_INVALID",
                        "workflow run path binding changed",
                    )
                definition = definitions.load(run.workflow_id, run.workflow_version)
                projection = replay.reconstruct(run.run_id)
                approvals: set[tuple[str | None, int | None]] = set()
                approval_root = (
                    self.workspace.receipts / "workflows" / run.run_id / "approvals"
                )
                for approval_path in self._regular_json(approval_root):
                    approval = WorkflowApproval.from_dict(
                        read_json(approval_path), verified_by=keys
                    )
                    verify_document(approval.as_dict(), keys)
                    self._require_scope(approval.tenant_id, approval.project_id)
                    if approval.run_id != run.run_id:
                        raise ProtocolError(
                            "OPERATOR_CANONICAL_RECORD_INVALID",
                            "workflow approval crosses runs",
                        )
                    if (
                        approval.decision == "APPROVED"
                        and _time(
                            approval.expires_at,
                            code="OPERATOR_CANONICAL_RECORD_INVALID",
                        )
                        > self.now
                    ):
                        approvals.add((approval.step_id, approval.attempt))
                stale_sessions: list[str] = []
                sessions: list[dict[str, Any]] = []
                session_root = (
                    self.workspace.receipts / "workflows" / run.run_id / "sessions"
                )
                if session_root.exists():
                    if session_root.is_symlink() or not session_root.is_dir():
                        raise ProtocolError(
                            "OPERATOR_CANONICAL_RECORD_INVALID",
                            "workflow session root is unsafe",
                        )
                    for directory in sorted(session_root.iterdir()):
                        if directory.is_symlink() or not directory.is_dir():
                            raise ProtocolError(
                                "OPERATOR_CANONICAL_RECORD_INVALID",
                                "workflow session directory is unsafe",
                            )
                        snapshots = self._regular_json(directory)
                        if not snapshots:
                            continue
                        session = AgentSession.from_dict(
                            read_json(snapshots[-1]), verified_by=keys
                        )
                        verify_document(session.as_dict(), keys)
                        self._require_scope(session.tenant_id, session.project_id)
                        if session.run_id != run.run_id:
                            raise ProtocolError(
                                "OPERATOR_CANONICAL_RECORD_INVALID",
                                "workflow session crosses runs",
                            )
                        heartbeat = _time(
                            session.heartbeat_at,
                            code="OPERATOR_CANONICAL_RECORD_INVALID",
                        )
                        if (
                            session.state == "ACTIVE"
                            and (self.now - heartbeat).total_seconds()
                            > run.policy["stale_after_seconds"]
                        ):
                            stale_sessions.append(session.session_id)
                        sessions.append(session.as_dict())
            except (KeyError, TypeError, ProtocolError) as exc:
                raise self._canonical_invalid(exc, "workflow run is malformed") from exc
            results.append(
                {
                    "run": run.as_dict(),
                    "definition": definition.as_dict(),
                    "projection": projection,
                    "object_version": document_digest(projection),
                    "approved_steps": sorted(
                        [
                            {"step_id": step_id, "attempt": attempt}
                            for step_id, attempt in approvals
                        ],
                        key=lambda item: (item["step_id"] or "", item["attempt"] or 0),
                    ),
                    "stale_sessions": sorted(stale_sessions),
                    "sessions": sorted(
                        sessions, key=lambda item: item["session_id"]
                    ),
                }
            )
        return results

    def _agent_state(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        registry_path = self.workspace.meta / "agent-operations" / "registry.json"
        if not registry_path.exists() and not registry_path.is_symlink():
            return [], []
        try:
            registry = read_json(registry_path)
            validate_agent_registry(registry)
            agents = []
            for record in sorted(
                registry["agents"].values(), key=lambda item: item["agent_id"]
            ):
                if record["tenant_id"] != self.tenant_id or any(
                    project not in self.project_ids
                    for project in record.get("project_ids", [self.default_project_id])
                ):
                    raise ProtocolError(
                        "OPERATOR_CANONICAL_SCOPE_MISMATCH",
                        "agent registry record is outside the operator scope",
                    )
                agents.append(
                    {key: value for key, value in record.items() if key != "public_key_pem"}
                )
            tasks = list_tasks(self.root)
        except (KeyError, TypeError, ProtocolError) as exc:
            raise self._canonical_invalid(exc, "agent operation record is malformed") from exc
        return agents, tasks

    def _retention_and_deletion_reviews(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        retention_root = self.workspace.staging / "memory" / "reviews" / "retention"
        for path in self._regular_json(retention_root):
            document = read_json(path)
            try:
                self._require_scope(document["tenant_id"], document["project_id"])
                if (
                    document.get("schema_version")
                    != "hive.memory-retention-review.v1"
                    or document.get("action") != "REVIEW_REQUIRED"
                    or document.get("automatic_delete") is not False
                ):
                    raise ProtocolError(
                        "OPERATOR_CANONICAL_RECORD_INVALID",
                        "retention review shape changed",
                    )
            except (KeyError, TypeError, ProtocolError) as exc:
                raise self._canonical_invalid(exc, "retention review is malformed") from exc
            items.append(
                {
                    "kind": "RETENTION_REVIEW",
                    "item_id": document["request_id"],
                    "lane": "memory",
                    "state": "REVIEW_REQUIRED",
                    "project_id": document["project_id"],
                    "evidence_ref": path.relative_to(self.root).as_posix(),
                }
            )
        deletion_root = (
            self.workspace.staging / "memory" / "reviews" / "deletion-plans"
        )
        for path in self._regular_json(deletion_root):
            try:
                plan = MemoryDeletionPlan.from_dict(read_json(path))
                self._require_scope(plan.tenant_id, plan.project_id)
            except (KeyError, TypeError, ProtocolError) as exc:
                raise self._canonical_invalid(exc, "deletion plan is malformed") from exc
            items.append(
                {
                    "kind": "RETENTION_REVIEW",
                    "item_id": plan.plan_id,
                    "lane": "memory",
                    "state": "DELETION_APPROVAL_REQUIRED",
                    "project_id": plan.project_id,
                    "evidence_ref": path.relative_to(self.root).as_posix(),
                }
            )
        return items

    def _canonical(self) -> dict[str, Any]:
        self.workspace.ensure_projection_index()
        sources, captures = self._sources_and_captures()
        research, artifacts = self._research()
        candidates, knowledge = self._memory()
        tasks = OperatorProjection(self.root).governed_tasks(
            project_ids=self.project_ids
        )
        agents, agent_tasks = self._agent_state()
        workflows = self._workflows()
        return {
            "sources": sources,
            "captures": captures,
            "research": research,
            "research_artifacts": artifacts,
            "memory": candidates,
            "knowledge": knowledge,
            "tasks": tasks,
            "agents": agents,
            "agent_tasks": agent_tasks,
            "workflows": workflows,
        }

    @staticmethod
    def _lane(document: Mapping[str, Any]) -> str:
        marker = " ".join(
            str(document.get(field, ""))
            for field in ("schema_version", "kind", "event", "outcome")
        ).lower()
        for lane in ("capture", "research", "memory", "knowledge", "workflow"):
            if lane in marker or (lane == "memory" and "cognition" in marker):
                return lane
        if "task" in marker or "cycle2" in marker or "agent" in marker:
            return "agents"
        if any(
            word in marker
            for word in ("provider", "adapter", "snapshot", "rollback", "export", "vault")
        ):
            return "settings"
        return "historical"

    @staticmethod
    def _nested_values(value: Any, field: str) -> list[str]:
        results: list[str] = []
        if isinstance(value, Mapping):
            child = value.get(field)
            if isinstance(child, str):
                results.append(child)
            for item in value.values():
                results.extend(ShellService._nested_values(item, field))
        elif isinstance(value, list):
            for item in value:
                results.extend(ShellService._nested_values(item, field))
        return results

    def _receipt_paths(self) -> list[Path]:
        paths = self._regular_json(self.workspace.receipts, recursive=True)
        legacy = self.root / "receipts"
        paths.extend(self._regular_json(legacy))
        return sorted(set(paths))

    def _verify_capture_receipt(
        self, document: Mapping[str, Any], *, path: Path
    ) -> None:
        operation_key = str(document["operation_key"])
        original_sha256 = str(document["original_sha256"])
        capture_id = f"capture:{operation_key}"
        source_id = f"source:{original_sha256}"
        receipt_ref = f"receipt:capture:{operation_key[:32]}"
        envelope_path = (
            self.workspace.staging
            / "captures"
            / f"capture-{operation_key}.json"
        )
        source_path = self.workspace.provenance / f"source-{original_sha256}.json"
        expected_receipt_path = (
            self.workspace.receipts / f"capture-operation-{operation_key}.json"
        )
        for canonical_path in (envelope_path, source_path):
            require_no_symlink_components(
                self.root,
                canonical_path,
                code="OPERATOR_CANONICAL_RECORD_INVALID",
                detail="capture receipt binding contains a symlink",
            )
        envelope = CaptureEnvelope.from_dict(read_json(envelope_path))
        source = SourceRecord.from_dict(read_json(source_path))
        self._require_scope(envelope.tenant_id, envelope.project_id)
        self._require_scope(source.tenant_id, source.project_id)
        if (
            path != expected_receipt_path
            or document["capture_id"] != capture_id
            or document["source_id"] != source_id
            or document["receipt_ref"] != receipt_ref
            or envelope.capture_id != capture_id
            or envelope.source_record_id != source_id
            or envelope.receipt_ref != receipt_ref
            or envelope.original_sha256 != original_sha256
            or envelope.admission_state != document["outcome"]
            or envelope.acquired_at != document["recorded_at"]
            or source.source_id != source_id
            or source.original_sha256 != original_sha256
            or source.normalized_sha256 != document["normalized_sha256"]
            or capture_id not in source.capture_ids
            or source.tenant_id != envelope.tenant_id
            or source.project_id != envelope.project_id
        ):
            raise ProtocolError(
                "OPERATOR_CANONICAL_RECORD_INVALID",
                "capture receipt is not bound to its canonical capture",
            )
        self._owned_file(
            source.original_asset_path,
            roots=frozenset({"assets"}),
            sha256=source.original_sha256,
        )
        if source.normalized_text_path is not None:
            self._owned_file(
                source.normalized_text_path,
                roots=frozenset({"sources"}),
                sha256=str(source.normalized_sha256),
            )

    def _verify_receipt(
        self,
        document: Mapping[str, Any],
        *,
        path: Path,
        workflow_keys: Mapping[str, Ed25519PublicKey],
    ) -> str:
        schema = document.get("schema_version")
        try:
            if schema in {
                "hive.capture-receipt.v1",
                "hive.cycle2.receipt.v1",
                "nukotech.hive-local.receipt.v1",
                *_WORKFLOW_RECEIPTS,
                *_COGNITION_RECEIPTS,
            }:
                # Only keys this method verifies the same receipt with; local
                # receipts are not signature-verified here, so they get none.
                if schema == "hive.cycle2.receipt.v1":
                    receipt_keys = self.trusted_receipt_keys
                elif schema in _WORKFLOW_RECEIPTS:
                    receipt_keys = workflow_keys
                elif schema in _COGNITION_RECEIPTS:
                    receipt_keys = self._cognition_keys()
                else:
                    receipt_keys = None
                reject_credential_values(
                    document, location="operator receipt", verified_by=receipt_keys
                )
            if schema == "hive.capture-receipt.v1":
                expected = {
                    "schema_version",
                    "receipt_ref",
                    "operation_key",
                    "capture_id",
                    "source_id",
                    "original_sha256",
                    "normalized_sha256",
                    "outcome",
                    "recorded_at",
                }
                if (
                    set(document) != expected
                    or _SHA256.fullmatch(str(document.get("operation_key", ""))) is None
                    or document.get("capture_id")
                    != f"capture:{document.get('operation_key')}"
                    or _SHA256.fullmatch(str(document.get("original_sha256", ""))) is None
                    or (
                        document.get("normalized_sha256") is not None
                        and _SHA256.fullmatch(str(document["normalized_sha256"])) is None
                    )
                ):
                    raise ValueError("capture receipt binding changed")
                self._verify_capture_receipt(document, path=path)
                return "DIGEST_VERIFIED"
            if schema == "hive.cycle2.receipt.v1":
                validate_cycle2_receipt(document)
                signature = document.get("signature", {})
                key_id = signature.get("key_id")
                if key_id in self.trusted_receipt_keys:
                    verify_document(document, self.trusted_receipt_keys)
                    return "SIGNATURE_VERIFIED"
                return "SIGNATURE_UNVERIFIED"
            if schema in _WORKFLOW_RECEIPTS:
                model = (
                    WorkflowApproval.from_dict(document, verified_by=workflow_keys)
                    if schema == "hive.workflow-approval.v1"
                    else WorkflowEvent.from_dict(document, verified_by=workflow_keys)
                )
                verify_document(model.as_dict(), workflow_keys)
                return "SIGNATURE_VERIFIED"
            if schema in _COGNITION_RECEIPTS:
                signature = document.get("signature")
                if (
                    not isinstance(signature, Mapping)
                    or signature.get("algorithm") != "Ed25519"
                    or not isinstance(signature.get("key_id"), str)
                    or not isinstance(signature.get("value"), str)
                ):
                    raise ValueError("cognition signature shape changed")
                cognition_keys = self._cognition_keys()
                key_id = str(signature["key_id"])
                if key_id not in cognition_keys:
                    return "SIGNATURE_UNVERIFIED"
                verify_document(document, cognition_keys)
                return "SIGNATURE_VERIFIED"
            if schema == "nukotech.hive-local.receipt.v1":
                if not all(
                    isinstance(document.get(field), str)
                    for field in ("receipt_id", "kind", "recorded_at")
                ) or not isinstance(document.get("detail"), Mapping):
                    raise ValueError("local receipt shape changed")
                return "STRUCTURE_VERIFIED"
        except (KeyError, TypeError, ValueError, ProtocolError) as exc:
            raise ProtocolError(
                "OPERATOR_CANONICAL_RECORD_INVALID",
                "supported receipt is malformed or unverifiable",
            ) from exc
        return "UNSUPPORTED_OR_HISTORICAL"

    def _cognition_keys(self) -> dict[str, Ed25519PublicKey]:
        root = self.workspace.provenance / "cognition-public-keys"
        keys: dict[str, Ed25519PublicKey] = {}
        if not root.exists():
            return keys
        if root.is_symlink() or not root.is_dir():
            raise ProtocolError(
                "OPERATOR_CANONICAL_RECORD_INVALID",
                "cognition trust root is unsafe",
            )
        for path in sorted(root.glob("*.public.pem")):
            if path.is_symlink() or not path.is_file():
                raise ProtocolError(
                    "OPERATOR_CANONICAL_RECORD_INVALID",
                    "cognition public key is unsafe",
                )
            key = _public_key(path.read_text(encoding="utf-8"))
            keys[public_key_id(key)] = key
        return keys

    def _receipt_project(
        self,
        document: Mapping[str, Any],
        capture_projects: Mapping[str, str],
    ) -> str:
        projects = set(self._nested_values(document, "project_id"))
        capture_id = document.get("capture_id")
        if isinstance(capture_id, str) and capture_id in capture_projects:
            projects.add(capture_projects[capture_id])
        if not projects:
            return self.default_project_id
        if len(projects) != 1:
            raise ProtocolError(
                "OPERATOR_CANONICAL_SCOPE_MISMATCH",
                "receipt contains conflicting project identities",
            )
        project = next(iter(projects))
        if project not in self.project_ids:
            raise ProtocolError(
                "OPERATOR_CANONICAL_SCOPE_MISMATCH",
                "receipt project is outside the operator scope",
            )
        return project

    def _receipts(
        self,
        canonical: Mapping[str, Any],
        *,
        project_id: str,
        query: Mapping[str, str],
    ) -> list[dict[str, Any]]:
        capture_projects = {
            item["capture_id"]: item["project_id"] for item in canonical["captures"]
        }
        workflow_keys = self._workflow_keys()
        results: list[dict[str, Any]] = []
        for path in self._receipt_paths():
            document = read_json(path)
            verification = self._verify_receipt(
                document, path=path, workflow_keys=workflow_keys
            )
            if verification == "UNSUPPORTED_OR_HISTORICAL":
                if "project_id" not in document:
                    receipt_project = self.default_project_id
                else:
                    direct_project = document["project_id"]
                    if (
                        not isinstance(direct_project, str)
                        or direct_project not in self.project_ids
                    ):
                        raise ProtocolError(
                            "OPERATOR_CANONICAL_SCOPE_MISMATCH",
                            "historical receipt project is outside the operator scope",
                        )
                    receipt_project = direct_project
            else:
                receipt_project = self._receipt_project(document, capture_projects)
            if receipt_project != project_id:
                continue
            signature = document.get("signature")
            key_id = (
                signature.get("key_id") if isinstance(signature, Mapping) else None
            )
            actor_values = []
            if verification != "UNSUPPORTED_OR_HISTORICAL":
                for name in (
                    "actor",
                    "approver",
                    "reviewer",
                    "promoter",
                    "publisher",
                ):
                    actor_values.extend(
                        self._nested_values(document.get(name), "app_actor")
                    )
                    actor_values.extend(
                        self._nested_values(document.get(name), "actor_id")
                    )
            recorded_at = next(
                (
                    str(document[field])
                    for field in (
                        "recorded_at",
                        "created_at",
                        "decided_at",
                        "promoted_at",
                        "deleted_at",
                    )
                    if isinstance(document.get(field), str)
                ),
                None,
            )
            historical = verification == "UNSUPPORTED_OR_HISTORICAL"
            lane = "historical" if historical else self._lane(document)
            action = (
                "historical-record"
                if historical
                else str(
                    document.get("kind")
                    or document.get("event")
                    or document.get("outcome")
                    or document.get("schema_version")
                )
            )
            outcome = (
                "RECORDED"
                if historical
                else str(
                    document.get("outcome")
                    or document.get("state_after")
                    or document.get("decision")
                    or "RECORDED"
                )
            )
            receipt_id = str(
                document.get("receipt_id")
                or document.get("receipt_ref")
                or document.get("operation_id")
                or document.get("approval_id")
                or document.get("event_id")
                or document_digest(document)
            )
            item = {
                "receipt_id": receipt_id,
                "receipt_ref": path.relative_to(self.root).as_posix(),
                "schema_version": str(document.get("schema_version", "UNKNOWN")),
                "project_id": receipt_project,
                "lane": lane,
                "action": action,
                "actor": sorted(set(actor_values)),
                "key_id": key_id,
                "outcome": outcome,
                "recorded_at": recorded_at,
                "sha256": document_digest(document),
                "verification_state": verification,
                "historical": historical,
            }
            if query.get("lane") not in {None, lane}:
                continue
            if query.get("action") not in {None, action}:
                continue
            actor_filter = query.get("actor")
            if actor_filter is not None and actor_filter not in {
                *item["actor"],
                item["key_id"],
            }:
                continue
            if query.get("outcome") not in {None, outcome}:
                continue
            if recorded_at is not None:
                observed = _time(
                    recorded_at, code="OPERATOR_CANONICAL_RECORD_INVALID"
                )
                if "from" in query and observed < _time(
                    query["from"], code="OPERATOR_RECEIPT_FILTER_INVALID"
                ):
                    continue
                if "to" in query and observed > _time(
                    query["to"], code="OPERATOR_RECEIPT_FILTER_INVALID"
                ):
                    continue
            elif "from" in query or "to" in query:
                continue
            results.append(item)
        return sorted(
            results,
            key=lambda item: (item["recorded_at"] or "", item["receipt_ref"]),
            reverse=True,
        )

    def _inbox(self, canonical: Mapping[str, Any], project_id: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        capture_projects = {
            item["capture_id"]: item["project_id"] for item in canonical["captures"]
        }
        for path in self._regular_json(self.workspace.capture_queue):
            document = read_json(path)
            capture_id = document.get("capture_id")
            project = capture_projects.get(str(capture_id))
            if (
                set(document)
                != {
                    "schema_version",
                    "capture_id",
                    "source_id",
                    "channel",
                    "original_sha256",
                    "provider_reason",
                    "state",
                }
                or document.get("schema_version")
                != "hive.capture-provider-queue.v1"
                or document.get("state") != "QUEUED_PROVIDER"
                or project is None
            ):
                raise ProtocolError(
                    "OPERATOR_CANONICAL_RECORD_INVALID",
                    "capture degraded queue item is malformed",
                )
            if project == project_id:
                items.append(
                    {
                        "kind": "CAPTURE_DEGRADED",
                        "item_id": capture_id,
                        "lane": "capture",
                        "state": "QUEUED_PROVIDER",
                        "project_id": project,
                        "evidence_ref": path.relative_to(self.root).as_posix(),
                    }
                )
        for task in canonical["tasks"]:
            if task["project_id"] == project_id and task["state"] not in _TERMINAL_TASK_STATES:
                items.append(
                    {
                        "kind": "GOVERNED_TASK",
                        "item_id": task["task_id"],
                        "lane": "agents",
                        "state": task["state"],
                        "project_id": project_id,
                        "evidence_ref": f"tasks/{task['task_id']}.json",
                    }
                )
        for record in canonical["memory"]:
            candidate = record["candidate"]
            if candidate["project_id"] == project_id and record["review"] is None:
                items.append(
                    {
                        "kind": "MEMORY_REVIEW",
                        "item_id": candidate["candidate_id"],
                        "lane": "memory",
                        "state": "PROPOSED",
                        "project_id": project_id,
                        "evidence_ref": "staging/memory/candidates",
                    }
                )
        items.extend(
            item
            for item in self._retention_and_deletion_reviews()
            if item["project_id"] == project_id
        )
        for workflow in canonical["workflows"]:
            run = workflow["run"]
            if run["project_id"] != project_id:
                continue
            projection = workflow["projection"]
            if projection["state"] == "RUNNING":
                approved_steps = {
                    item["step_id"] for item in workflow["approved_steps"]
                }
                for step in workflow["definition"]["steps"]:
                    attempts = projection["steps"].get(step["step_id"], {}).get(
                        "attempts", {}
                    )
                    completed = any(
                        attempt.get("state") == "COMPLETED"
                        for attempt in attempts.values()
                    )
                    if (
                        step["approval"]["required"]
                        and step["step_id"] not in approved_steps
                        and not completed
                    ):
                        items.append(
                            {
                                "kind": "WORKFLOW_APPROVAL",
                                "item_id": f"{run['run_id']}:{step['step_id']}",
                                "lane": "workflows",
                                "state": "APPROVAL_REQUIRED",
                                "project_id": project_id,
                                "evidence_ref": f"workflows/runs/{run['run_id']}/run.json",
                            }
                        )
            for session_id in workflow["stale_sessions"]:
                items.append(
                    {
                        "kind": "WORKFLOW_STALE_SESSION",
                        "item_id": session_id,
                        "lane": "workflows",
                        "state": "STALE_REVIEW_REQUIRED",
                        "project_id": project_id,
                        "evidence_ref": (
                            f".hive/receipts/workflows/{run['run_id']}/sessions/"
                            f"{session_id}"
                        ),
                    }
                )
            for conflict_id in projection["conflicts"]:
                items.append(
                    {
                        "kind": "WORKFLOW_CONFLICT",
                        "item_id": conflict_id,
                        "lane": "workflows",
                        "state": "BLOCKED",
                        "project_id": project_id,
                        "evidence_ref": f"workflows/runs/{run['run_id']}/run.json",
                    }
                )
            for attempt in (
                attempt
                for step in projection["steps"].values()
                for attempt in step["attempts"].values()
            ):
                if attempt.get("state") in {"FAILED", "ABANDONED"}:
                    items.append(
                        {
                            "kind": "ERROR",
                            "item_id": str(attempt["events"][-1]),
                            "lane": "workflows",
                            "state": str(attempt["state"]),
                            "project_id": project_id,
                            "evidence_ref": f"workflows/runs/{run['run_id']}/run.json",
                        }
                    )
        for artifact in canonical["research_artifacts"]:
            if artifact["project_id"] == project_id and artifact["status"] in {
                "DEGRADED",
                "FAILED",
                "MODEL_OUTPUT_REJECTED",
            }:
                items.append(
                    {
                        "kind": "ERROR",
                        "item_id": artifact["artifact_id"],
                        "lane": "research",
                        "state": artifact["status"],
                        "project_id": project_id,
                        "evidence_ref": artifact["markdown_path"],
                    }
                )
        return sorted(items, key=lambda item: (item["kind"], item["item_id"]))

    def _provider(self, receipts: list[dict[str, Any]]) -> dict[str, Any]:
        status = self.workspace.provider_configuration()
        try:
            reject_credential_values(status, location="operator provider status")
        except ProtocolError as exc:
            raise ProtocolError(
                "OPERATOR_CANONICAL_RECORD_INVALID",
                "provider status contains unsafe material",
            ) from exc
        configured = status.get("mode") in {
            "auto",
            "ollama",
            "retrieval-only",
        }
        installed = False
        running = False
        working = False
        verified = any(
            item["action"] == "provider-verified" for item in receipts
        )
        authorized = any(
            item["action"] == "provider-authorized" for item in receipts
        )
        if status["availability_state"] == "RETRIEVAL_ONLY":
            label = "Retrieval only; no provider will be used"
        elif configured and not running:
            label = "Configured; provider not running"
        elif installed and not verified:
            label = "Installed; verification not yet recorded"
        elif working:
            label = "Working"
        else:
            label = "Not configured"
        return {
            "provider": (
                "none"
                if status["availability_state"] == "RETRIEVAL_ONLY"
                else status["mode"]
            ),
            "model": status.get("model"),
            "configured_mode": status.get("mode"),
            "availability_state": status["availability_state"],
            "provider_attempted": status["provider_attempted"],
            "states": {
                "authorized": authorized,
                "configured": configured,
                "installed": installed,
                "running": running,
                "verified": verified,
                "working": working,
            },
            "label": label,
        }

    def _adapters(self, receipts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for item in adapter_status(self.root):
            adapter_id = item["adapter_id"]
            states = {
                "authorized": any(
                    receipt["action"] == "adapter-authorized"
                    and adapter_id in receipt["receipt_id"]
                    for receipt in receipts
                ),
                "configured": item["health"]["status"] != "NOT_INITIALIZED",
                "installed": True,
                "running": False,
                "verified": item["health"]["status"] == "VERIFIED",
                "working": item["health"]["status"] in {"HEALTHY", "VERIFIED"}
                and not item["revoked"],
            }
            label = (
                "Installed; verification not yet recorded"
                if states["installed"] and not states["verified"]
                else "Verified"
            )
            results.append(
                {
                    "adapter_id": adapter_id,
                    "version": item["version"],
                    "compatible": item["compatible"],
                    "revoked": item["revoked"],
                    "credential_state": item["credential_state"],
                    "states": states,
                    "label": label,
                }
            )
        return results

    @staticmethod
    def _count_project(canonical: Mapping[str, Any], project_id: str) -> dict[str, int]:
        return {
            "sources": sum(item["project_id"] == project_id for item in canonical["sources"]),
            "captures": sum(item["project_id"] == project_id for item in canonical["captures"]),
            "research_workspaces": sum(
                item["project_id"] == project_id for item in canonical["research"]
            ),
            "memory_candidates": sum(
                item["candidate"]["project_id"] == project_id
                for item in canonical["memory"]
            ),
            "knowledge_nodes": sum(
                item["project_id"] == project_id
                for item in canonical["knowledge"]
            ),
            "workflow_runs": sum(
                item["run"]["project_id"] == project_id
                for item in canonical["workflows"]
            ),
            "agents": sum(
                project_id in item.get("project_ids", [project_id])
                for item in canonical["agents"]
            ),
            "tasks": sum(item["project_id"] == project_id for item in canonical["tasks"]),
        }

    def read(
        self,
        route: RouteContract,
        *,
        tenant_id: str,
        project_id: str,
        query: dict[str, str],
    ) -> Mapping[str, Any]:
        self._refresh_now()
        if tenant_id != self.tenant_id or project_id not in self.project_ids:
            raise ProtocolError(
                "OPERATOR_SCOPE_DENIED", "operator read is outside the shell scope"
            )
        if route.action not in _READ_ACTIONS:
            raise ProtocolError(
                "OPERATOR_DOMAIN_UNAVAILABLE",
                "operator lane projection is not installed yet",
            )
        if route.action == "loadouts.read":
            if query.get("project_id") not in {None, project_id}:
                raise ProtocolError("OPERATOR_SCOPE_DENIED", "loadout query crosses project scope")
            data = {"project_id": project_id, "loadouts": self.loadouts.status(project_id)}
            return {"outcome": "OK", "reason_code": None, "object_version": document_digest(data),
                    "changed": False, "data": data, "technical_evidence": []}
        canonical = self._canonical()
        receipt_query = query if route.action == "receipts.read" else {}
        if query.get("project_id") not in {None, project_id}:
            raise ProtocolError(
                "OPERATOR_SCOPE_DENIED", "projection query crosses project scope"
            )
        if route.action == "receipts.read":
            try:
                limit = int(query.get("limit", "100"))
            except ValueError as exc:
                raise ProtocolError(
                    "OPERATOR_RECEIPT_FILTER_INVALID", "receipt limit is invalid"
                ) from exc
            if not 1 <= limit <= 200:
                raise ProtocolError(
                    "OPERATOR_RECEIPT_FILTER_INVALID",
                    "receipt limit must be between 1 and 200",
                )
        else:
            limit = 100
        receipts = self._receipts(
            canonical, project_id=project_id, query=receipt_query
        )
        receipts = receipts[:limit]
        inbox = self._inbox(canonical, project_id)
        counts = self._count_project(canonical, project_id)
        counts.update(
            {
                "receipts": len(
                    self._receipts(canonical, project_id=project_id, query={})
                ),
                "inbox": len(inbox),
            }
        )

        if route.action == "projects.read":
            projects = []
            discovered = {
                self.default_project_id,
                *(item["project_id"] for item in canonical["sources"]),
                *(item["project_id"] for item in canonical["captures"]),
                *(item["project_id"] for item in canonical["research"]),
                *(item["candidate"]["project_id"] for item in canonical["memory"]),
                *(item["project_id"] for item in canonical["knowledge"]),
                *(item["run"]["project_id"] for item in canonical["workflows"]),
                *(item["project_id"] for item in canonical["tasks"]),
                *(
                    project
                    for item in canonical["agents"]
                    for project in item.get("project_ids", [])
                ),
            }
            discovered.update(
                configured_project
                for configured_project in self.project_ids
                if self._receipts(
                    canonical, project_id=configured_project, query={}
                )
            )
            for discovered_project in sorted(discovered):
                project_counts = self._count_project(canonical, discovered_project)
                project_inbox = self._inbox(canonical, discovered_project)
                project_receipts = self._receipts(
                    canonical, project_id=discovered_project, query={}
                )
                project_counts["receipts"] = len(project_receipts)
                projects.append(
                    {
                        "project_id": discovered_project,
                        "counts": project_counts,
                        "inbox": len(project_inbox),
                    }
                )
            data: dict[str, Any] = {"projects": projects}
        elif route.action == "inbox.read":
            data = {"project_id": project_id, "items": inbox}
        elif route.action == "receipts.read":
            data = {
                "project_id": project_id,
                "filters": dict(sorted(query.items())),
                "receipts": receipts,
            }
        elif route.action == "settings.read":
            config = read_json(self.workspace.config_path)
            checkpoints = []
            for path in self._regular_json(
                self.settings_lifecycle.hive_checkpoints
            ):
                checkpoint = read_json(path)
                verified_checkpoint = self.settings_lifecycle._read_checkpoint(
                    checkpoint
                )
                checkpoints.append(
                    {
                        "checkpoint": verified_checkpoint,
                        "checkpoint_sha256": document_digest(
                            verified_checkpoint
                        ),
                    }
                )
            checkpoints.sort(
                key=lambda item: (
                    item["checkpoint"]["created_at"],
                    item["checkpoint"]["checkpoint_id"],
                )
            )
            data = {
                "project_id": project_id,
                "privacy_mode": config["privacy_mode"],
                "provider": self._provider(receipts),
                "adapters": self._adapters(receipts),
                "checkpoints": checkpoints,
                "action_versions": {
                    "settings.provider.preview": document_digest(config),
                    "settings.snapshot": self.settings_lifecycle._portable_state_version(),
                },
                "release_holds": list(RELEASE_HOLDS),
            }
        elif route.action == "capture.read":
            data = {
                "project_id": project_id,
                "sources": [
                    copy.deepcopy(item)
                    for item in canonical["sources"]
                    if item["project_id"] == project_id
                ],
                "captures": [
                    copy.deepcopy(item)
                    for item in canonical["captures"]
                    if item["project_id"] == project_id
                ],
            }
        elif route.action == "research.read":
            data = {
                "project_id": project_id,
                "workspaces": [
                    copy.deepcopy(item)
                    for item in canonical["research"]
                    if item["project_id"] == project_id
                ],
                "artifacts": [
                    copy.deepcopy(item)
                    for item in canonical["research_artifacts"]
                    if item["project_id"] == project_id
                ],
            }
        elif route.action == "memory.read":
            retention_nodes = sorted(
                [
                    copy.deepcopy(item)
                    for item in canonical["knowledge"]
                    if item["project_id"] == project_id
                    and item.get("retention_until") is not None
                    and item["retention_until"]
                    <= self.now.isoformat().replace("+00:00", "Z")
                ],
                key=lambda item: item["node_id"],
            )
            data = {
                "project_id": project_id,
                "candidates": [
                    copy.deepcopy(item)
                    for item in canonical["memory"]
                    if item["candidate"]["project_id"] == project_id
                ],
                "reviews": [
                    item
                    for item in self._retention_and_deletion_reviews()
                    if item["project_id"] == project_id
                ],
                "action_versions": {
                    "memory.retention.scan": document_digest(retention_nodes),
                },
            }
        elif route.action == "knowledge.read":
            data = {
                "project_id": project_id,
                "nodes": [
                    copy.deepcopy(item)
                    for item in canonical["knowledge"]
                    if item["project_id"] == project_id
                ],
                "action_versions": {
                    "knowledge.graph.rebuild": self.cognition_knowledge.graph_version(),
                },
            }
        elif route.action == "workflows.read":
            diff_fields = {"workflow_id", "from_version", "to_version"}
            present = diff_fields & set(query)
            if present and present != diff_fields:
                raise ProtocolError(
                    "WORKFLOW_DEFINITION_DIFF_INVALID",
                    "definition diff requires workflow ID and two exact versions",
                )
            if present:
                workflow_id = query["workflow_id"]
                try:
                    from_version = int(query["from_version"])
                    to_version = int(query["to_version"])
                except ValueError as exc:
                    raise ProtocolError(
                        "WORKFLOW_DEFINITION_DIFF_INVALID",
                        "definition diff versions must be positive integers",
                    ) from exc
                if (
                    from_version < 1
                    or to_version < 1
                    or str(from_version) != query["from_version"]
                    or str(to_version) != query["to_version"]
                ):
                    raise ProtocolError(
                        "WORKFLOW_DEFINITION_DIFF_INVALID",
                        "definition diff versions must be canonical positive integers",
                    )
                store = WorkflowDefinitionStore(self.root, self._workflow_keys())
                left = store.load(workflow_id, from_version)
                right = store.load(workflow_id, to_version)
                self._require_scope(left.tenant_id, left.project_id)
                self._require_scope(right.tenant_id, right.project_id)
                data = {
                    "project_id": project_id,
                    "definition_diff": {
                        "workflow_id": workflow_id,
                        "from_version": from_version,
                        "to_version": to_version,
                        "from_sha256": left.digest,
                        "to_sha256": right.digest,
                        "changes": diff_workflow_documents(
                            {
                                key: value
                                for key, value in left.as_dict().items()
                                if key != "signature"
                            },
                            {
                                key: value
                                for key, value in right.as_dict().items()
                                if key != "signature"
                            },
                        ),
                    },
                }
            else:
                data = {
                    "project_id": project_id,
                    "workflows": [
                        copy.deepcopy(item)
                        for item in canonical["workflows"]
                        if item["run"]["project_id"] == project_id
                    ],
                }
        elif route.action == "agents.read":
            project_workflows = [
                item
                for item in canonical["workflows"]
                if item["run"]["project_id"] == project_id
            ]
            project_agents = {
                item["agent_id"]
                for item in canonical["agents"]
                if project_id in item.get("project_ids", [])
            }
            data = {
                "project_id": project_id,
                "agents": [
                    copy.deepcopy(item)
                    for item in canonical["agents"]
                    if project_id in item.get("project_ids", [])
                ],
                "agent_health": [
                    {
                        "agent_id": item["agent_id"],
                        "active": bool(item["active"]),
                        "status": (
                            "REGISTERED_ATTENDED"
                            if item["active"]
                            else "INACTIVE"
                        ),
                    }
                    for item in canonical["agents"]
                    if project_id in item.get("project_ids", [])
                ],
                "governed_tasks": [
                    copy.deepcopy(item)
                    for item in canonical["tasks"]
                    if item["project_id"] == project_id
                ],
                "agent_task_receipts": [
                    copy.deepcopy(item)
                    for item in canonical["agent_tasks"]
                    if item["sender"] in project_agents
                    and item["recipient"] in project_agents
                ],
                "sessions": [
                    copy.deepcopy(session)
                    for workflow in project_workflows
                    for session in workflow["sessions"]
                ],
                "resource_summaries": [
                    {
                        "run_id": workflow["run"]["run_id"],
                        "resources": copy.deepcopy(
                            workflow["projection"]["resource_use"]
                        ),
                    }
                    for workflow in project_workflows
                ],
                "adapter_health": self._adapters(receipts),
            }
        else:
            data = {
                "project_id": project_id,
                "counts": counts,
                "recent_work": receipts[:10],
                "blocked_count": sum(
                    item["state"] in {"BLOCKED", "FAILED", "ABANDONED"}
                    for item in inbox
                ),
                "approval_count": sum(
                    "APPROVAL" in item["state"] or "REVIEW" in item["state"]
                    or item["kind"] == "MEMORY_REVIEW"
                    for item in inbox
                ),
                "provider": self._provider(receipts),
                "adapters": self._adapters(receipts),
            }
        return {
            "outcome": "OK",
            "reason_code": None,
            "object_version": document_digest(data),
            "changed": False,
            "data": data,
            "technical_evidence": [],
        }
