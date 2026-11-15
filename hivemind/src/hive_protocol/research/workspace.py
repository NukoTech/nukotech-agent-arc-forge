"""Immutable, source-digest-bound bounded research workspaces."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path, PurePosixPath
from typing import Any, Mapping
from uuid import NAMESPACE_URL, uuid5

from hive_protocol.capture.models import CitationAnchor, SourceRecord, capture_document_digest
from hive_protocol.core import ProtocolError, canonical_bytes, document_digest
from hive_protocol.product.workspace import HiveWorkspace
from hive_protocol.storage import atomic_write_bytes, atomic_write_json, exclusive_lock, read_json, utc_now

from .models import ResearchSourceSet, ResearchWorkspace


_SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class BoundedResearchWorkspaceStore:
    """Creates immutable workspace metadata and append-only source-set DAGs."""

    def __init__(self, workspace: HiveWorkspace) -> None:
        self.workspace = workspace

    @staticmethod
    def _slug(workspace_id: str) -> str:
        if not isinstance(workspace_id, str) or _SAFE_ID.fullmatch(workspace_id) is None:
            raise ProtocolError(
                "RESEARCH_WORKSPACE_ID_INVALID", "research workspace ID is invalid"
            )
        return f"workspace-{hashlib.sha256(workspace_id.encode()).hexdigest()[:32]}"

    def _workspace_root(self, workspace_id: str) -> Path:
        return self.workspace.research / "workspaces" / self._slug(workspace_id)

    def _ensure_directory(self, path: Path, *, private: bool = False) -> None:
        try:
            relative = path.relative_to(self.workspace.root)
        except ValueError as exc:
            raise ProtocolError(
                "RESEARCH_WORKSPACE_BOUNDARY", "research path escapes the Hive root"
            ) from exc
        current = self.workspace.root
        for part in relative.parts:
            current /= part
            if current.is_symlink():
                raise ProtocolError(
                    "RESEARCH_WORKSPACE_BOUNDARY",
                    "research path may not contain symlinks",
                )
        path.mkdir(parents=True, exist_ok=True, mode=0o700 if private else 0o755)
        if path.is_symlink() or not path.is_dir() or path.stat().st_uid != os.geteuid():
            raise ProtocolError(
                "RESEARCH_WORKSPACE_BOUNDARY",
                "research directory is not an owned regular directory",
            )
        if private:
            os.chmod(path, 0o700)

    def _lock_path(self, workspace_id: str) -> Path:
        root = self.workspace.runtime / "research-locks"
        self._ensure_directory(root, private=True)
        return root / f"{self._slug(workspace_id)}.lock"

    def workspace_path(self, workspace_id: str) -> Path:
        return self._workspace_root(workspace_id) / "workspace.json"

    def _require_regular_file(self, path: Path, *, code: str) -> None:
        try:
            relative = path.relative_to(self.workspace.root)
        except ValueError as exc:
            raise ProtocolError(code, "research file escapes the Hive root") from exc
        current = self.workspace.root
        for part in relative.parts:
            current /= part
            if current.is_symlink():
                raise ProtocolError(code, "research file path contains a symlink")
        if not path.is_file():
            raise ProtocolError(code, "research file is absent")

    def source_set_path(self, workspace_id: str, source_set_digest: str) -> Path:
        if not isinstance(source_set_digest, str) or _SHA256.fullmatch(source_set_digest) is None:
            raise ProtocolError(
                "RESEARCH_SOURCE_SET_DIGEST_INVALID",
                "research source-set digest must be an exact SHA-256",
            )
        return self._workspace_root(workspace_id) / "source-sets" / f"{source_set_digest}.json"

    def _snapshot_path(self, workspace_id: str, record_digest: str) -> Path:
        return self._workspace_root(workspace_id) / "source-records" / f"{record_digest}.json"

    def create_workspace(
        self,
        *,
        workspace_id: str,
        tenant_id: str,
        project_id: str,
        name: str,
        privacy_class: str,
        created_at: str | None = None,
    ) -> ResearchWorkspace:
        self._slug(workspace_id)
        if not isinstance(name, str) or not name.strip() or name != name.strip():
            raise ProtocolError(
                "RESEARCH_WORKSPACE_INVALID", "research workspace name is invalid"
            )
        with exclusive_lock(self._lock_path(workspace_id)):
            path = self.workspace_path(workspace_id)
            self._ensure_directory(path.parent)
            if path.is_symlink():
                raise ProtocolError(
                    "RESEARCH_WORKSPACE_BOUNDARY", "workspace metadata is a symlink"
                )
            if path.exists():
                existing = ResearchWorkspace.from_dict(read_json(path))
                if (
                    existing.workspace_id != workspace_id
                    or existing.tenant_id != tenant_id
                    or existing.project_id != project_id
                    or existing.name != name
                    or existing.privacy_class != privacy_class
                    or created_at is not None
                    and existing.created_at != created_at
                ):
                    raise ProtocolError(
                        "RESEARCH_WORKSPACE_MISMATCH",
                        "research workspace metadata is immutable",
                    )
                return existing
            model = ResearchWorkspace(
                workspace_id=workspace_id,
                tenant_id=tenant_id,
                project_id=project_id,
                name=name,
                privacy_class=privacy_class,
                created_at=created_at or utc_now(),
            )
            document = model.as_dict()
            model = ResearchWorkspace.from_dict(document)
            atomic_write_json(path, document)
            self._write_receipt(
                f"research-workspace-{self._slug(workspace_id)}.json",
                "research-workspace-created",
                {
                    "workspace_id": workspace_id,
                    "workspace_path": path.relative_to(self.workspace.root).as_posix(),
                    "workspace_digest": document_digest(document),
                },
                model.created_at,
            )
            return model

    def open_workspace(self, workspace_id: str) -> ResearchWorkspace:
        path = self.workspace_path(workspace_id)
        if not path.exists() and not path.is_symlink():
            raise ProtocolError(
                "RESEARCH_WORKSPACE_ABSENT", "research workspace does not exist"
            )
        self._require_regular_file(path, code="RESEARCH_WORKSPACE_BOUNDARY")
        model = ResearchWorkspace.from_dict(read_json(path))
        if model.workspace_id != workspace_id:
            raise ProtocolError(
                "RESEARCH_WORKSPACE_MISMATCH", "workspace ID changed on disk"
            )
        return model

    def source_record_path(self, source_id: str) -> Path:
        if (
            not isinstance(source_id, str)
            or not source_id.startswith("source:")
            or _SHA256.fullmatch(source_id.removeprefix("source:")) is None
        ):
            raise ProtocolError("RESEARCH_SOURCE_ID_INVALID", "source ID is invalid")
        return self.workspace.provenance / f"source-{source_id.removeprefix('source:')}.json"

    @staticmethod
    def source_record_digest(document: Mapping[str, Any]) -> str:
        return capture_document_digest(document)

    def _portable_file(self, relative: str, *, prefix: str) -> Path:
        candidate = PurePosixPath(relative)
        if (
            candidate.is_absolute()
            or candidate.as_posix() != relative
            or not candidate.parts
            or candidate.parts[0] != prefix
            or any(part in {"", ".", ".."} for part in candidate.parts)
        ):
            raise ProtocolError(
                "RESEARCH_SOURCE_DRIFT", "source path exceeds its portable root"
            )
        current = self.workspace.root
        for part in candidate.parts:
            current /= part
            if current.is_symlink():
                raise ProtocolError(
                    "RESEARCH_SOURCE_DRIFT", "source path contains a symlink"
                )
        if not current.is_file():
            raise ProtocolError("RESEARCH_SOURCE_DRIFT", "source bytes are absent")
        return current

    def _verify_record(
        self, record: SourceRecord, research_workspace: ResearchWorkspace
    ) -> None:
        if (
            record.tenant_id != research_workspace.tenant_id
            or record.project_id != research_workspace.project_id
            or record.privacy_class != research_workspace.privacy_class
        ):
            raise ProtocolError(
                "RESEARCH_SOURCE_SCOPE_MISMATCH",
                "source record is outside the research workspace scope",
            )
        original = self._portable_file(record.original_asset_path, prefix="assets")
        original_bytes = original.read_bytes()
        if (
            len(original_bytes) != record.original_size_bytes
            or _sha256(original_bytes) != record.original_sha256
        ):
            raise ProtocolError(
                "RESEARCH_SOURCE_DRIFT", "original source bytes changed"
            )
        if record.normalized_text_path is None or record.normalized_sha256 is None:
            raise ProtocolError(
                "RESEARCH_SOURCE_NOT_NORMALIZED",
                "research source requires verified normalized text",
            )
        normalized = self._portable_file(record.normalized_text_path, prefix="sources")
        normalized_bytes = normalized.read_bytes()
        if _sha256(normalized_bytes) != record.normalized_sha256:
            raise ProtocolError(
                "RESEARCH_SOURCE_DRIFT", "normalized source bytes changed"
            )
        try:
            normalized_text = normalized_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProtocolError(
                "RESEARCH_SOURCE_DRIFT", "normalized source is not UTF-8"
            ) from exc
        for anchor_document in record.anchors:
            CitationAnchor.from_dict(anchor_document).verify(normalized_text)

    def _current_record(
        self, source_id: str, research_workspace: ResearchWorkspace
    ) -> tuple[SourceRecord, dict[str, Any], str]:
        path = self.source_record_path(source_id)
        if not path.exists() and not path.is_symlink():
            raise ProtocolError("RESEARCH_SOURCE_ABSENT", "source record is absent")
        self._require_regular_file(path, code="RESEARCH_SOURCE_DRIFT")

        try:
            document = read_json(path)
            record = SourceRecord.from_dict(document)
        except ProtocolError as exc:
            raise ProtocolError(
                "RESEARCH_SOURCE_DRIFT", "source record is malformed"
            ) from exc
        if record.source_id != source_id:
            raise ProtocolError("RESEARCH_SOURCE_DRIFT", "source record ID changed")
        self._verify_record(record, research_workspace)
        return record, document, self.source_record_digest(document)

    def _write_snapshot(
        self, workspace_id: str, document: dict[str, Any], digest: str
    ) -> None:
        path = self._snapshot_path(workspace_id, digest)
        self._ensure_directory(path.parent)
        payload = canonical_bytes(document) + b"\n"
        if path.is_symlink():
            raise ProtocolError(
                "RESEARCH_SOURCE_SNAPSHOT_MISMATCH",
                "source record snapshot is a symlink",
            )
        if path.exists():
            if path.read_bytes() != payload:
                raise ProtocolError(
                    "RESEARCH_SOURCE_SNAPSHOT_MISMATCH",
                    "source record snapshot changed",
                )
            return
        atomic_write_bytes(path, payload)

    def _source_sets(self, workspace_id: str) -> dict[str, ResearchSourceSet]:
        research_workspace = self.open_workspace(workspace_id)
        root = self._workspace_root(workspace_id) / "source-sets"
        self._ensure_directory(root)
        versions: dict[str, ResearchSourceSet] = {}
        for path in sorted(root.glob("*.json")):
            if path.is_symlink() or not path.is_file() or _SHA256.fullmatch(path.stem) is None:
                raise ProtocolError(
                    "RESEARCH_SOURCE_SET_DIGEST_MISMATCH",
                    "research source-set path is invalid",
                )
            document = read_json(path)
            digest = document_digest(document)
            if digest != path.stem:
                raise ProtocolError(
                    "RESEARCH_SOURCE_SET_DIGEST_MISMATCH",
                    "research source-set content changed",
                )
            model = ResearchSourceSet.from_dict(document)
            if (
                model.workspace_id != workspace_id
                or model.tenant_id != research_workspace.tenant_id
                or model.project_id != research_workspace.project_id
            ):
                raise ProtocolError(
                    "RESEARCH_SOURCE_SET_SCOPE_MISMATCH",
                    "source-set workspace binding changed",
                )
            versions[digest] = model
        if not versions:
            return versions
        roots = [digest for digest, model in versions.items() if model.parent_digest is None]
        if len(roots) != 1:
            raise ProtocolError(
                "RESEARCH_SOURCE_SET_GRAPH_INVALID", "source-set history has no single root"
            )
        child_count = {digest: 0 for digest in versions}
        for model in versions.values():
            if model.parent_digest is not None:
                if model.parent_digest not in versions:
                    raise ProtocolError(
                        "RESEARCH_SOURCE_SET_GRAPH_INVALID",
                        "source-set parent is absent",
                    )
                child_count[model.parent_digest] += 1
        if any(count > 1 for count in child_count.values()):
            raise ProtocolError(
                "RESEARCH_SOURCE_SET_GRAPH_INVALID", "source-set history forked"
            )
        heads = [digest for digest, count in child_count.items() if count == 0]
        if len(heads) != 1:
            raise ProtocolError(
                "RESEARCH_SOURCE_SET_GRAPH_INVALID", "source-set history has no single head"
            )
        visited: set[str] = set()
        cursor: str | None = heads[0]
        while cursor is not None and cursor not in visited:
            visited.add(cursor)
            cursor = versions[cursor].parent_digest
        if cursor is not None or len(visited) != len(versions):
            raise ProtocolError(
                "RESEARCH_SOURCE_SET_GRAPH_INVALID",
                "source-set history is cyclic or disconnected",
            )
        return versions

    def current_source_set(self, workspace_id: str) -> dict[str, Any] | None:
        self.open_workspace(workspace_id)
        versions = self._source_sets(workspace_id)
        if not versions:
            return None
        parents = {
            model.parent_digest
            for model in versions.values()
            if model.parent_digest is not None
        }
        head_digest = next(digest for digest in versions if digest not in parents)
        return {
            "source_set_digest": head_digest,
            "source_set": versions[head_digest],
        }

    def update_source_set(
        self,
        workspace_id: str,
        *,
        expected_parent_digest: str | None,
        source_ids: list[str],
        retrieval_policy: dict[str, Any],
        created_at: str | None = None,
    ) -> dict[str, Any]:
        if (
            not isinstance(source_ids, list)
            or not source_ids
            or not all(isinstance(source_id, str) for source_id in source_ids)
            or len(source_ids) != len(set(source_ids))
        ):
            raise ProtocolError(
                "RESEARCH_SOURCE_SET_NONCANONICAL",
                "research source IDs must be a non-empty unique list",
            )
        if expected_parent_digest is not None and (
            not isinstance(expected_parent_digest, str)
            or _SHA256.fullmatch(expected_parent_digest) is None
        ):
            raise ProtocolError(
                "RESEARCH_SOURCE_SET_STALE", "expected parent digest is invalid"
            )
        with exclusive_lock(self._lock_path(workspace_id)):
            research_workspace = self.open_workspace(workspace_id)
            current = self.current_source_set(workspace_id)
            current_digest = current["source_set_digest"] if current is not None else None
            if current_digest != expected_parent_digest:
                raise ProtocolError(
                    "RESEARCH_SOURCE_SET_STALE",
                    "research source-set head changed",
                )
            sources: list[dict[str, str]] = []
            snapshots: list[tuple[dict[str, Any], str]] = []
            for source_id in sorted(source_ids):
                _, document, digest = self._current_record(
                    source_id, research_workspace
                )
                sources.append(
                    {"source_id": source_id, "source_record_digest": digest}
                )
                snapshots.append((document, digest))
            moment = created_at or utc_now()
            identity = document_digest(
                {
                    "workspace_id": workspace_id,
                    "parent_digest": current_digest,
                    "sources": sources,
                    "retrieval_policy": retrieval_policy,
                    "created_at": moment,
                }
            )
            model = ResearchSourceSet(
                source_set_id=f"source-set:{identity}",
                workspace_id=workspace_id,
                tenant_id=research_workspace.tenant_id,
                project_id=research_workspace.project_id,
                parent_digest=current_digest,
                sources=sources,
                retrieval_policy=retrieval_policy,
                created_at=moment,
            )
            document = model.as_dict()
            model = ResearchSourceSet.from_dict(document)
            digest = model.digest()
            for snapshot, snapshot_digest in snapshots:
                self._write_snapshot(workspace_id, snapshot, snapshot_digest)
            path = self.source_set_path(workspace_id, digest)
            self._ensure_directory(path.parent)
            payload = canonical_bytes(document) + b"\n"
            if path.is_symlink():
                raise ProtocolError(
                    "RESEARCH_SOURCE_SET_DIGEST_MISMATCH",
                    "immutable source-set path is a symlink",
                )
            if path.exists():
                if path.read_bytes() != payload:
                    raise ProtocolError(
                        "RESEARCH_SOURCE_SET_DIGEST_MISMATCH",
                        "immutable source-set path changed",
                    )
            else:
                atomic_write_bytes(path, payload)
            self._write_receipt(
                f"research-source-set-{digest}.json",
                "research-source-set-created",
                {
                    "workspace_id": workspace_id,
                    "source_set_digest": digest,
                    "source_set_path": path.relative_to(self.workspace.root).as_posix(),
                    "parent_digest": current_digest,
                },
                moment,
            )
            return {"source_set_digest": digest, "source_set": model}

    def verify_source_set(
        self, workspace_id: str, source_set_digest: str
    ) -> ResearchSourceSet:
        research_workspace = self.open_workspace(workspace_id)
        path = self.source_set_path(workspace_id, source_set_digest)
        if not path.exists() and not path.is_symlink():
            raise ProtocolError(
                "RESEARCH_SOURCE_SET_ABSENT", "research source-set is absent"
            )
        self._require_regular_file(path, code="RESEARCH_SOURCE_SET_DIGEST_MISMATCH")
        document = read_json(path)
        if document_digest(document) != source_set_digest:
            raise ProtocolError(
                "RESEARCH_SOURCE_SET_DIGEST_MISMATCH",
                "research source-set content changed",
            )
        model = ResearchSourceSet.from_dict(document)
        if (
            model.workspace_id != workspace_id
            or model.tenant_id != research_workspace.tenant_id
            or model.project_id != research_workspace.project_id
        ):
            raise ProtocolError(
                "RESEARCH_SOURCE_SET_SCOPE_MISMATCH",
                "research source-set scope changed",
            )
        for source in model.sources:
            snapshot_path = self._snapshot_path(
                workspace_id, source["source_record_digest"]
            )
            try:
                self._require_regular_file(
                    snapshot_path, code="RESEARCH_SOURCE_SNAPSHOT_MISMATCH"
                )
            except ProtocolError as exc:
                raise ProtocolError(
                    "RESEARCH_SOURCE_SNAPSHOT_MISMATCH",
                    "source record snapshot is absent",
                ) from exc
            snapshot = read_json(snapshot_path)
            if self.source_record_digest(snapshot) != source["source_record_digest"]:
                raise ProtocolError(
                    "RESEARCH_SOURCE_SNAPSHOT_MISMATCH",
                    "source record snapshot changed",
                )
            record = SourceRecord.from_dict(snapshot)
            if record.source_id != source["source_id"]:
                raise ProtocolError(
                    "RESEARCH_SOURCE_SNAPSHOT_MISMATCH",
                    "source record snapshot ID changed",
                )
            self._verify_record(record, research_workspace)
        return model

    def load_source_record_snapshot(
        self,
        workspace_id: str,
        source_record_digest: str,
    ) -> tuple[SourceRecord, dict[str, Any]]:
        if _SHA256.fullmatch(source_record_digest) is None:
            raise ProtocolError(
                "RESEARCH_SOURCE_SNAPSHOT_MISMATCH",
                "source record snapshot digest is invalid",
            )
        path = self._snapshot_path(workspace_id, source_record_digest)
        self._require_regular_file(
            path, code="RESEARCH_SOURCE_SNAPSHOT_MISMATCH"
        )
        document = read_json(path)
        if self.source_record_digest(document) != source_record_digest:
            raise ProtocolError(
                "RESEARCH_SOURCE_SNAPSHOT_MISMATCH",
                "source record snapshot changed",
            )
        record = SourceRecord.from_dict(document)
        research_workspace = self.open_workspace(workspace_id)
        self._verify_record(record, research_workspace)
        return record, document

    def _write_receipt(
        self, filename: str, kind: str, detail: dict[str, Any], recorded_at: str
    ) -> None:
        self._ensure_directory(self.workspace.receipts)
        receipt_id = str(uuid5(NAMESPACE_URL, f"{kind}:{document_digest(detail)}"))
        document = {
            "schema_version": "nukotech.hive-local.receipt.v1",
            "receipt_id": receipt_id,
            "kind": kind,
            "recorded_at": recorded_at,
            "detail": detail,
        }
        path = self.workspace.receipts / filename
        if path.is_symlink():
            raise ProtocolError(
                "RESEARCH_RECEIPT_MISMATCH", "research receipt is a symlink"
            )
        if path.exists():
            if read_json(path) != document:
                raise ProtocolError(
                    "RESEARCH_RECEIPT_MISMATCH", "research receipt changed"
                )
            return
        atomic_write_json(path, document)
