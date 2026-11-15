"""Deterministic, exact-source-set research export and verified reopen."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import shutil
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.capture.models import CaptureEnvelope
from hive_protocol.core import ProtocolError, canonical_bytes
from hive_protocol.product.workspace import ALPHA_VERSION, HiveWorkspace
from hive_protocol.storage import atomic_write_bytes, atomic_write_json, read_json

from .artifacts import ResearchArtifactStore
from .models import ResearchArtifact, ResearchSourceSet, ResearchWorkspace
from .workspace import BoundedResearchWorkspaceStore


ARCHIVE_ROOT = "hive-research-export"
MANIFEST_NAME = f"{ARCHIVE_ROOT}/manifest.json"
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_UNPACKED_BYTES = 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_MEMBERS = 20_000
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _json_bytes(document: Mapping[str, Any]) -> bytes:
    return canonical_bytes(document) + b"\n"


def _json_object(payload: bytes, *, code: str) -> dict[str, Any]:
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(code, "portable JSON document is invalid") from exc
    if not isinstance(document, dict):
        raise ProtocolError(code, "portable JSON document must be an object")
    return document


def _safe_relative(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or "\\" in value
        or any(ord(character) < 32 for character in value)
        or path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ProtocolError(
            "RESEARCH_BUNDLE_PATH", "research bundle path is not portable"
        )
    return value


def _add_payload(payloads: dict[str, bytes], relative: str, payload: bytes) -> None:
    relative = _safe_relative(relative)
    if len(payload) > MAX_MEMBER_BYTES:
        raise ProtocolError(
            "RESEARCH_BUNDLE_LIMIT", "research bundle member exceeds its size limit"
        )
    casefolded = relative.casefold()
    if relative in payloads or any(name.casefold() == casefolded for name in payloads):
        raise ProtocolError(
            "RESEARCH_BUNDLE_CASE_COLLISION",
            "research bundle paths collide on a case-insensitive filesystem",
        )
    payloads[relative] = payload


def _read_regular(root: Path, relative: str) -> bytes:
    relative = _safe_relative(relative)
    path = root.joinpath(*PurePosixPath(relative).parts)
    current = root
    for part in PurePosixPath(relative).parts:
        current /= part
        if current.is_symlink():
            raise ProtocolError(
                "RESEARCH_BUNDLE_SOURCE_BOUNDARY",
                "research bundle source path contains a symlink",
            )
    if not path.is_file() or path.stat().st_uid != os.geteuid():
        raise ProtocolError(
            "RESEARCH_BUNDLE_SOURCE_BOUNDARY",
            "research bundle source is not an owned regular file",
        )
    payload = path.read_bytes()
    if len(payload) > MAX_MEMBER_BYTES:
        raise ProtocolError(
            "RESEARCH_BUNDLE_LIMIT", "research bundle member exceeds its size limit"
        )
    return payload


def _tar_info(name: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = 0o644
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.type = tarfile.REGTYPE
    return info


@dataclass(frozen=True)
class ReopenedResearchWorkspace:
    workspace: HiveWorkspace
    workspace_id: str
    source_set_digest: str
    artifact_ids: tuple[str, ...]
    bundle_sha256: str


class ResearchPortableService:
    """Export and reopen one immutable research workspace source-set version."""

    def __init__(self, store: BoundedResearchWorkspaceStore) -> None:
        self.store = store

    @staticmethod
    def _relative(root: Path, path: Path) -> str:
        try:
            return path.relative_to(root).as_posix()
        except ValueError as exc:
            raise ProtocolError(
                "RESEARCH_BUNDLE_SOURCE_BOUNDARY",
                "research bundle source escapes the Hive root",
            ) from exc

    @staticmethod
    def _capture_paths(capture_id: str) -> tuple[str, str]:
        if not capture_id.startswith("capture:") or _SHA256.fullmatch(
            capture_id.removeprefix("capture:")
        ) is None:
            raise ProtocolError(
                "RESEARCH_BUNDLE_PROVENANCE_INVALID",
                "source record contains an invalid capture ID",
            )
        operation_key = capture_id.removeprefix("capture:")
        return (
            f"staging/captures/capture-{operation_key}.json",
            f".hive/receipts/capture-operation-{operation_key}.json",
        )

    @staticmethod
    def _research_receipt_paths(
        workspace_id: str, source_set_digest: str, artifact_ids: list[str]
    ) -> list[str]:
        slug = BoundedResearchWorkspaceStore._slug(workspace_id)
        paths = [
            f".hive/receipts/research-workspace-{slug}.json",
            f".hive/receipts/research-source-set-{source_set_digest}.json",
        ]
        paths.extend(
            f".hive/receipts/research-artifact-{artifact_id.removeprefix('artifact:')}.json"
            for artifact_id in artifact_ids
        )
        return paths

    def _selected_artifacts(
        self, workspace_id: str, source_set_digest: str
    ) -> list[ResearchArtifact]:
        verifier = ResearchArtifactStore(
            self.store,
            self.store.workspace.runtime / "portable-artifact-verifier",
            signing_key=Ed25519PrivateKey.generate(),
        )
        return verifier.list_artifacts(
            workspace_id, source_set_digest=source_set_digest
        )

    def _payloads(
        self, workspace_id: str, source_set_digest: str
    ) -> tuple[dict[str, bytes], ResearchWorkspace, ResearchSourceSet, list[str]]:
        workspace = self.store.open_workspace(workspace_id)
        source_set = self.store.verify_source_set(workspace_id, source_set_digest)
        root = self.store.workspace.root
        payloads: dict[str, bytes] = {}

        workspace_path = self.store.workspace_path(workspace_id)
        source_set_path = self.store.source_set_path(workspace_id, source_set_digest)
        _add_payload(
            payloads,
            self._relative(root, workspace_path),
            _read_regular(root, self._relative(root, workspace_path)),
        )
        _add_payload(
            payloads,
            self._relative(root, source_set_path),
            _read_regular(root, self._relative(root, source_set_path)),
        )

        for source in source_set.sources:
            record, document = self.store.load_source_record_snapshot(
                workspace_id, source["source_record_digest"]
            )
            snapshot_relative = (
                self.store.workspace_path(workspace_id).parent
                / "source-records"
                / f"{source['source_record_digest']}.json"
            ).relative_to(root).as_posix()
            snapshot_payload = _json_bytes(document)
            _add_payload(payloads, snapshot_relative, snapshot_payload)
            provenance_relative = (
                f".hive/provenance/source-{record.source_id.removeprefix('source:')}.json"
            )
            _add_payload(payloads, provenance_relative, snapshot_payload)
            for relative in (record.original_asset_path, record.normalized_text_path):
                if relative is None:
                    raise ProtocolError(
                        "RESEARCH_BUNDLE_PROVENANCE_INVALID",
                        "research source lacks normalized text",
                    )
                _add_payload(payloads, relative, _read_regular(root, relative))
            for capture_id in record.capture_ids:
                envelope_relative, receipt_relative = self._capture_paths(capture_id)
                envelope_payload = _read_regular(root, envelope_relative)
                envelope = CaptureEnvelope.from_dict(
                    _json_object(
                        envelope_payload, code="RESEARCH_BUNDLE_PROVENANCE_INVALID"
                    )
                )
                if (
                    envelope.capture_id != capture_id
                    or envelope.source_record_id != record.source_id
                    or envelope.original_sha256 != record.original_sha256
                    or envelope.tenant_id != workspace.tenant_id
                    or envelope.project_id != workspace.project_id
                ):
                    raise ProtocolError(
                        "RESEARCH_BUNDLE_PROVENANCE_INVALID",
                        "capture envelope does not match its source record",
                    )
                _add_payload(payloads, envelope_relative, envelope_payload)
                receipt_payload = _read_regular(root, receipt_relative)
                receipt = _json_object(
                    receipt_payload, code="RESEARCH_BUNDLE_PROVENANCE_INVALID"
                )
                if (
                    receipt.get("schema_version") != "hive.capture-receipt.v1"
                    or receipt.get("capture_id") != capture_id
                    or receipt.get("source_id") != record.source_id
                ):
                    raise ProtocolError(
                        "RESEARCH_BUNDLE_PROVENANCE_INVALID",
                        "capture receipt does not match its source record",
                    )
                _add_payload(payloads, receipt_relative, receipt_payload)

        artifacts = self._selected_artifacts(workspace_id, source_set_digest)
        artifact_ids = [artifact.artifact_id for artifact in artifacts]
        for artifact in artifacts:
            markdown_relative = artifact.markdown_path
            sidecar_relative = str(
                PurePosixPath(markdown_relative).with_suffix(".json")
            )
            _add_payload(
                payloads, markdown_relative, _read_regular(root, markdown_relative)
            )
            _add_payload(
                payloads, sidecar_relative, _read_regular(root, sidecar_relative)
            )
        for receipt_relative in self._research_receipt_paths(
            workspace_id, source_set_digest, artifact_ids
        ):
            _add_payload(
                payloads, receipt_relative, _read_regular(root, receipt_relative)
            )
        if sum(len(payload) for payload in payloads.values()) > MAX_UNPACKED_BYTES:
            raise ProtocolError(
                "RESEARCH_BUNDLE_LIMIT", "research bundle exceeds its unpacked limit"
            )
        return payloads, workspace, source_set, artifact_ids

    def export(
        self,
        *,
        workspace_id: str,
        source_set_digest: str,
        output: Path,
    ) -> dict[str, Any]:
        raw_output = output.expanduser()
        for candidate in [raw_output, *raw_output.parents]:
            if candidate.is_symlink():
                raise ProtocolError(
                    "RESEARCH_BUNDLE_OUTPUT_BOUNDARY",
                    "research bundle output path contains a symlink",
                )
        output = raw_output.resolve(strict=False)
        root = self.store.workspace.root
        if output == root or root in output.parents:
            raise ProtocolError(
                "RESEARCH_BUNDLE_OUTPUT_BOUNDARY",
                "research bundle output must be outside the source Hive",
            )
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.exists() and not output.is_file():
            raise ProtocolError(
                "RESEARCH_BUNDLE_OUTPUT_BOUNDARY",
                "research bundle output is not a regular file path",
            )
        payloads, workspace, source_set, artifact_ids = self._payloads(
            workspace_id, source_set_digest
        )
        entries = [
            {"path": relative, "sha256": _sha256(payload), "size_bytes": len(payload)}
            for relative, payload in sorted(payloads.items())
        ]
        manifest = {
            "schema_version": "hive.research-portable-export.v1",
            "product_version": ALPHA_VERSION,
            "workspace_id": workspace.workspace_id,
            "tenant_id": workspace.tenant_id,
            "project_id": workspace.project_id,
            "source_set_digest": source_set_digest,
            "artifact_ids": artifact_ids,
            "created_at": source_set.created_at,
            "files": entries,
        }
        manifest_payload = _json_bytes(manifest)
        if len(manifest_payload) > MAX_MANIFEST_BYTES:
            raise ProtocolError(
                "RESEARCH_BUNDLE_LIMIT", "research bundle manifest is too large"
            )
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            with temporary.open("wb") as raw:
                with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
                    with tarfile.open(
                        fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
                    ) as archive:
                        archive.addfile(
                            _tar_info(MANIFEST_NAME, len(manifest_payload)),
                            io.BytesIO(manifest_payload),
                        )
                        for relative, payload in sorted(payloads.items()):
                            name = f"{ARCHIVE_ROOT}/{relative}"
                            archive.addfile(
                                _tar_info(name, len(payload)), io.BytesIO(payload)
                            )
                raw.flush()
                os.fsync(raw.fileno())
            if temporary.stat().st_size > MAX_ARCHIVE_BYTES:
                raise ProtocolError(
                    "RESEARCH_BUNDLE_LIMIT", "research bundle exceeds its archive limit"
                )
            os.replace(temporary, output)
            directory_fd = os.open(output.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if temporary.exists():
                temporary.unlink()
        return {
            "outcome": "EXPORTED",
            "artifact": str(output),
            "sha256": _sha256(output.read_bytes()),
            "workspace_id": workspace_id,
            "source_set_digest": source_set_digest,
            "artifact_ids": artifact_ids,
            "files": len(entries),
        }

    @staticmethod
    def _archive_payloads(bundle: Path) -> tuple[dict[str, bytes], dict[str, Any]]:
        raw_bundle = bundle.expanduser()
        if raw_bundle.is_symlink() or not raw_bundle.is_file():
            raise ProtocolError(
                "RESEARCH_BUNDLE_INVALID", "research bundle is not a regular file"
            )
        bundle = raw_bundle.resolve()
        if bundle.stat().st_size > MAX_ARCHIVE_BYTES:
            raise ProtocolError(
                "RESEARCH_BUNDLE_LIMIT", "research bundle exceeds its archive limit"
            )
        try:
            archive = tarfile.open(bundle, "r:gz")
        except (OSError, tarfile.TarError) as exc:
            raise ProtocolError(
                "RESEARCH_BUNDLE_INVALID", "research bundle cannot be opened"
            ) from exc
        with archive:
            members = archive.getmembers()
            if len(members) > MAX_MEMBERS:
                raise ProtocolError(
                    "RESEARCH_BUNDLE_LIMIT", "research bundle has too many members"
                )
            names: set[str] = set()
            casefolded: set[str] = set()
            total = 0
            payloads: dict[str, bytes] = {}
            for member in members:
                if not member.isfile():
                    raise ProtocolError(
                        "RESEARCH_BUNDLE_MEMBER",
                        "research bundle accepts regular files only",
                    )
                name = _safe_relative(member.name)
                if name in names:
                    raise ProtocolError(
                        "RESEARCH_BUNDLE_DUPLICATE",
                        "research bundle contains a duplicate member",
                    )
                folded = name.casefold()
                if folded in casefolded:
                    raise ProtocolError(
                        "RESEARCH_BUNDLE_CASE_COLLISION",
                        "research bundle paths collide by case",
                    )
                path = PurePosixPath(name)
                if not path.parts or path.parts[0] != ARCHIVE_ROOT or len(path.parts) < 2:
                    raise ProtocolError(
                        "RESEARCH_BUNDLE_PATH", "research bundle member has the wrong root"
                    )
                names.add(name)
                casefolded.add(folded)
                if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                    raise ProtocolError(
                        "RESEARCH_BUNDLE_LIMIT", "research bundle member is oversized"
                    )
                total += member.size
                if total > MAX_UNPACKED_BYTES:
                    raise ProtocolError(
                        "RESEARCH_BUNDLE_LIMIT", "research bundle is oversized"
                    )
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ProtocolError(
                        "RESEARCH_BUNDLE_MEMBER", "research bundle member cannot be read"
                    )
                payload = extracted.read(member.size + 1)
                if len(payload) != member.size:
                    raise ProtocolError(
                        "RESEARCH_BUNDLE_MEMBER", "research bundle member size changed"
                    )
                payloads[name] = payload
        manifest_payload = payloads.get(MANIFEST_NAME)
        if manifest_payload is None:
            raise ProtocolError(
                "RESEARCH_BUNDLE_MANIFEST", "research bundle manifest is absent"
            )
        if len(manifest_payload) > MAX_MANIFEST_BYTES:
            raise ProtocolError(
                "RESEARCH_BUNDLE_LIMIT", "research bundle manifest is oversized"
            )
        try:
            manifest = json.loads(manifest_payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProtocolError(
                "RESEARCH_BUNDLE_MANIFEST", "research bundle manifest is invalid"
            ) from exc
        if not isinstance(manifest, dict):
            raise ProtocolError(
                "RESEARCH_BUNDLE_MANIFEST", "research bundle manifest is invalid"
            )
        return payloads, manifest

    @staticmethod
    def _validate_manifest(
        payloads: dict[str, bytes], manifest: dict[str, Any]
    ) -> dict[str, bytes]:
        if set(manifest) != {
            "schema_version",
            "product_version",
            "workspace_id",
            "tenant_id",
            "project_id",
            "source_set_digest",
            "artifact_ids",
            "created_at",
            "files",
        } or manifest.get("schema_version") != "hive.research-portable-export.v1":
            raise ProtocolError(
                "RESEARCH_BUNDLE_MANIFEST", "research bundle manifest shape is invalid"
            )
        if (
            manifest.get("product_version") != ALPHA_VERSION
            or
            _SAFE_ID.fullmatch(str(manifest.get("workspace_id", ""))) is None
            or _SAFE_ID.fullmatch(str(manifest.get("tenant_id", ""))) is None
            or _SAFE_ID.fullmatch(str(manifest.get("project_id", ""))) is None
            or _SHA256.fullmatch(str(manifest.get("source_set_digest", ""))) is None
            or not isinstance(manifest.get("artifact_ids"), list)
            or not isinstance(manifest.get("files"), list)
        ):
            raise ProtocolError(
                "RESEARCH_BUNDLE_MANIFEST", "research bundle manifest values are invalid"
            )
        artifact_ids = manifest["artifact_ids"]
        if (
            not all(
                isinstance(artifact_id, str)
                and artifact_id.startswith("artifact:")
                and _SHA256.fullmatch(artifact_id.removeprefix("artifact:")) is not None
                for artifact_id in artifact_ids
            )
            or artifact_ids != sorted(artifact_ids)
            or len(artifact_ids) != len(set(artifact_ids))
        ):
            raise ProtocolError(
                "RESEARCH_BUNDLE_MANIFEST", "research artifact inventory is noncanonical"
            )
        entries = manifest["files"]
        if not all(
            isinstance(entry, dict)
            and set(entry) == {"path", "sha256", "size_bytes"}
            and isinstance(entry.get("path"), str)
            and isinstance(entry.get("sha256"), str)
            and isinstance(entry.get("size_bytes"), int)
            and not isinstance(entry.get("size_bytes"), bool)
            for entry in entries
        ):
            raise ProtocolError(
                "RESEARCH_BUNDLE_MANIFEST", "research file inventory is invalid"
            )
        paths = [entry.get("path") for entry in entries]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ProtocolError(
                "RESEARCH_BUNDLE_MANIFEST", "research file inventory is noncanonical"
            )
        files = {
            name.removeprefix(f"{ARCHIVE_ROOT}/"): payload
            for name, payload in payloads.items()
            if name != MANIFEST_NAME
        }
        if set(files) != set(paths):
            raise ProtocolError(
                "RESEARCH_BUNDLE_FILE_SET",
                "research bundle files do not exactly match the manifest",
            )
        for entry in entries:
            relative = _safe_relative(entry["path"])
            payload = files[relative]
            if (
                not isinstance(entry["size_bytes"], int)
                or isinstance(entry["size_bytes"], bool)
                or entry["size_bytes"] != len(payload)
                or _SHA256.fullmatch(str(entry["sha256"])) is None
                or entry["sha256"] != _sha256(payload)
            ):
                raise ProtocolError(
                    "RESEARCH_BUNDLE_HASH",
                    "research bundle file failed size or digest verification",
                )
        return files

    @classmethod
    def _verify_staged(
        cls, workspace: HiveWorkspace, manifest: dict[str, Any], files: dict[str, bytes]
    ) -> None:
        store = BoundedResearchWorkspaceStore(workspace)
        workspace_id = manifest["workspace_id"]
        source_set_digest = manifest["source_set_digest"]
        research_workspace = store.open_workspace(workspace_id)
        source_set = store.verify_source_set(workspace_id, source_set_digest)
        if (
            research_workspace.tenant_id != manifest["tenant_id"]
            or research_workspace.project_id != manifest["project_id"]
            or source_set.tenant_id != manifest["tenant_id"]
            or source_set.project_id != manifest["project_id"]
            or source_set.created_at != manifest["created_at"]
        ):
            raise ProtocolError(
                "RESEARCH_BUNDLE_SCOPE", "research bundle scope changed"
            )
        expected: set[str] = {
            store.workspace_path(workspace_id).relative_to(workspace.root).as_posix(),
            store.source_set_path(workspace_id, source_set_digest)
            .relative_to(workspace.root)
            .as_posix(),
        }
        for source in source_set.sources:
            record, _ = store.load_source_record_snapshot(
                workspace_id, source["source_record_digest"]
            )
            expected.update(
                {
                    (
                        store.workspace_path(workspace_id).parent
                        / "source-records"
                        / f"{source['source_record_digest']}.json"
                    )
                    .relative_to(workspace.root)
                    .as_posix(),
                    f".hive/provenance/source-{record.source_id.removeprefix('source:')}.json",
                    record.original_asset_path,
                    str(record.normalized_text_path),
                }
            )
            provenance = read_json(
                workspace.provenance
                / f"source-{record.source_id.removeprefix('source:')}.json"
            )
            if store.source_record_digest(provenance) != source["source_record_digest"]:
                raise ProtocolError(
                    "RESEARCH_BUNDLE_PROVENANCE_INVALID",
                    "portable provenance differs from the source-set snapshot",
                )
            for capture_id in record.capture_ids:
                envelope_relative, receipt_relative = cls._capture_paths(capture_id)
                expected.update({envelope_relative, receipt_relative})
                envelope = CaptureEnvelope.from_dict(
                    read_json(workspace.root / envelope_relative)
                )
                receipt = read_json(workspace.root / receipt_relative)
                if (
                    envelope.source_record_id != record.source_id
                    or envelope.capture_id != capture_id
                    or receipt.get("capture_id") != capture_id
                    or receipt.get("source_id") != record.source_id
                ):
                    raise ProtocolError(
                        "RESEARCH_BUNDLE_PROVENANCE_INVALID",
                        "portable capture provenance changed",
                    )
        verifier = ResearchArtifactStore(
            store,
            workspace.runtime / "portable-artifact-verifier",
            signing_key=Ed25519PrivateKey.generate(),
        )
        artifact_ids = manifest["artifact_ids"]
        for artifact_id in artifact_ids:
            if (
                not isinstance(artifact_id, str)
                or not artifact_id.startswith("artifact:")
                or _SHA256.fullmatch(artifact_id.removeprefix("artifact:")) is None
            ):
                raise ProtocolError(
                    "RESEARCH_BUNDLE_MANIFEST", "research artifact ID is invalid"
                )
            artifact = verifier.verify_artifact(workspace_id, artifact_id)
            if artifact.source_set_digest != source_set_digest:
                raise ProtocolError(
                    "RESEARCH_BUNDLE_SCOPE", "artifact belongs to another source set"
                )
            expected.add(artifact.markdown_path)
            expected.add(str(PurePosixPath(artifact.markdown_path).with_suffix(".json")))
        research_receipts = cls._research_receipt_paths(
            workspace_id, source_set_digest, artifact_ids
        )
        expected.update(research_receipts)
        workspace_receipt = read_json(workspace.root / research_receipts[0])
        source_set_receipt = read_json(workspace.root / research_receipts[1])
        if (
            workspace_receipt.get("kind") != "research-workspace-created"
            or workspace_receipt.get("detail", {}).get("workspace_id") != workspace_id
            or source_set_receipt.get("kind") != "research-source-set-created"
            or source_set_receipt.get("detail", {}).get("workspace_id") != workspace_id
            or source_set_receipt.get("detail", {}).get("source_set_digest")
            != source_set_digest
        ):
            raise ProtocolError(
                "RESEARCH_BUNDLE_PROVENANCE_INVALID",
                "research workspace or source-set receipt changed",
            )
        for artifact_id, receipt_relative in zip(
            artifact_ids, research_receipts[2:], strict=True
        ):
            receipt = read_json(workspace.root / receipt_relative)
            detail = receipt.get("detail")
            if (
                receipt.get("kind") != "research-artifact-created"
                or not isinstance(detail, dict)
                or detail.get("artifact_id") != artifact_id
                or detail.get("workspace_id") != workspace_id
                or detail.get("source_set_digest") != source_set_digest
            ):
                raise ProtocolError(
                    "RESEARCH_BUNDLE_PROVENANCE_INVALID",
                    "research artifact receipt changed",
                )
        if expected != set(files):
            raise ProtocolError(
                "RESEARCH_BUNDLE_FILE_SET",
                "research bundle contains missing or unrelated portable files",
            )

    @classmethod
    def reopen(cls, bundle: Path, target: Path) -> ReopenedResearchWorkspace:
        payloads, manifest = cls._archive_payloads(bundle)
        files = cls._validate_manifest(payloads, manifest)
        raw_target = target.expanduser()
        for candidate in [raw_target, *raw_target.parents]:
            if candidate.is_symlink():
                raise ProtocolError(
                    "RESEARCH_REOPEN_TARGET_BOUNDARY",
                    "research reopen target path contains a symlink",
                )
        target = raw_target.resolve(strict=False)
        if target.exists() and (
            not target.is_dir() or any(target.iterdir())
        ):
            raise ProtocolError(
                "RESEARCH_REOPEN_TARGET_NOT_EMPTY",
                "research reopen target must be an empty directory",
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        staged = Path(
            tempfile.mkdtemp(prefix=f".{target.name}.research-reopen-", dir=target.parent)
        )
        try:
            workspace = HiveWorkspace(staged)
            for directory in (
                workspace.sources,
                workspace.assets,
                workspace.staging,
                workspace.research,
                workspace.provenance,
                workspace.receipts,
            ):
                directory.mkdir(parents=True, exist_ok=True)
            for relative, payload in sorted(files.items()):
                destination = staged.joinpath(*PurePosixPath(relative).parts)
                atomic_write_bytes(destination, payload)
            cls._verify_staged(workspace, manifest, files)
            config = {
                "schema_version": "nukotech.hive-local.config.v1",
                "product": "NukoTech Hive Local Alpha",
                "version": ALPHA_VERSION,
                "created_at": manifest["created_at"],
                "vault_path": str(target),
                "privacy_mode": "local-only",
                "tenant_id": manifest["tenant_id"],
                "project_id": manifest["project_id"],
                "provider": {"mode": "retrieval-only", "model": None},
            }
            atomic_write_json(workspace.config_path, config)
            atomic_write_bytes(
                staged / ".gitignore",
                (
                    ".hive/index.sqlite3\n"
                    ".hive/index.sqlite3-shm\n"
                    ".hive/index.sqlite3-wal\n"
                    ".hive/intelligence.sqlite3\n"
                    ".hive/intelligence.sqlite3-shm\n"
                    ".hive/intelligence.sqlite3-wal\n"
                    ".hive/keys/\n"
                    ".hive/runtime/\n"
                ).encode(),
            )
            if target.exists():
                target.rmdir()
            os.replace(staged, target)
            staged = Path()
        finally:
            if staged != Path() and staged.exists():
                shutil.rmtree(staged)
        reopened = HiveWorkspace.open(target)
        reopened.rebuild_index()
        bundle_sha256 = _sha256(bundle.expanduser().resolve().read_bytes())
        reopened._receipt(
            "research-export-reopened",
            {
                "bundle_sha256": bundle_sha256,
                "workspace_id": manifest["workspace_id"],
                "source_set_digest": manifest["source_set_digest"],
            },
        )
        return ReopenedResearchWorkspace(
            workspace=reopened,
            workspace_id=manifest["workspace_id"],
            source_set_digest=manifest["source_set_digest"],
            artifact_ids=tuple(manifest["artifact_ids"]),
            bundle_sha256=bundle_sha256,
        )
