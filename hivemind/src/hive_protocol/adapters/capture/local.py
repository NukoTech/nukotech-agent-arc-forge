"""Local-only text and file capture through the portable Hive workspace."""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import os
import re
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.adapters.lifecycle_state import LifecycleOperationStore
from hive_protocol.adapters.models import AdapterRequest
from hive_protocol.capture.admission import CaptureAdmissionService
from hive_protocol.capture.normalizers import NormalizerRegistry
from hive_protocol.core import (
    ProtocolError,
    document_digest,
    public_key_id,
    sign_document,
    verify_document,
)
from hive_protocol.product.workspace import HiveWorkspace
from hive_protocol.storage import (
    atomic_write_bytes,
    atomic_write_json,
    exclusive_lock,
    read_json,
)


CAPTURE_SIDE_EFFECTS = [
    "workspace:sources",
    "workspace:provenance",
    "workspace:receipt",
]
CAPTURE_M31_SIDE_EFFECTS = [
    "workspace:assets",
    "workspace:sources",
    "workspace:staging",
    "workspace:provenance",
    "workspace:receipt",
    "workspace:offline-provider-queue",
]
_M31_CAPABILITY_BY_KIND = {
    "markdown": "capture.markdown",
    "clipboard": "capture.clipboard",
    "webpage_snapshot": "capture.webpage-snapshot",
    "browser_handoff": "capture.browser-handoff",
    "pdf": "capture.pdf",
    "image": "capture.image",
    "audio": "capture.audio",
    "video": "capture.video",
    "meeting_recording": "capture.meeting-recording",
    "transcript": "capture.transcript",
    "folder_handoff": "capture.folder-handoff",
}
_M31_CHANNEL_BY_KIND = {
    "markdown": "MARKDOWN",
    "clipboard": "CLIPBOARD",
    "webpage_snapshot": "WEBPAGE_SNAPSHOT",
    "browser_handoff": "BROWSER_HANDOFF",
    "pdf": "PDF",
    "image": "IMAGE",
    "audio": "AUDIO",
    "video": "VIDEO",
    "meeting_recording": "MEETING_RECORDING",
    "transcript": "TRANSCRIPT",
}
_TEXT_SUFFIXES = frozenset({".md", ".markdown", ".txt"})
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_STABLE_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)
_ROLLBACK_DOCUMENT_KEYS = frozenset(
    {
        "schema_version",
        "operation_key",
        "payload_digest",
        "state",
        "deduplicated",
        "entries",
        "signature",
    }
)
_ROLLBACK_ENTRY_KEYS = frozenset(
    {
        "path",
        "before_sha256",
        "before_bytes_b64",
        "after_sha256",
        "restore_state",
    }
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class LocalCaptureAdapter:
    """Imports project-scoped local evidence without network or credential access."""

    def __init__(
        self,
        workspace: HiveWorkspace,
        staging_root: Path,
        *,
        state_signing_key: Ed25519PrivateKey,
        max_input_bytes: int = 10 * 1024 * 1024,
        normalizer_registry: NormalizerRegistry | None = None,
        tenant_id: str = "local-user",
        project_id: str = "HiveMind",
        privacy_class: str = "PROJECT_PRIVATE",
    ) -> None:
        raw_staging = staging_root.expanduser()
        for candidate in [raw_staging, *raw_staging.parents]:
            if candidate.is_symlink():
                raise ProtocolError(
                    "CAPTURE_STAGING_BOUNDARY",
                    "capture staging path may not contain symlinks",
                )
        self.workspace = workspace
        self.staging_root = raw_staging.resolve(strict=False)
        if (
            self.staging_root == workspace.root
            or workspace.root in self.staging_root.parents
        ):
            raise ProtocolError(
                "CAPTURE_STAGING_BOUNDARY",
                "capture staging must remain outside the destination Hive",
            )
        if max_input_bytes < 1:
            raise ValueError("max_input_bytes must be positive")
        self.max_input_bytes = max_input_bytes
        self.state_signing_key = state_signing_key
        self.tenant_id = tenant_id
        self.project_id = project_id
        self.privacy_class = privacy_class
        self.state_key_id = public_key_id(state_signing_key.public_key())
        self.trusted_state_keys = {
            self.state_key_id: state_signing_key.public_key()
        }
        self.lifecycle_operations = LifecycleOperationStore(
            self.staging_root / "lifecycle-operations",
            "nukotech.hive.local-capture",
            signing_key=state_signing_key,
            trusted_state_keys=self.trusted_state_keys,
        )
        self.admission = CaptureAdmissionService(
            workspace,
            self.staging_root / "admission-operations",
            registry=normalizer_registry or NormalizerRegistry(),
            signing_key=state_signing_key,
        )

    def _write_state_record(self, path: Path, document: dict[str, Any]) -> None:
        signed = sign_document(document, self.state_signing_key)
        verify_document(signed, self.trusted_state_keys)
        atomic_write_json(path, signed, mode=0o600)

    def _read_state_record(self, path: Path, *, code: str) -> dict[str, Any]:
        try:
            document = read_json(path)
            verify_document(document, self.trusted_state_keys)
            signature = document.get("signature")
            if (
                not isinstance(signature, dict)
                or signature.get("key_id") != self.state_key_id
            ):
                raise ProtocolError(code, "capture state signer changed")
            return document
        except ProtocolError as exc:
            if exc.code == code:
                raise
            raise ProtocolError(code, "capture state record is not authentic") from exc

    def _ensure_staging(self) -> None:
        if self.staging_root.is_symlink():
            raise ProtocolError(
                "CAPTURE_STAGING_BOUNDARY", "capture staging root is a symlink"
            )
        self.staging_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if (
            self.staging_root.is_symlink()
            or not self.staging_root.is_dir()
            or self.staging_root.resolve() != self.staging_root
        ):
            raise ProtocolError(
                "CAPTURE_STAGING_BOUNDARY", "capture staging root changed identity"
            )
        os.chmod(self.staging_root, 0o700)

    def _workspace_lock_path(self) -> Path:
        self._ensure_staging()
        path = self.staging_root / "workspace.lock"
        if path.is_symlink():
            raise ProtocolError(
                "CAPTURE_STAGING_BOUNDARY", "capture workspace lock is a symlink"
            )
        return path

    def _operation_path(self, operation_key: str) -> Path:
        if not re.fullmatch(r"[0-9a-f]{64}", operation_key):
            raise ProtocolError(
                "ADAPTER_OPERATION_KEY_INVALID",
                "capture operation key must be an exact SHA-256",
            )
        self._ensure_staging()
        operations = self.staging_root / "operations"
        if operations.is_symlink():
            raise ProtocolError(
                "CAPTURE_STAGING_BOUNDARY", "capture operations root is a symlink"
            )
        operations.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(operations, 0o700)
        return operations / f"{operation_key}.json"

    def _begin_operation(
        self, operation_key: str, payload: dict[str, Any]
    ) -> dict[str, Any] | None:
        path = self._operation_path(operation_key)
        payload_digest = document_digest(payload)
        if path.exists():
            document = self._read_state_record(
                path, code="ADAPTER_OPERATION_KEY_MISMATCH"
            )
            if (
                set(document)
                != {
                    "schema_version",
                    "operation_key",
                    "payload_digest",
                    "state",
                    "result",
                    "signature",
                }
                or
                document.get("schema_version") != "hive.capture-operation.v1"
                or document.get("operation_key") != operation_key
                or document.get("payload_digest") != payload_digest
                or document.get("state") not in {"PREPARED", "TERMINAL"}
                or (
                    document.get("state") == "TERMINAL"
                    and not isinstance(document.get("result"), dict)
                )
            ):
                raise ProtocolError(
                    "ADAPTER_OPERATION_KEY_MISMATCH",
                    "capture operation record does not match its payload",
                )
            return (
                copy.deepcopy(document["result"])
                if document["state"] == "TERMINAL"
                else None
            )
        self._write_state_record(
            path,
            {
                "schema_version": "hive.capture-operation.v1",
                "operation_key": operation_key,
                "payload_digest": payload_digest,
                "state": "PREPARED",
                "result": None,
            },
        )
        return None

    def _finish_operation(
        self, operation_key: str, payload: dict[str, Any], result: dict[str, Any]
    ) -> None:
        self._write_state_record(
            self._operation_path(operation_key),
            {
                "schema_version": "hive.capture-operation.v1",
                "operation_key": operation_key,
                "payload_digest": document_digest(payload),
                "state": "TERMINAL",
                "result": copy.deepcopy(result),
            },
        )

    def recover(self, operation_key: str) -> dict[str, Any] | None:
        path = self._operation_path(operation_key)
        if not path.exists():
            return None
        document = self._read_state_record(
            path, code="ADAPTER_OPERATION_KEY_MISMATCH"
        )
        if (
            set(document)
            != {
                "schema_version",
                "operation_key",
                "payload_digest",
                "state",
                "result",
                "signature",
            }
            or
            document.get("schema_version") != "hive.capture-operation.v1"
            or document.get("operation_key") != operation_key
            or document.get("state") not in {"PREPARED", "TERMINAL"}
        ):
            raise ProtocolError(
                "ADAPTER_OPERATION_KEY_MISMATCH",
                "capture recovery record is invalid",
            )
        if document["state"] == "PREPARED":
            return None
        result = document.get("result")
        if not isinstance(result, dict):
            raise ProtocolError(
                "ADAPTER_OPERATION_KEY_MISMATCH",
                "capture recovery result is invalid",
            )
        return copy.deepcopy(result)

    def _rollback_path(self, operation_key: str) -> Path:
        if not re.fullmatch(r"[0-9a-f]{64}", operation_key):
            raise ProtocolError(
                "CAPTURE_ROLLBACK_REFUSED",
                "capture rollback key must be an exact SHA-256",
            )
        self._ensure_staging()
        root = self.staging_root / "rollback"
        if root.is_symlink():
            raise ProtocolError(
                "CAPTURE_STAGING_BOUNDARY", "capture rollback root is a symlink"
            )
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(root, 0o700)
        return root / f"{operation_key}.json"

    def _expected_workspace_targets(self, source: Path) -> tuple[Path, Path]:
        digest = _sha256_file(source)
        stable_id = uuid5(NAMESPACE_URL, f"nukotech-hive:{source.name}:{digest}")
        destination = self.workspace.sources / str(stable_id) / source.name
        provenance = self.workspace.provenance / f"{stable_id}.json"
        return destination, provenance

    def _rollback_entry(self, target: Path) -> dict[str, Any]:
        resolved_parent = target.parent.resolve(strict=False)
        allowed_roots = {self.workspace.sources, self.workspace.provenance}
        if target.is_symlink() or not any(
            root == resolved_parent or root in resolved_parent.parents
            for root in allowed_roots
        ):
            raise ProtocolError(
                "CAPTURE_ROLLBACK_BOUNDARY",
                "capture rollback target is outside portable source ownership",
            )
        if target.exists() and not target.is_file():
            raise ProtocolError(
                "CAPTURE_ROLLBACK_BOUNDARY",
                "capture rollback target must be a regular file",
            )
        before = target.read_bytes() if target.exists() else None
        return {
            "path": target.relative_to(self.workspace.root).as_posix(),
            "before_sha256": (
                hashlib.sha256(before).hexdigest() if before is not None else None
            ),
            "before_bytes_b64": (
                base64.b64encode(before).decode("ascii") if before is not None else None
            ),
            "after_sha256": None,
            "restore_state": "PENDING",
        }

    def _bounded_rollback_target(self, raw_relative: Any) -> Path:
        if not isinstance(raw_relative, str) or not raw_relative:
            raise ProtocolError(
                "CAPTURE_ROLLBACK_MISMATCH",
                "capture rollback path must be an exact relative path",
            )
        relative = PurePosixPath(raw_relative)
        if (
            relative.is_absolute()
            or relative.as_posix() != raw_relative
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise ProtocolError(
                "CAPTURE_ROLLBACK_MISMATCH",
                "capture rollback path is not canonical",
            )
        parts = relative.parts
        if len(parts) == 3 and parts[0] == "sources":
            stable_id = parts[1]
            allowed_root = self.workspace.sources
        elif len(parts) == 3 and parts[:2] == (".hive", "provenance"):
            stable_id = parts[2].removesuffix(".json")
            if parts[2] != f"{stable_id}.json":
                raise ProtocolError(
                    "CAPTURE_ROLLBACK_MISMATCH",
                    "capture provenance rollback path is malformed",
                )
            allowed_root = self.workspace.provenance
        else:
            raise ProtocolError(
                "CAPTURE_ROLLBACK_MISMATCH",
                "capture rollback path exceeds portable source ownership",
            )
        if _STABLE_ID_RE.fullmatch(stable_id) is None:
            raise ProtocolError(
                "CAPTURE_ROLLBACK_MISMATCH",
                "capture rollback stable identifier is malformed",
            )

        target = self.workspace.root.joinpath(*parts)
        current = self.workspace.root
        for part in parts[:-1]:
            current /= part
            if current.is_symlink():
                raise ProtocolError(
                    "CAPTURE_ROLLBACK_MISMATCH",
                    "capture rollback path contains a symlink",
                )
        if target.is_symlink():
            raise ProtocolError(
                "CAPTURE_ROLLBACK_MISMATCH",
                "capture rollback target may not be a symlink",
            )
        resolved_parent = target.parent.resolve(strict=False)
        if resolved_parent != allowed_root and allowed_root not in resolved_parent.parents:
            raise ProtocolError(
                "CAPTURE_ROLLBACK_MISMATCH",
                "capture rollback path escapes its owned root",
            )
        return target

    def _validate_rollback_document(
        self,
        operation_key: str,
        document: Any,
        *,
        allowed_states: frozenset[str],
    ) -> list[tuple[dict[str, Any], Path, bytes | None]]:
        if (
            not isinstance(document, dict)
            or set(document) != _ROLLBACK_DOCUMENT_KEYS
            or document.get("schema_version") != "hive.capture-rollback.v1"
            or document.get("operation_key") != operation_key
            or _SHA256_RE.fullmatch(str(document.get("payload_digest"))) is None
            or document.get("state") not in allowed_states
            or not isinstance(document.get("deduplicated"), bool)
            or not isinstance(document.get("entries"), list)
            or len(document["entries"]) != 2
        ):
            raise ProtocolError(
                "CAPTURE_ROLLBACK_MISMATCH",
                "capture rollback record is invalid",
            )

        validated: list[tuple[dict[str, Any], Path, bytes | None]] = []
        seen_paths: set[str] = set()
        stable_ids: set[str] = set()
        for entry in document["entries"]:
            if (
                not isinstance(entry, dict)
                or set(entry) != _ROLLBACK_ENTRY_KEYS
                or entry.get("restore_state")
                not in {"PENDING", "RESTORING", "RESTORED"}
            ):
                raise ProtocolError(
                    "CAPTURE_ROLLBACK_MISMATCH",
                    "capture rollback entry is invalid",
                )
            raw_relative = entry.get("path")
            target = self._bounded_rollback_target(raw_relative)
            if raw_relative in seen_paths:
                raise ProtocolError(
                    "CAPTURE_ROLLBACK_MISMATCH",
                    "capture rollback paths must be unique",
                )
            seen_paths.add(raw_relative)
            parts = PurePosixPath(raw_relative).parts
            stable_ids.add(
                parts[1] if parts[0] == "sources" else parts[2].removesuffix(".json")
            )

            before_sha256 = entry.get("before_sha256")
            encoded = entry.get("before_bytes_b64")
            if before_sha256 is None:
                if encoded is not None:
                    raise ProtocolError(
                        "CAPTURE_ROLLBACK_MISMATCH",
                        "capture rollback prior bytes lack a digest",
                    )
                before = None
            elif (
                not isinstance(before_sha256, str)
                or _SHA256_RE.fullmatch(before_sha256) is None
                or not isinstance(encoded, str)
            ):
                raise ProtocolError(
                    "CAPTURE_ROLLBACK_MISMATCH",
                    "capture rollback prior state is invalid",
                )
            else:
                try:
                    before = base64.b64decode(encoded, validate=True)
                except (ValueError, binascii.Error) as exc:
                    raise ProtocolError(
                        "CAPTURE_ROLLBACK_MISMATCH",
                        "capture rollback prior bytes are invalid",
                    ) from exc
                if hashlib.sha256(before).hexdigest() != before_sha256:
                    raise ProtocolError(
                        "CAPTURE_ROLLBACK_MISMATCH",
                        "capture rollback prior bytes do not match their digest",
                    )

            after_sha256 = entry.get("after_sha256")
            if document["state"] == "PREPARED":
                if after_sha256 is not None or entry["restore_state"] != "PENDING":
                    raise ProtocolError(
                        "CAPTURE_ROLLBACK_MISMATCH",
                        "prepared capture rollback contains applied state",
                    )
            elif (
                not isinstance(after_sha256, str)
                or _SHA256_RE.fullmatch(after_sha256) is None
            ):
                raise ProtocolError(
                    "CAPTURE_ROLLBACK_MISMATCH",
                    "applied capture rollback lacks an exact result digest",
                )
            validated.append((entry, target, before))

        path_kinds = [
            "source" if PurePosixPath(path).parts[0] == "sources" else "provenance"
            for path in (entry["path"] for entry in document["entries"])
        ]
        if path_kinds != ["source", "provenance"] or len(stable_ids) != 1:
            raise ProtocolError(
                "CAPTURE_ROLLBACK_MISMATCH",
                "capture rollback must bind one source and its provenance",
            )
        if document["deduplicated"] != (
            document["entries"][0]["before_sha256"] is not None
        ):
            raise ProtocolError(
                "CAPTURE_ROLLBACK_MISMATCH",
                "capture rollback deduplication state is inconsistent",
            )
        if document["state"] == "APPLIED" and any(
            entry["restore_state"] != "PENDING" for entry, _, _ in validated
        ):
            raise ProtocolError(
                "CAPTURE_ROLLBACK_MISMATCH",
                "applied capture rollback contains restored entries",
            )
        if document["state"] == "ROLLED_BACK" and not all(
            entry["restore_state"] == "RESTORED" for entry, _, _ in validated
        ):
            raise ProtocolError(
                "CAPTURE_ROLLBACK_MISMATCH",
                "completed capture rollback contains pending entries",
            )
        return validated

    def _prepare_rollback(
        self, operation_key: str, payload: dict[str, Any], source: Path
    ) -> dict[str, Any]:
        path = self._rollback_path(operation_key)
        targets = self._expected_workspace_targets(source)
        expected_paths = [
            target.relative_to(self.workspace.root).as_posix() for target in targets
        ]
        if path.exists():
            document = self._read_state_record(
                path, code="CAPTURE_ROLLBACK_MISMATCH"
            )
            self._validate_rollback_document(
                operation_key,
                document,
                allowed_states=frozenset(
                    {"PREPARED", "APPLIED", "ROLLING_BACK", "ROLLED_BACK"}
                ),
            )
            if (
                document.get("payload_digest") != document_digest(payload)
                or [entry["path"] for entry in document["entries"]] != expected_paths
            ):
                raise ProtocolError(
                    "CAPTURE_ROLLBACK_MISMATCH",
                    "capture rollback record does not match the exact operation",
                )
            return document
        entries = [self._rollback_entry(target) for target in targets]
        document = {
            "schema_version": "hive.capture-rollback.v1",
            "operation_key": operation_key,
            "payload_digest": document_digest(payload),
            "state": "PREPARED",
            "deduplicated": entries[0]["before_sha256"] is not None,
            "entries": entries,
        }
        self._write_state_record(path, document)
        return self._read_state_record(path, code="CAPTURE_ROLLBACK_MISMATCH")

    def _finish_rollback_record(
        self, operation_key: str, document: dict[str, Any]
    ) -> None:
        validated = self._validate_rollback_document(
            operation_key, document, allowed_states=frozenset({"PREPARED"})
        )
        for entry, target, _ in validated:
            if target.is_symlink() or not target.is_file():
                raise ProtocolError(
                    "CAPTURE_ROLLBACK_MISMATCH",
                    "captured portable target is missing after import",
                )
            entry["after_sha256"] = _sha256_file(target)
        document["state"] = "APPLIED"
        self._write_state_record(self._rollback_path(operation_key), document)

    def _external_file(self, raw_path: Any) -> Path:
        if not isinstance(raw_path, str) or not raw_path:
            raise ProtocolError(
                "CAPTURE_PAYLOAD_INVALID", "file capture requires an exact path string"
            )
        candidate = Path(raw_path).expanduser()
        if not candidate.is_absolute() or ".." in candidate.parts:
            raise ProtocolError(
                "CAPTURE_SOURCE_BOUNDARY",
                "capture source must be an absolute canonical path",
            )
        current = Path(candidate.anchor)
        for part in candidate.parts[1:]:
            current /= part
            if current.is_symlink():
                raise ProtocolError(
                    "CAPTURE_SOURCE_BOUNDARY",
                    "capture source path may not contain symlinks",
                )
        resolved = candidate.resolve(strict=True)
        if str(resolved) != raw_path or not resolved.is_file():
            raise ProtocolError(
                "CAPTURE_SOURCE_BOUNDARY",
                "capture source must be an exact regular file",
            )
        if resolved == self.workspace.root or self.workspace.root in resolved.parents:
            raise ProtocolError(
                "CAPTURE_SOURCE_BOUNDARY",
                "capture source must remain outside the destination Hive",
            )
        if resolved.suffix.lower() not in _TEXT_SUFFIXES:
            raise ProtocolError(
                "CAPTURE_SOURCE_TYPE_DENIED",
                "capture file must be UTF-8 Markdown or text",
            )
        if resolved.stat().st_size > self.max_input_bytes:
            raise ProtocolError(
                "ADAPTER_INPUT_LIMIT_EXCEEDED",
                "capture file exceeds the adapter input limit",
            )
        return resolved

    def _validate_capture(
        self, payload: Any, *, allow_planned_binding: bool = False
    ) -> tuple[str, bytes | Path, str | None]:
        if not isinstance(payload, dict):
            raise ProtocolError(
                "CAPTURE_PAYLOAD_INVALID", "capture payload must be an object"
            )
        kind = payload.get("kind")
        if kind == "text" and set(payload) == {"kind", "text", "title"}:
            text = payload["text"]
            title = payload["title"]
            if (
                not isinstance(text, str)
                or not text
                or not isinstance(title, str)
                or not title.strip()
                or len(title) > 256
            ):
                raise ProtocolError(
                    "CAPTURE_PAYLOAD_INVALID",
                    "text capture requires non-empty text and title",
                )
            encoded = text.encode("utf-8")
            if len(encoded) > self.max_input_bytes:
                raise ProtocolError(
                    "ADAPTER_INPUT_LIMIT_EXCEEDED",
                    "capture text exceeds the adapter input limit",
                )
            return kind, encoded, title.strip()
        if kind == "file" and (
            set(payload) == {"kind", "path"}
            or (
                allow_planned_binding
                and set(payload) == {"kind", "path", "sha256", "size_bytes"}
            )
        ):
            source = self._external_file(payload["path"])
            if allow_planned_binding and (
                payload.get("sha256") != _sha256_file(source)
                or payload.get("size_bytes") != source.stat().st_size
            ):
                raise ProtocolError(
                    "CAPTURE_SOURCE_DIGEST_MISMATCH",
                    "capture source changed after the signed plan was created",
                )
            return kind, source, None
        raise ProtocolError(
            "CAPTURE_PAYLOAD_INVALID",
            "capture accepts only exact text or file payloads",
        )

    def _m31_external_path(self, raw_path: Any) -> Path:
        if not isinstance(raw_path, str) or not raw_path:
            raise ProtocolError(
                "CAPTURE_PAYLOAD_INVALID", "capture path must be an exact string"
            )
        candidate = Path(raw_path).expanduser()
        if not candidate.is_absolute() or ".." in candidate.parts:
            raise ProtocolError(
                "CAPTURE_SOURCE_BOUNDARY",
                "capture source must be an absolute canonical path",
            )
        current = Path(candidate.anchor)
        for part in candidate.parts[1:]:
            current /= part
            if current.is_symlink():
                raise ProtocolError(
                    "CAPTURE_SOURCE_BOUNDARY",
                    "capture source path may not contain symlinks",
                )
        resolved = candidate.resolve(strict=True)
        if (
            str(resolved) != raw_path
            or not resolved.is_file()
            or resolved.stat().st_uid != os.geteuid()
            or resolved == self.workspace.root
            or self.workspace.root in resolved.parents
        ):
            raise ProtocolError(
                "CAPTURE_SOURCE_BOUNDARY",
                "capture source must be one owned external regular file",
            )
        if resolved.stat().st_size > self.max_input_bytes:
            raise ProtocolError(
                "ADAPTER_INPUT_LIMIT_EXCEEDED",
                "capture file exceeds the adapter input limit",
            )
        return resolved

    def _m31_admission_plans(self, payload: Any) -> list[dict[str, Any]]:
        if not isinstance(payload, dict):
            raise ProtocolError(
                "CAPTURE_PAYLOAD_INVALID", "capture payload must be an object"
            )
        kind = payload.get("kind")
        requests: list[tuple[Path | bytes, str, str, str]] = []
        if kind in {"markdown", "clipboard"} and set(payload) == {
            "kind",
            "text",
            "title",
        }:
            text = payload["text"]
            title = payload["title"]
            if (
                not isinstance(text, str)
                or not text
                or not isinstance(title, str)
                or not title.strip()
                or len(title) > 256
            ):
                raise ProtocolError(
                    "CAPTURE_PAYLOAD_INVALID",
                    "inline capture requires non-empty text and title",
                )
            encoded = text.encode("utf-8")
            digest = hashlib.sha256(encoded).hexdigest()
            suffix = ".md" if kind == "markdown" else ".txt"
            media_type = "text/markdown" if kind == "markdown" else "text/plain"
            requests.append(
                (encoded, _M31_CHANNEL_BY_KIND[kind], media_type, f"capture-{digest}{suffix}")
            )
        elif kind in _M31_CHANNEL_BY_KIND and kind not in {"markdown", "clipboard"}:
            if set(payload) != {"kind", "path", "media_type"}:
                raise ProtocolError(
                    "CAPTURE_PAYLOAD_INVALID", "typed capture path shape is invalid"
                )
            source = self._m31_external_path(payload["path"])
            requests.append(
                (source, _M31_CHANNEL_BY_KIND[kind], payload["media_type"], source.name)
            )
        elif kind == "file" and set(payload) == {
            "kind",
            "path",
            "media_type",
            "channel",
        }:
            if payload["channel"] != "FILE":
                raise ProtocolError(
                    "ADAPTER_CAPABILITY_PAYLOAD_MISMATCH",
                    "generic file capability cannot authorize another capture channel",
                )
            source = self._m31_external_path(payload["path"])
            requests.append((source, payload["channel"], payload["media_type"], source.name))
        elif kind == "folder_handoff" and set(payload) == {"kind", "items"}:
            items = payload["items"]
            if not isinstance(items, list) or not items or len(items) > 64:
                raise ProtocolError(
                    "CAPTURE_PAYLOAD_INVALID",
                    "folder handoff requires one to 64 exact items",
                )
            seen: set[str] = set()
            for item in items:
                if not isinstance(item, dict) or set(item) != {
                    "path",
                    "channel",
                    "media_type",
                }:
                    raise ProtocolError(
                        "CAPTURE_PAYLOAD_INVALID", "folder handoff item is invalid"
                    )
                source = self._m31_external_path(item["path"])
                if str(source) in seen:
                    raise ProtocolError(
                        "CAPTURE_PAYLOAD_INVALID", "folder handoff paths must be unique"
                    )
                seen.add(str(source))
                requests.append((source, item["channel"], item["media_type"], source.name))
        else:
            raise ProtocolError(
                "CAPTURE_PAYLOAD_INVALID", "M3.1 capture payload shape is invalid"
            )

        plans: list[dict[str, Any]] = []
        total_bytes = 0
        for source, channel, media_type, filename in requests:
            common = {
                "tenant_id": self.tenant_id,
                "project_id": self.project_id,
                "privacy_class": self.privacy_class,
                "channel": channel,
                "source_owner": "attended-local-operator",
                "rights_assertion": "USER_PROVIDED",
                "media_type": media_type,
                "destination": "STAGING",
            }
            if isinstance(source, bytes):
                plan = self.admission.plan_bytes(source, filename=filename, **common)
            else:
                plan = self.admission.plan_path(source, **common)
            total_bytes += plan["original_size_bytes"]
            plans.append(plan)
        if total_bytes > self.max_input_bytes:
            raise ProtocolError(
                "ADAPTER_INPUT_LIMIT_EXCEEDED",
                "capture batch exceeds the adapter input limit",
            )
        return plans

    def health(self) -> dict[str, Any]:
        opened = HiveWorkspace.open(self.workspace.root)
        config = read_json(opened.config_path)
        if config["privacy_mode"] != "local-only":
            raise ProtocolError(
                "CAPTURE_PRIVACY_DENIED", "capture requires a local-only Hive"
            )
        self._ensure_staging()
        probe = self.staging_root / ".health-probe"
        descriptor = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, b"local-only\n")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
            if probe.is_file() and not probe.is_symlink():
                probe.unlink()
        return {
            "status": "HEALTHY",
            "evidence": [
                {"privacy_mode": "local-only"},
                {"staging_root": str(self.staging_root), "writable": True},
            ],
        }

    def validate_request(self, request: AdapterRequest) -> None:
        expected = {
            "text": "capture.text",
            "file": "capture.file",
            **_M31_CAPABILITY_BY_KIND,
        }.get(request.payload.get("kind"))
        if request.payload.get("kind") == "file" and set(request.payload) == {
            "kind",
            "path",
            "media_type",
            "channel",
        }:
            expected = "capture.file"
        if expected is not None and request.capability_id != expected:
            raise ProtocolError(
                "ADAPTER_CAPABILITY_PAYLOAD_MISMATCH",
                "capture payload kind exceeds the signed capability",
            )

    def validate_evidence(self, request: AdapterRequest) -> None:
        if request.payload.get("kind") in _M31_CAPABILITY_BY_KIND or (
            request.payload.get("kind") == "file"
            and set(request.payload) == {"kind", "path", "media_type", "channel"}
        ):
            digests = [
                plan["original_sha256"]
                for plan in self._m31_admission_plans(request.payload)
            ]
            if request.evidence_sha256 != digests:
                raise ProtocolError(
                    "ADAPTER_EVIDENCE_MISMATCH",
                    "capture evidence digests do not match the exact source bytes",
                )
            return
        kind, source, _ = self._validate_capture(request.payload)
        if kind == "text":
            if not isinstance(source, bytes):
                raise ProtocolError(
                    "CAPTURE_INTERNAL_STATE_INVALID",
                    "validated text evidence did not produce bytes",
                )
            digest = hashlib.sha256(source).hexdigest()
        else:
            if not isinstance(source, Path):
                raise ProtocolError(
                    "CAPTURE_INTERNAL_STATE_INVALID",
                    "validated file evidence did not produce a path",
                )
            digest = _sha256_file(source)
        if request.evidence_sha256 != [digest]:
            raise ProtocolError(
                "ADAPTER_EVIDENCE_MISMATCH",
                "capture evidence digest does not match the exact source bytes",
            )

    def plan(self, payload: dict[str, Any]) -> dict[str, Any]:
        if payload.get("kind") in _M31_CAPABILITY_BY_KIND or (
            payload.get("kind") == "file"
            and set(payload) == {"kind", "path", "media_type", "channel"}
        ):
            admission_plans = self._m31_admission_plans(payload)
            return {
                "side_effects": list(CAPTURE_M31_SIDE_EFFECTS),
                "network_destinations": [],
                "requires_approval": False,
                "payload": {
                    "kind": "m31_capture",
                    "request_kind": payload["kind"],
                    "admission_plans": admission_plans,
                },
            }
        kind, source, _ = self._validate_capture(payload)
        planned_payload = copy.deepcopy(payload)
        if kind == "file":
            if not isinstance(source, Path):
                raise ProtocolError(
                    "CAPTURE_INTERNAL_STATE_INVALID",
                    "validated file capture did not produce a source path",
                )
            planned_payload["sha256"] = _sha256_file(source)
            planned_payload["size_bytes"] = source.stat().st_size
        return {
            "side_effects": list(CAPTURE_SIDE_EFFECTS),
            "network_destinations": [],
            "requires_approval": False,
            "payload": json.loads(json.dumps(planned_payload)),
        }

    def apply(
        self, payload: dict[str, Any], *, operation_key: str
    ) -> dict[str, Any]:
        with exclusive_lock(self._workspace_lock_path()):
            return self._apply_locked(payload, operation_key=operation_key)

    def _apply_locked(
        self, payload: dict[str, Any], *, operation_key: str
    ) -> dict[str, Any]:
        if isinstance(payload, dict) and payload.get("kind") == "m31_capture":
            return self._apply_m31_locked(payload, operation_key=operation_key)
        existing = self._begin_operation(operation_key, payload)
        if existing is not None:
            return existing
        kind, source_value, title = self._validate_capture(
            payload, allow_planned_binding=True
        )
        temporary: Path | None = None
        if kind == "text":
            self._ensure_staging()
            if not isinstance(source_value, bytes) or title is None:
                raise ProtocolError(
                    "CAPTURE_INTERNAL_STATE_INVALID",
                    "validated text capture did not produce bytes and a title",
                )
            digest = hashlib.sha256(source_value).hexdigest()
            temporary = self.staging_root / f"{digest}.md"
            if temporary.exists() or temporary.is_symlink():
                if temporary.is_symlink() or _sha256_file(temporary) != digest:
                    raise ProtocolError(
                        "CAPTURE_STAGING_BOUNDARY",
                        "capture staging target is occupied or altered",
                    )
            else:
                atomic_write_bytes(temporary, source_value, mode=0o600)
            source = temporary
            input_bytes = len(source_value)
        else:
            if not isinstance(source_value, Path):
                raise ProtocolError(
                    "CAPTURE_INTERNAL_STATE_INVALID",
                    "validated file capture did not produce a source path",
                )
            source = source_value
            input_bytes = source.stat().st_size

        rollback_record = self._prepare_rollback(operation_key, payload, source)
        try:
            imported = self.workspace.import_content(
                source, operation_id=operation_key
            )
            self._finish_rollback_record(operation_key, rollback_record)
        finally:
            if temporary is not None and temporary.is_file() and not temporary.is_symlink():
                temporary.unlink()

        operation_receipts = sorted(
            path.relative_to(self.workspace.root).as_posix()
            for path in self.workspace.receipts.glob(
                f"operation-{operation_key}-*-content-imported.json"
            )
        )
        if len(operation_receipts) != 1:
            raise ProtocolError(
                "CAPTURE_OPERATION_RECEIPT_MISMATCH",
                "capture operation must produce one exact import receipt",
            )
        evidence_refs = [item.as_dict() for item in imported]
        result = {
            "outcome": "APPLIED",
            "evidence_refs": evidence_refs,
            "side_effects": list(CAPTURE_SIDE_EFFECTS),
            "resource_use": {
                "input_bytes": input_bytes,
                "documents": len(imported),
                "writes": len(evidence_refs) + len(operation_receipts),
            },
            "rollback_ref": f"capture-delta:{operation_key}",
            "detail": {
                "kind": kind,
                "title": title,
                "deduplicated": rollback_record["deduplicated"],
                "receipt_paths": operation_receipts,
                "byte_preserving": True,
            },
        }
        self._finish_operation(operation_key, payload, result)
        return result

    def _apply_m31_locked(
        self, payload: dict[str, Any], *, operation_key: str
    ) -> dict[str, Any]:
        if set(payload) != {"kind", "request_kind", "admission_plans"} or not isinstance(
            payload.get("request_kind"), str
        ) or not isinstance(payload.get("admission_plans"), list) or not payload[
            "admission_plans"
        ]:
            raise ProtocolError(
                "CAPTURE_PAYLOAD_INVALID", "planned M3.1 capture payload is invalid"
            )
        existing = self._begin_operation(operation_key, payload)
        if existing is not None:
            return existing
        admissions: list[dict[str, Any]] = []
        child_keys: list[str] = []
        for index, admission_plan in enumerate(payload["admission_plans"]):
            if not isinstance(admission_plan, dict):
                raise ProtocolError(
                    "CAPTURE_PAYLOAD_INVALID", "planned capture item is invalid"
                )
            child_key = document_digest(
                {
                    "parent_operation_key": operation_key,
                    "item_index": index,
                    "plan_digest": admission_plan.get("plan_digest"),
                }
            )
            child_keys.append(child_key)
            admissions.append(self.admission.apply(admission_plan, child_key))
        evidence_refs = [
            {
                "capture_id": item["capture_id"],
                "source_id": item["source_id"],
                "asset_path": item["asset_path"],
                "normalized_text_path": item["normalized_text_path"],
                "source_record_path": item["source_record_path"],
            }
            for item in admissions
        ]
        degraded = any(item["outcome"] == "QUEUED_PROVIDER" for item in admissions)
        result = {
            "outcome": "DEGRADED" if degraded else "APPLIED",
            "evidence_refs": evidence_refs,
            "side_effects": list(CAPTURE_M31_SIDE_EFFECTS),
            "resource_use": {
                "input_bytes": sum(
                    item["original_size_bytes"] for item in payload["admission_plans"]
                ),
                "documents": len(admissions),
                "writes": sum(
                    5 + (1 if item["normalized_text_path"] else 0)
                    for item in admissions
                ),
            },
            "rollback_ref": f"capture-admission-group:{operation_key}",
            "detail": {
                "kind": payload["request_kind"],
                "admissions": copy.deepcopy(admissions),
                "child_operation_keys": child_keys,
                "local_only": True,
                "byte_preserving": True,
            },
        }
        self._finish_operation(operation_key, payload, result)
        return result

    def export(
        self, scope: dict[str, Any], *, operation_key: str
    ) -> dict[str, Any]:
        existing = self.lifecycle_operations.begin("export", operation_key, scope)
        if existing is not None:
            return existing
        if not isinstance(scope, dict) or set(scope) != {"root", "filename"}:
            raise ProtocolError(
                "CAPTURE_EXPORT_SCOPE_INVALID",
                "capture export requires an exact root and filename",
            )
        root = Path(scope["root"])
        filename = scope["filename"]
        if (
            not isinstance(filename, str)
            or not filename
            or PurePosixPath(filename).name != filename
            or root.is_symlink()
            or not root.is_dir()
            or str(root.resolve()) != scope["root"]
        ):
            raise ProtocolError(
                "CAPTURE_EXPORT_BOUNDARY", "capture export target is unsafe"
            )
        output = root / filename
        if output.is_symlink():
            raise ProtocolError(
                "CAPTURE_EXPORT_BOUNDARY", "capture export file may not be a symlink"
            )
        exported = self.workspace.export(output)
        result = {
            "outcome": "APPLIED",
            "files": [filename],
            "side_effects": ["workspace:export"],
            "resource_use": {"output_bytes": output.stat().st_size},
            "rollback_ref": None,
            "detail": {"workspace_export": exported},
        }
        self.lifecycle_operations.finish("export", operation_key, scope, result)
        return result

    def rollback(
        self, rollback_ref: str, *, operation_key: str
    ) -> dict[str, Any]:
        with exclusive_lock(self._workspace_lock_path()):
            return self._rollback_locked(
                rollback_ref, operation_key=operation_key
            )

    def _rollback_locked(
        self, rollback_ref: str, *, operation_key: str
    ) -> dict[str, Any]:
        lifecycle_input = {"rollback_ref": rollback_ref}
        existing = self.lifecycle_operations.begin(
            "rollback", operation_key, lifecycle_input
        )
        if existing is not None:
            return existing
        if isinstance(rollback_ref, str) and rollback_ref.startswith(
            "capture-admission-group:"
        ):
            return self._rollback_m31_group(
                rollback_ref,
                operation_key=operation_key,
                lifecycle_input=lifecycle_input,
            )
        if not isinstance(rollback_ref, str) or not rollback_ref.startswith(
            "capture-delta:"
        ):
            raise ProtocolError(
                "CAPTURE_ROLLBACK_REFUSED",
                "capture rollback requires an exact delta reference",
            )
        capture_operation_key = rollback_ref.removeprefix("capture-delta:")
        path = self._rollback_path(capture_operation_key)
        document = self._read_state_record(path, code="CAPTURE_ROLLBACK_MISMATCH")
        validated = self._validate_rollback_document(
            capture_operation_key,
            document,
            allowed_states=frozenset({"APPLIED", "ROLLING_BACK", "ROLLED_BACK"}),
        )
        if document["state"] == "ROLLED_BACK":
            for entry, target, _ in validated:
                before_sha256 = entry["before_sha256"]
                if before_sha256 is None:
                    if target.exists() or target.is_symlink():
                        raise ProtocolError(
                            "CAPTURE_ROLLBACK_DRIFT",
                            "rolled-back capture target was recreated",
                        )
                elif (
                    target.is_symlink()
                    or not target.is_file()
                    or _sha256_file(target) != before_sha256
                ):
                    raise ProtocolError(
                        "CAPTURE_ROLLBACK_DRIFT",
                        "rolled-back capture target changed after restoration",
                    )
            result = {
                "outcome": "NO_OP",
                "evidence_refs": [],
                "side_effects": [],
                "resource_use": {},
                "rollback_ref": None,
                "detail": {"already_rolled_back": True},
            }
            self.lifecycle_operations.finish(
                "rollback", operation_key, lifecycle_input, result
            )
            return result

        for entry, target, _ in validated:
            before_sha256 = entry["before_sha256"]
            matches_before = (
                not target.exists() and not target.is_symlink()
                if before_sha256 is None
                else (
                    not target.is_symlink()
                    and target.is_file()
                    and _sha256_file(target) == before_sha256
                )
            )
            matches_after = (
                not target.is_symlink()
                and target.is_file()
                and _sha256_file(target) == entry["after_sha256"]
            )
            restore_state = entry["restore_state"]
            matches_expected = (
                matches_after
                if restore_state == "PENDING"
                else matches_before
                if restore_state == "RESTORED"
                else matches_before or matches_after
            )
            if not matches_expected:
                raise ProtocolError(
                    "CAPTURE_ROLLBACK_DRIFT",
                    "capture-owned target changed after the recorded operation",
                )
        document["state"] = "ROLLING_BACK"
        self._write_state_record(path, document)
        restored_paths: list[str] = []
        for entry, target, before in validated:
            if entry["restore_state"] == "RESTORED":
                restored_paths.append(entry["path"])
                continue
            if entry["restore_state"] == "PENDING":
                entry["restore_state"] = "RESTORING"
                self._write_state_record(path, document)
            before_sha256 = entry["before_sha256"]
            matches_before = (
                not target.exists() and not target.is_symlink()
                if before_sha256 is None
                else (
                    not target.is_symlink()
                    and target.is_file()
                    and _sha256_file(target) == before_sha256
                )
            )
            if not matches_before:
                if before is None:
                    target.unlink()
                    portable_root = (
                        self.workspace.sources
                        if self.workspace.sources in target.parents
                        else self.workspace.provenance
                    )
                    parent = target.parent
                    while parent != portable_root and not any(parent.iterdir()):
                        parent.rmdir()
                        parent = parent.parent
                else:
                    atomic_write_bytes(target, before, mode=0o600)
            entry["restore_state"] = "RESTORED"
            restored_paths.append(entry["path"])
            self._write_state_record(path, document)
        self.workspace.rebuild_index()
        document["state"] = "ROLLED_BACK"
        self._write_state_record(path, document)
        result = {
            "outcome": "APPLIED",
            "evidence_refs": [],
            "side_effects": list(CAPTURE_SIDE_EFFECTS),
            "resource_use": {"writes": len(restored_paths)},
            "rollback_ref": None,
            "detail": {
                "restored_paths": restored_paths,
                "receipts_preserved": True,
            },
        }
        self.lifecycle_operations.finish(
            "rollback", operation_key, lifecycle_input, result
        )
        return result

    def _rollback_m31_group(
        self,
        rollback_ref: str,
        *,
        operation_key: str,
        lifecycle_input: dict[str, Any],
    ) -> dict[str, Any]:
        capture_operation_key = rollback_ref.removeprefix(
            "capture-admission-group:"
        )
        if _SHA256_RE.fullmatch(capture_operation_key) is None:
            raise ProtocolError(
                "CAPTURE_ROLLBACK_REFUSED",
                "capture admission rollback key is invalid",
            )
        operation = self._read_state_record(
            self._operation_path(capture_operation_key),
            code="CAPTURE_ROLLBACK_MISMATCH",
        )
        result = operation.get("result")
        if (
            operation.get("schema_version") != "hive.capture-operation.v1"
            or operation.get("operation_key") != capture_operation_key
            or operation.get("state") != "TERMINAL"
            or not isinstance(result, dict)
            or result.get("rollback_ref") != rollback_ref
            or not isinstance(result.get("detail"), dict)
            or not isinstance(result["detail"].get("child_operation_keys"), list)
        ):
            raise ProtocolError(
                "CAPTURE_ROLLBACK_MISMATCH",
                "capture admission group record is invalid",
            )
        child_keys = result["detail"]["child_operation_keys"]
        if not child_keys or not all(
            isinstance(child, str) and _SHA256_RE.fullmatch(child)
            for child in child_keys
        ):
            raise ProtocolError(
                "CAPTURE_ROLLBACK_MISMATCH",
                "capture admission group children are invalid",
            )
        restored: list[str] = []
        for child in reversed(child_keys):
            self.admission.rollback(child)
            restored.append(child)
        lifecycle_result = {
            "outcome": "APPLIED",
            "evidence_refs": [],
            "side_effects": list(CAPTURE_M31_SIDE_EFFECTS),
            "resource_use": {"writes": len(restored)},
            "rollback_ref": None,
            "detail": {
                "restored_child_operations": restored,
                "receipts_preserved": False,
            },
        }
        self.lifecycle_operations.finish(
            "rollback", operation_key, lifecycle_input, lifecycle_result
        )
        return lifecycle_result

    def recover_lifecycle(
        self, operation: str, operation_key: str
    ) -> dict[str, Any] | None:
        return self.lifecycle_operations.recover(operation, operation_key)
