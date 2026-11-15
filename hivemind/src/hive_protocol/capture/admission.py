"""Governed, replay-safe capture admission into one portable Hive workspace."""

from __future__ import annotations

import base64
import copy
import hashlib
import os
import re
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.core import ProtocolError, canonical_bytes, document_digest
from hive_protocol.product.workspace import HiveWorkspace
from hive_protocol.storage import atomic_write_bytes, exclusive_lock, read_json, utc_now

from .models import CaptureEnvelope, SourceRecord
from .normalizers import NormalizerRegistry
from .store import CaptureOperationStore


_SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PRIVACY = frozenset(
    {"PROJECT_PRIVATE", "CUSTOMER_PRIVATE", "PERSONA_PRIVATE", "NON_PRIVATE"}
)
_CHANNELS = frozenset(
    {
        "TEXT",
        "MARKDOWN",
        "CLIPBOARD",
        "FILE",
        "FOLDER_HANDOFF",
        "BROWSER_HANDOFF",
        "WEBPAGE_SNAPSHOT",
        "PDF",
        "IMAGE",
        "AUDIO",
        "VIDEO",
        "MEETING_RECORDING",
        "TRANSCRIPT",
    }
)
_RIGHTS = frozenset(
    {
        "USER_PROVIDED",
        "AUTHORIZED_PROJECT_SOURCE",
        "PUBLIC_OR_LICENSED",
        "UNKNOWN_REVIEW_REQUIRED",
    }
)
_DESTINATIONS = frozenset({"STAGING", "RESEARCH"})
_PLAN_KEYS = frozenset(
    {
        "schema_version",
        "mode",
        "source_path",
        "payload_b64",
        "original_sha256",
        "original_size_bytes",
        "filename",
        "metadata",
        "normalization",
        "plan_digest",
    }
)
_METADATA_KEYS = frozenset(
    {
        "tenant_id",
        "project_id",
        "privacy_class",
        "channel",
        "source_owner",
        "rights_assertion",
        "media_type",
        "destination",
        "acquired_at",
    }
)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _json_payload(document: Mapping[str, Any]) -> bytes:
    return canonical_bytes(document) + b"\n"


def _encode(payload: bytes | None) -> str | None:
    return base64.b64encode(payload).decode("ascii") if payload is not None else None


def _decode(value: Any, *, code: str) -> bytes | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ProtocolError(code, "capture staged bytes are malformed")
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ProtocolError(code, "capture staged bytes are malformed") from exc


class CaptureAdmissionService:
    """Admit local evidence with an authenticated resumable exact-delta journal."""

    def __init__(
        self,
        workspace: HiveWorkspace,
        state_root: Path,
        *,
        registry: NormalizerRegistry,
        signing_key: Ed25519PrivateKey,
    ) -> None:
        self.workspace = workspace
        self.registry = registry
        self.operations = CaptureOperationStore(state_root, signing_key=signing_key)
        self.state_root = self.operations.root

    def _validate_metadata(
        self,
        *,
        tenant_id: str,
        project_id: str,
        privacy_class: str,
        channel: str,
        source_owner: str,
        rights_assertion: str,
        media_type: str,
        destination: str,
        acquired_at: str | None,
    ) -> dict[str, Any]:
        normalized_channel = channel.upper() if isinstance(channel, str) else ""
        normalized_destination = destination.upper() if isinstance(destination, str) else ""
        if (
            not isinstance(tenant_id, str)
            or _SAFE_ID.fullmatch(tenant_id) is None
            or not isinstance(project_id, str)
            or _SAFE_ID.fullmatch(project_id) is None
        ):
            raise ProtocolError(
                "CAPTURE_SCOPE_INVALID", "capture tenant and project are required"
            )
        if privacy_class not in _PRIVACY:
            raise ProtocolError(
                "CAPTURE_CLASSIFICATION_INVALID",
                "capture privacy classification is unsupported",
            )
        if normalized_channel not in _CHANNELS:
            raise ProtocolError("CAPTURE_CHANNEL_INVALID", "capture channel is unsupported")
        if (
            not isinstance(source_owner, str)
            or not source_owner.strip()
            or len(source_owner) > 256
            or rights_assertion not in _RIGHTS
            or not isinstance(media_type, str)
            or re.fullmatch(r"[A-Za-z0-9.+-]+/[A-Za-z0-9.+-]+", media_type) is None
            or normalized_destination not in _DESTINATIONS
            or acquired_at is not None
            and not isinstance(acquired_at, str)
        ):
            raise ProtocolError(
                "CAPTURE_POLICY_INVALID", "capture policy metadata is malformed"
            )
        return {
            "tenant_id": tenant_id,
            "project_id": project_id,
            "privacy_class": privacy_class,
            "channel": normalized_channel,
            "source_owner": source_owner.strip(),
            "rights_assertion": rights_assertion,
            "media_type": media_type.lower(),
            "destination": normalized_destination,
            "acquired_at": acquired_at,
        }

    def _plan(
        self,
        payload: bytes,
        *,
        mode: str,
        source_path: str | None,
        filename: str,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(payload, bytes):
            raise ProtocolError("CAPTURE_INPUT_INVALID", "capture payload must be bytes")
        if len(payload) > self.registry.limits.max_input_bytes:
            raise ProtocolError(
                "CAPTURE_INPUT_LIMIT_EXCEEDED", "capture input exceeds its byte limit"
            )
        document = {
            "schema_version": "hive.capture-plan.v1",
            "mode": mode,
            "source_path": source_path,
            "payload_b64": _encode(payload) if mode == "BYTES" else None,
            "original_sha256": _sha256(payload),
            "original_size_bytes": len(payload),
            "filename": filename,
            "metadata": copy.deepcopy(metadata),
            "normalization": self.registry.describe(metadata["channel"]),
        }
        document["plan_digest"] = document_digest(document)
        return document

    def plan_bytes(
        self,
        payload: bytes,
        *,
        tenant_id: str,
        project_id: str,
        privacy_class: str,
        channel: str,
        source_owner: str,
        rights_assertion: str,
        media_type: str,
        filename: str,
        destination: str,
        acquired_at: str | None = None,
    ) -> dict[str, Any]:
        metadata = self._validate_metadata(
            tenant_id=tenant_id,
            project_id=project_id,
            privacy_class=privacy_class,
            channel=channel,
            source_owner=source_owner,
            rights_assertion=rights_assertion,
            media_type=media_type,
            destination=destination,
            acquired_at=acquired_at,
        )
        return self._plan(
            payload,
            mode="BYTES",
            source_path=None,
            filename=filename,
            metadata=metadata,
        )

    def plan_path(
        self,
        source: Path,
        *,
        tenant_id: str,
        project_id: str,
        privacy_class: str,
        channel: str,
        source_owner: str,
        rights_assertion: str,
        media_type: str,
        destination: str,
        acquired_at: str | None = None,
    ) -> dict[str, Any]:
        # Scope and policy deliberately resolve before source identity or bytes.
        metadata = self._validate_metadata(
            tenant_id=tenant_id,
            project_id=project_id,
            privacy_class=privacy_class,
            channel=channel,
            source_owner=source_owner,
            rights_assertion=rights_assertion,
            media_type=media_type,
            destination=destination,
            acquired_at=acquired_at,
        )
        raw = source.expanduser()
        for candidate in [raw, *raw.parents]:
            if candidate.is_symlink():
                raise ProtocolError(
                    "CAPTURE_SOURCE_BOUNDARY",
                    "capture source path may not contain symlinks",
                )
        resolved = raw.resolve(strict=False)
        if (
            not resolved.is_file()
            or resolved.is_symlink()
            or resolved.stat().st_uid != os.geteuid()
        ):
            raise ProtocolError(
                "CAPTURE_SOURCE_BOUNDARY",
                "capture source must be an owned regular file",
            )
        payload = resolved.read_bytes()
        return self._plan(
            payload,
            mode="PATH",
            source_path=str(resolved),
            filename=resolved.name,
            metadata=metadata,
        )

    def _validate_plan(self, plan: Mapping[str, Any]) -> dict[str, Any]:
        candidate = copy.deepcopy(dict(plan))
        if (
            set(candidate) != _PLAN_KEYS
            or candidate.get("schema_version") != "hive.capture-plan.v1"
            or candidate.get("mode") not in {"BYTES", "PATH"}
            or not isinstance(candidate.get("metadata"), dict)
            or set(candidate["metadata"]) != _METADATA_KEYS
            or not isinstance(candidate.get("filename"), str)
            or not isinstance(candidate.get("original_sha256"), str)
            or _SHA256.fullmatch(candidate["original_sha256"]) is None
            or not isinstance(candidate.get("original_size_bytes"), int)
            or isinstance(candidate.get("original_size_bytes"), bool)
            or candidate["original_size_bytes"] < 0
        ):
            raise ProtocolError("CAPTURE_PLAN_INVALID", "capture plan is malformed")
        supplied_digest = candidate.pop("plan_digest", None)
        if supplied_digest != document_digest(candidate):
            raise ProtocolError("CAPTURE_PLAN_INVALID", "capture plan digest changed")
        candidate["plan_digest"] = supplied_digest
        metadata = self._validate_metadata(**candidate["metadata"])
        if metadata != candidate["metadata"]:
            raise ProtocolError("CAPTURE_PLAN_INVALID", "capture plan policy changed")
        if candidate.get("normalization") != self.registry.describe(metadata["channel"]):
            raise ProtocolError(
                "CAPTURE_PLAN_INVALID", "capture normalization decision changed"
            )
        return candidate

    def _planned_payload(self, plan: dict[str, Any]) -> bytes:
        if plan["mode"] == "BYTES":
            if plan["source_path"] is not None:
                raise ProtocolError("CAPTURE_PLAN_INVALID", "byte plan has a source path")
            payload = _decode(plan["payload_b64"], code="CAPTURE_PLAN_INVALID")
            if payload is None:
                raise ProtocolError("CAPTURE_PLAN_INVALID", "byte plan lacks bytes")
        else:
            if plan["payload_b64"] is not None or not isinstance(plan["source_path"], str):
                raise ProtocolError("CAPTURE_PLAN_INVALID", "path plan is malformed")
            path = Path(plan["source_path"])
            if any(candidate.is_symlink() for candidate in [path, *path.parents]) or (
                not path.is_file()
                or path.stat().st_uid != os.geteuid()
            ):
                raise ProtocolError(
                    "CAPTURE_SOURCE_CHANGED", "planned capture source is unavailable"
                )
            payload = path.read_bytes()
        if (
            len(payload) != plan["original_size_bytes"]
            or _sha256(payload) != plan["original_sha256"]
        ):
            raise ProtocolError(
                "CAPTURE_SOURCE_CHANGED", "capture source changed after planning"
            )
        return payload

    def _ensure_portable_root(self, path: Path) -> None:
        root = self.workspace.root
        if root.is_symlink() or not root.is_dir() or root.stat().st_uid != os.geteuid():
            raise ProtocolError(
                "CAPTURE_PORTABLE_BOUNDARY", "Hive root is not an owned directory"
            )
        try:
            relative = path.relative_to(root)
        except ValueError as exc:
            raise ProtocolError(
                "CAPTURE_PORTABLE_BOUNDARY", "capture path escapes the Hive root"
            ) from exc
        current = root
        for part in relative.parts:
            current /= part
            if current.is_symlink():
                raise ProtocolError(
                    "CAPTURE_PORTABLE_BOUNDARY",
                    "capture portable path may not contain symlinks",
                )
        path.mkdir(parents=True, exist_ok=True)
        if path.is_symlink() or not path.is_dir() or path.stat().st_uid != os.geteuid():
            raise ProtocolError(
                "CAPTURE_PORTABLE_BOUNDARY",
                "capture portable root is not an owned directory",
            )

    def _bounded_target(self, relative: str) -> Path:
        candidate = PurePosixPath(relative)
        if (
            candidate.is_absolute()
            or candidate.as_posix() != relative
            or any(part in {"", ".", ".."} for part in candidate.parts)
        ):
            raise ProtocolError(
                "CAPTURE_PORTABLE_BOUNDARY", "capture target is not canonical"
            )
        parts = candidate.parts
        allowed = (
            len(parts) == 3
            and parts[0] in {"assets", "sources"}
            or len(parts) == 3
            and parts[:2] == ("staging", "captures")
            or len(parts) == 3
            and parts[:2] in {(".hive", "provenance"), (".hive", "receipts")}
            or len(parts) == 4
            and parts[:3] == (".hive", "runtime", "capture-queue")
        )
        if not allowed:
            raise ProtocolError(
                "CAPTURE_PORTABLE_BOUNDARY", "capture target exceeds owned roots"
            )
        target = self.workspace.root.joinpath(*parts)
        self._ensure_portable_root(target.parent)
        if target.is_symlink() or target.exists() and not target.is_file():
            raise ProtocolError(
                "CAPTURE_PORTABLE_BOUNDARY",
                "capture target must be a regular non-symlink file",
            )
        return target

    def _prepare_transaction(
        self, plan: dict[str, Any], payload: bytes, operation_key: str
    ) -> dict[str, Any]:
        metadata = plan["metadata"]
        result = self.registry.normalize(
            channel=metadata["channel"],
            payload=payload,
            media_type=metadata["media_type"],
            filename=plan["filename"],
        )
        original_sha = plan["original_sha256"]
        source_id = f"source:{original_sha}"
        source_slug = f"source-{original_sha}"
        asset_relative = f"assets/asset-{original_sha}/{plan['filename']}"
        normalized_relative = (
            f"sources/{source_slug}/normalized.md"
            if result.normalized_text is not None
            else None
        )
        source_relative = f".hive/provenance/{source_slug}.json"
        capture_id = f"capture:{operation_key}"
        capture_slug = f"capture-{operation_key}"
        envelope_relative = f"staging/captures/{capture_slug}.json"
        receipt_relative = f".hive/receipts/capture-operation-{operation_key}.json"
        receipt_ref = f"receipt:capture:{operation_key[:32]}"
        queue_relative = (
            f".hive/runtime/capture-queue/{capture_slug}.json"
            if result.normalized_text is None
            else None
        )
        acquired_at = metadata["acquired_at"] or utc_now()
        parser = result.parser or {
            "parser_id": "provider.unavailable",
            "version": "1.0.0",
        }
        normalized_bytes = (
            result.normalized_text.encode("utf-8")
            if result.normalized_text is not None
            else None
        )
        normalized_sha = _sha256(normalized_bytes) if normalized_bytes is not None else None
        anchors = [
            anchor.as_dict()
            for anchor in result.citation_anchors(
                source_id=source_id, source_sha256=original_sha
            )
        ]

        source_target = self._bounded_target(source_relative)
        if source_target.exists():
            prior = SourceRecord.from_dict(read_json(source_target))
            if (
                prior.source_id != source_id
                or prior.tenant_id != metadata["tenant_id"]
                or prior.project_id != metadata["project_id"]
                or prior.privacy_class != metadata["privacy_class"]
                or prior.original_sha256 != original_sha
                or prior.original_size_bytes != len(payload)
                or prior.media_type != metadata["media_type"]
                or prior.normalized_sha256 != normalized_sha
            ):
                raise ProtocolError(
                    "CAPTURE_SOURCE_COLLISION",
                    "existing source record does not match this capture",
                )
            asset_relative = prior.original_asset_path
            normalized_relative = prior.normalized_text_path
            capture_ids = sorted(set([*prior.capture_ids, capture_id]))
            created_at = prior.created_at
        else:
            capture_ids = [capture_id]
            created_at = acquired_at

        source_document = SourceRecord(
            source_id=source_id,
            tenant_id=metadata["tenant_id"],
            project_id=metadata["project_id"],
            privacy_class=metadata["privacy_class"],
            original_asset_path=asset_relative,
            original_sha256=original_sha,
            original_size_bytes=len(payload),
            normalized_text_path=normalized_relative,
            normalized_sha256=normalized_sha,
            media_type=metadata["media_type"],
            parser=parser,
            transformations=result.transformations,
            capture_ids=capture_ids,
            anchors=anchors,
            created_at=created_at,
        ).as_dict()
        SourceRecord.from_dict(source_document)

        admission_state = (
            "QUEUED_PROVIDER"
            if normalized_bytes is None
            else f"ADMITTED_{metadata['destination']}"
        )
        destination = "OFFLINE_QUEUE" if normalized_bytes is None else metadata["destination"]
        transformation_documents = [
            {
                "kind": kind,
                "input_sha256": original_sha,
                "output_sha256": normalized_sha,
            }
            for kind in result.transformations
            if normalized_sha is not None
        ]
        envelope_document = CaptureEnvelope(
            capture_id=capture_id,
            tenant_id=metadata["tenant_id"],
            project_id=metadata["project_id"],
            privacy_class=metadata["privacy_class"],
            channel=metadata["channel"],
            source_owner=metadata["source_owner"],
            acquired_at=acquired_at,
            rights_assertion=metadata["rights_assertion"],
            original_sha256=original_sha,
            original_size_bytes=len(payload),
            media_type=metadata["media_type"],
            parser=parser,
            transformations=transformation_documents,
            risk_flags=sorted(set(result.risk_flags)),
            admission_state=admission_state,
            destination=destination,
            source_record_id=source_id,
            receipt_ref=receipt_ref,
        ).as_dict()
        CaptureEnvelope.from_dict(envelope_document)
        receipt_document = {
            "schema_version": "hive.capture-receipt.v1",
            "receipt_ref": receipt_ref,
            "operation_key": operation_key,
            "capture_id": capture_id,
            "source_id": source_id,
            "original_sha256": original_sha,
            "normalized_sha256": normalized_sha,
            "outcome": admission_state,
            "recorded_at": acquired_at,
        }
        queue_document = (
            {
                "schema_version": "hive.capture-provider-queue.v1",
                "capture_id": capture_id,
                "source_id": source_id,
                "channel": metadata["channel"],
                "original_sha256": original_sha,
                "provider_reason": result.provider_reason,
                "state": "QUEUED_PROVIDER",
            }
            if queue_relative is not None
            else None
        )

        files: dict[str, bytes] = {
            asset_relative: payload,
            source_relative: _json_payload(source_document),
            envelope_relative: _json_payload(envelope_document),
            receipt_relative: _json_payload(receipt_document),
        }
        if normalized_relative is not None and normalized_bytes is not None:
            files[normalized_relative] = normalized_bytes
        if queue_relative is not None and queue_document is not None:
            files[queue_relative] = _json_payload(queue_document)

        rollback: list[dict[str, Any]] = []
        for relative, after in files.items():
            target = self._bounded_target(relative)
            before = target.read_bytes() if target.exists() else None
            if before is not None and relative in {
                envelope_relative,
                receipt_relative,
                queue_relative,
            }:
                raise ProtocolError(
                    "CAPTURE_CONTENT_COLLISION",
                    "operation-specific capture target already exists without its journal",
                )
            if before is not None and relative in {asset_relative, normalized_relative} and before != after:
                raise ProtocolError(
                    "CAPTURE_CONTENT_COLLISION",
                    "existing canonical capture bytes changed",
                )
            rollback.append(
                {
                    "path": relative,
                    "before_sha256": _sha256(before) if before is not None else None,
                    "before_bytes_b64": _encode(before),
                    "after_sha256": _sha256(after),
                    "restore_state": "PENDING",
                }
            )
        response = {
            "outcome": admission_state,
            "operation_key": operation_key,
            "capture_id": capture_id,
            "source_id": source_id,
            "asset_path": asset_relative,
            "normalized_text_path": normalized_relative,
            "source_record_path": source_relative,
            "capture_envelope_path": envelope_relative,
            "receipt_path": receipt_relative,
            "queue_path": queue_relative,
            "risk_flags": sorted(set(result.risk_flags)),
        }
        return {
            "original_path": asset_relative,
            "normalized_path": normalized_relative,
            "files": {relative: _encode(value) for relative, value in files.items()},
            "result": response,
            "rollback": rollback,
        }

    def _new_journal(
        self, plan: dict[str, Any], payload: bytes, operation_key: str
    ) -> dict[str, Any]:
        transaction = self._prepare_transaction(plan, payload, operation_key)
        rollback = transaction.pop("rollback")
        return {
            "schema_version": "hive.capture-operation.v2",
            "operation_key": operation_key,
            "plan_digest": plan["plan_digest"],
            "stage": "PREPARED",
            "transaction": transaction,
            "rollback": rollback,
            "result": None,
        }

    def _transaction_files(self, document: dict[str, Any]) -> dict[str, bytes]:
        raw_files = document["transaction"].get("files")
        if not isinstance(raw_files, dict) or not raw_files:
            raise ProtocolError(
                "CAPTURE_OPERATION_MISMATCH", "capture transaction files are invalid"
            )
        files: dict[str, bytes] = {}
        for relative, encoded in raw_files.items():
            if not isinstance(relative, str):
                raise ProtocolError(
                    "CAPTURE_OPERATION_MISMATCH", "capture transaction path is invalid"
                )
            payload = _decode(encoded, code="CAPTURE_OPERATION_MISMATCH")
            if payload is None:
                raise ProtocolError(
                    "CAPTURE_OPERATION_MISMATCH", "capture transaction bytes are absent"
                )
            self._bounded_target(relative)
            files[relative] = payload
        return files

    def _write_exact(
        self, document: dict[str, Any], relative: str, payload: bytes
    ) -> None:
        target = self._bounded_target(relative)
        entry = next(
            (
                item
                for item in document["rollback"]
                if isinstance(item, dict) and item.get("path") == relative
            ),
            None,
        )
        if not isinstance(entry, dict) or entry.get("after_sha256") != _sha256(payload):
            raise ProtocolError(
                "CAPTURE_OPERATION_MISMATCH",
                "capture target is not bound to its authenticated delta",
            )
        if target.exists():
            current = target.read_bytes()
            if current == payload:
                return
            if entry.get("before_sha256") != _sha256(current):
                raise ProtocolError(
                    "CAPTURE_OPERATION_MISMATCH", "capture target drifted during recovery"
                )
        elif entry.get("before_sha256") is not None:
            raise ProtocolError(
                "CAPTURE_OPERATION_MISMATCH", "capture prior target disappeared"
            )
        atomic_write_bytes(target, payload)

    def _after_stage(self, stage: str) -> None:
        """Test seam for simulating loss of process after a durable stage."""

    def _resume(self, document: dict[str, Any]) -> dict[str, Any]:
        if document["stage"] == "TERMINAL":
            return copy.deepcopy(document["result"])
        if document["stage"] == "ROLLED_BACK":
            raise ProtocolError(
                "CAPTURE_OPERATION_ROLLED_BACK", "capture operation was rolled back"
            )
        files = self._transaction_files(document)
        original = document["transaction"].get("original_path")
        normalized = document["transaction"].get("normalized_path")
        if not isinstance(original, str) or original not in files:
            raise ProtocolError(
                "CAPTURE_OPERATION_MISMATCH", "capture original path is invalid"
            )
        self._write_exact(document, original, files[original])
        if document["stage"] == "PREPARED":
            document["stage"] = "ORIGINAL_WRITTEN"
            self.operations.write(document)
            self._after_stage("ORIGINAL_WRITTEN")
        if normalized is not None:
            if not isinstance(normalized, str) or normalized not in files:
                raise ProtocolError(
                    "CAPTURE_OPERATION_MISMATCH", "capture normalized path is invalid"
                )
            self._write_exact(document, normalized, files[normalized])
        if document["stage"] == "ORIGINAL_WRITTEN":
            document["stage"] = "NORMALIZED_WRITTEN"
            self.operations.write(document)
            self._after_stage("NORMALIZED_WRITTEN")
        for relative, payload in files.items():
            if relative not in {original, normalized}:
                self._write_exact(document, relative, payload)
        result = document["transaction"].get("result")
        if not isinstance(result, dict):
            raise ProtocolError(
                "CAPTURE_OPERATION_MISMATCH", "capture transaction result is invalid"
            )
        document["stage"] = "TERMINAL"
        document["result"] = copy.deepcopy(result)
        self.operations.write(document)
        return copy.deepcopy(result)

    def apply(self, plan: Mapping[str, Any], operation_key: str) -> dict[str, Any]:
        validated = self._validate_plan(plan)
        self.operations.ensure_root()
        with exclusive_lock(self.state_root / "workspace.lock"):
            existing = self.operations.read(operation_key)
            if existing is not None:
                if existing["plan_digest"] != validated["plan_digest"]:
                    raise ProtocolError(
                        "CAPTURE_OPERATION_MISMATCH",
                        "operation key is bound to another capture plan",
                    )
                return self._resume(existing)
            payload = self._planned_payload(validated)
            journal = self._new_journal(validated, payload, operation_key)
            self.operations.write(journal)
            return self._resume(journal)

    def recover(self, operation_key: str) -> dict[str, Any] | None:
        self.operations.ensure_root()
        with exclusive_lock(self.state_root / "workspace.lock"):
            document = self.operations.read(operation_key)
            if document is None:
                return None
            return self._resume(document)

    def rollback(self, operation_key: str) -> dict[str, Any]:
        self.operations.ensure_root()
        with exclusive_lock(self.state_root / "workspace.lock"):
            document = self.operations.read(operation_key)
            if document is None or document["stage"] not in {
                "TERMINAL",
                "ROLLING_BACK",
                "ROLLED_BACK",
            }:
                raise ProtocolError(
                    "CAPTURE_ROLLBACK_MISMATCH",
                    "capture rollback requires one terminal operation",
                )
            validated: list[tuple[dict[str, Any], Path, bytes | None, str]] = []
            for entry in document["rollback"]:
                if not isinstance(entry, dict) or set(entry) != {
                    "path",
                    "before_sha256",
                    "before_bytes_b64",
                    "after_sha256",
                    "restore_state",
                }:
                    raise ProtocolError(
                        "CAPTURE_ROLLBACK_MISMATCH", "capture rollback entry changed"
                    )
                target = self._bounded_target(entry["path"])
                before = _decode(
                    entry["before_bytes_b64"], code="CAPTURE_ROLLBACK_MISMATCH"
                )
                restore_state = entry["restore_state"]
                if restore_state not in {"PENDING", "RESTORING", "RESTORED"}:
                    raise ProtocolError(
                        "CAPTURE_ROLLBACK_MISMATCH", "capture restore state changed"
                    )
                before_matches = (
                    not target.exists()
                    if before is None
                    else target.is_file() and _sha256(target.read_bytes()) == entry["before_sha256"]
                )
                after_matches = target.is_file() and _sha256(target.read_bytes()) == entry["after_sha256"]
                if (
                    before is None
                    and entry["before_sha256"] is not None
                    or before is not None
                    and _sha256(before) != entry["before_sha256"]
                    or document["stage"] == "TERMINAL"
                    and not after_matches
                    or document["stage"] == "ROLLING_BACK"
                    and (
                        restore_state == "PENDING"
                        and not after_matches
                        or restore_state == "RESTORING"
                        and not (before_matches or after_matches)
                        or restore_state == "RESTORED"
                        and not before_matches
                    )
                    or document["stage"] == "ROLLED_BACK"
                    and (restore_state != "RESTORED" or not before_matches)
                ):
                    raise ProtocolError(
                        "CAPTURE_ROLLBACK_MISMATCH",
                        "capture rollback current or prior bytes do not match",
                    )
                validated.append((entry, target, before, entry["path"]))
            if document["stage"] == "ROLLED_BACK":
                return copy.deepcopy(document["result"])
            document["stage"] = "ROLLING_BACK"
            self.operations.write(document)
            for entry, target, before, _ in reversed(validated):
                if entry["restore_state"] == "RESTORED":
                    continue
                entry["restore_state"] = "RESTORING"
                self.operations.write(document)
                before_matches = (
                    not target.exists()
                    if before is None
                    else target.is_file() and target.read_bytes() == before
                )
                if not before_matches:
                    if before is None:
                        target.unlink()
                    else:
                        atomic_write_bytes(target, before)
                entry["restore_state"] = "RESTORED"
                self.operations.write(document)
            document["stage"] = "ROLLED_BACK"
            document["result"] = {
                "outcome": "ROLLED_BACK",
                "operation_key": operation_key,
                "paths": [relative for _, _, _, relative in validated],
            }
            self.operations.write(document)
            return copy.deepcopy(document["result"])
