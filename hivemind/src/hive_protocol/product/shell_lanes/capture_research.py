"""Browser-safe capture and exact-source-set research application lane."""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import os
import re
import unicodedata
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.adapters.execution import operation_key as adapter_operation_key
from hive_protocol.adapters.models import AdapterRequest
from hive_protocol.core import (
    ProtocolError,
    document_digest,
    public_key_id,
    sign_document,
)
from hive_protocol.research.artifacts import ARTIFACT_TYPES, ResearchArtifactStore
from hive_protocol.research.models import ResearchWorkspace
from hive_protocol.research.workspace import BoundedResearchWorkspaceStore
from hive_protocol.storage import (
    atomic_write_bytes,
    atomic_write_json,
    ensure_owned_directory,
    read_json,
    require_no_symlink_components,
)

from ..agent_adapter import adapter_invocation_context, product_adapter_services
from ..shell_contracts import OperatorRequest, RouteContract
from ..workspace import HiveWorkspace


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$")
_SAFE_MEDIA_TYPE = re.compile(
    r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,127}$"
)
_CAPTURE_ACTIONS = frozenset({"capture.preview", "capture.admit"})
_RESEARCH_ACTIONS = frozenset(
    {
        "research.workspaces.create",
        "research.sources.add",
        "research.sources.remove",
        "research.search",
        "research.ask",
        "research.artifacts.create",
        "research.export",
    }
)
_ACTIONS = _CAPTURE_ACTIONS | _RESEARCH_ACTIONS
_CHANNEL_KIND = {
    "MARKDOWN": ("markdown", "capture.markdown"),
    "CLIPBOARD": ("clipboard", "capture.clipboard"),
    "FILE": ("file", "capture.file"),
    "WEBPAGE_SNAPSHOT": ("webpage_snapshot", "capture.webpage-snapshot"),
    "BROWSER_HANDOFF": ("browser_handoff", "capture.browser-handoff"),
    "PDF": ("pdf", "capture.pdf"),
    "IMAGE": ("image", "capture.image"),
    "AUDIO": ("audio", "capture.audio"),
    "VIDEO": ("video", "capture.video"),
    "MEETING_RECORDING": ("meeting_recording", "capture.meeting-recording"),
    "TRANSCRIPT": ("transcript", "capture.transcript"),
}
_TEXT_CHANNELS = frozenset({"MARKDOWN", "CLIPBOARD"})
_MEDIA_RULES: dict[str, frozenset[str] | str] = {
    "MARKDOWN": frozenset({"text/markdown", "text/plain"}),
    "CLIPBOARD": frozenset({"text/plain", "text/markdown"}),
    "PDF": frozenset({"application/pdf"}),
    "IMAGE": "image/",
    "AUDIO": "audio/",
    "VIDEO": "video/",
    "MEETING_RECORDING": frozenset(
        {"audio/mpeg", "audio/mp4", "audio/wav", "video/mp4", "video/webm"}
    ),
    "TRANSCRIPT": frozenset({"text/plain", "text/vtt", "application/json"}),
    "WEBPAGE_SNAPSHOT": frozenset({"text/html", "application/xhtml+xml"}),
    "BROWSER_HANDOFF": frozenset({"application/json", "text/html"}),
}
_PREVIEW_SCHEMA = "hive.operator-capture-preview.v1"
_OPERATION_SCHEMA = "hive.operator-capture-research-operation.v1"
_ADMISSION_SCHEMA = "hive.operator-capture-admission.v1"
_EXPORT_SCHEMA = "hive.operator-research-export.v1"
_PREVIEW_TTL = timedelta(hours=1)
MAX_UPLOAD_BYTES = 512 * 1024
MAX_ENCODED_CHARS = ((MAX_UPLOAD_BYTES + 2) // 3) * 4


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _moment(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: Any, *, code: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError(code, "stored operator time is invalid") from exc
    if parsed.tzinfo is None:
        raise ProtocolError(code, "stored operator time lacks a timezone")
    return parsed.astimezone(timezone.utc)


class CaptureResearchLane:
    """Expose existing signed adapters without accepting browser filesystem paths."""

    def __init__(
        self,
        workspace: HiveWorkspace,
        *,
        tenant_id: str,
        project_ids: frozenset[str],
        now: datetime,
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        self.workspace = workspace
        self.root = workspace.root
        self.tenant_id = tenant_id
        self.project_ids = project_ids
        self.now = now.astimezone(timezone.utc)
        self.fault_hook = fault_hook
        self.runtime = workspace.runtime / "operator-shell"
        self.uploads = self.runtime / "uploads"
        self.previews = self.runtime / "capture-previews"
        self.admissions = self.runtime / "capture-admissions"
        self.operations = self.runtime / "lanes" / "capture-research" / "operations"
        self.locks = self.runtime / "lanes" / "capture-research" / "locks"
        self.downloads = self.runtime / "downloads"
        self.exports = self.runtime / "research-exports"

    @staticmethod
    def supports(action: str) -> bool:
        return action in _ACTIONS

    def _fault(self, stage: str) -> None:
        if self.fault_hook is not None:
            self.fault_hook(stage)

    def _ensure_runtime(self) -> None:
        for directory in (
            self.runtime,
            self.uploads,
            self.previews,
            self.admissions,
            self.operations,
            self.locks,
            self.downloads,
            self.exports,
        ):
            ensure_owned_directory(
                self.root,
                directory,
                code="OPERATOR_RUNTIME_BOUNDARY",
                detail="capture/research runtime path is unsafe",
            )

    def _runtime_path(self, root: Path, name: str, *, suffix: str = ".json") -> Path:
        self._ensure_runtime()
        if _SHA256.fullmatch(name) is None:
            raise ProtocolError(
                "OPERATOR_RUNTIME_BOUNDARY", "runtime identifier is invalid"
            )
        path = root / f"{name}{suffix}"
        require_no_symlink_components(
            self.root,
            path,
            code="OPERATOR_RUNTIME_BOUNDARY",
            detail="capture/research runtime path contains a symlink",
        )
        if path.is_symlink():
            raise ProtocolError(
                "OPERATOR_RUNTIME_BOUNDARY", "capture/research runtime path is a symlink"
            )
        return path

    @staticmethod
    def _require_scope(request: OperatorRequest) -> None:
        if request.input.get("privacy_class", "PROJECT_PRIVATE") != "PROJECT_PRIVATE":
            raise ProtocolError(
                "CAPTURE_PRIVACY_DENIED", "operator capture is project-private only"
            )

    @staticmethod
    def _filename(value: Any) -> str:
        if (
            not isinstance(value, str)
            or unicodedata.normalize("NFKC", value) != value
            or value.encode("ascii", errors="ignore").decode("ascii") != value
            or _SAFE_FILENAME.fullmatch(value) is None
            or value in {".", ".."}
            or value.startswith(".")
            or value.endswith((".", " "))
            or ".." in value
            or "/" in value
            or "\\" in value
        ):
            raise ProtocolError(
                "CAPTURE_UPLOAD_FILENAME_INVALID",
                "browser upload filename is not a canonical portable basename",
            )
        return value

    @staticmethod
    def _channel_media(channel: Any, media_type: Any) -> tuple[str, str, str]:
        if channel not in _CHANNEL_KIND or not isinstance(media_type, str):
            raise ProtocolError(
                "CAPTURE_CHANNEL_MEDIA_MISMATCH",
                "capture channel or media type is not supported",
            )
        if _SAFE_MEDIA_TYPE.fullmatch(media_type) is None:
            raise ProtocolError(
                "CAPTURE_CHANNEL_MEDIA_MISMATCH", "capture media type is invalid"
            )
        rule = _MEDIA_RULES.get(channel)
        if isinstance(rule, frozenset) and media_type not in rule:
            raise ProtocolError(
                "CAPTURE_CHANNEL_MEDIA_MISMATCH",
                "capture media type does not match its declared channel",
            )
        if isinstance(rule, str) and not media_type.startswith(rule):
            raise ProtocolError(
                "CAPTURE_CHANNEL_MEDIA_MISMATCH",
                "capture media type does not match its declared channel",
            )
        kind, capability = _CHANNEL_KIND[channel]
        return str(channel), kind, capability

    def _capture_bytes(self, document: Mapping[str, Any]) -> tuple[bytes, dict[str, Any]]:
        if "path" in document:
            raise ProtocolError(
                "CAPTURE_BROWSER_PATH_DENIED", "browser capture may not provide a path"
            )
        kind = document.get("kind")
        common = {
            "kind",
            "filename",
            "title",
            "channel",
            "media_type",
            "privacy_class",
            "sha256",
        }
        expected = common | ({"text"} if kind == "text" else {"data_b64"})
        if kind not in {"text", "file"} or set(document) != expected:
            raise ProtocolError(
                "CAPTURE_UPLOAD_INVALID", "browser capture document shape is invalid"
            )
        filename = self._filename(document.get("filename"))
        channel, adapter_kind, capability = self._channel_media(
            document.get("channel"), document.get("media_type")
        )
        if kind == "text":
            if channel not in _TEXT_CHANNELS or not isinstance(document.get("text"), str):
                raise ProtocolError(
                    "CAPTURE_CHANNEL_MEDIA_MISMATCH",
                    "pasted text requires a supported text channel",
                )
            payload = document["text"].encode("utf-8")
        else:
            encoded = document.get("data_b64")
            if not isinstance(encoded, str) or len(encoded) > MAX_ENCODED_CHARS:
                raise ProtocolError(
                    "CAPTURE_UPLOAD_LIMIT", "browser upload encoding exceeds its limit"
                )
            try:
                payload = base64.b64decode(encoded, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise ProtocolError(
                    "CAPTURE_UPLOAD_ENCODING", "browser upload is not exact base64"
                ) from exc
        if not payload or len(payload) > MAX_UPLOAD_BYTES:
            raise ProtocolError(
                "CAPTURE_UPLOAD_LIMIT", "browser upload bytes exceed their limit"
            )
        digest = document.get("sha256")
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            raise ProtocolError("CAPTURE_UPLOAD_HASH_INVALID", "upload hash is invalid")
        if _sha256(payload) != digest:
            raise ProtocolError(
                "CAPTURE_UPLOAD_HASH_MISMATCH", "upload bytes do not match their hash"
            )
        title = document.get("title")
        if (
            not isinstance(title, str)
            or not title.strip()
            or title != title.strip()
            or len(title) > 256
        ):
            raise ProtocolError("CAPTURE_UPLOAD_INVALID", "capture title is invalid")
        return payload, {
            "kind": kind,
            "filename": filename,
            "title": title,
            "channel": channel,
            "adapter_kind": adapter_kind,
            "capability": capability,
            "media_type": document["media_type"],
            "privacy_class": document["privacy_class"],
            "sha256": digest,
            "size_bytes": len(payload),
        }

    @staticmethod
    def _signed_request(
        services: Any,
        *,
        adapter_id: str,
        capability: str,
        payload: dict[str, Any],
        evidence: list[str],
    ) -> dict[str, Any]:
        manifest = services.manifests.get(adapter_id)
        if manifest is None or capability not in manifest["capability_ids"]:
            raise ProtocolError(
                "ADAPTER_CAPABILITY_DENIED", "adapter capability is not declared"
            )
        grant = services.authority.resolve(
            public_key_id(services.request_key.public_key()), adapter_id
        )
        now = datetime.now(timezone.utc)
        request = AdapterRequest(
            request_id=str(uuid4()),
            adapter_id=adapter_id,
            adapter_version=manifest["version"],
            sender=dict(grant.identity),
            project_id=grant.project_id,
            capability_id=capability,
            data_classification="PROJECT_PRIVATE",
            authorization_ref=grant.authorization_ref,
            evidence_sha256=evidence,
            payload=copy.deepcopy(payload),
            nonce=uuid4().hex,
            expires_at=_moment(now + timedelta(minutes=10)),
        )
        return sign_document(request.as_dict(), services.request_key)

    @staticmethod
    def _persist_request(services: Any, document: Mapping[str, Any]) -> None:
        root = services.runtime.root / "requests"
        services.runtime.require_owned_directory(root)
        atomic_write_json(
            root / f"{document['request_id']}.json", document, mode=0o600
        )

    def _preview_path(self, preview_id: str) -> Path:
        return self._runtime_path(self.previews, preview_id)

    def _admission_path(self, preview_id: str) -> Path:
        return self._runtime_path(self.admissions, preview_id)

    def _operation_path(self, operation_key: str) -> Path:
        return self._runtime_path(self.operations, operation_key)

    def _read_preview(
        self, preview_id: Any, *, allow_expired: bool = False
    ) -> dict[str, Any]:
        if not isinstance(preview_id, str) or _SHA256.fullmatch(preview_id) is None:
            raise ProtocolError("CAPTURE_PREVIEW_INVALID", "capture preview ID is invalid")
        path = self._preview_path(preview_id)
        if not path.exists():
            raise ProtocolError("CAPTURE_PREVIEW_ABSENT", "capture preview is absent")
        document = read_json(path)
        required = {
            "schema_version",
            "preview_id",
            "preview_digest",
            "tenant_id",
            "project_id",
            "metadata",
            "upload_ref",
            "adapter_input",
            "request",
            "plan",
            "request_digest",
            "plan_digest",
            "operator_request_digest",
            "operator_operation_key",
            "created_at",
            "expires_at",
        }
        unsigned = copy.deepcopy(document)
        preview_digest = unsigned.pop("preview_digest", None)
        if (
            set(document) != required
            or document.get("schema_version") != _PREVIEW_SCHEMA
            or document.get("preview_id") != preview_id
            or document.get("tenant_id") != self.tenant_id
            or document.get("project_id") not in self.project_ids
            or preview_digest != document_digest(unsigned)
            or document.get("request_digest") != document_digest(document.get("request", {}))
            or document.get("plan_digest") != document_digest(document.get("plan", {}))
        ):
            raise ProtocolError("CAPTURE_PREVIEW_INVALID", "capture preview changed")
        if (
            not allow_expired
            and _parse_time(document["expires_at"], code="CAPTURE_PREVIEW_INVALID")
            <= self.now
        ):
            raise ProtocolError("CAPTURE_PREVIEW_EXPIRED", "capture preview expired")
        return document

    def _upload_path(self, document: Mapping[str, Any]) -> Path:
        relative = document.get("upload_ref")
        expected = (
            ".hive/runtime/operator-shell/uploads/"
            f"{document['preview_id']}/{document['metadata']['filename']}"
        )
        if relative != expected:
            raise ProtocolError("CAPTURE_PREVIEW_INVALID", "capture upload binding changed")
        path = self.root / expected
        require_no_symlink_components(
            self.root,
            path,
            code="CAPTURE_UPLOAD_BOUNDARY",
            detail="capture upload path contains a symlink",
        )
        if (
            path.is_symlink()
            or not path.is_file()
            or path.stat().st_uid != os.geteuid()
            or path.stat().st_size != document["metadata"]["size_bytes"]
            or _sha256_file(path) != document["metadata"]["sha256"]
        ):
            raise ProtocolError(
                "CAPTURE_UPLOAD_BYTES_CHANGED", "capture upload changed after preview"
            )
        return path

    def _adapter_staging_root(self) -> Path:
        suffix = hashlib.sha256(str(self.root).encode("utf-8")).hexdigest()[:16]
        return self.root.parent / f".nukotech-hive-capture-{suffix}"

    def _expected_adapter_input(self, document: Mapping[str, Any]) -> Path | None:
        metadata = document.get("metadata")
        if not isinstance(metadata, Mapping):
            raise ProtocolError("CAPTURE_PREVIEW_INVALID", "capture metadata changed")
        raw = document.get("adapter_input")
        if metadata.get("kind") == "text":
            if raw is not None:
                raise ProtocolError(
                    "CAPTURE_PREVIEW_INVALID", "pasted capture gained a file binding"
                )
            return None
        expected = (
            self._adapter_staging_root()
            / "operator-shell-inputs"
            / str(document.get("preview_id"))
            / str(metadata.get("filename"))
        ).absolute()
        if not isinstance(raw, str) or raw != str(expected):
            raise ProtocolError(
                "CAPTURE_PREVIEW_INVALID", "capture adapter input binding changed"
            )
        require_no_symlink_components(
            self.root.parent,
            expected,
            code="CAPTURE_STAGING_BOUNDARY",
            detail="capture adapter input path contains a symlink",
        )
        return expected

    def _verify_adapter_input(self, document: Mapping[str, Any]) -> Path | None:
        path = self._expected_adapter_input(document)
        if path is None:
            return None
        if (
            path.is_symlink()
            or not path.is_file()
            or path.stat().st_uid != os.geteuid()
            or _sha256_file(path) != document["metadata"]["sha256"]
        ):
            raise ProtocolError(
                "CAPTURE_UPLOAD_BYTES_CHANGED",
                "capture adapter bytes changed after preview",
            )
        return path

    def _write_operation(
        self,
        operation_key: str,
        request: OperatorRequest,
        result: Mapping[str, Any] | None,
    ) -> None:
        document = {
            "schema_version": _OPERATION_SCHEMA,
            "operation_key": operation_key,
            "action": request.action,
            "request_digest": request.digest,
            "state": "TERMINAL" if result is not None else "PREPARED",
            "result": copy.deepcopy(dict(result)) if result is not None else None,
            "result_digest": document_digest(result) if result is not None else None,
        }
        atomic_write_json(self._operation_path(operation_key), document, mode=0o600)

    def _read_operation(
        self, operation_key: str, request: OperatorRequest
    ) -> dict[str, Any] | None:
        path = self._operation_path(operation_key)
        if not path.exists():
            return None
        document = read_json(path)
        if (
            set(document)
            != {
                "schema_version",
                "operation_key",
                "action",
                "request_digest",
                "state",
                "result",
                "result_digest",
            }
            or document.get("schema_version") != _OPERATION_SCHEMA
            or document.get("operation_key") != operation_key
            or document.get("action") != request.action
            or document.get("request_digest") != request.digest
            or document.get("state") not in {"PREPARED", "TERMINAL"}
        ):
            raise ProtocolError(
                "OPERATOR_DOMAIN_RECOVERY_INVALID", "lane recovery record changed"
            )
        if document["state"] == "PREPARED":
            return None
        result = document.get("result")
        if not isinstance(result, dict) or document.get(
            "result_digest"
        ) != document_digest(result):
            raise ProtocolError(
                "OPERATOR_DOMAIN_RECOVERY_INVALID", "lane recovery result changed"
            )
        return copy.deepcopy(result)

    @staticmethod
    def _result(
        request: OperatorRequest,
        operation_key: str,
        *,
        outcome: str,
        object_version: str,
        changed: bool,
        data: Mapping[str, Any],
        evidence: list[dict[str, Any]],
        reason_code: str | None = None,
    ) -> dict[str, Any]:
        return {
            "operation_key": operation_key,
            "request_digest": request.digest,
            "outcome": outcome,
            "reason_code": reason_code,
            "object_version": object_version,
            "changed": changed,
            "data": copy.deepcopy(dict(data)),
            "technical_evidence": copy.deepcopy(evidence),
        }

    def object_key(self, route: RouteContract, request: OperatorRequest) -> str:
        action = route.action
        if action == "capture.preview":
            value = document_digest(
                {
                    "project_id": request.project_id,
                    "action": action,
                    "input": request.input,
                }
            )
        elif action == "capture.admit":
            value = str(request.input.get("preview_id", "invalid"))
        else:
            value = str(request.input.get("workspace_id", "invalid"))
        return f"{request.project_id}:{action}:{value}"

    def current_version(self, route: RouteContract, request: OperatorRequest) -> str:
        action = route.action
        if action == "capture.preview":
            self._require_scope(request)
            payload, metadata = self._capture_bytes(request.input)
            preview_id = document_digest(
                {
                    "project_id": request.project_id,
                    "metadata": metadata,
                    "payload_sha256": _sha256(payload),
                }
            )
            self._preflight_upload_target(
                preview_id, metadata["filename"], payload
            )
            path = self._preview_path(preview_id)
            return (
                self._read_preview(preview_id)["preview_digest"]
                if path.exists()
                else "ABSENT"
            )
        if action == "capture.admit":
            if set(request.input) != {"preview_id", "preview_digest"}:
                raise ProtocolError(
                    "CAPTURE_APPROVAL_INVALID",
                    "capture admission requires one exact preview",
                )
            preview = self._read_preview(request.input.get("preview_id"))
            if request.input.get("preview_digest") != preview["preview_digest"]:
                raise ProtocolError(
                    "CAPTURE_PREVIEW_MISMATCH", "admission does not bind the exact preview"
                )
            self._upload_path(preview)
            self._verify_adapter_input(preview)
            admission_path = self._admission_path(preview["preview_id"])
            if admission_path.exists():
                admission = self._read_admission(preview["preview_id"])
                return str(admission["object_version"])
            return str(preview["preview_digest"])
        workspace_id = self._workspace_id(request.input)
        store = BoundedResearchWorkspaceStore(self.workspace)
        if action == "research.workspaces.create":
            self._validate_workspace_create(request)
            path = store.workspace_path(workspace_id)
            if not path.exists():
                return "ABSENT"
            return document_digest(read_json(path))
        current = store.current_source_set(workspace_id)
        head = current["source_set_digest"] if current is not None else "ABSENT"
        if action in {
            "research.search",
            "research.ask",
            "research.artifacts.create",
            "research.export",
        }:
            requested = request.input.get("source_set_digest")
            if requested != head:
                raise ProtocolError(
                    "RESEARCH_SOURCE_SET_STALE", "research source-set head changed"
                )
        if action not in {
            "research.sources.add",
            "research.sources.remove",
        } or head == request.expected_version:
            self._validate_research_intent(request, store, current)
        return str(head)

    def _preflight_upload_target(
        self, preview_id: str, filename: str, payload: bytes
    ) -> None:
        directory = self.uploads / preview_id
        require_no_symlink_components(
            self.root,
            directory,
            code="CAPTURE_UPLOAD_BOUNDARY",
            detail="capture upload path contains a symlink",
        )
        if not directory.exists():
            return
        if (
            directory.is_symlink()
            or not directory.is_dir()
            or directory.stat().st_uid != os.geteuid()
        ):
            raise ProtocolError(
                "CAPTURE_UPLOAD_BOUNDARY", "capture upload directory is unsafe"
            )
        folded = filename.casefold()
        for child in directory.iterdir():
            if child.is_symlink() or not child.is_file():
                raise ProtocolError(
                    "CAPTURE_UPLOAD_BOUNDARY", "capture upload target is unsafe"
                )
            if child.name.casefold() == folded and child.name != filename:
                raise ProtocolError(
                    "CAPTURE_UPLOAD_CASE_COLLISION",
                    "upload filenames collide by case",
                )
        target = directory / filename
        if target.exists() and target.read_bytes() != payload:
            raise ProtocolError(
                "CAPTURE_UPLOAD_BOUNDARY", "capture upload target is occupied"
            )

    def _validate_workspace_create(self, request: OperatorRequest) -> None:
        if set(request.input) != {"workspace_id", "name", "privacy_class"}:
            raise ProtocolError(
                "RESEARCH_WORKSPACE_INVALID", "research workspace request is not exact"
            )
        if request.input.get("privacy_class") != "PROJECT_PRIVATE":
            raise ProtocolError(
                "RESEARCH_SCOPE_DENIED", "research workspace must be project-private"
            )
        ResearchWorkspace.from_dict(
            {
                "schema_version": "hive.research-workspace.v1",
                "workspace_id": request.input["workspace_id"],
                "tenant_id": self.tenant_id,
                "project_id": str(request.project_id),
                "name": request.input.get("name"),
                "privacy_class": "PROJECT_PRIVATE",
                "created_at": _moment(self.now),
            }
        )

    @staticmethod
    def _retrieval_policy(value: Any) -> dict[str, Any]:
        if (
            not isinstance(value, dict)
            or set(value)
            != {"exact_first", "semantic_allowed", "max_results", "max_quote_bytes"}
            or value.get("exact_first") is not True
            or not isinstance(value.get("semantic_allowed"), bool)
            or not isinstance(value.get("max_results"), int)
            or isinstance(value.get("max_results"), bool)
            or not 1 <= value["max_results"] <= 100
            or not isinstance(value.get("max_quote_bytes"), int)
            or isinstance(value.get("max_quote_bytes"), bool)
            or not 32 <= value["max_quote_bytes"] <= 16_384
        ):
            raise ProtocolError(
                "RESEARCH_SOURCE_SET_NONCANONICAL",
                "research retrieval policy is invalid",
            )
        return copy.deepcopy(value)

    def _validate_research_intent(
        self,
        request: OperatorRequest,
        store: BoundedResearchWorkspaceStore,
        current: Mapping[str, Any] | None,
    ) -> None:
        action = request.action
        if action in {"research.sources.add", "research.sources.remove"}:
            add = action == "research.sources.add"
            expected = {"workspace_id", "source_id"} | (
                {"retrieval_policy"} if add else set()
            )
            if set(request.input) != expected:
                raise ProtocolError(
                    "RESEARCH_SOURCE_SET_NONCANONICAL",
                    "source-set request is not exact",
                )
            source_id = request.input.get("source_id")
            if not isinstance(source_id, str):
                raise ProtocolError("RESEARCH_SOURCE_ID_INVALID", "source ID is invalid")
            current_ids = (
                [item["source_id"] for item in current["source_set"].sources]
                if current is not None
                else []
            )
            if add:
                policy = self._retrieval_policy(request.input.get("retrieval_policy"))
                if current is not None and policy != current["source_set"].retrieval_policy:
                    raise ProtocolError(
                        "RESEARCH_SOURCE_SET_NONCANONICAL",
                        "source addition may not silently change retrieval policy",
                    )
                if source_id in current_ids:
                    raise ProtocolError(
                        "RESEARCH_SOURCE_ALREADY_PRESENT",
                        "source already belongs to source set",
                    )
                research_workspace = store.open_workspace(request.input["workspace_id"])
                store._current_record(source_id, research_workspace)
            else:
                if source_id not in current_ids:
                    raise ProtocolError("RESEARCH_SOURCE_ABSENT", "source is absent")
                if len(current_ids) == 1:
                    raise ProtocolError(
                        "RESEARCH_SOURCE_SET_EMPTY", "final source cannot be removed"
                    )
            return
        if action in {"research.search", "research.ask"}:
            operation = "search" if action == "research.search" else "ask"
            field = "query" if operation == "search" else "question"
            if set(request.input) != {
                "workspace_id",
                "source_set_digest",
                field,
                "limit",
            }:
                raise ProtocolError(
                    "RESEARCH_PAYLOAD_INVALID", "research query is not exact"
                )
            text = request.input.get(field)
            limit = request.input.get("limit")
            policy_limit = (
                current["source_set"].retrieval_policy["max_results"]
                if current is not None
                else 0
            )
            if (
                not isinstance(text, str)
                or not text.strip()
                or text != text.strip()
                or len(text.encode("utf-8")) > 64 * 1024
                or not isinstance(limit, int)
                or isinstance(limit, bool)
                or not 1 <= limit <= policy_limit
            ):
                raise ProtocolError(
                    "RESEARCH_PAYLOAD_INVALID", "research query is invalid or excessive"
                )
            return
        if action == "research.artifacts.create":
            expected = {
                "workspace_id",
                "source_set_digest",
                "artifact_type",
                "title",
                "research_result",
            }
            if set(request.input) != expected:
                raise ProtocolError(
                    "RESEARCH_PAYLOAD_INVALID", "artifact request is not exact"
                )
            artifact_type = request.input.get("artifact_type")
            title = request.input.get("title")
            if artifact_type not in ARTIFACT_TYPES:
                raise ProtocolError(
                    "RESEARCH_ARTIFACT_TYPE_INVALID", "research artifact type is invalid"
                )
            if (
                not isinstance(title, str)
                or not title.strip()
                or title != title.strip()
                or "\n" in title
                or len(title) > 256
            ):
                raise ProtocolError(
                    "RESEARCH_ARTIFACT_INPUT_INVALID",
                    "research artifact title is invalid",
                )
            verifier = ResearchArtifactStore(
                store,
                self.runtime / "artifact-preflight",
                signing_key=Ed25519PrivateKey.generate(),
            )
            verifier._verify_result(
                request.input["workspace_id"],
                request.input["source_set_digest"],
                request.input.get("research_result"),
            )
            return
        if action == "research.export":
            if set(request.input) != {
                "workspace_id",
                "source_set_digest",
                "filename",
                "preview_digest",
            }:
                raise ProtocolError(
                    "RESEARCH_EXPORT_SCOPE_INVALID", "export request is not exact"
                )
            if request.input.get("preview_digest") != request.input.get(
                "source_set_digest"
            ):
                raise ProtocolError(
                    "RESEARCH_EXPORT_PREVIEW_MISMATCH",
                    "export does not bind the exact source set",
                )
            filename = self._filename(request.input.get("filename"))
            if not filename.endswith(".tar.gz"):
                raise ProtocolError(
                    "RESEARCH_EXPORT_FILENAME_INVALID",
                    "research export requires .tar.gz",
                )

    @staticmethod
    def _workspace_id(document: Mapping[str, Any]) -> str:
        value = document.get("workspace_id")
        if not isinstance(value, str):
            raise ProtocolError(
                "RESEARCH_WORKSPACE_ID_INVALID", "research workspace ID is required"
            )
        BoundedResearchWorkspaceStore._slug(value)
        return value

    def mutate(
        self,
        route: RouteContract,
        request: OperatorRequest,
        *,
        operation_key: str,
    ) -> Mapping[str, Any]:
        existing = self._read_operation(operation_key, request)
        if existing is not None:
            return existing
        self._write_operation(operation_key, request, None)
        if route.action == "capture.preview":
            result = self._capture_preview(request, operation_key)
        elif route.action == "capture.admit":
            result = self._capture_admit(request, operation_key)
        elif route.action == "research.workspaces.create":
            result = self._research_workspace_create(request, operation_key)
        elif route.action in {"research.sources.add", "research.sources.remove"}:
            result = self._research_sources(request, operation_key)
        elif route.action in {"research.search", "research.ask"}:
            result = self._research_query(request, operation_key)
        elif route.action == "research.artifacts.create":
            result = self._research_artifact(request, operation_key)
        elif route.action == "research.export":
            result = self._research_export(request, operation_key)
        else:  # pragma: no cover - supports closes the action set
            raise ProtocolError("OPERATOR_DOMAIN_UNAVAILABLE", "lane action is unavailable")
        self._write_operation(operation_key, request, result)
        self._fault(f"{route.action}:after_domain_result")
        return result

    def recover(
        self,
        route: RouteContract,
        request: OperatorRequest,
        *,
        operation_key: str,
    ) -> Mapping[str, Any] | None:
        result = self._read_operation(operation_key, request)
        if result is not None:
            return result
        if route.action == "capture.admit":
            preview_id = request.input.get("preview_id")
            if isinstance(preview_id, str) and _SHA256.fullmatch(preview_id):
                path = self._admission_path(preview_id)
                if path.exists():
                    admission = self._read_admission(preview_id)
                    if (
                        admission.get("operation_key") == operation_key
                        and admission.get("request_digest") == request.digest
                        and isinstance(admission.get("result"), dict)
                    ):
                        self._write_operation(operation_key, request, admission["result"])
                        return copy.deepcopy(admission["result"])
            preview = self._read_preview(request.input.get("preview_id"))
            self._upload_path(preview)
            self._verify_adapter_input(preview)
            services = product_adapter_services(self.root)
            adapter_request = AdapterRequest.from_dict(preview["request"])
            invocation_key = adapter_operation_key(
                document_digest(preview["request"]),
                document_digest(preview["plan"]),
            )
            result_id = services.runtime.result_id(invocation_key)
            result_path = services.runtime.results / f"{result_id}.json"
            if result_path.exists():
                adapter_result = services.runtime.durable_result(
                    result_id,
                    preview["request"],
                    preview["plan"],
                    adapter_request,
                )
                result = self._admission_result(
                    request, operation_key, adapter_result
                )
                self._persist_admission(preview, request, operation_key, result)
                self._write_operation(operation_key, request, result)
                return result
            recovery_path = services.runtime.recovery / f"{adapter_request.request_id}.json"
            if recovery_path.exists():
                for journal_path in sorted(services.runtime.recovery.glob("*.json")):
                    journal = services.runtime.read_recovery_journal(journal_path)
                    if (
                        journal_path != recovery_path
                        and journal.get("state") != "TERMINAL"
                    ):
                        raise ProtocolError(
                            "ADAPTER_EFFECT_STATE_PENDING",
                            "another adapter effect requires separate attended recovery",
                        )
                services.runtime.recover_pending()
                if result_path.exists():
                    adapter_result = services.runtime.durable_result(
                        result_id,
                        preview["request"],
                        preview["plan"],
                        adapter_request,
                    )
                    result = self._admission_result(
                        request, operation_key, adapter_result
                    )
                    self._persist_admission(preview, request, operation_key, result)
                    self._write_operation(operation_key, request, result)
                    return result
            else:
                result = self._capture_admit(request, operation_key)
                self._write_operation(operation_key, request, result)
                return result
        if route.action == "capture.preview":
            payload, metadata = self._capture_bytes(request.input)
            preview_id = document_digest(
                {
                    "project_id": request.project_id,
                    "metadata": metadata,
                    "payload_sha256": _sha256(payload),
                }
            )
            path = self._preview_path(preview_id)
            if path.exists():
                preview = self._read_preview(preview_id)
                if (
                    preview.get("operator_operation_key") == operation_key
                    and preview.get("operator_request_digest") == request.digest
                ):
                    result = self._preview_result(request, operation_key, preview, path)
                    self._write_operation(operation_key, request, result)
                    return result
            result = self._capture_preview(request, operation_key)
            self._write_operation(operation_key, request, result)
            return result
        if route.action == "research.export":
            path = self._export_path(operation_key)
            if path.exists():
                export = self._read_export(operation_key, request)
                self._write_operation(operation_key, request, export["result"])
                return copy.deepcopy(export["result"])
        return None

    def _stage_upload(self, preview_id: str, filename: str, payload: bytes) -> Path:
        directory = self.uploads / preview_id
        ensure_owned_directory(
            self.root,
            directory,
            code="CAPTURE_UPLOAD_BOUNDARY",
            detail="capture upload directory is unsafe",
        )
        folded = filename.casefold()
        for child in directory.iterdir():
            if child.name.casefold() == folded and child.name != filename:
                raise ProtocolError(
                    "CAPTURE_UPLOAD_CASE_COLLISION", "upload filenames collide by case"
                )
        path = directory / filename
        require_no_symlink_components(
            self.root,
            path,
            code="CAPTURE_UPLOAD_BOUNDARY",
            detail="capture upload path contains a symlink",
        )
        if path.exists() or path.is_symlink():
            if path.is_symlink() or not path.is_file() or path.read_bytes() != payload:
                raise ProtocolError(
                    "CAPTURE_UPLOAD_BOUNDARY", "capture upload target is occupied"
                )
            return path
        atomic_write_bytes(path, payload, mode=0o600)
        return path

    def _adapter_file(self, services: Any, preview_id: str, filename: str, payload: bytes) -> Path:
        adapter = services.registry.require_current("nukotech.hive.local-capture").adapter
        staging_root = Path(adapter.staging_root)
        if staging_root != self._adapter_staging_root():
            raise ProtocolError(
                "CAPTURE_STAGING_BOUNDARY", "capture adapter staging root changed"
            )
        adapter._ensure_staging()
        directory = staging_root / "operator-shell-inputs" / preview_id
        ensure_owned_directory(
            staging_root,
            directory,
            code="CAPTURE_STAGING_BOUNDARY",
            detail="capture adapter input path is unsafe",
        )
        target = directory / filename
        if target.exists() or target.is_symlink():
            if target.is_symlink() or not target.is_file() or target.read_bytes() != payload:
                raise ProtocolError(
                    "CAPTURE_STAGING_BOUNDARY", "capture adapter input changed"
                )
        else:
            atomic_write_bytes(target, payload, mode=0o600)
        return target

    def _capture_preview(
        self, request: OperatorRequest, operation_key: str
    ) -> dict[str, Any]:
        self._require_scope(request)
        payload, metadata = self._capture_bytes(request.input)
        preview_id = document_digest(
            {
                "project_id": request.project_id,
                "metadata": metadata,
                "payload_sha256": _sha256(payload),
            }
        )
        preview_path = self._preview_path(preview_id)
        if preview_path.exists():
            raise ProtocolError("CAPTURE_PREVIEW_EXISTS", "capture preview already exists")
        upload = self._stage_upload(preview_id, metadata["filename"], payload)
        services = product_adapter_services(self.root)
        if metadata["kind"] == "text":
            adapter_payload = {
                "kind": metadata["adapter_kind"],
                "text": payload.decode("utf-8"),
                "title": metadata["title"],
            }
            adapter_input: str | None = None
        else:
            adapter_source = self._adapter_file(
                services, preview_id, metadata["filename"], payload
            )
            adapter_payload = {
                "kind": metadata["adapter_kind"],
                "path": str(adapter_source),
                "media_type": metadata["media_type"],
            }
            if metadata["channel"] == "FILE":
                adapter_payload["channel"] = "FILE"
            adapter_input = str(adapter_source)
        signed_request = self._signed_request(
            services,
            adapter_id="nukotech.hive.local-capture",
            capability=metadata["capability"],
            payload=adapter_payload,
            evidence=[metadata["sha256"]],
        )
        context = adapter_invocation_context(services, signed_request)
        plan = services.runtime.plan(signed_request, context)
        self._persist_request(services, signed_request)
        created_at = self.now
        document: dict[str, Any] = {
            "schema_version": _PREVIEW_SCHEMA,
            "preview_id": preview_id,
            "tenant_id": self.tenant_id,
            "project_id": str(request.project_id),
            "metadata": metadata,
            "upload_ref": upload.relative_to(self.root).as_posix(),
            "adapter_input": adapter_input,
            "request": signed_request,
            "plan": plan,
            "request_digest": document_digest(signed_request),
            "plan_digest": document_digest(plan),
            "operator_request_digest": request.digest,
            "operator_operation_key": operation_key,
            "created_at": _moment(created_at),
            "expires_at": _moment(created_at + _PREVIEW_TTL),
        }
        document["preview_digest"] = document_digest(document)
        atomic_write_json(preview_path, document, mode=0o600)
        self._fault("capture.preview:after_preview_record")
        return self._preview_result(request, operation_key, document, preview_path)

    def _preview_result(
        self,
        request: OperatorRequest,
        operation_key: str,
        document: Mapping[str, Any],
        preview_path: Path,
    ) -> dict[str, Any]:
        metadata = document["metadata"]
        evidence = [
            {
                "kind": "capture-preview",
                "ref": preview_path.relative_to(self.root).as_posix(),
                "sha256": _sha256_file(preview_path),
            }
        ]
        return self._result(
            request,
            operation_key,
            outcome="APPLIED",
            object_version=document["preview_digest"],
            changed=True,
            data={
                "preview_id": document["preview_id"],
                "upload_ref": document["upload_ref"],
                "filename": metadata["filename"],
                "channel": metadata["channel"],
                "media_type": metadata["media_type"],
                "original_sha256": metadata["sha256"],
                "size_bytes": metadata["size_bytes"],
                "request_digest": document["request_digest"],
                "plan_digest": document["plan_digest"],
                "side_effects": copy.deepcopy(document["plan"]["side_effects"]),
                "requires_approval": True,
                "expires_at": document["expires_at"],
            },
            evidence=evidence,
        )

    def _read_admission(self, preview_id: str) -> dict[str, Any]:
        document = read_json(self._admission_path(preview_id))
        if (
            set(document)
            != {
                "schema_version",
                "preview_id",
                "preview_digest",
                "operation_key",
                "request_digest",
                "object_version",
                "result",
                "result_digest",
            }
            or document.get("schema_version") != _ADMISSION_SCHEMA
            or document.get("preview_id") != preview_id
            or document.get("result_digest") != document_digest(document.get("result", {}))
            or document.get("object_version")
            != document.get("result", {}).get("object_version")
        ):
            raise ProtocolError(
                "CAPTURE_ADMISSION_RECOVERY_INVALID", "capture admission record changed"
            )
        return document

    def _admission_result(
        self,
        request: OperatorRequest,
        operation_key: str,
        adapter_result: Mapping[str, Any],
    ) -> dict[str, Any]:
        object_version = document_digest(adapter_result)
        admissions = adapter_result.get("detail", {}).get("admissions", [])
        if not isinstance(admissions, list) or not all(
            isinstance(item, Mapping) for item in admissions
        ):
            raise ProtocolError(
                "CAPTURE_ADMISSION_RECOVERY_INVALID",
                "capture adapter result is malformed",
            )
        source_ids = [item["source_id"] for item in admissions]
        capture_ids = [item["capture_id"] for item in admissions]
        evidence: list[dict[str, Any]] = []
        for item in admissions:
            ref = item.get("receipt_path")
            if not isinstance(ref, str):
                operation = item["capture_id"].removeprefix("capture:")
                ref = f".hive/receipts/capture-operation-{operation}.json"
            path = self.root / ref
            if path.is_file() and not path.is_symlink():
                evidence.append(
                    {
                        "kind": "capture-receipt",
                        "ref": ref,
                        "sha256": _sha256_file(path),
                    }
                )
        return self._result(
            request,
            operation_key,
            outcome="APPLIED",
            object_version=object_version,
            changed=True,
            data={
                "domain_outcome": adapter_result["outcome"],
                "capture_ids": capture_ids,
                "source_ids": source_ids,
                "admissions": copy.deepcopy(admissions),
                "local_only": True,
                "remote_fallback": False,
            },
            evidence=evidence
            or [
                {
                    "kind": "adapter-result",
                    "ref": f"adapter-result:{adapter_result['result_id']}",
                    "sha256": object_version,
                }
            ],
        )

    def _persist_admission(
        self,
        preview: Mapping[str, Any],
        request: OperatorRequest,
        operation_key: str,
        result: Mapping[str, Any],
    ) -> None:
        atomic_write_json(
            self._admission_path(str(preview["preview_id"])),
            {
                "schema_version": _ADMISSION_SCHEMA,
                "preview_id": preview["preview_id"],
                "preview_digest": preview["preview_digest"],
                "operation_key": operation_key,
                "request_digest": request.digest,
                "object_version": result["object_version"],
                "result": copy.deepcopy(dict(result)),
                "result_digest": document_digest(result),
            },
            mode=0o600,
        )

    def _capture_admit(
        self, request: OperatorRequest, operation_key: str
    ) -> dict[str, Any]:
        if set(request.input) != {"preview_id", "preview_digest"}:
            raise ProtocolError(
                "CAPTURE_APPROVAL_INVALID", "capture admission requires one exact preview"
            )
        preview = self._read_preview(request.input["preview_id"])
        if request.input["preview_digest"] != preview["preview_digest"]:
            raise ProtocolError(
                "CAPTURE_PREVIEW_MISMATCH", "capture admission preview binding changed"
            )
        self._upload_path(preview)
        admission_path = self._admission_path(preview["preview_id"])
        if admission_path.exists():
            raise ProtocolError("CAPTURE_ALREADY_ADMITTED", "capture preview was admitted")
        self._verify_adapter_input(preview)
        services = product_adapter_services(self.root)
        context = adapter_invocation_context(services, preview["request"])
        adapter_result = services.runtime.invoke(
            preview["request"], preview["plan"], context, None
        )
        self._fault("capture.admit:after_adapter_result")
        result = self._admission_result(request, operation_key, adapter_result)
        self._persist_admission(preview, request, operation_key, result)
        self._fault("capture.admit:after_admission_record")
        return result

    def _research_workspace_create(
        self, request: OperatorRequest, operation_key: str
    ) -> dict[str, Any]:
        if set(request.input) != {"workspace_id", "name", "privacy_class"}:
            raise ProtocolError(
                "RESEARCH_WORKSPACE_INVALID", "research workspace request is not exact"
            )
        workspace_id = self._workspace_id(request.input)
        if request.input["privacy_class"] != "PROJECT_PRIVATE":
            raise ProtocolError(
                "RESEARCH_SCOPE_DENIED", "research workspace must be project-private"
            )
        store = BoundedResearchWorkspaceStore(self.workspace)
        model = store.create_workspace(
            workspace_id=workspace_id,
            tenant_id=self.tenant_id,
            project_id=str(request.project_id),
            name=request.input["name"],
            privacy_class="PROJECT_PRIVATE",
            created_at=_moment(self.now),
        )
        path = store.workspace_path(workspace_id)
        version = document_digest(model.as_dict())
        return self._result(
            request,
            operation_key,
            outcome="APPLIED",
            object_version=version,
            changed=True,
            data={"workspace": model.as_dict()},
            evidence=[
                {
                    "kind": "research-workspace",
                    "ref": path.relative_to(self.root).as_posix(),
                    "sha256": _sha256_file(path),
                }
            ],
        )

    def _research_sources(
        self, request: OperatorRequest, operation_key: str
    ) -> dict[str, Any]:
        add = request.action == "research.sources.add"
        expected = {"workspace_id", "source_id"} | (
            {"retrieval_policy"} if add else set()
        )
        if set(request.input) != expected:
            raise ProtocolError(
                "RESEARCH_SOURCE_SET_NONCANONICAL", "source-set request is not exact"
            )
        workspace_id = self._workspace_id(request.input)
        store = BoundedResearchWorkspaceStore(self.workspace)
        current = store.current_source_set(workspace_id)
        current_digest = current["source_set_digest"] if current is not None else None
        expected_parent = (
            None if request.expected_version == "ABSENT" else request.expected_version
        )
        if current_digest != expected_parent:
            raise ProtocolError("RESEARCH_SOURCE_SET_STALE", "source-set head changed")
        current_ids = (
            [item["source_id"] for item in current["source_set"].sources]
            if current is not None
            else []
        )
        source_id = request.input["source_id"]
        if not isinstance(source_id, str):
            raise ProtocolError("RESEARCH_SOURCE_ID_INVALID", "source ID is invalid")
        if add:
            if source_id in current_ids:
                raise ProtocolError(
                    "RESEARCH_SOURCE_ALREADY_PRESENT", "source already belongs to source set"
                )
            source_ids = [*current_ids, source_id]
            policy = (
                request.input["retrieval_policy"]
                if current is None
                else current["source_set"].retrieval_policy
            )
        else:
            if source_id not in current_ids:
                raise ProtocolError("RESEARCH_SOURCE_ABSENT", "source is absent")
            source_ids = [item for item in current_ids if item != source_id]
            if not source_ids:
                raise ProtocolError(
                    "RESEARCH_SOURCE_SET_EMPTY", "final source cannot be removed"
                )
            policy = current["source_set"].retrieval_policy
        updated = store.update_source_set(
            workspace_id,
            expected_parent_digest=expected_parent,
            source_ids=source_ids,
            retrieval_policy=copy.deepcopy(policy),
            created_at=_moment(self.now),
        )
        version = updated["source_set_digest"]
        path = store.source_set_path(workspace_id, version)
        return self._result(
            request,
            operation_key,
            outcome="APPLIED",
            object_version=version,
            changed=True,
            data={
                "workspace_id": workspace_id,
                "source_set_digest": version,
                "parent_digest": updated["source_set"].parent_digest,
                "source_ids": [item["source_id"] for item in updated["source_set"].sources],
            },
            evidence=[
                {
                    "kind": "research-source-set",
                    "ref": path.relative_to(self.root).as_posix(),
                    "sha256": _sha256_file(path),
                }
            ],
        )

    def _invoke_research(
        self,
        workspace_id: str,
        capability: str,
        payload: dict[str, Any],
        evidence: list[str],
    ) -> dict[str, Any]:
        services = product_adapter_services(
            self.root, research_workspace_id=workspace_id
        )
        request = self._signed_request(
            services,
            adapter_id="nukotech.hive.bounded-research",
            capability=capability,
            payload=payload,
            evidence=evidence,
        )
        context = adapter_invocation_context(services, request)
        plan = services.runtime.plan(request, context)
        self._persist_request(services, request)
        return services.runtime.invoke(request, plan, context, None)

    def _research_query(
        self, request: OperatorRequest, operation_key: str
    ) -> dict[str, Any]:
        operation = "search" if request.action == "research.search" else "ask"
        field = "query" if operation == "search" else "question"
        if set(request.input) != {"workspace_id", "source_set_digest", field, "limit"}:
            raise ProtocolError("RESEARCH_PAYLOAD_INVALID", "research query is not exact")
        workspace_id = self._workspace_id(request.input)
        source_set = request.input["source_set_digest"]
        text = request.input[field]
        payload = {
            "operation": operation,
            "tenant_id": self.tenant_id,
            "workspace_id": workspace_id,
            "source_set_digest": source_set,
            field: text,
            "limit": request.input["limit"],
        }
        adapter_result = self._invoke_research(
            workspace_id,
            f"research.{operation}",
            payload,
            [hashlib.sha256(str(text).encode("utf-8")).hexdigest(), source_set],
        )
        detail = copy.deepcopy(adapter_result["detail"])
        if adapter_result["outcome"] in {"FAILED", "REFUSED"}:
            raise ProtocolError("RESEARCH_OPERATION_FAILED", "bounded research was refused")
        return self._result(
            request,
            operation_key,
            outcome="OK",
            object_version=source_set,
            changed=False,
            data=detail,
            evidence=[
                {
                    "kind": "research-result",
                    "ref": f"adapter-result:{adapter_result['result_id']}",
                    "sha256": document_digest(adapter_result),
                }
            ],
            reason_code=None,
        )

    def _research_artifact(
        self, request: OperatorRequest, operation_key: str
    ) -> dict[str, Any]:
        expected = {
            "workspace_id",
            "source_set_digest",
            "artifact_type",
            "title",
            "research_result",
        }
        if set(request.input) != expected:
            raise ProtocolError("RESEARCH_PAYLOAD_INVALID", "artifact request is not exact")
        workspace_id = self._workspace_id(request.input)
        source_set = request.input["source_set_digest"]
        research_result = request.input["research_result"]
        artifact_type = request.input["artifact_type"]
        title = request.input["title"]
        if artifact_type not in ARTIFACT_TYPES:
            raise ProtocolError(
                "RESEARCH_ARTIFACT_TYPE_INVALID", "research artifact type is invalid"
            )
        if (
            not isinstance(title, str)
            or not title.strip()
            or title != title.strip()
            or "\n" in title
            or len(title) > 256
        ):
            raise ProtocolError(
                "RESEARCH_ARTIFACT_INPUT_INVALID", "research artifact title is invalid"
            )
        payload = {
            "operation": "artifact",
            "tenant_id": self.tenant_id,
            "workspace_id": workspace_id,
            "source_set_digest": source_set,
            "artifact_type": artifact_type,
            "title": title,
            "research_result": copy.deepcopy(research_result),
        }
        adapter_result = self._invoke_research(
            workspace_id,
            "research.artifact",
            payload,
            [document_digest(research_result), source_set],
        )
        detail = copy.deepcopy(adapter_result["detail"])
        artifact_id = detail.get("artifact_id")
        artifact_digest = detail.get("artifact_digest")
        ref = detail.get("markdown_path", f"research-artifact:{artifact_id}")
        return self._result(
            request,
            operation_key,
            outcome="APPLIED",
            object_version=source_set,
            changed=True,
            data=detail,
            evidence=[
                {
                    "kind": "research-artifact",
                    "ref": str(ref),
                    "sha256": str(artifact_digest),
                }
            ],
        )

    def _export_external_root(self) -> Path:
        suffix = hashlib.sha256(str(self.root).encode("utf-8")).hexdigest()[:16]
        root = self.root.parent / f".nukotech-hive-research-exports-{suffix}"
        ensure_owned_directory(
            self.root.parent,
            root,
            code="RESEARCH_EXPORT_BOUNDARY",
            detail="research export staging root is unsafe",
        )
        return root

    def _export_path(self, operation_key: str) -> Path:
        return self._runtime_path(self.exports, operation_key)

    def _read_export(
        self, operation_key: str, request: OperatorRequest
    ) -> dict[str, Any]:
        document = read_json(self._export_path(operation_key))
        if (
            set(document)
            != {
                "schema_version",
                "operation_key",
                "request_digest",
                "result",
                "result_digest",
            }
            or document.get("schema_version") != _EXPORT_SCHEMA
            or document.get("operation_key") != operation_key
            or document.get("request_digest") != request.digest
            or not isinstance(document.get("result"), dict)
            or document.get("result_digest") != document_digest(document["result"])
        ):
            raise ProtocolError(
                "RESEARCH_EXPORT_RECOVERY_INVALID", "research export record changed"
            )
        result = document["result"]
        ref = result.get("data", {}).get("download_ref")
        digest = result.get("data", {}).get("sha256")
        if not isinstance(ref, str) or not isinstance(digest, str):
            raise ProtocolError(
                "RESEARCH_EXPORT_RECOVERY_INVALID", "research export binding is invalid"
            )
        target = self.root / ref
        require_no_symlink_components(
            self.root,
            target,
            code="RESEARCH_EXPORT_RECOVERY_INVALID",
            detail="research export path contains a symlink",
        )
        if target.is_symlink() or not target.is_file() or _sha256_file(target) != digest:
            raise ProtocolError(
                "RESEARCH_EXPORT_RECOVERY_INVALID", "research export bytes changed"
            )
        return document

    def _research_export(
        self, request: OperatorRequest, operation_key: str
    ) -> dict[str, Any]:
        if set(request.input) != {
            "workspace_id",
            "source_set_digest",
            "filename",
            "preview_digest",
        }:
            raise ProtocolError("RESEARCH_EXPORT_SCOPE_INVALID", "export request is not exact")
        workspace_id = self._workspace_id(request.input)
        source_set = request.input["source_set_digest"]
        if request.input["preview_digest"] != source_set:
            raise ProtocolError(
                "RESEARCH_EXPORT_PREVIEW_MISMATCH", "export does not bind the exact source set"
            )
        filename = self._filename(request.input["filename"])
        if not filename.endswith(".tar.gz"):
            raise ProtocolError(
                "RESEARCH_EXPORT_FILENAME_INVALID", "research export requires .tar.gz"
            )
        services = product_adapter_services(
            self.root, research_workspace_id=workspace_id
        )
        external_root = self._export_external_root()
        external = external_root / f"{operation_key}-{filename}"
        scope = {
            "root": str(external_root),
            "bundle": str(external),
            "workspace_id": workspace_id,
            "source_set_digest": source_set,
        }
        grant = services.authority.resolve(
            public_key_id(services.request_key.public_key()),
            "nukotech.hive.bounded-research",
        )
        plan = services.lifecycle.plan(
            "nukotech.hive.bounded-research", "export", scope, grant.project_id
        )
        adapter_result = services.lifecycle.export(
            "nukotech.hive.bounded-research", scope, plan
        )
        if not external.is_file() or external.is_symlink():
            raise ProtocolError("RESEARCH_EXPORT_RECOVERY_INVALID", "export bundle is absent")
        digest = _sha256_file(external)
        detail_digest = adapter_result.get("detail", {}).get("sha256")
        if digest != detail_digest:
            raise ProtocolError("RESEARCH_EXPORT_RECOVERY_INVALID", "export bundle changed")
        target_dir = self.downloads / operation_key
        ensure_owned_directory(
            self.root,
            target_dir,
            code="RESEARCH_EXPORT_BOUNDARY",
            detail="operator download path is unsafe",
        )
        target = target_dir / filename
        atomic_write_bytes(target, external.read_bytes(), mode=0o600)
        download_ref = target.relative_to(self.root).as_posix()
        result = self._result(
            request,
            operation_key,
            outcome="APPLIED",
            object_version=source_set,
            changed=True,
            data={
                "workspace_id": workspace_id,
                "source_set_digest": source_set,
                "download_ref": download_ref,
                "sha256": digest,
                "artifact_ids": copy.deepcopy(
                    adapter_result.get("detail", {}).get("artifact_ids", [])
                ),
            },
            evidence=[
                {"kind": "research-export", "ref": download_ref, "sha256": digest}
            ],
        )
        atomic_write_json(
            self._export_path(operation_key),
            {
                "schema_version": _EXPORT_SCHEMA,
                "operation_key": operation_key,
                "request_digest": request.digest,
                "result": result,
                "result_digest": document_digest(result),
            },
            mode=0o600,
        )
        self._fault("research.export:after_export_record")
        return result

    def expire_unadmitted(self, now: datetime) -> list[str]:
        self._ensure_runtime()
        expired: list[str] = []
        for path in sorted(self.previews.glob("*.json")):
            if path.is_symlink() or not path.is_file():
                raise ProtocolError(
                    "CAPTURE_PREVIEW_INVALID", "capture preview path is unsafe"
                )
            preview_id = path.stem
            preview = self._read_preview(preview_id, allow_expired=True)
            if self._admission_path(preview_id).exists():
                continue
            if _parse_time(
                preview["expires_at"], code="CAPTURE_PREVIEW_INVALID"
            ) > now.astimezone(timezone.utc):
                continue
            upload = self.root / preview["upload_ref"]
            if upload.is_symlink():
                raise ProtocolError("CAPTURE_UPLOAD_BOUNDARY", "expired upload is a symlink")
            if upload.is_file():
                upload.unlink()
            candidate = self._expected_adapter_input(preview)
            if candidate is not None:
                if candidate.is_symlink():
                    raise ProtocolError(
                        "CAPTURE_STAGING_BOUNDARY", "expired adapter input is a symlink"
                    )
                if candidate.is_file():
                    candidate.unlink()
            path.unlink()
            expired.append(preview_id)
        return expired
