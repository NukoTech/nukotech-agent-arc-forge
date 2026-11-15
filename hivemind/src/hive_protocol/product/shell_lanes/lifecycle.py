"""Exact provider, adapter, and portable lifecycle controls for the M4 shell."""

from __future__ import annotations

import copy
import dataclasses
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping
from uuid import NAMESPACE_URL, uuid5

from hive_protocol.adapters.execution import operation_key as adapter_operation_key
from hive_protocol.adapters.models import (
    AdapterPlan,
    AdapterRequest,
    validate_adapter_document,
)
from hive_protocol.adapters.policy import authorize_adapter_request
from hive_protocol.adapters.security import reject_credential_values
from hive_protocol.core import (
    ProtocolError,
    canonical_bytes,
    document_digest,
    public_key_id,
    sign_document,
    verify_document,
)
from hive_protocol.storage import (
    atomic_write_json,
    ensure_owned_directory,
    read_json,
    require_no_symlink_components,
)

from ..shell_contracts import OperatorRequest, RouteContract
from ..agent_adapter import adapter_invocation_context, adapter_status, product_adapter_services
from ..workspace import HiveWorkspace


_SHA256 = __import__("re").compile(r"^[0-9a-f]{64}$")
_ACTIONS = frozenset(
    {
        "settings.provider.preview",
        "settings.provider.apply",
        "settings.adapters.plan",
        "settings.adapters.invoke",
        "settings.lifecycle.preview",
        "settings.lifecycle.approve",
        "settings.lifecycle.apply",
        "settings.snapshot",
        "settings.export",
        "settings.reopen",
        "settings.rollback",
    }
)
_PREVIEW_SCHEMA = "hive.operator-provider-preview.v1"
_OPERATION_SCHEMA = "hive.operator-settings-lifecycle-operation.v1"


def _moment(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class SettingsLifecycleLane:
    """Compose existing authorities without probing or inventing authority."""

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
        self.previews = self.runtime / "provider-previews"
        self.adapter_plans = self.runtime / "adapter-plans"
        self.lifecycle_plans = self.runtime / "lifecycle-plans"
        self.lifecycle_approvals = self.runtime / "lifecycle-approvals"
        self.hive_checkpoints = self.runtime / "hive-checkpoints"
        self.operations = self.runtime / "lanes" / "settings-lifecycle" / "operations"

    @staticmethod
    def supports(action: str) -> bool:
        return action in _ACTIONS

    def _fault(self, stage: str) -> None:
        if self.fault_hook is not None:
            self.fault_hook(stage)

    def _ensure_runtime(self) -> None:
        for directory in (
            self.runtime,
            self.previews,
            self.adapter_plans,
            self.lifecycle_plans,
            self.lifecycle_approvals,
            self.hive_checkpoints,
            self.operations,
        ):
            ensure_owned_directory(
                self.root,
                directory,
                code="OPERATOR_RUNTIME_BOUNDARY",
                detail="settings lifecycle runtime path is unsafe",
            )

    def _runtime_path(self, root: Path, identifier: str) -> Path:
        self._ensure_runtime()
        if not isinstance(identifier, str) or _SHA256.fullmatch(identifier) is None:
            raise ProtocolError(
                "OPERATOR_RUNTIME_BOUNDARY", "settings runtime identifier is invalid"
            )
        path = root / f"{identifier}.json"
        require_no_symlink_components(
            self.root,
            path,
            code="OPERATOR_RUNTIME_BOUNDARY",
            detail="settings runtime path contains a symlink",
        )
        if path.is_symlink():
            raise ProtocolError(
                "OPERATOR_RUNTIME_BOUNDARY", "settings runtime path is a symlink"
            )
        return path

    def _config(self) -> tuple[dict[str, Any], str]:
        config = read_json(self.workspace.config_path)
        self.workspace._validate_config(config)
        return config, document_digest(config)

    @staticmethod
    def _provider_input(document: Mapping[str, Any]) -> dict[str, Any]:
        if set(document) != {"mode", "model"}:
            raise ProtocolError(
                "PROVIDER_PREVIEW_INVALID", "provider preview input is not exact"
            )
        return HiveWorkspace._provider_selection(
            document.get("mode"), document.get("model")
        )

    def _preview_id(
        self, request: OperatorRequest, before_sha256: str, provider: Mapping[str, Any]
    ) -> str:
        return document_digest(
            {
                "schema_version": "hive.operator-provider-intent.v1",
                "tenant_id": request.tenant_id,
                "project_id": request.project_id,
                "before_sha256": before_sha256,
                "provider": dict(provider),
            }
        )

    def _preview_path(self, preview_id: str) -> Path:
        return self._runtime_path(self.previews, preview_id)

    def _read_preview(self, preview_id: Any) -> dict[str, Any]:
        if not isinstance(preview_id, str) or _SHA256.fullmatch(preview_id) is None:
            raise ProtocolError("PROVIDER_PREVIEW_INVALID", "provider preview ID is invalid")
        path = self._preview_path(preview_id)
        if not path.is_file() or path.is_symlink():
            raise ProtocolError("PROVIDER_PREVIEW_INVALID", "provider preview is absent")
        preview = read_json(path)
        expected = {
            "schema_version",
            "preview_id",
            "tenant_id",
            "project_id",
            "before_sha256",
            "after_sha256",
            "proposed_provider",
            "updated_at",
            "created_at",
            "expires_at",
            "availability_state",
            "provider_attempted",
            "execution_started",
        }
        if (
            set(preview) != expected
            or preview.get("schema_version") != _PREVIEW_SCHEMA
            or preview.get("preview_id") != preview_id
            or preview.get("tenant_id") != self.tenant_id
            or preview.get("project_id") not in self.project_ids
            or _SHA256.fullmatch(str(preview.get("before_sha256", ""))) is None
            or _SHA256.fullmatch(str(preview.get("after_sha256", ""))) is None
            or preview.get("provider_attempted") is not False
            or preview.get("execution_started") is not False
            or not isinstance(preview.get("proposed_provider"), dict)
        ):
            raise ProtocolError("PROVIDER_PREVIEW_INVALID", "provider preview changed")
        provider = self._provider_input(preview["proposed_provider"])
        if provider != preview["proposed_provider"]:
            raise ProtocolError("PROVIDER_PREVIEW_INVALID", "provider preview changed")
        return preview

    def _operation_path(self, operation_key: str) -> Path:
        return self._runtime_path(self.operations, operation_key)

    def _adapter_plan_path(self, request_digest: str) -> Path:
        return self._runtime_path(self.adapter_plans, request_digest)

    def _lifecycle_plan_path(self, request_digest: str) -> Path:
        return self._runtime_path(self.lifecycle_plans, request_digest)

    def _lifecycle_approval_path(self, plan_digest: str) -> Path:
        return self._runtime_path(self.lifecycle_approvals, plan_digest)

    def _checkpoint_path(self, checkpoint_id: str) -> Path:
        return self._runtime_path(self.hive_checkpoints, checkpoint_id)

    def _portable_manifest(self, commit: str | None = None) -> dict[str, Any]:
        manifest = {
            "schema_version": "hive.operator-portable-manifest.v1",
            "files": self.workspace.portable_manifest(commit),
        }
        return manifest

    def _portable_state_version(self) -> str:
        return document_digest(self._portable_manifest())

    def _read_checkpoint(self, supplied: Any) -> dict[str, Any]:
        if not isinstance(supplied, dict):
            raise ProtocolError(
                "ROLLBACK_CHECKPOINT_INVALID", "rollback checkpoint is invalid"
            )
        checkpoint_id = supplied.get("checkpoint_id")
        if not isinstance(checkpoint_id, str) or _SHA256.fullmatch(checkpoint_id) is None:
            raise ProtocolError(
                "ROLLBACK_CHECKPOINT_INVALID", "rollback checkpoint ID is invalid"
            )
        path = self._checkpoint_path(checkpoint_id)
        if not path.is_file() or path.is_symlink():
            raise ProtocolError(
                "ROLLBACK_CHECKPOINT_INVALID", "rollback checkpoint is absent"
            )
        checkpoint = read_json(path)
        expected = {
            "schema_version",
            "checkpoint_id",
            "commit",
            "message",
            "portable_manifest",
            "portable_manifest_sha256",
            "created_at",
            "receipt_id",
            "receipt_ref",
            "receipt_sha256",
        }
        if (
            set(checkpoint) != expected
            or checkpoint.get("schema_version")
            != "hive.operator-hive-checkpoint.v1"
            or checkpoint != supplied
            or checkpoint.get("checkpoint_id") != checkpoint_id
            or not isinstance(checkpoint.get("portable_manifest"), list)
            or checkpoint.get("portable_manifest_sha256")
            != document_digest(
                {
                    "schema_version": "hive.operator-portable-manifest.v1",
                    "files": checkpoint.get("portable_manifest"),
                }
            )
        ):
            raise ProtocolError(
                "ROLLBACK_CHECKPOINT_INVALID", "rollback checkpoint changed"
            )
        identity = document_digest(
            {
                "schema_version": checkpoint["schema_version"],
                "commit": checkpoint["commit"],
                "message": checkpoint["message"],
                "portable_manifest_sha256": checkpoint[
                    "portable_manifest_sha256"
                ],
                "receipt_id": checkpoint["receipt_id"],
                "receipt_sha256": checkpoint["receipt_sha256"],
            }
        )
        if identity != checkpoint_id:
            raise ProtocolError(
                "ROLLBACK_CHECKPOINT_INVALID", "rollback checkpoint identity changed"
            )
        receipt_ref = checkpoint["receipt_ref"]
        if not isinstance(receipt_ref, str):
            raise ProtocolError(
                "ROLLBACK_CHECKPOINT_INVALID",
                "rollback checkpoint receipt reference is invalid",
            )
        relative_receipt = PurePosixPath(receipt_ref)
        if (
            relative_receipt.is_absolute()
            or relative_receipt.as_posix() != receipt_ref
            or len(relative_receipt.parts) != 3
            or relative_receipt.parts[:2] != (".hive", "receipts")
            or any(part in {"", ".", ".."} for part in relative_receipt.parts)
        ):
            raise ProtocolError(
                "ROLLBACK_CHECKPOINT_INVALID",
                "rollback checkpoint receipt path is unsafe",
            )
        receipt_path = self.root.joinpath(*relative_receipt.parts)
        require_no_symlink_components(
            self.root,
            receipt_path,
            code="ROLLBACK_CHECKPOINT_INVALID",
            detail="rollback checkpoint receipt path is unsafe",
        )
        if (
            receipt_path.is_symlink()
            or not receipt_path.is_file()
            or _sha256_file(receipt_path) != checkpoint["receipt_sha256"]
        ):
            raise ProtocolError(
                "ROLLBACK_CHECKPOINT_INVALID",
                "rollback checkpoint receipt bytes changed",
            )
        receipt = read_json(receipt_path)
        if (
            receipt.get("schema_version") != "nukotech.hive-local.receipt.v1"
            or receipt.get("receipt_id") != checkpoint["receipt_id"]
            or receipt.get("kind") != "git-snapshot"
            or receipt.get("recorded_at") != checkpoint["created_at"]
            or receipt.get("detail")
            != {
                "commit": checkpoint["commit"],
                "message": checkpoint["message"],
            }
            or not receipt_path.name.endswith(
                f"-{checkpoint['receipt_id']}-git-snapshot.json"
            )
        ):
            raise ProtocolError(
                "ROLLBACK_CHECKPOINT_INVALID",
                "rollback checkpoint receipt binding changed",
            )
        manifest = self._portable_manifest(str(checkpoint["commit"]))
        if (
            manifest["files"] != checkpoint["portable_manifest"]
            or document_digest(manifest) != checkpoint["portable_manifest_sha256"]
        ):
            raise ProtocolError(
                "ROLLBACK_CHECKPOINT_INVALID", "rollback checkpoint tree changed"
            )
        return checkpoint

    def _operator_receipt(
        self, kind: str, request_digest: str
    ) -> tuple[dict[str, Any], Path] | None:
        if not self.workspace.receipts.exists():
            return None
        for path in sorted(self.workspace.receipts.glob("*.json")):
            if path.is_symlink() or not path.is_file():
                raise ProtocolError(
                    "OPERATOR_LIFECYCLE_RECEIPT_INVALID",
                    "operator lifecycle receipt is unsafe",
                )
            receipt = read_json(path)
            detail = receipt.get("detail")
            if (
                receipt.get("schema_version") == "nukotech.hive-local.receipt.v1"
                and receipt.get("kind") == kind
                and isinstance(detail, dict)
                and detail.get("request_digest") == request_digest
            ):
                return receipt, path
        return None

    def _adapter_plan_input(self, document: Mapping[str, Any]) -> dict[str, Any]:
        if set(document) != {
            "adapter_id",
            "capability_id",
            "payload",
            "evidence_sha256",
        }:
            raise ProtocolError(
                "ADAPTER_REQUEST_INVALID", "adapter plan input is not exact"
            )
        adapter_id = document.get("adapter_id")
        capability_id = document.get("capability_id")
        payload = document.get("payload")
        evidence = document.get("evidence_sha256")
        if (
            not isinstance(adapter_id, str)
            or not isinstance(capability_id, str)
            or not isinstance(payload, dict)
            or not isinstance(evidence, list)
            or not all(
                isinstance(item, str) and _SHA256.fullmatch(item) is not None
                for item in evidence
            )
            or evidence != sorted(set(evidence))
        ):
            raise ProtocolError(
                "ADAPTER_REQUEST_INVALID", "adapter plan input is invalid"
            )
        available = {item["adapter_id"]: item for item in adapter_status(self.root)}
        if adapter_id not in available:
            raise ProtocolError("ADAPTER_NOT_REGISTERED", "adapter is not registered")
        return {
            "adapter_id": adapter_id,
            "capability_id": capability_id,
            "payload": copy.deepcopy(payload),
            "evidence_sha256": list(evidence),
        }

    @staticmethod
    def _adapter_request_id(operation_key: str) -> str:
        return str(uuid5(NAMESPACE_URL, f"hive-operator-adapter:{operation_key}"))

    def _adapter_request_path(self, services: Any, operation_key: str) -> Path:
        requests_root = services.runtime.root / "requests"
        services.runtime.require_owned_directory(requests_root)
        path = requests_root / f"{self._adapter_request_id(operation_key)}.json"
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise ProtocolError(
                "ADAPTER_PLAN_RECOVERY_INVALID",
                "stored adapter request is unsafe",
            )
        return path

    def _store_adapter_request(
        self, services: Any, operation_key: str, request_document: Mapping[str, Any]
    ) -> Path:
        path = self._adapter_request_path(services, operation_key)
        if path.exists():
            if canonical_bytes(read_json(path)) != canonical_bytes(request_document):
                raise ProtocolError(
                    "ADAPTER_PLAN_RECOVERY_INVALID",
                    "stored adapter request changed",
                )
        else:
            atomic_write_json(path, request_document, mode=0o600)
        return path

    def _validate_recoverable_adapter_request(
        self,
        services: Any,
        request: OperatorRequest,
        operation_key: str,
        normalized: Mapping[str, Any],
        request_document: Mapping[str, Any],
    ) -> tuple[AdapterRequest, Any, Any]:
        try:
            validate_adapter_document(
                "adapter-request.v1.schema.json", request_document
            )
            reject_credential_values(
                request_document,
                location="recovered adapter request",
                verified_by=services.runtime.trusted_request_keys,
            )
            verify_document(request_document, services.runtime.trusted_request_keys)
            parsed = AdapterRequest.from_dict(request_document)
            context = adapter_invocation_context(services, dict(request_document))
            entry = services.registry.require(
                parsed.adapter_id, parsed.adapter_version
            )
            grant = services.authority.resolve(
                str(request_document["signature"]["key_id"]), parsed.adapter_id
            )
        except (KeyError, ProtocolError) as exc:
            raise ProtocolError(
                "ADAPTER_PLAN_RECOVERY_INVALID",
                "stored adapter request is not authentic and authorized",
            ) from exc
        if (
            parsed.request_id != self._adapter_request_id(operation_key)
            or parsed.nonce != operation_key
            or parsed.adapter_id != normalized["adapter_id"]
            or parsed.adapter_version
            != services.manifests[normalized["adapter_id"]]["version"]
            or parsed.capability_id != normalized["capability_id"]
            or parsed.project_id != grant.project_id
            or parsed.authorization_ref != grant.authorization_ref
            or parsed.sender != grant.identity
            or parsed.payload != normalized["payload"]
            or parsed.evidence_sha256 != normalized["evidence_sha256"]
            or request.project_id != parsed.project_id
        ):
            raise ProtocolError(
                "ADAPTER_PLAN_RECOVERY_INVALID",
                "stored adapter request does not bind the operator request",
            )
        return parsed, context, entry

    def _recover_runtime_adapter_plan(
        self,
        services: Any,
        request_document: Mapping[str, Any],
        parsed_request: AdapterRequest,
        context: Any,
        entry: Any,
    ) -> dict[str, Any] | None:
        request_sha256 = document_digest(request_document)
        if not services.runtime.plans.exists():
            return None
        decision = authorize_adapter_request(
            entry.manifest,
            parsed_request,
            context,
            revoked=services.registry.is_revoked(parsed_request.adapter_id),
        )
        expected_policy_digest = document_digest(dataclasses.asdict(decision))
        matches: list[dict[str, Any]] = []
        for path in sorted(services.runtime.plans.glob("*.json")):
            if path.is_symlink() or not path.is_file():
                raise ProtocolError(
                    "ADAPTER_PLAN_RECOVERY_INVALID",
                    "stored adapter plan path is unsafe",
                )
            candidate = read_json(path)
            if candidate.get("request_digest") != request_sha256:
                continue
            try:
                validate_adapter_document(
                    "adapter-plan.v1.schema.json", candidate
                )
                reject_credential_values(
                    candidate,
                    location="recovered adapter plan",
                    verified_by=services.runtime.verification_keys(),
                )
                verify_document(
                    candidate,
                    services.runtime.verification_keys(),
                )
                plan = AdapterPlan.from_dict(candidate)
            except ProtocolError as exc:
                raise ProtocolError(
                    "ADAPTER_PLAN_RECOVERY_INVALID",
                    "stored adapter plan is not authentic",
                ) from exc
            if (
                path.name != f"{plan.plan_id}.json"
                or plan.manifest_digest != entry.manifest_digest
                or plan.policy_digest != expected_policy_digest
                or plan.adapter_id != parsed_request.adapter_id
                or plan.adapter_version != parsed_request.adapter_version
                or plan.capability_id != parsed_request.capability_id
                or plan.project_id != parsed_request.project_id
            ):
                raise ProtocolError(
                    "ADAPTER_PLAN_RECOVERY_INVALID",
                    "stored adapter plan does not bind the signed request",
                )
            matches.append(candidate)
        if len(matches) > 1:
            raise ProtocolError(
                "ADAPTER_PLAN_RECOVERY_INVALID",
                "multiple signed plans bind the same adapter request",
            )
        return matches[0] if matches else None

    def _store_adapter_plan_record(
        self,
        request: OperatorRequest,
        normalized: Mapping[str, Any],
        request_document: Mapping[str, Any],
        plan_document: Mapping[str, Any],
    ) -> tuple[dict[str, Any], Path]:
        record = {
            "schema_version": "hive.operator-adapter-plan.v1",
            "operator_request_digest": request.digest,
            "input_digest": document_digest(normalized),
            "request": copy.deepcopy(dict(request_document)),
            "request_digest": document_digest(request_document),
            "plan": copy.deepcopy(dict(plan_document)),
            "plan_digest": document_digest(plan_document),
        }
        path = self._adapter_plan_path(request.digest)
        if path.exists() and canonical_bytes(read_json(path)) != canonical_bytes(record):
            raise ProtocolError(
                "ADAPTER_PLAN_RECOVERY_INVALID",
                "operator adapter plan bridge changed",
            )
        atomic_write_json(path, record, mode=0o600)
        return record, path

    def _adapter_plan_result(
        self,
        request: OperatorRequest,
        operation_key: str,
        record: Mapping[str, Any],
        path: Path,
    ) -> dict[str, Any]:
        return self._result(
            request,
            operation_key,
            outcome="APPLIED",
            object_version=str(record["plan_digest"]),
            changed=True,
            data={
                "request": record["request"],
                "plan": record["plan"],
                "execution_started": False,
            },
            evidence=[
                {
                    "kind": "adapter-plan",
                    "ref": path.relative_to(self.root).as_posix(),
                    "sha256": _sha256_file(path),
                }
            ],
        )

    def _read_adapter_plan(self, operator_request_digest: str) -> dict[str, Any]:
        path = self._adapter_plan_path(operator_request_digest)
        if not path.is_file() or path.is_symlink():
            raise ProtocolError("ADAPTER_PLAN_INVALID", "operator adapter plan is absent")
        record = read_json(path)
        if (
            set(record)
            != {
                "schema_version",
                "operator_request_digest",
                "input_digest",
                "request",
                "request_digest",
                "plan",
                "plan_digest",
            }
            or record.get("schema_version") != "hive.operator-adapter-plan.v1"
            or record.get("operator_request_digest") != operator_request_digest
            or not isinstance(record.get("request"), dict)
            or not isinstance(record.get("plan"), dict)
            or record.get("request_digest") != document_digest(record["request"])
            or record.get("plan_digest") != document_digest(record["plan"])
            or record["plan"].get("request_digest") != record["request_digest"]
        ):
            raise ProtocolError("ADAPTER_PLAN_INVALID", "operator adapter plan changed")
        try:
            services = product_adapter_services(self.root)
            request_document = record["request"]
            validate_adapter_document(
                "adapter-request.v1.schema.json", request_document
            )
            reject_credential_values(
                request_document,
                location="stored operator adapter request",
                verified_by=services.runtime.trusted_request_keys,
            )
            verify_document(
                request_document, services.runtime.trusted_request_keys
            )
            parsed = AdapterRequest.from_dict(request_document)
            if (
                _SHA256.fullmatch(parsed.nonce) is None
                or parsed.request_id != self._adapter_request_id(parsed.nonce)
            ):
                raise ProtocolError(
                    "ADAPTER_PLAN_INVALID",
                    "stored adapter request identity changed",
                )
            request_path = self._adapter_request_path(services, parsed.nonce)
            if (
                not request_path.exists()
                or canonical_bytes(read_json(request_path))
                != canonical_bytes(request_document)
            ):
                raise ProtocolError(
                    "ADAPTER_PLAN_INVALID",
                    "stored adapter request bytes changed",
                )
            context = adapter_invocation_context(services, request_document)
            entry = services.registry.require(
                parsed.adapter_id, parsed.adapter_version
            )
            recovered_plan = self._recover_runtime_adapter_plan(
                services, request_document, parsed, context, entry
            )
            if (
                recovered_plan is None
                or canonical_bytes(recovered_plan)
                != canonical_bytes(record["plan"])
            ):
                raise ProtocolError(
                    "ADAPTER_PLAN_INVALID",
                    "operator bridge does not bind the authentic runtime plan",
                )
        except ProtocolError as exc:
            if exc.code == "ADAPTER_PLAN_INVALID":
                raise
            raise ProtocolError(
                "ADAPTER_PLAN_INVALID",
                "operator adapter plan authenticity check failed",
            ) from exc
        return record

    @staticmethod
    def _adapter_invoke_input(document: Mapping[str, Any]) -> tuple[dict, dict, Any]:
        if set(document) != {"request", "plan", "approval"}:
            raise ProtocolError(
                "ADAPTER_INVOCATION_INVALID", "adapter invocation input is not exact"
            )
        request = document.get("request")
        plan = document.get("plan")
        approval = document.get("approval")
        if (
            not isinstance(request, dict)
            or not isinstance(plan, dict)
            or (approval is not None and not isinstance(approval, dict))
        ):
            raise ProtocolError(
                "ADAPTER_INVOCATION_INVALID", "adapter invocation documents are invalid"
            )
        validate_adapter_document("adapter-request.v1.schema.json", request)
        validate_adapter_document("adapter-plan.v1.schema.json", plan)
        if approval is not None:
            validate_adapter_document("adapter-approval.v1.schema.json", approval)
        if plan.get("request_digest") != document_digest(request):
            raise ProtocolError(
                "ADAPTER_PLAN_REQUEST_MISMATCH", "adapter plan binds another request"
            )
        return request, plan, approval

    def _adapter_result(self, services: Any, request: dict, plan: dict) -> dict | None:
        invocation_key = adapter_operation_key(
            document_digest(request), document_digest(plan)
        )
        result_id = services.runtime.result_id(invocation_key)
        path = services.runtime.results / f"{result_id}.json"
        if not path.exists():
            return None
        return services.runtime.durable_result(
            result_id,
            request,
            plan,
            AdapterRequest.from_dict(request),
        )

    @staticmethod
    def _lifecycle_preview_input(document: Mapping[str, Any]) -> tuple[str, str, dict]:
        if set(document) != {"adapter_id", "operation", "payload"}:
            raise ProtocolError(
                "ADAPTER_LIFECYCLE_INPUT_INVALID",
                "lifecycle preview input is not exact",
            )
        adapter_id = document.get("adapter_id")
        operation = document.get("operation")
        payload = document.get("payload")
        if (
            not isinstance(adapter_id, str)
            or operation not in {"export", "rollback", "uninstall"}
            or not isinstance(payload, dict)
        ):
            raise ProtocolError(
                "ADAPTER_LIFECYCLE_INPUT_INVALID", "lifecycle preview is invalid"
            )
        return adapter_id, operation, copy.deepcopy(payload)

    def _recover_runtime_lifecycle_plan(
        self,
        services: Any,
        adapter_id: str,
        operation: str,
        payload: Mapping[str, Any],
        project_id: str,
    ) -> dict[str, Any] | None:
        if not services.runtime.plans.exists():
            return None
        entry = services.registry.require_current(adapter_id)
        expected_payload, expected_side_effects = (
            services.lifecycle._normalize_plan_payload(
                adapter_id,
                operation,
                payload,
                project_id,
                entry.manifest.version,
            )
        )
        request_projection = {
            "schema_version": "hive.adapter-lifecycle-input.v1",
            "adapter_id": adapter_id,
            "adapter_version": entry.manifest.version,
            "operation": operation,
            "project_id": project_id,
            "input_digest": document_digest(payload),
        }
        expected_request_digest = document_digest(request_projection)
        expected_policy_digest = document_digest(
            {
                "schema_version": "hive.adapter-lifecycle-policy.v1",
                "adapter_id": adapter_id,
                "manifest_digest": entry.manifest_digest,
                "operation": operation,
                "project_id": project_id,
                "execution": "attended-local",
            }
        )
        matches: list[dict[str, Any]] = []
        for path in sorted(services.runtime.plans.glob("*.json")):
            if path.is_symlink() or not path.is_file():
                raise ProtocolError(
                    "ADAPTER_LIFECYCLE_RECOVERY_INVALID",
                    "stored lifecycle plan path is unsafe",
                )
            candidate = read_json(path)
            if candidate.get("request_digest") != expected_request_digest:
                continue
            try:
                parsed, _ = services.lifecycle._verify_plan(
                    adapter_id, candidate, operation
                )
            except ProtocolError as exc:
                raise ProtocolError(
                    "ADAPTER_LIFECYCLE_RECOVERY_INVALID",
                    "stored lifecycle plan is not authentic",
                ) from exc
            if (
                path.name != f"{parsed.plan_id}.json"
                or parsed.project_id != project_id
                or parsed.policy_digest != expected_policy_digest
                or parsed.side_effects != expected_side_effects
                or parsed.network_destinations
                or parsed.requires_approval != (operation != "export")
                or parsed.payload != expected_payload
            ):
                raise ProtocolError(
                    "ADAPTER_LIFECYCLE_RECOVERY_INVALID",
                    "stored lifecycle plan does not bind the exact input",
                )
            matches.append(candidate)
        if len(matches) > 1:
            raise ProtocolError(
                "ADAPTER_LIFECYCLE_RECOVERY_INVALID",
                "multiple signed lifecycle plans bind the same input",
            )
        return matches[0] if matches else None

    def _store_lifecycle_plan_record(
        self,
        request: OperatorRequest,
        plan_document: Mapping[str, Any],
    ) -> tuple[dict[str, Any], Path]:
        record = {
            "schema_version": "hive.operator-lifecycle-plan.v1",
            "operator_request_digest": request.digest,
            "input_digest": document_digest(request.input),
            "plan": copy.deepcopy(dict(plan_document)),
            "plan_digest": document_digest(plan_document),
        }
        path = self._lifecycle_plan_path(request.digest)
        if path.exists() and canonical_bytes(read_json(path)) != canonical_bytes(record):
            raise ProtocolError(
                "ADAPTER_LIFECYCLE_RECOVERY_INVALID",
                "operator lifecycle plan bridge changed",
            )
        atomic_write_json(path, record, mode=0o600)
        return record, path

    def _lifecycle_plan_result(
        self,
        request: OperatorRequest,
        operation_key: str,
        record: Mapping[str, Any],
        path: Path,
    ) -> dict[str, Any]:
        return self._result(
            request,
            operation_key,
            outcome="APPLIED",
            object_version=str(record["plan_digest"]),
            changed=True,
            data={"plan": record["plan"], "execution_started": False},
            evidence=[
                {
                    "kind": "adapter-lifecycle-plan",
                    "ref": path.relative_to(self.root).as_posix(),
                    "sha256": _sha256_file(path),
                }
            ],
        )

    def _recover_runtime_lifecycle_approval(
        self, services: Any, plan_document: Mapping[str, Any]
    ) -> dict[str, Any] | None:
        if not services.lifecycle.approvals.exists():
            return None
        plan_digest = document_digest(plan_document)
        operation = str(plan_document.get("capability_id", "")).removeprefix(
            "lifecycle."
        )
        parsed_plan, _ = services.lifecycle._verify_plan(
            str(plan_document.get("adapter_id", "")), plan_document, operation
        )
        matches: list[dict[str, Any]] = []
        for path in sorted(services.lifecycle.approvals.glob("*.json")):
            if path.is_symlink() or not path.is_file():
                raise ProtocolError(
                    "ADAPTER_APPROVAL_RECOVERY_INVALID",
                    "stored lifecycle approval path is unsafe",
                )
            candidate = read_json(path)
            if candidate.get("plan_digest") != plan_digest:
                continue
            try:
                approval = services.lifecycle._verify_approval(
                    plan_document, parsed_plan, candidate
                )
            except ProtocolError as exc:
                raise ProtocolError(
                    "ADAPTER_APPROVAL_RECOVERY_INVALID",
                    "stored lifecycle approval is not authentic",
                ) from exc
            if approval is None or path.name != f"{approval.approval_id}.json":
                raise ProtocolError(
                    "ADAPTER_APPROVAL_RECOVERY_INVALID",
                    "stored lifecycle approval does not bind the exact plan",
                )
            matches.append(candidate)
        if len(matches) > 1:
            raise ProtocolError(
                "ADAPTER_APPROVAL_RECOVERY_INVALID",
                "multiple approvals bind the same lifecycle plan",
            )
        return matches[0] if matches else None

    def _store_lifecycle_approval_record(
        self, plan_document: Mapping[str, Any], approval: Mapping[str, Any]
    ) -> tuple[dict[str, Any], Path]:
        plan_digest = document_digest(plan_document)
        record = {
            "schema_version": "hive.operator-lifecycle-approval.v1",
            "plan_digest": plan_digest,
            "approval": copy.deepcopy(dict(approval)),
            "approval_digest": document_digest(approval),
        }
        path = self._lifecycle_approval_path(plan_digest)
        if path.exists() and canonical_bytes(read_json(path)) != canonical_bytes(record):
            raise ProtocolError(
                "ADAPTER_APPROVAL_RECOVERY_INVALID",
                "operator lifecycle approval bridge changed",
            )
        atomic_write_json(path, record, mode=0o600)
        return record, path

    def _lifecycle_approval_result(
        self,
        request: OperatorRequest,
        operation_key: str,
        record: Mapping[str, Any],
        path: Path,
    ) -> dict[str, Any]:
        return self._result(
            request,
            operation_key,
            outcome="APPLIED",
            object_version=str(record["approval_digest"]),
            changed=True,
            data={"approval": record["approval"], "execution_started": False},
            evidence=[
                {
                    "kind": "adapter-lifecycle-approval",
                    "ref": path.relative_to(self.root).as_posix(),
                    "sha256": _sha256_file(path),
                }
            ],
        )

    def _read_lifecycle_plan(
        self,
        request_digest: str,
        input_document: Mapping[str, Any],
    ) -> dict[str, Any]:
        path = self._lifecycle_plan_path(request_digest)
        if not path.is_file() or path.is_symlink():
            raise ProtocolError(
                "ADAPTER_LIFECYCLE_PLAN_MISMATCH", "operator lifecycle plan is absent"
            )
        record = read_json(path)
        if (
            set(record)
            != {
                "schema_version",
                "operator_request_digest",
                "input_digest",
                "plan",
                "plan_digest",
            }
            or record.get("schema_version") != "hive.operator-lifecycle-plan.v1"
            or record.get("operator_request_digest") != request_digest
            or not isinstance(record.get("plan"), dict)
            or record.get("plan_digest") != document_digest(record["plan"])
        ):
            raise ProtocolError(
                "ADAPTER_LIFECYCLE_PLAN_MISMATCH", "operator lifecycle plan changed"
            )
        try:
            adapter_id, operation, payload = self._lifecycle_preview_input(
                input_document
            )
            if record["input_digest"] != document_digest(input_document):
                raise ProtocolError(
                    "ADAPTER_LIFECYCLE_PLAN_MISMATCH",
                    "operator lifecycle input changed",
                )
            services = product_adapter_services(self.root)
            grant = services.authority.resolve(
                public_key_id(services.request_key.public_key()), adapter_id
            )
            recovered_plan = self._recover_runtime_lifecycle_plan(
                services,
                adapter_id,
                operation,
                payload,
                grant.project_id,
            )
            if (
                recovered_plan is None
                or canonical_bytes(recovered_plan)
                != canonical_bytes(record["plan"])
            ):
                raise ProtocolError(
                    "ADAPTER_LIFECYCLE_PLAN_MISMATCH",
                    "operator bridge does not bind the authentic lifecycle plan",
                )
        except ProtocolError as exc:
            if exc.code == "ADAPTER_LIFECYCLE_PLAN_MISMATCH":
                raise
            raise ProtocolError(
                "ADAPTER_LIFECYCLE_PLAN_MISMATCH",
                "operator lifecycle plan authenticity check failed",
            ) from exc
        return record

    def _read_lifecycle_approval(
        self,
        plan_digest: str,
        plan_document: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        path = self._lifecycle_approval_path(plan_digest)
        if not path.exists():
            return None
        if not path.is_file() or path.is_symlink():
            raise ProtocolError(
                "ADAPTER_APPROVAL_INVALID", "operator lifecycle approval is unsafe"
            )
        record = read_json(path)
        if (
            set(record)
            != {
                "schema_version",
                "plan_digest",
                "approval",
                "approval_digest",
            }
            or record.get("schema_version")
            != "hive.operator-lifecycle-approval.v1"
            or record.get("plan_digest") != plan_digest
            or not isinstance(record.get("approval"), dict)
            or record.get("approval_digest")
            != document_digest(record["approval"])
            or record["approval"].get("plan_digest") != plan_digest
        ):
            raise ProtocolError(
                "ADAPTER_APPROVAL_INVALID", "operator lifecycle approval changed"
            )
        try:
            if document_digest(plan_document) != plan_digest:
                raise ProtocolError(
                    "ADAPTER_APPROVAL_INVALID",
                    "operator approval plan binding changed",
                )
            services = product_adapter_services(self.root)
            recovered_approval = self._recover_runtime_lifecycle_approval(
                services, plan_document
            )
            if (
                recovered_approval is None
                or canonical_bytes(recovered_approval)
                != canonical_bytes(record["approval"])
            ):
                raise ProtocolError(
                    "ADAPTER_APPROVAL_INVALID",
                    "operator bridge does not bind the authentic approval",
                )
        except ProtocolError as exc:
            if exc.code == "ADAPTER_APPROVAL_INVALID":
                raise
            raise ProtocolError(
                "ADAPTER_APPROVAL_INVALID",
                "operator lifecycle approval authenticity check failed",
            ) from exc
        return record

    @staticmethod
    def _lifecycle_apply_input(
        document: Mapping[str, Any]
    ) -> tuple[str, str, dict, dict, dict | None]:
        if set(document) != {"adapter_id", "operation", "input", "plan", "approval"}:
            raise ProtocolError(
                "ADAPTER_LIFECYCLE_INPUT_INVALID",
                "lifecycle apply input is not exact",
            )
        adapter_id = document.get("adapter_id")
        operation = document.get("operation")
        input_document = document.get("input")
        plan = document.get("plan")
        approval = document.get("approval")
        if (
            not isinstance(adapter_id, str)
            or operation not in {"export", "rollback", "uninstall"}
            or not isinstance(input_document, dict)
            or not isinstance(plan, dict)
            or (approval is not None and not isinstance(approval, dict))
        ):
            raise ProtocolError(
                "ADAPTER_LIFECYCLE_INPUT_INVALID", "lifecycle apply is invalid"
            )
        validate_adapter_document("adapter-plan.v1.schema.json", plan)
        if approval is not None:
            validate_adapter_document("adapter-approval.v1.schema.json", approval)
        return adapter_id, operation, input_document, plan, approval

    def _lifecycle_result(
        self, services: Any, adapter_id: str, operation: str, plan_document: dict
    ) -> dict | None:
        plan, entry = services.lifecycle._verify_plan(
            adapter_id, plan_document, operation
        )
        lifecycle_operation_key = adapter_operation_key(
            plan.request_digest, document_digest(plan_document)
        )
        result_id = services.lifecycle._result_id(lifecycle_operation_key)
        path = services.runtime.results / f"{result_id}.json"
        if not path.exists():
            return None
        return services.lifecycle._durable_result(
            result_id,
            plan_document,
            plan,
            lifecycle_operation_key,
            max_output_bytes=entry.manifest.resource_limits["max_output_bytes"],
        )

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
                "request_digest",
                "state",
                "result",
                "result_digest",
            }
            or document.get("schema_version") != _OPERATION_SCHEMA
            or document.get("operation_key") != operation_key
            or document.get("request_digest") != request.digest
            or document.get("state") not in {"PREPARED", "TERMINAL"}
        ):
            raise ProtocolError(
                "OPERATOR_DOMAIN_RECOVERY_INVALID", "settings operation record changed"
            )
        if document["state"] == "PREPARED":
            return None
        result = document.get("result")
        if (
            not isinstance(result, dict)
            or document.get("result_digest") != document_digest(result)
        ):
            raise ProtocolError(
                "OPERATOR_DOMAIN_RECOVERY_INVALID", "settings result record changed"
            )
        return copy.deepcopy(result)

    def _write_operation(
        self,
        operation_key: str,
        request: OperatorRequest,
        result: Mapping[str, Any] | None,
    ) -> None:
        atomic_write_json(
            self._operation_path(operation_key),
            {
                "schema_version": _OPERATION_SCHEMA,
                "operation_key": operation_key,
                "request_digest": request.digest,
                "state": "TERMINAL" if result is not None else "PREPARED",
                "result": copy.deepcopy(dict(result)) if result is not None else None,
                "result_digest": document_digest(result) if result is not None else None,
            },
            mode=0o600,
        )

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
        if route.action == "settings.provider.preview":
            value = document_digest(request.input)
        elif route.action == "settings.provider.apply":
            preview = request.input.get("preview")
            value = (
                preview.get("preview_id", "invalid")
                if isinstance(preview, dict)
                else "invalid"
            )
        elif route.action == "settings.adapters.plan":
            value = request.digest
        elif route.action == "settings.adapters.invoke":
            plan = request.input.get("plan")
            value = plan.get("plan_id", "invalid") if isinstance(plan, dict) else "invalid"
        elif route.action == "settings.lifecycle.preview":
            value = request.digest
        elif route.action == "settings.snapshot":
            value = request.digest
        elif route.action == "settings.export":
            value = document_digest(
                {
                    "project_id": request.project_id,
                    "destination": request.input.get("destination"),
                }
            )
        elif route.action == "settings.reopen":
            value = document_digest(
                {
                    "project_id": request.project_id,
                    "target": request.input.get("target"),
                }
            )
        elif route.action == "settings.rollback":
            checkpoint = request.input.get("checkpoint")
            value = (
                checkpoint.get("checkpoint_id", "invalid")
                if isinstance(checkpoint, dict)
                else "invalid"
            )
        else:
            plan = request.input.get("plan")
            value = plan.get("plan_id", "invalid") if isinstance(plan, dict) else "invalid"
        return f"{request.project_id}:{route.action}:{value}"

    def current_version(self, route: RouteContract, request: OperatorRequest) -> str:
        config, current_sha256 = self._config()
        if route.action == "settings.provider.preview":
            provider = self._provider_input(request.input)
            preview_id = self._preview_id(request, current_sha256, provider)
            path = self._preview_path(preview_id)
            if path.exists():
                preview = self._read_preview(preview_id)
                return document_digest(preview)
            return current_sha256
        if route.action == "settings.provider.apply":
            if set(request.input) != {"preview"} or not isinstance(
                request.input.get("preview"), dict
            ):
                raise ProtocolError(
                    "PROVIDER_PREVIEW_INVALID", "provider apply requires one exact preview"
                )
            supplied = request.input["preview"]
            stored = self._read_preview(supplied.get("preview_id"))
            if supplied != stored:
                raise ProtocolError("PROVIDER_PREVIEW_MISMATCH", "provider preview changed")
            if current_sha256 == stored["before_sha256"]:
                return document_digest(stored)
            if current_sha256 == stored["after_sha256"]:
                return current_sha256
            raise ProtocolError(
                "PROVIDER_PREVIEW_STALE", "provider configuration changed after preview"
            )
        if route.action == "settings.adapters.plan":
            normalized = self._adapter_plan_input(request.input)
            path = self._adapter_plan_path(request.digest)
            if not path.exists():
                return "ABSENT"
            record = self._read_adapter_plan(request.digest)
            if record["input_digest"] != document_digest(normalized):
                raise ProtocolError("ADAPTER_PLAN_INVALID", "adapter plan input changed")
            return str(record["plan_digest"])
        if route.action == "settings.snapshot":
            if set(request.input) != {"message"}:
                raise ProtocolError(
                    "SNAPSHOT_INPUT_INVALID", "snapshot input is not exact"
                )
            message = request.input.get("message")
            if (
                not isinstance(message, str)
                or not message.strip()
                or message != message.strip()
                or "\n" in message
                or len(message) > 256
            ):
                raise ProtocolError(
                    "SNAPSHOT_INPUT_INVALID", "snapshot message is invalid"
                )
            return self._portable_state_version()
        if route.action == "settings.export":
            if set(request.input) != {"destination", "expected_state_version"}:
                raise ProtocolError(
                    "EXPORT_INPUT_INVALID", "Hive export input is not exact"
                )
            destination = request.input.get("destination")
            expected = request.input.get("expected_state_version")
            if (
                not isinstance(destination, str)
                or not Path(destination).is_absolute()
                or _SHA256.fullmatch(str(expected)) is None
            ):
                raise ProtocolError(
                    "EXPORT_INPUT_INVALID", "Hive export binding is invalid"
                )
            current = self._portable_state_version()
            completed = self._operator_receipt("operator-hive-export", request.digest)
            if completed is None:
                if expected != current:
                    raise ProtocolError(
                        "EXPORT_PREVIEW_STALE", "Hive changed after export preview"
                    )
                raw = Path(destination).expanduser()
                if raw.exists() or raw.is_symlink():
                    raise ProtocolError(
                        "EXPORT_OUTPUT_EXISTS",
                        "portable export refuses to replace an existing output",
                    )
            return current
        if route.action == "settings.reopen":
            bundle, target, _ = self._verified_reopen_input(request.input)
            if target.exists() and (
                target.is_symlink() or not target.is_dir() or any(target.iterdir())
            ):
                reopened = HiveWorkspace.verify_reopened_export(bundle, target)
                return document_digest(
                    {
                        "schema_version": "hive.operator-portable-manifest.v1",
                        "files": reopened.portable_manifest(),
                    }
                )
            return "ABSENT"
        if route.action == "settings.adapters.invoke":
            request_document, plan_document, _ = self._adapter_invoke_input(
                request.input
            )
            services = product_adapter_services(self.root)
            adapter_invocation_context(services, request_document)
            stored_plan = read_json(
                services.runtime.plans / f"{plan_document['plan_id']}.json"
            )
            if stored_plan != plan_document:
                raise ProtocolError("ADAPTER_STORED_PLAN_MISMATCH", "adapter plan changed")
            result = self._adapter_result(services, request_document, plan_document)
            return (
                document_digest(result)
                if result is not None
                else document_digest(plan_document)
            )
        if route.action == "settings.lifecycle.preview":
            self._lifecycle_preview_input(request.input)
            path = self._lifecycle_plan_path(request.digest)
            if not path.exists():
                return "ABSENT"
            return str(
                self._read_lifecycle_plan(
                    request.digest, request.input
                )["plan_digest"]
            )
        if route.action == "settings.lifecycle.approve":
            if set(request.input) != {"plan"} or not isinstance(
                request.input.get("plan"), dict
            ):
                raise ProtocolError(
                    "ADAPTER_APPROVAL_INVALID",
                    "lifecycle approval requires one exact plan",
                )
            plan_document = request.input["plan"]
            validate_adapter_document("adapter-plan.v1.schema.json", plan_document)
            plan_digest = document_digest(plan_document)
            services = product_adapter_services(self.root)
            services.lifecycle._verify_plan(
                str(plan_document.get("adapter_id", "")),
                plan_document,
                str(plan_document.get("capability_id", "")).removeprefix("lifecycle."),
            )
            approval = self._read_lifecycle_approval(
                plan_digest, plan_document
            )
            return (
                str(approval["approval_digest"])
                if approval is not None
                else plan_digest
            )
        if route.action == "settings.rollback":
            if set(request.input) != {"checkpoint", "approval"} or not isinstance(
                request.input.get("approval"), dict
            ):
                raise ProtocolError(
                    "ROLLBACK_APPROVAL_INVALID",
                    "rollback requires one exact checkpoint approval",
                )
            checkpoint = self._read_checkpoint(request.input.get("checkpoint"))
            approval = request.input["approval"]
            current = self._portable_state_version()
            if (
                set(approval)
                != {
                    "checkpoint_sha256",
                    "expected_current_version",
                    "confirmation",
                }
                or approval.get("checkpoint_sha256") != document_digest(checkpoint)
                or approval.get("confirmation")
                != f"ROLLBACK {checkpoint['commit']}"
                or _SHA256.fullmatch(
                    str(approval.get("expected_current_version", ""))
                )
                is None
            ):
                raise ProtocolError(
                    "ROLLBACK_APPROVAL_INVALID", "rollback approval binding changed"
                )
            completed = self._operator_receipt(
                "operator-hive-rollback", request.digest
            )
            if completed is not None:
                detail = completed[0]["detail"]
                if (
                    detail.get("checkpoint_sha256") != document_digest(checkpoint)
                    or detail.get("target") != checkpoint["commit"]
                ):
                    raise ProtocolError(
                        "OPERATOR_LIFECYCLE_RECEIPT_INVALID",
                        "rollback receipt binding changed",
                    )
                return current
            if approval["expected_current_version"] != current:
                raise ProtocolError(
                    "ROLLBACK_APPROVAL_STALE", "Hive changed after rollback approval"
                )
            return current
        adapter_id, operation, _, plan_document, approval_document = (
            self._lifecycle_apply_input(request.input)
        )
        services = product_adapter_services(self.root)
        parsed, _ = services.lifecycle._verify_plan(
            adapter_id, plan_document, operation
        )
        verified_approval = services.lifecycle._verify_approval(
            plan_document, parsed, approval_document
        )
        result = self._lifecycle_result(
            services, adapter_id, operation, plan_document
        )
        if result is not None:
            return document_digest(result)
        return (
            document_digest(approval_document)
            if verified_approval is not None
            else document_digest(plan_document)
        )

    def _verified_reopen_input(
        self, document: Mapping[str, Any]
    ) -> tuple[Path, Path, dict[str, Any]]:
        if set(document) != {
            "bundle",
            "bundle_sha256",
            "manifest_sha256",
            "target",
        }:
            raise ProtocolError(
                "REOPEN_INPUT_INVALID", "verified reopen input is not exact"
            )
        bundle_value = document.get("bundle")
        target_value = document.get("target")
        if (
            not isinstance(bundle_value, str)
            or not Path(bundle_value).is_absolute()
            or not isinstance(target_value, str)
            or not Path(target_value).is_absolute()
            or _SHA256.fullmatch(str(document.get("bundle_sha256", ""))) is None
            or _SHA256.fullmatch(str(document.get("manifest_sha256", ""))) is None
        ):
            raise ProtocolError(
                "REOPEN_INPUT_INVALID", "verified reopen binding is invalid"
            )
        bundle = Path(bundle_value).expanduser()
        target = Path(target_value).expanduser()
        if any(candidate.is_symlink() for candidate in (target, *target.parents)):
            raise ProtocolError(
                "REOPEN_TARGET_BOUNDARY", "reopen target path contains a symlink"
            )
        resolved_target = target.resolve(strict=False)
        if resolved_target == self.root or self.root in resolved_target.parents:
            raise ProtocolError(
                "REOPEN_TARGET_BOUNDARY", "reopen target must be outside the source Hive"
            )
        bundle_info = HiveWorkspace.inspect_export(bundle)
        if (
            bundle_info["sha256"] != document["bundle_sha256"]
            or bundle_info["manifest_sha256"] != document["manifest_sha256"]
        ):
            raise ProtocolError(
                "REOPEN_BUNDLE_MISMATCH", "bundle or manifest digest changed"
            )
        return bundle.resolve(), resolved_target, bundle_info

    def _hive_export(
        self,
        request: OperatorRequest,
        operation_key: str,
        *,
        recovering: bool = False,
    ) -> dict[str, Any]:
        destination = Path(str(request.input["destination"])).expanduser()
        if destination.exists() or destination.is_symlink():
            if not recovering:
                raise ProtocolError(
                    "EXPORT_OUTPUT_EXISTS",
                    "portable export refuses to replace an existing output",
                )
        else:
            self.workspace.export(destination)
        inspected = HiveWorkspace.inspect_export(destination)
        exported_state = document_digest(
            {
                "schema_version": "hive.operator-portable-manifest.v1",
                "files": inspected["manifest"]["files"],
            }
        )
        if exported_state != request.input["expected_state_version"]:
            raise ProtocolError(
                "EXPORT_PREVIEW_STALE",
                "portable export files do not match the approved Hive state",
            )
        detail = {
            "request_digest": request.digest,
            "artifact_sha256": inspected["sha256"],
            "manifest_sha256": inspected["manifest_sha256"],
            "state_version": exported_state,
        }
        receipt = self.workspace._receipt(
            "operator-hive-export", detail, operation_id=operation_key
        )
        receipt_path = next(
            path
            for path in self.workspace.receipts.glob(
                f"operation-{operation_key}-*-operator-hive-export.json"
            )
            if path.is_file() and not path.is_symlink()
        )
        return self._result(
            request,
            operation_key,
            outcome="APPLIED",
            object_version=self._portable_state_version(),
            changed=True,
            data={
                "export": {
                    **inspected,
                    "state_version": exported_state,
                    "receipt_id": receipt["receipt_id"],
                },
                "execution_started": True,
            },
            evidence=[
                {
                    "kind": "hive-export-receipt",
                    "ref": receipt_path.relative_to(self.root).as_posix(),
                    "sha256": _sha256_file(receipt_path),
                }
            ],
        )

    def _hive_reopen(
        self, request: OperatorRequest, operation_key: str
    ) -> dict[str, Any]:
        bundle, target, bundle_info = self._verified_reopen_input(request.input)
        if target.exists() and (
            target.is_symlink() or not target.is_dir() or any(target.iterdir())
        ):
            if target.is_symlink() or not target.is_dir():
                raise ProtocolError(
                    "REOPEN_TARGET_BOUNDARY", "reopen target is not a safe directory"
                )
            reopened = HiveWorkspace.verify_reopened_export(bundle, target)
        else:
            reopened = HiveWorkspace.reopen_export(bundle, target)
            self._fault("settings.reopen:after_workspace_reopen")
            reopened = HiveWorkspace.verify_reopened_export(bundle, target)
        target_manifest = {
            "schema_version": "hive.operator-portable-manifest.v1",
            "files": reopened.portable_manifest(),
        }
        detail = {
            "request_digest": request.digest,
            "bundle_sha256": bundle_info["sha256"],
            "manifest_sha256": bundle_info["manifest_sha256"],
            "target_state_version": document_digest(target_manifest),
        }
        receipt = self.workspace._receipt(
            "operator-hive-reopen", detail, operation_id=operation_key
        )
        receipt_path = next(
            path
            for path in self.workspace.receipts.glob(
                f"operation-{operation_key}-*-operator-hive-reopen.json"
            )
            if path.is_file() and not path.is_symlink()
        )
        return self._result(
            request,
            operation_key,
            outcome="APPLIED",
            object_version=document_digest(target_manifest),
            changed=True,
            data={
                "target": str(target),
                "bundle_sha256": bundle_info["sha256"],
                "manifest_sha256": bundle_info["manifest_sha256"],
                "target_state_version": document_digest(target_manifest),
                "receipt_id": receipt["receipt_id"],
                "execution_started": True,
            },
            evidence=[
                {
                    "kind": "hive-reopen-receipt",
                    "ref": receipt_path.relative_to(self.root).as_posix(),
                    "sha256": _sha256_file(receipt_path),
                }
            ],
        )

    def _hive_snapshot(
        self, request: OperatorRequest, operation_key: str
    ) -> dict[str, Any]:
        message = request.input["message"]
        snapshotted = self.workspace.snapshot(message, operation_id=operation_key)
        self._fault("settings.snapshot:after_workspace_snapshot")
        commit = str(snapshotted["commit"])
        manifest = self._portable_manifest(commit)
        receipt_path = next(
            path
            for path in self.workspace.receipts.glob(
                f"operation-{operation_key}-*-git-snapshot.json"
            )
            if path.is_file() and not path.is_symlink()
        )
        receipt = snapshotted["receipt"]
        core = {
            "schema_version": "hive.operator-hive-checkpoint.v1",
            "commit": commit,
            "message": message,
            "portable_manifest_sha256": document_digest(manifest),
            "receipt_id": receipt["receipt_id"],
            "receipt_sha256": _sha256_file(receipt_path),
        }
        checkpoint = {
            **core,
            "checkpoint_id": document_digest(core),
            "portable_manifest": manifest["files"],
            "created_at": receipt["recorded_at"],
            "receipt_ref": receipt_path.relative_to(self.root).as_posix(),
        }
        path = self._checkpoint_path(checkpoint["checkpoint_id"])
        if path.exists() and read_json(path) != checkpoint:
            raise ProtocolError(
                "ROLLBACK_CHECKPOINT_INVALID", "snapshot checkpoint changed"
            )
        atomic_write_json(path, checkpoint, mode=0o600)
        return self._result(
            request,
            operation_key,
            outcome="APPLIED",
            object_version=self._portable_state_version(),
            changed=True,
            data={"checkpoint": checkpoint, "execution_started": True},
            evidence=[
                {
                    "kind": "hive-checkpoint",
                    "ref": path.relative_to(self.root).as_posix(),
                    "sha256": _sha256_file(path),
                },
                {
                    "kind": "hive-snapshot-receipt",
                    "ref": receipt_path.relative_to(self.root).as_posix(),
                    "sha256": _sha256_file(receipt_path),
                },
            ],
        )

    def _hive_rollback(
        self, request: OperatorRequest, operation_key: str
    ) -> dict[str, Any]:
        checkpoint = self._read_checkpoint(request.input["checkpoint"])
        rolled_back = self.workspace.rollback(
            checkpoint["commit"],
            operation_id=operation_key,
            preserve_receipt_refs=[checkpoint["receipt_ref"]],
        )
        detail = {
            "request_digest": request.digest,
            "checkpoint_sha256": document_digest(checkpoint),
            "target": checkpoint["commit"],
        }
        receipt = self.workspace._receipt(
            "operator-hive-rollback", detail, operation_id=operation_key
        )
        receipt_path = next(
            path
            for path in self.workspace.receipts.glob(
                f"operation-{operation_key}-*-operator-hive-rollback.json"
            )
            if path.is_file() and not path.is_symlink()
        )
        return self._result(
            request,
            operation_key,
            outcome="APPLIED",
            object_version=self._portable_state_version(),
            changed=True,
            data={
                "target": rolled_back["target"],
                "receipt_id": receipt["receipt_id"],
                "execution_started": True,
            },
            evidence=[
                {
                    "kind": "hive-rollback-receipt",
                    "ref": receipt_path.relative_to(self.root).as_posix(),
                    "sha256": _sha256_file(receipt_path),
                }
            ],
        )

    def _adapter_plan(
        self, request: OperatorRequest, operation_key: str
    ) -> dict[str, Any]:
        normalized = self._adapter_plan_input(request.input)
        services = product_adapter_services(self.root)
        manifest = services.manifests.get(normalized["adapter_id"])
        if (
            manifest is None
            or normalized["capability_id"] not in manifest["capability_ids"]
        ):
            raise ProtocolError(
                "ADAPTER_CAPABILITY_DENIED", "adapter capability is not declared"
            )
        grant = services.authority.resolve(
            public_key_id(services.request_key.public_key()),
            normalized["adapter_id"],
        )
        now = datetime.now(timezone.utc)
        request_document = sign_document(
            AdapterRequest(
                request_id=self._adapter_request_id(operation_key),
                adapter_id=normalized["adapter_id"],
                adapter_version=manifest["version"],
                sender=dict(grant.identity),
                project_id=grant.project_id,
                capability_id=normalized["capability_id"],
                data_classification="PROJECT_PRIVATE",
                authorization_ref=grant.authorization_ref,
                evidence_sha256=normalized["evidence_sha256"],
                payload=normalized["payload"],
                nonce=operation_key,
                expires_at=_moment(now + timedelta(minutes=10)),
            ).as_dict(),
            services.request_key,
        )
        self._store_adapter_request(services, operation_key, request_document)
        context = adapter_invocation_context(services, request_document)
        plan_document = services.runtime.plan(request_document, context)
        self._fault("settings.adapters.plan:after_runtime_plan")
        record, path = self._store_adapter_plan_record(
            request, normalized, request_document, plan_document
        )
        self._fault("settings.adapters.plan:after_operator_plan_bridge")
        return self._adapter_plan_result(request, operation_key, record, path)

    def _adapter_invoke(
        self, request: OperatorRequest, operation_key: str, *, recovering: bool = False
    ) -> dict[str, Any] | None:
        request_document, plan_document, approval = self._adapter_invoke_input(
            request.input
        )
        services = product_adapter_services(self.root)
        context = adapter_invocation_context(services, request_document)
        if recovering:
            services.runtime.recover_pending()
            adapter_result = self._adapter_result(
                services, request_document, plan_document
            )
            if adapter_result is None:
                return None
        else:
            adapter_result = services.runtime.invoke(
                request_document, plan_document, context, approval
            )
        result_path = services.runtime.results / f"{adapter_result['result_id']}.json"
        return self._result(
            request,
            operation_key,
            outcome="APPLIED",
            object_version=document_digest(adapter_result),
            changed=True,
            data={"result": adapter_result, "execution_started": True},
            evidence=[
                {
                    "kind": "adapter-result",
                    "ref": result_path.relative_to(self.root).as_posix(),
                    "sha256": _sha256_file(result_path),
                }
            ],
        )

    def _lifecycle_preview(
        self, request: OperatorRequest, operation_key: str
    ) -> dict[str, Any]:
        adapter_id, operation, payload = self._lifecycle_preview_input(request.input)
        services = product_adapter_services(self.root)
        grant = services.authority.resolve(
            public_key_id(services.request_key.public_key()), adapter_id
        )
        plan_document = services.lifecycle.plan(
            adapter_id, operation, payload, grant.project_id
        )
        self._fault("settings.lifecycle.preview:after_domain_plan")
        record, path = self._store_lifecycle_plan_record(
            request, plan_document
        )
        self._fault("settings.lifecycle.preview:after_operator_plan_bridge")
        return self._lifecycle_plan_result(request, operation_key, record, path)

    def _lifecycle_approve(
        self, request: OperatorRequest, operation_key: str
    ) -> dict[str, Any]:
        if set(request.input) != {"plan"} or not isinstance(
            request.input.get("plan"), dict
        ):
            raise ProtocolError(
                "ADAPTER_APPROVAL_INVALID",
                "lifecycle approval requires one exact plan",
            )
        plan_document = request.input["plan"]
        validate_adapter_document("adapter-plan.v1.schema.json", plan_document)
        adapter_id = str(plan_document.get("adapter_id", ""))
        services = product_adapter_services(self.root)
        grant = services.authority.resolve(
            public_key_id(services.request_key.public_key()), adapter_id
        )
        approval = services.lifecycle.approve(
            plan_document, grant.identity, services.approver_key
        )
        self._fault("settings.lifecycle.approve:after_domain_approval")
        record, path = self._store_lifecycle_approval_record(
            plan_document, approval
        )
        self._fault("settings.lifecycle.approve:after_operator_approval_bridge")
        return self._lifecycle_approval_result(
            request, operation_key, record, path
        )

    def _lifecycle_apply(
        self,
        request: OperatorRequest,
        operation_key: str,
        *,
        recovering: bool = False,
    ) -> dict[str, Any] | None:
        adapter_id, operation, input_document, plan_document, approval = (
            self._lifecycle_apply_input(request.input)
        )
        services = product_adapter_services(self.root)
        if recovering:
            services.lifecycle.recover_pending()
            lifecycle_result = self._lifecycle_result(
                services, adapter_id, operation, plan_document
            )
            if lifecycle_result is None:
                return None
        elif operation == "export":
            lifecycle_result = services.lifecycle.export(
                adapter_id, input_document, plan_document
            )
        elif operation == "rollback":
            if approval is None:
                raise ProtocolError(
                    "ADAPTER_APPROVAL_REQUIRED", "rollback requires exact approval"
                )
            lifecycle_result = services.lifecycle.rollback(
                input_document, plan_document, approval
            )
        else:
            if approval is None:
                raise ProtocolError(
                    "ADAPTER_APPROVAL_REQUIRED", "uninstall requires exact approval"
                )
            lifecycle_result = services.lifecycle.uninstall(
                adapter_id, input_document, plan_document, approval
            )
        result_path = (
            services.runtime.results / f"{lifecycle_result['result_id']}.json"
        )
        return self._result(
            request,
            operation_key,
            outcome="APPLIED",
            object_version=document_digest(lifecycle_result),
            changed=True,
            data={"result": lifecycle_result, "execution_started": True},
            evidence=[
                {
                    "kind": "adapter-lifecycle-result",
                    "ref": result_path.relative_to(self.root).as_posix(),
                    "sha256": _sha256_file(result_path),
                }
            ],
        )

    def _provider_preview(
        self, request: OperatorRequest, operation_key: str
    ) -> dict[str, Any]:
        provider = self._provider_input(request.input)
        config, before_sha256 = self._config()
        preview_id = self._preview_id(request, before_sha256, provider)
        updated_at = _moment(self.now)
        proposed = dict(config)
        proposed["provider"] = provider
        proposed["updated_at"] = updated_at
        preview = {
            "schema_version": _PREVIEW_SCHEMA,
            "preview_id": preview_id,
            "tenant_id": request.tenant_id,
            "project_id": request.project_id,
            "before_sha256": before_sha256,
            "after_sha256": document_digest(proposed),
            "proposed_provider": provider,
            "updated_at": updated_at,
            "created_at": _moment(self.now),
            "expires_at": _moment(self.now + timedelta(minutes=15)),
            "availability_state": (
                "RETRIEVAL_ONLY"
                if provider["mode"] == "retrieval-only"
                else "UNAVAILABLE_NOT_PROBED"
            ),
            "provider_attempted": False,
            "execution_started": False,
        }
        path = self._preview_path(preview_id)
        if path.exists() and read_json(path) != preview:
            raise ProtocolError("PROVIDER_PREVIEW_CONFLICT", "provider preview changed")
        atomic_write_json(path, preview, mode=0o600)
        return self._result(
            request,
            operation_key,
            outcome="APPLIED",
            object_version=document_digest(preview),
            changed=True,
            data={"preview": preview},
            evidence=[
                {
                    "kind": "provider-preview",
                    "ref": path.relative_to(self.root).as_posix(),
                    "sha256": _sha256_file(path),
                }
            ],
        )

    def _provider_apply(
        self, request: OperatorRequest, operation_key: str
    ) -> dict[str, Any]:
        preview = self._read_preview(request.input["preview"].get("preview_id"))
        if request.input["preview"] != preview:
            raise ProtocolError("PROVIDER_PREVIEW_MISMATCH", "provider preview changed")
        expires = datetime.fromisoformat(preview["expires_at"].replace("Z", "+00:00"))
        if expires <= self.now:
            raise ProtocolError("PROVIDER_PREVIEW_EXPIRED", "provider preview expired")
        configured = self.workspace.configure_provider_exact(
            preview["proposed_provider"]["mode"],
            preview["proposed_provider"]["model"],
            expected_before_sha256=preview["before_sha256"],
            expected_after_sha256=preview["after_sha256"],
            updated_at=preview["updated_at"],
            operation_id=operation_key,
        )
        receipt = configured["receipt"]
        receipt_path = next(
            path
            for path in self.workspace.receipts.glob(f"operation-{operation_key}-*.json")
            if path.is_file() and not path.is_symlink()
        )
        changed = preview["before_sha256"] != preview["after_sha256"]
        return self._result(
            request,
            operation_key,
            outcome="APPLIED" if changed else "OK",
            object_version=(
                preview["after_sha256"] if changed else document_digest(preview)
            ),
            changed=changed,
            data={
                "provider": configured["provider"],
                "execution_started": False,
                "receipt_id": receipt["receipt_id"],
            },
            evidence=[
                {
                    "kind": "provider-configuration-receipt",
                    "ref": receipt_path.relative_to(self.root).as_posix(),
                    "sha256": _sha256_file(receipt_path),
                }
            ],
        )

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
        if route.action == "settings.provider.preview":
            result = self._provider_preview(request, operation_key)
        elif route.action == "settings.provider.apply":
            result = self._provider_apply(request, operation_key)
        elif route.action == "settings.adapters.plan":
            result = self._adapter_plan(request, operation_key)
        elif route.action == "settings.adapters.invoke":
            result = self._adapter_invoke(request, operation_key)
        elif route.action == "settings.lifecycle.preview":
            result = self._lifecycle_preview(request, operation_key)
        elif route.action == "settings.lifecycle.approve":
            result = self._lifecycle_approve(request, operation_key)
        elif route.action == "settings.lifecycle.apply":
            result = self._lifecycle_apply(request, operation_key)
            if result is None:  # pragma: no cover - non-recovery apply is terminal
                raise ProtocolError(
                    "ADAPTER_EFFECT_STATE_PENDING",
                    "lifecycle effect state requires attended recovery",
                )
        elif route.action == "settings.snapshot":
            result = self._hive_snapshot(request, operation_key)
        elif route.action == "settings.export":
            result = self._hive_export(request, operation_key)
        elif route.action == "settings.reopen":
            result = self._hive_reopen(request, operation_key)
        elif route.action == "settings.rollback":
            result = self._hive_rollback(request, operation_key)
        else:  # pragma: no cover
            raise ProtocolError("OPERATOR_DOMAIN_UNAVAILABLE", "settings action is unavailable")
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
        if route.action == "settings.provider.preview":
            result = self._provider_preview(request, operation_key)
        elif route.action == "settings.provider.apply":
            result = self._provider_apply(request, operation_key)
        elif route.action == "settings.adapters.plan":
            path = self._adapter_plan_path(request.digest)
            if path.exists():
                record = self._read_adapter_plan(request.digest)
            else:
                normalized = self._adapter_plan_input(request.input)
                services = product_adapter_services(self.root)
                request_path = self._adapter_request_path(services, operation_key)
                if not request_path.exists():
                    result = self._adapter_plan(request, operation_key)
                    self._write_operation(operation_key, request, result)
                    return result
                request_document = read_json(request_path)
                parsed, context, entry = (
                    self._validate_recoverable_adapter_request(
                        services,
                        request,
                        operation_key,
                        normalized,
                        request_document,
                    )
                )
                plan_document = self._recover_runtime_adapter_plan(
                    services, request_document, parsed, context, entry
                )
                if plan_document is None:
                    plan_document = services.runtime.plan(
                        request_document, context
                    )
                record, path = self._store_adapter_plan_record(
                    request, normalized, request_document, plan_document
                )
            result = self._adapter_plan_result(
                request, operation_key, record, path
            )
        elif route.action == "settings.adapters.invoke":
            result = self._adapter_invoke(request, operation_key, recovering=True)
            if result is None:
                return None
        elif route.action == "settings.lifecycle.preview":
            path = self._lifecycle_plan_path(request.digest)
            if path.exists():
                record = self._read_lifecycle_plan(
                    request.digest, request.input
                )
            else:
                adapter_id, operation, payload = (
                    self._lifecycle_preview_input(request.input)
                )
                services = product_adapter_services(self.root)
                grant = services.authority.resolve(
                    public_key_id(services.request_key.public_key()), adapter_id
                )
                plan_document = self._recover_runtime_lifecycle_plan(
                    services,
                    adapter_id,
                    operation,
                    payload,
                    grant.project_id,
                )
                if plan_document is None:
                    plan_document = services.lifecycle.plan(
                        adapter_id, operation, payload, grant.project_id
                    )
                record, path = self._store_lifecycle_plan_record(
                    request, plan_document
                )
            result = self._lifecycle_plan_result(
                request, operation_key, record, path
            )
        elif route.action == "settings.lifecycle.approve":
            plan = request.input.get("plan")
            if not isinstance(plan, dict):
                return None
            path = self._lifecycle_approval_path(document_digest(plan))
            record = self._read_lifecycle_approval(
                document_digest(plan), plan
            )
            if record is None:
                services = product_adapter_services(self.root)
                approval = self._recover_runtime_lifecycle_approval(
                    services, plan
                )
                if approval is None:
                    return None
                record, path = self._store_lifecycle_approval_record(
                    plan, approval
                )
            result = self._lifecycle_approval_result(
                request, operation_key, record, path
            )
        elif route.action == "settings.lifecycle.apply":
            result = self._lifecycle_apply(
                request, operation_key, recovering=True
            )
            if result is None:
                return None
        elif route.action == "settings.snapshot":
            result = self._hive_snapshot(request, operation_key)
        elif route.action == "settings.export":
            result = self._hive_export(request, operation_key, recovering=True)
        elif route.action == "settings.reopen":
            result = self._hive_reopen(request, operation_key)
        elif route.action == "settings.rollback":
            result = self._hive_rollback(request, operation_key)
        else:
            return None
        self._write_operation(operation_key, request, result)
        return result
