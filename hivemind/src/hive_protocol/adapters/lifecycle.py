"""Replay-safe, attended lifecycle orchestration for registered adapters."""

from __future__ import annotations

import copy
import hashlib
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping
from uuid import NAMESPACE_URL, uuid4, uuid5

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.adapters.execution import execution_deadline, operation_key
from hive_protocol.adapters.models import (
    AdapterApproval,
    AdapterPlan,
    AdapterResult,
    validate_adapter_document,
)
from hive_protocol.adapters.runtime import (
    AdapterRuntime,
    _date_time,
    _enforce_document_bound,
)
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
    ReplayLedger,
    atomic_write_json,
    exclusive_lock,
    read_json,
    utc_now,
)


_OPERATIONS = frozenset({"export", "rollback", "uninstall"})
_JOURNAL_FIELDS = frozenset(
    {
        "schema_version",
        "adapter_id",
        "operation",
        "operation_key",
        "input",
        "input_digest",
        "plan",
        "approval",
        "state",
        "prepared_at",
        "claimed_at",
        "completed_at",
        "result_id",
        "removals",
        "signature",
    }
)
_REMOVAL_FIELDS = frozenset({"path", "kind", "sha256", "state"})


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _directory_digest(path: Path) -> str:
    entries: list[dict[str, str]] = []
    for descendant in sorted(path.rglob("*")):
        if descendant.is_symlink():
            raise ProtocolError(
                "ADAPTER_OWNERSHIP_BOUNDARY",
                "owned directories may not contain symlinks",
            )
        relative = descendant.relative_to(path).as_posix()
        if descendant.is_file():
            entries.append(
                {"path": relative, "kind": "file", "sha256": _sha256_file(descendant)}
            )
        elif descendant.is_dir():
            entries.append({"path": relative, "kind": "directory", "sha256": ""})
        else:
            raise ProtocolError(
                "ADAPTER_OWNERSHIP_BOUNDARY",
                "owned directories may contain only regular files and directories",
            )
    return hashlib.sha256(canonical_bytes(entries)).hexdigest()


class AdapterLifecycle:
    """Owns lifecycle plans, approvals, replay claims, recovery, and uninstall."""

    def __init__(self, runtime: AdapterRuntime) -> None:
        self.runtime = runtime
        self.registry = runtime.registry
        self.root = runtime.root / "lifecycle"
        if self.root.is_symlink():
            raise ProtocolError(
                "ADAPTER_LIFECYCLE_ROOT_BOUNDARY",
                "adapter lifecycle root must not be a symlink",
            )
        self._require_directory(self.root)
        self.approvals = self.root / "approvals"
        self.journals = self.root / "recovery"
        self.replay = ReplayLedger(self.root / "replay.json", mode=0o600)

    def _require_directory(self, path: Path) -> None:
        if path.is_symlink():
            raise ProtocolError(
                "ADAPTER_LIFECYCLE_ROOT_BOUNDARY",
                "adapter lifecycle directory must not be a symlink",
            )
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        if (
            path.is_symlink()
            or path.resolve() != path
            or path.stat().st_uid != os.geteuid()
        ):
            raise ProtocolError(
                "ADAPTER_LIFECYCLE_ROOT_BOUNDARY",
                "adapter lifecycle directory is not owned and canonical",
            )
        os.chmod(path, 0o700)

    def _write_journal(self, path: Path, journal: dict[str, Any]) -> None:
        unsigned = copy.deepcopy(journal)
        unsigned.pop("signature", None)
        reject_credential_values(
            unsigned,
            location="lifecycle recovery journal",
            verified_by=self.runtime.signature_keys(),
        )
        signed = self.runtime.sign_document(unsigned)
        verify_document(
            signed, self.runtime.verification_keys()
        )
        journal["signature"] = copy.deepcopy(signed["signature"])
        atomic_write_json(path, signed, mode=0o600)

    def _read_journal(self, path: Path) -> dict[str, Any]:
        try:
            journal = read_json(path)
            verify_document(
                journal,
                self.runtime.verification_keys(),
            )
            unsigned = copy.deepcopy(journal)
            unsigned.pop("signature", None)
            reject_credential_values(
                unsigned,
                location="lifecycle recovery journal",
                verified_by=self.runtime.signature_keys(),
            )
            return journal
        except ProtocolError as exc:
            if exc.code == "ADAPTER_LIFECYCLE_RECOVERY_MISMATCH":
                raise
            raise ProtocolError(
                "ADAPTER_LIFECYCLE_RECOVERY_MISMATCH",
                "lifecycle recovery journal is not authentic",
            ) from exc

    @staticmethod
    def _result_id(lifecycle_operation_key: str) -> str:
        return str(uuid5(NAMESPACE_URL, f"hive-lifecycle:{lifecycle_operation_key}"))

    @staticmethod
    def _bounded_export_root(scope: Mapping[str, Any]) -> Path:
        root_value = scope.get("root")
        if not isinstance(root_value, str):
            raise ProtocolError(
                "ADAPTER_EXPORT_BOUNDARY", "export scope must bind an absolute root"
            )
        root = Path(root_value)
        if (
            not root.is_absolute()
            or ".." in root.parts
            or root.is_symlink()
            or not root.is_dir()
            or str(root.resolve()) != root_value
        ):
            raise ProtocolError(
                "ADAPTER_EXPORT_BOUNDARY",
                "export root must be an exact, real directory",
            )
        return root.resolve()

    @staticmethod
    def _owned_target(root: Path, raw_relative: Any) -> Path:
        if not isinstance(raw_relative, str) or not raw_relative:
            raise ProtocolError(
                "ADAPTER_OWNERSHIP_BOUNDARY",
                "ownership path must be a canonical relative path",
            )
        relative = PurePosixPath(raw_relative)
        if (
            relative.is_absolute()
            or not relative.parts
            or any(part in {"", ".", ".."} for part in relative.parts)
            or relative.as_posix() != raw_relative
        ):
            raise ProtocolError(
                "ADAPTER_OWNERSHIP_BOUNDARY",
                "ownership path must be a canonical relative path",
            )
        target = root.joinpath(*relative.parts)
        current = root
        for component in relative.parts:
            current /= component
            if current.is_symlink():
                raise ProtocolError(
                    "ADAPTER_OWNERSHIP_BOUNDARY",
                    "ownership paths may not contain symlinks",
                )
        parent = target.parent.resolve(strict=False)
        if parent != root and root not in parent.parents:
            raise ProtocolError(
                "ADAPTER_OWNERSHIP_BOUNDARY", "ownership path escapes its bound root"
            )
        return target

    def _validate_ownership(
        self, ownership_manifest: Mapping[str, Any]
    ) -> tuple[Path, list[dict[str, str]]]:
        try:
            validate_adapter_document(
                "adapter-ownership-manifest.v1.schema.json", ownership_manifest
            )
            raw_root = ownership_manifest["root"]
            root = Path(raw_root)
            if (
                not isinstance(raw_root, str)
                or not root.is_absolute()
                or ".." in root.parts
                or root.is_symlink()
                or not root.is_dir()
                or str(root.resolve()) != raw_root
            ):
                raise ProtocolError(
                    "ADAPTER_OWNERSHIP_BOUNDARY", "ownership root is not exact and safe"
                )
            root = root.resolve()
            seen: set[str] = set()
            validated: list[dict[str, str]] = []
            for entry in ownership_manifest["paths"]:
                raw_relative = entry["path"]
                if raw_relative in seen:
                    raise ProtocolError(
                        "ADAPTER_OWNERSHIP_BOUNDARY",
                        "ownership paths must be unique",
                    )
                seen.add(raw_relative)
                target = self._owned_target(root, raw_relative)
                kind = entry["kind"]
                if kind == "file":
                    if not target.is_file() or _sha256_file(target) != entry["sha256"]:
                        raise ProtocolError(
                            "ADAPTER_OWNERSHIP_BOUNDARY",
                            "owned file is missing, unsafe, or altered",
                        )
                elif (
                    kind != "directory"
                    or not target.is_dir()
                    or _directory_digest(target) != entry["sha256"]
                ):
                    raise ProtocolError(
                        "ADAPTER_OWNERSHIP_BOUNDARY",
                        "owned directory is missing, unsafe, or altered",
                    )
                validated.append(copy.deepcopy(entry))
            return root, validated
        except (KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
            raise ProtocolError(
                "ADAPTER_OWNERSHIP_BOUNDARY",
                "ownership manifest failed exact boundary validation",
            ) from exc
        except ProtocolError as exc:
            if exc.code == "ADAPTER_OWNERSHIP_BOUNDARY":
                raise
            raise ProtocolError(
                "ADAPTER_OWNERSHIP_BOUNDARY",
                "ownership manifest failed schema validation",
            ) from exc

    def _signed_prior_result(
        self, result_document: Mapping[str, Any]
    ) -> AdapterResult:
        validate_adapter_document("adapter-result.v1.schema.json", result_document)
        reject_credential_values(
            result_document,
            location="lifecycle prior result",
            verified_by=self.runtime.verification_keys(),
        )
        verify_document(
            result_document,
            self.runtime.verification_keys(),
        )
        prior = AdapterResult.from_dict(result_document)
        if prior.outcome != "APPLIED" or not prior.rollback_ref:
            raise ProtocolError(
                "ADAPTER_ROLLBACK_REFUSED",
                "rollback requires an APPLIED signed result with a rollback reference",
            )
        return prior

    def _normalize_plan_payload(
        self,
        adapter_id: str,
        operation: str,
        payload: Mapping[str, Any],
        project_id: str,
        adapter_version: str,
    ) -> tuple[dict[str, Any], list[str]]:
        if operation == "export":
            scope = copy.deepcopy(dict(payload))
            self._bounded_export_root(scope)
            return {"operation": operation, "scope": scope}, [
                "adapter:owned-paths",
                "workspace:export",
            ]
        if operation == "rollback":
            prior = self._signed_prior_result(payload)
            if (
                prior.adapter_id != adapter_id
                or prior.adapter_version != adapter_version
                or prior.project_id != project_id
            ):
                raise ProtocolError(
                    "ADAPTER_LIFECYCLE_PLAN_MISMATCH",
                    "rollback input crosses an adapter, version, or project boundary",
                )
            return {
                "operation": operation,
                "result_digest": document_digest(payload),
                "rollback_ref": prior.rollback_ref,
            }, sorted(set(prior.side_effects) | {"adapter:owned-paths"})
        self._validate_ownership(payload)
        if (
            payload["adapter_id"] != adapter_id
            or payload["adapter_version"] != adapter_version
        ):
            raise ProtocolError(
                "ADAPTER_LIFECYCLE_PLAN_MISMATCH",
                "uninstall input crosses an adapter or version boundary",
            )
        return {
            "operation": operation,
            "installation_id": payload["installation_id"],
            "ownership_manifest_digest": document_digest(payload),
        }, ["adapter:owned-paths"]

    def plan(
        self,
        adapter_id: str,
        operation: str,
        payload: Mapping[str, Any],
        project_id: str,
    ) -> dict[str, Any]:
        if operation not in _OPERATIONS:
            raise ProtocolError(
                "ADAPTER_LIFECYCLE_OPERATION_INVALID",
                "lifecycle operation must be export, rollback, or uninstall",
            )
        if not isinstance(payload, Mapping) or not isinstance(project_id, str) or not project_id:
            raise ProtocolError(
                "ADAPTER_LIFECYCLE_INPUT_INVALID",
                "lifecycle planning requires an exact object and project",
            )
        entry = self.registry.require_current(adapter_id)
        _enforce_document_bound(
            payload,
            max_bytes=entry.manifest.resource_limits["max_input_bytes"],
        )
        reject_credential_values(payload, location="lifecycle planning input")
        normalized, side_effects = self._normalize_plan_payload(
            adapter_id,
            operation,
            payload,
            project_id,
            entry.manifest.version,
        )
        request_projection = {
            "schema_version": "hive.adapter-lifecycle-input.v1",
            "adapter_id": adapter_id,
            "adapter_version": entry.manifest.version,
            "operation": operation,
            "project_id": project_id,
            "input_digest": document_digest(payload),
        }
        policy_projection = {
            "schema_version": "hive.adapter-lifecycle-policy.v1",
            "adapter_id": adapter_id,
            "manifest_digest": entry.manifest_digest,
            "operation": operation,
            "project_id": project_id,
            "execution": "attended-local",
        }
        now = datetime.now(timezone.utc)
        plan = AdapterPlan(
            plan_id=str(uuid4()),
            request_digest=document_digest(request_projection),
            manifest_digest=entry.manifest_digest,
            policy_digest=document_digest(policy_projection),
            adapter_id=adapter_id,
            adapter_version=entry.manifest.version,
            capability_id=f"lifecycle.{operation}",
            project_id=project_id,
            side_effects=side_effects,
            network_destinations=[],
            requires_approval=operation != "export",
            expires_at=(now + timedelta(minutes=15)).isoformat().replace("+00:00", "Z"),
            payload=normalized,
        )
        signed = self.runtime.sign_document(plan.as_dict())
        validate_adapter_document("adapter-plan.v1.schema.json", signed)
        reject_credential_values(
            signed,
            location="signed lifecycle plan",
            verified_by=self.runtime.verification_keys(),
        )
        if len(canonical_bytes(signed)) > entry.manifest.resource_limits["max_output_bytes"]:
            raise ProtocolError(
                "ADAPTER_OUTPUT_LIMIT_EXCEEDED",
                "signed lifecycle plan exceeds the manifest limit",
            )
        self.runtime.require_owned_directory(self.runtime.plans)
        atomic_write_json(
            self.runtime.plans / f"{plan.plan_id}.json", signed, mode=0o600
        )
        return signed

    def _verify_plan(
        self,
        adapter_id: str,
        plan_document: Mapping[str, Any],
        operation: str,
        *,
        evaluated_at: datetime | None = None,
    ) -> tuple[AdapterPlan, Any]:
        validate_adapter_document("adapter-plan.v1.schema.json", plan_document)
        reject_credential_values(
            plan_document,
            location="lifecycle plan",
            verified_by=self.runtime.verification_keys(),
        )
        verify_document(
            plan_document,
            self.runtime.verification_keys(),
        )
        plan = AdapterPlan.from_dict(plan_document)
        entry = self.registry.require(adapter_id, plan.adapter_version)
        evaluation_time = evaluated_at or datetime.now(timezone.utc)
        if (
            plan.adapter_id != adapter_id
            or plan.manifest_digest != entry.manifest_digest
            or plan.capability_id != f"lifecycle.{operation}"
            or plan.payload.get("operation") != operation
        ):
            raise ProtocolError(
                "ADAPTER_LIFECYCLE_PLAN_MISMATCH",
                "lifecycle plan does not bind the registered operation",
            )
        if _date_time(plan.expires_at, code="ADAPTER_PLAN_EXPIRY_INVALID") <= evaluation_time:
            raise ProtocolError("ADAPTER_PLAN_EXPIRED", "adapter plan has expired")
        stored = read_json(self.runtime.plans / f"{plan.plan_id}.json")
        if canonical_bytes(stored) != canonical_bytes(plan_document):
            raise ProtocolError(
                "ADAPTER_STORED_PLAN_MISMATCH",
                "lifecycle plan differs from the stored signed plan",
            )
        return plan, entry

    def approve(
        self,
        plan_document: Mapping[str, Any],
        approver: Mapping[str, str],
        signing_key: Ed25519PrivateKey,
    ) -> dict[str, Any]:
        operation = str(plan_document.get("capability_id", "")).removeprefix(
            "lifecycle."
        )
        plan, _ = self._verify_plan(
            str(plan_document.get("adapter_id", "")), plan_document, operation
        )
        if not plan.requires_approval:
            raise ProtocolError(
                "ADAPTER_APPROVAL_NOT_REQUIRED", "export plans do not accept approval"
            )
        key_id = public_key_id(signing_key.public_key())
        if key_id not in self.runtime.trusted_approver_keys:
            raise ProtocolError(
                "ADAPTER_APPROVER_KEY_UNTRUSTED",
                "attended approver key is not trusted by this runtime",
            )
        bound_identity = self.runtime.trusted_approver_identities.get(key_id)
        if (
            bound_identity is None
            or dict(approver) != bound_identity
            or dict(approver).get("project_id") != plan.project_id
        ):
            raise ProtocolError(
                "ADAPTER_APPROVER_IDENTITY_MISMATCH",
                "approval identity does not match the lifecycle project",
            )
        approval = AdapterApproval(
            approval_id=str(uuid4()),
            plan_digest=document_digest(plan_document),
            approver=copy.deepcopy(dict(approver)),
            decision="APPROVED",
            expires_at=plan.expires_at,
            nonce=uuid4().hex,
        )
        signed = sign_document(approval.as_dict(), signing_key)
        validate_adapter_document("adapter-approval.v1.schema.json", signed)
        reject_credential_values(
            signed,
            location="signed lifecycle approval",
            verified_by=self.runtime.trusted_approver_keys,
        )
        verify_document(signed, self.runtime.trusted_approver_keys)
        self._require_directory(self.approvals)
        atomic_write_json(self.approvals / f"{approval.approval_id}.json", signed, mode=0o600)
        return signed

    def _verify_approval(
        self,
        plan_document: Mapping[str, Any],
        plan: AdapterPlan,
        approval_document: Mapping[str, Any] | None,
        *,
        evaluated_at: datetime | None = None,
    ) -> AdapterApproval | None:
        if not plan.requires_approval:
            if approval_document is not None:
                raise ProtocolError(
                    "ADAPTER_APPROVAL_NOT_REQUIRED",
                    "approval-free lifecycle plans reject approval documents",
                )
            return None
        if approval_document is None:
            raise ProtocolError(
                "ADAPTER_APPROVAL_REQUIRED",
                "rollback and uninstall require an exact attended approval",
            )
        validate_adapter_document("adapter-approval.v1.schema.json", approval_document)
        reject_credential_values(
            approval_document,
            location="lifecycle approval",
            verified_by=self.runtime.trusted_approver_keys,
        )
        verify_document(approval_document, self.runtime.trusted_approver_keys)
        approval = AdapterApproval.from_dict(approval_document)
        signature = approval_document.get("signature")
        key_id = signature.get("key_id") if isinstance(signature, Mapping) else None
        bound_identity = self.runtime.trusted_approver_identities.get(str(key_id))
        if approval.decision != "APPROVED":
            raise ProtocolError(
                "ADAPTER_APPROVAL_REJECTED", "approval decision is not APPROVED"
            )
        if approval.plan_digest != document_digest(plan_document):
            raise ProtocolError(
                "APPROVAL_PLAN_MISMATCH",
                "approval does not bind the exact signed lifecycle plan",
            )
        evaluation_time = evaluated_at or datetime.now(timezone.utc)
        if _date_time(
            approval.expires_at, code="ADAPTER_APPROVAL_EXPIRY_INVALID"
        ) <= evaluation_time:
            raise ProtocolError("ADAPTER_APPROVAL_EXPIRED", "approval has expired")
        if (
            bound_identity is None
            or approval.approver != bound_identity
            or approval.approver.get("project_id") != plan.project_id
        ):
            raise ProtocolError(
                "ADAPTER_APPROVER_IDENTITY_MISMATCH",
                "approval identity does not match the lifecycle project",
            )
        return approval

    def _bind_input(
        self,
        operation: str,
        input_document: Mapping[str, Any],
        plan: AdapterPlan,
        *,
        recovery_removals: Any = None,
    ) -> tuple[Any, Any]:
        if operation == "export":
            scope = copy.deepcopy(dict(input_document))
            root = self._bounded_export_root(scope)
            if plan.payload != {"operation": "export", "scope": scope}:
                raise ProtocolError(
                    "ADAPTER_LIFECYCLE_PLAN_MISMATCH",
                    "export plan does not bind the exact scope",
                )
            return root, scope
        if operation == "rollback":
            prior = self._signed_prior_result(input_document)
            if (
                plan.project_id != prior.project_id
                or plan.adapter_id != prior.adapter_id
                or plan.adapter_version != prior.adapter_version
                or plan.payload
                != {
                    "operation": "rollback",
                    "result_digest": document_digest(input_document),
                    "rollback_ref": prior.rollback_ref,
                }
            ):
                raise ProtocolError(
                    "ADAPTER_LIFECYCLE_PLAN_MISMATCH",
                    "rollback plan crosses an adapter, version, project, or result boundary",
                )
            return prior, prior.rollback_ref
        validate_adapter_document(
            "adapter-ownership-manifest.v1.schema.json", input_document
        )
        validated_ownership = (
            self._validate_ownership(input_document)
            if recovery_removals is None
            else self._validate_removals(input_document, recovery_removals)
        )
        if (
            input_document["adapter_id"] != plan.adapter_id
            or input_document["adapter_version"] != plan.adapter_version
            or plan.payload
            != {
                "operation": "uninstall",
                "installation_id": input_document["installation_id"],
                "ownership_manifest_digest": document_digest(input_document),
            }
        ):
            raise ProtocolError(
                "ADAPTER_LIFECYCLE_PLAN_MISMATCH",
                "uninstall plan does not bind the exact ownership manifest",
            )
        return validated_ownership

    def _validate_removals(
        self,
        ownership_manifest: Mapping[str, Any],
        removals: Any,
    ) -> tuple[Path, list[dict[str, str]]]:
        raw_root = ownership_manifest["root"]
        root = Path(raw_root)
        if (
            not isinstance(raw_root, str)
            or not root.is_absolute()
            or root.is_symlink()
            or not root.is_dir()
            or str(root.resolve()) != raw_root
            or not isinstance(removals, list)
            or len(removals) != len(ownership_manifest["paths"])
        ):
            raise ProtocolError(
                "ADAPTER_OWNERSHIP_BOUNDARY", "uninstall recovery boundary is invalid"
            )
        root = root.resolve()
        for source, removal in zip(ownership_manifest["paths"], removals, strict=True):
            if (
                not isinstance(removal, dict)
                or set(removal) != _REMOVAL_FIELDS
                or {key: removal[key] for key in ("path", "kind", "sha256")}
                != {key: source[key] for key in ("path", "kind", "sha256")}
                or removal.get("state") not in {"PENDING", "REMOVING", "REMOVED"}
            ):
                raise ProtocolError(
                    "ADAPTER_OWNERSHIP_BOUNDARY", "uninstall recovery entry is invalid"
                )
            target = self._owned_target(root, removal["path"])
            state = removal["state"]
            exists = target.exists() or target.is_symlink()
            if removal["kind"] == "file":
                exact = (
                    not target.is_symlink()
                    and target.is_file()
                    and _sha256_file(target) == removal["sha256"]
                )
                if (state == "PENDING" and not exact) or (
                    state == "REMOVING" and exists and not exact
                ) or (state == "REMOVED" and exists):
                    raise ProtocolError(
                        "ADAPTER_OWNERSHIP_BOUNDARY",
                        "uninstall recovery file state drifted",
                    )
            else:
                safe_directory = not target.is_symlink() and target.is_dir()
                if (state == "PENDING" and not safe_directory) or (
                    state == "REMOVING"
                    and exists
                    and (not safe_directory or any(target.iterdir()))
                ) or (state == "REMOVED" and exists):
                    raise ProtocolError(
                        "ADAPTER_OWNERSHIP_BOUNDARY",
                        "uninstall recovery directory state drifted",
                    )
        return root, removals

    def _remove_owned_paths(
        self,
        root: Path,
        removals: list[dict[str, str]],
        journal: dict[str, Any],
        journal_path: Path,
    ) -> dict[str, Any]:
        self._validate_removals(journal["input"], removals)
        files = sorted(
            (item for item in removals if item["kind"] == "file"),
            key=lambda item: (len(PurePosixPath(item["path"]).parts), item["path"]),
            reverse=True,
        )
        directories = sorted(
            (item for item in removals if item["kind"] == "directory"),
            key=lambda item: (len(PurePosixPath(item["path"]).parts), item["path"]),
            reverse=True,
        )
        for removal in [*files, *directories]:
            if removal["state"] == "REMOVED":
                continue
            target = self._owned_target(root, removal["path"])
            if removal["state"] == "PENDING":
                if removal["kind"] == "file":
                    if not target.is_file() or _sha256_file(target) != removal["sha256"]:
                        raise ProtocolError(
                            "ADAPTER_OWNERSHIP_BOUNDARY",
                            "owned file changed before deletion",
                        )
                elif not target.is_dir() or any(target.iterdir()):
                    raise ProtocolError(
                        "ADAPTER_OWNERSHIP_BOUNDARY",
                        "owned directory is not empty before deletion",
                    )
                removal["state"] = "REMOVING"
                self._write_journal(journal_path, journal)
            if target.exists() or target.is_symlink():
                if removal["kind"] == "file":
                    if target.is_symlink() or _sha256_file(target) != removal["sha256"]:
                        raise ProtocolError(
                            "ADAPTER_OWNERSHIP_BOUNDARY",
                            "owned file changed during deletion",
                        )
                    target.unlink()
                else:
                    if target.is_symlink() or not target.is_dir() or any(target.iterdir()):
                        raise ProtocolError(
                            "ADAPTER_OWNERSHIP_BOUNDARY",
                            "owned directory changed during deletion",
                        )
                    target.rmdir()
            removal["state"] = "REMOVED"
            self._write_journal(journal_path, journal)
        return {
            "outcome": "APPLIED",
            "evidence_refs": [],
            "side_effects": ["adapter:owned-paths"],
            "resource_use": {"removed": len(removals)},
            "rollback_ref": None,
            "detail": {
                "removed": [item["path"] for item in removals],
                "orchestrator_owned": True,
            },
        }

    def _normalize_export_result(
        self,
        exported: Any,
        root: Path,
    ) -> dict[str, Any]:
        required = {
            "outcome",
            "files",
            "side_effects",
            "resource_use",
            "rollback_ref",
            "detail",
        }
        if not isinstance(exported, dict) or set(exported) != required:
            raise ProtocolError(
                "ADAPTER_EXPORT_RESULT_INVALID",
                "adapter export must return the closed export result",
            )
        files = exported["files"]
        if (
            not isinstance(files, list)
            or not all(isinstance(item, str) for item in files)
            or len(files) != len(set(files))
        ):
            raise ProtocolError(
                "ADAPTER_EXPORT_RESULT_INVALID", "exported files must be unique paths"
            )
        evidence_refs: list[dict[str, Any]] = []
        for raw_relative in files:
            relative = PurePosixPath(raw_relative)
            if (
                relative.is_absolute()
                or not relative.parts
                or any(part in {"", ".", ".."} for part in relative.parts)
                or relative.as_posix() != raw_relative
            ):
                raise ProtocolError(
                    "ADAPTER_EXPORT_BOUNDARY",
                    "exported file path escapes the export root",
                )
            path = root.joinpath(*relative.parts)
            if path.is_symlink() or not path.is_file() or root not in path.resolve().parents:
                raise ProtocolError(
                    "ADAPTER_EXPORT_BOUNDARY",
                    "exported file must be regular and remain inside the export root",
                )
            evidence_refs.append(
                {
                    "path": relative.as_posix(),
                    "sha256": _sha256_file(path),
                    "size_bytes": path.stat().st_size,
                }
            )
        return {
            "outcome": exported["outcome"],
            "evidence_refs": evidence_refs,
            "side_effects": exported["side_effects"],
            "resource_use": exported["resource_use"],
            "rollback_ref": exported["rollback_ref"],
            "detail": exported["detail"],
        }

    def _adapter_lifecycle_result(
        self,
        operation: str,
        registered: Any,
        bound_input: Any,
        lifecycle_operation_key: str,
        *,
        recovering: bool,
    ) -> Any:
        recovery = getattr(registered.adapter, "recover_lifecycle", None)
        if not callable(recovery):
            raise ProtocolError(
                "ADAPTER_PROTOCOL_INVALID",
                "adapter lifecycle recovery hook is required",
            )
        if recovering:
            applied = recovery(operation, lifecycle_operation_key)
            if applied is None:
                raise ProtocolError(
                    "ADAPTER_EFFECT_STATE_PENDING",
                    "lifecycle effect state requires attended recovery",
                )
            return applied
        method = getattr(registered.adapter, operation, None)
        if not callable(method):
            raise ProtocolError(
                "ADAPTER_PROTOCOL_INVALID", "adapter lifecycle hook is unavailable"
            )
        if operation == "export":
            return method(copy.deepcopy(bound_input), operation_key=lifecycle_operation_key)
        return method(bound_input, operation_key=lifecycle_operation_key)

    def _run_operation(
        self,
        operation: str,
        registered: Any,
        bound_primary: Any,
        bound_input: Any,
        lifecycle_operation_key: str,
        plan: AdapterPlan,
        journal: dict[str, Any],
        journal_path: Path,
        *,
        recovering: bool,
    ) -> dict[str, Any]:
        with execution_deadline(registered.manifest.resource_limits["timeout_seconds"]):
            if operation == "uninstall":
                applied = self._remove_owned_paths(
                    bound_primary,
                    journal["removals"],
                    journal,
                    journal_path,
                )
            else:
                contribution = self._adapter_lifecycle_result(
                    operation,
                    registered,
                    bound_input,
                    lifecycle_operation_key,
                    recovering=recovering,
                )
                reject_credential_values(
                    contribution, location=f"adapter lifecycle {operation} contribution"
                )
                applied = (
                    self._normalize_export_result(contribution, bound_primary)
                    if operation == "export"
                    else self.runtime.validate_apply_result(contribution, plan)
                )
        reject_credential_values(applied, location="validated lifecycle result")
        return self.runtime.validate_apply_result(applied, plan)

    def _write_result(
        self,
        plan_document: Mapping[str, Any],
        plan: AdapterPlan,
        applied: Mapping[str, Any],
        lifecycle_operation_key: str,
        *,
        max_output_bytes: int,
    ) -> dict[str, Any]:
        result = AdapterResult(
            result_id=self._result_id(lifecycle_operation_key),
            request_digest=plan.request_digest,
            plan_digest=document_digest(plan_document),
            adapter_id=plan.adapter_id,
            adapter_version=plan.adapter_version,
            project_id=plan.project_id,
            outcome=applied["outcome"],
            evidence_refs=copy.deepcopy(applied["evidence_refs"]),
            side_effects=list(applied["side_effects"]),
            resource_use=copy.deepcopy(applied["resource_use"]),
            rollback_ref=applied["rollback_ref"],
            detail=copy.deepcopy(applied["detail"]),
        )
        signed = self.runtime.sign_document(result.as_dict())
        validate_adapter_document("adapter-result.v1.schema.json", signed)
        reject_credential_values(
            signed,
            location="signed lifecycle result",
            verified_by=self.runtime.verification_keys(),
        )
        if len(canonical_bytes(signed)) > max_output_bytes:
            raise ProtocolError(
                "ADAPTER_OUTPUT_LIMIT_EXCEEDED",
                "terminal lifecycle result exceeds the manifest output limit",
            )
        self.runtime.require_owned_directory(self.runtime.results)
        path = self.runtime.results / f"{result.result_id}.json"
        if path.exists():
            durable = read_json(path)
            if canonical_bytes(durable) != canonical_bytes(signed):
                raise ProtocolError(
                    "ADAPTER_LIFECYCLE_RESULT_MISMATCH",
                    "durable lifecycle result differs from its operation",
                )
            return durable
        atomic_write_json(path, signed, mode=0o600)
        return signed

    def _complete(
        self,
        journal_path: Path,
        journal: dict[str, Any],
        nonce: str,
        signed_result: Mapping[str, Any],
    ) -> None:
        journal["state"] = "RESULT_WRITTEN"
        journal["result_id"] = signed_result["result_id"]
        self._write_journal(journal_path, journal)
        self.replay.complete(journal["plan"]["plan_id"], nonce)
        journal["state"] = "TERMINAL"
        journal["completed_at"] = utc_now()
        self._write_journal(journal_path, journal)

    def _execute(
        self,
        operation: str,
        adapter_id: str,
        input_document: Mapping[str, Any],
        plan_document: Mapping[str, Any],
        approval_document: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        plan, registered = self._verify_plan(adapter_id, plan_document, operation)
        approval = self._verify_approval(plan_document, plan, approval_document)
        _enforce_document_bound(
            input_document,
            max_bytes=registered.manifest.resource_limits["max_input_bytes"],
        )
        reject_credential_values(input_document, location="lifecycle execution input")
        bound_primary, bound_input = self._bind_input(operation, input_document, plan)
        plan_digest = document_digest(plan_document)
        lifecycle_operation_key = operation_key(plan.request_digest, plan_digest)
        nonce = approval.nonce if approval is not None else plan_digest
        removals = (
            [{**copy.deepcopy(entry), "state": "PENDING"} for entry in bound_input]
            if operation == "uninstall"
            else None
        )
        journal = {
            "schema_version": "hive.adapter-lifecycle-recovery.v1",
            "adapter_id": adapter_id,
            "operation": operation,
            "operation_key": lifecycle_operation_key,
            "input": copy.deepcopy(dict(input_document)),
            "input_digest": document_digest(input_document),
            "plan": copy.deepcopy(dict(plan_document)),
            "approval": (
                copy.deepcopy(dict(approval_document))
                if approval_document is not None
                else None
            ),
            "state": "PREPARED",
            "prepared_at": utc_now(),
            "claimed_at": None,
            "completed_at": None,
            "result_id": None,
            "removals": removals,
        }
        reject_credential_values(
            journal,
            location="lifecycle recovery journal",
            verified_by=self.runtime.signature_keys(),
        )
        self._require_directory(self.journals)
        journal_path = self.journals / f"{plan.plan_id}.json"
        with exclusive_lock(journal_path.with_suffix(".json.lock")):
            if journal_path.exists():
                raise ProtocolError(
                    "REPLAY_MESSAGE_ID", "lifecycle plan was already consumed", 3
                )
            self._write_journal(journal_path, journal)
            claim = self.replay.begin(plan.plan_id, nonce)
            if claim != "NEW":
                raise ProtocolError(
                    "REPLAY_MESSAGE_ID", "lifecycle plan already has a pending claim", 3
                )
            journal["state"] = "CLAIMED"
            journal["claimed_at"] = utc_now()
            self._write_journal(journal_path, journal)
            try:
                applied = self._run_operation(
                    operation,
                    registered,
                    bound_primary,
                    bound_input,
                    lifecycle_operation_key,
                    plan,
                    journal,
                    journal_path,
                    recovering=False,
                )
                signed_result = self._write_result(
                    plan_document,
                    plan,
                    applied,
                    lifecycle_operation_key,
                    max_output_bytes=registered.manifest.resource_limits[
                        "max_output_bytes"
                    ],
                )
            except Exception as exc:
                try:
                    applied = self._run_operation(
                        operation,
                        registered,
                        bound_primary,
                        bound_input,
                        lifecycle_operation_key,
                        plan,
                        journal,
                        journal_path,
                        recovering=True,
                    )
                    signed_result = self._write_result(
                        plan_document,
                        plan,
                        applied,
                        lifecycle_operation_key,
                        max_output_bytes=registered.manifest.resource_limits[
                            "max_output_bytes"
                        ],
                    )
                except Exception as recovery_exc:
                    raise ProtocolError(
                        "ADAPTER_EFFECT_STATE_PENDING",
                        "lifecycle effect state requires attended recovery",
                    ) from recovery_exc
            self._complete(journal_path, journal, nonce, signed_result)
            return signed_result

    def export(
        self,
        adapter_id: str,
        scope: Mapping[str, Any],
        plan_document: Mapping[str, Any],
    ) -> dict[str, Any]:
        return self._execute("export", adapter_id, scope, plan_document, None)

    def rollback(
        self,
        result_document: Mapping[str, Any],
        plan_document: Mapping[str, Any],
        approval_document: Mapping[str, Any],
    ) -> dict[str, Any]:
        return self._execute(
            "rollback",
            str(plan_document.get("adapter_id", "")),
            result_document,
            plan_document,
            approval_document,
        )

    def uninstall(
        self,
        adapter_id: str,
        ownership_manifest: Mapping[str, Any],
        plan_document: Mapping[str, Any],
        approval_document: Mapping[str, Any],
    ) -> dict[str, Any]:
        return self._execute(
            "uninstall",
            adapter_id,
            ownership_manifest,
            plan_document,
            approval_document,
        )

    def _replay_claim(self, plan_id: str, nonce: str) -> dict[str, Any] | None:
        if not self.replay.ledger_path.exists():
            return None
        with exclusive_lock(self.replay.lock_path):
            document = read_json(self.replay.ledger_path)
            messages = document.get("messages")
            if not isinstance(messages, dict):
                raise ProtocolError(
                    "ADAPTER_LIFECYCLE_RECOVERY_MISMATCH",
                    "lifecycle replay ledger is malformed",
                )
            claim = messages.get(plan_id)
        if claim is None:
            return None
        if (
            not isinstance(claim, dict)
            or claim.get("nonce") != nonce
            or claim.get("state") not in {"PENDING", "COMPLETE"}
        ):
            raise ProtocolError(
                "ADAPTER_LIFECYCLE_RECOVERY_MISMATCH",
                "lifecycle replay claim does not match its journal",
            )
        return claim

    def _durable_result(
        self,
        result_id: str,
        plan_document: Mapping[str, Any],
        plan: AdapterPlan,
        lifecycle_operation_key: str,
        *,
        max_output_bytes: int,
    ) -> dict[str, Any]:
        durable = read_json(self.runtime.results / f"{result_id}.json")
        validate_adapter_document("adapter-result.v1.schema.json", durable)
        reject_credential_values(
            durable,
            location="durable lifecycle result",
            verified_by=self.runtime.verification_keys(),
        )
        verify_document(
            durable, self.runtime.verification_keys()
        )
        parsed = AdapterResult.from_dict(durable)
        if (
            result_id != self._result_id(lifecycle_operation_key)
            or parsed.result_id != result_id
            or parsed.request_digest != plan.request_digest
            or parsed.plan_digest != document_digest(plan_document)
            or parsed.adapter_id != plan.adapter_id
            or parsed.adapter_version != plan.adapter_version
            or parsed.project_id != plan.project_id
            or len(canonical_bytes(durable)) > max_output_bytes
        ):
            raise ProtocolError(
                "ADAPTER_LIFECYCLE_RECOVERY_MISMATCH",
                "durable lifecycle result does not match its journal",
            )
        return durable

    def recover_pending(self) -> list[dict[str, Any]]:
        if not self.journals.exists():
            return []
        self._require_directory(self.journals)
        recovered: list[dict[str, Any]] = []
        for journal_path in sorted(self.journals.glob("*.json")):
            with exclusive_lock(journal_path.with_suffix(".json.lock")):
                journal = self._read_journal(journal_path)
                if (
                    set(journal) != _JOURNAL_FIELDS
                    or journal.get("schema_version")
                    != "hive.adapter-lifecycle-recovery.v1"
                    or journal.get("operation") not in _OPERATIONS
                    or journal.get("state")
                    not in {"PREPARED", "CLAIMED", "RESULT_WRITTEN", "TERMINAL"}
                    or not isinstance(journal.get("plan"), dict)
                    or not isinstance(journal.get("input"), dict)
                    or not isinstance(journal.get("prepared_at"), str)
                    or not isinstance(journal.get("adapter_id"), str)
                    or not isinstance(journal.get("operation_key"), str)
                    or len(journal.get("operation_key", "")) != 64
                    or any(
                        character not in "0123456789abcdef"
                        for character in journal.get("operation_key", "")
                    )
                    or not isinstance(journal.get("input_digest"), str)
                    or len(journal.get("input_digest", "")) != 64
                    or any(
                        character not in "0123456789abcdef"
                        for character in journal.get("input_digest", "")
                    )
                    or (
                        journal.get("result_id") is not None
                        and not isinstance(journal.get("result_id"), str)
                    )
                ):
                    raise ProtocolError(
                        "ADAPTER_LIFECYCLE_RECOVERY_MISMATCH",
                        "lifecycle recovery journal is malformed",
                    )
                prepared_at = _date_time(
                    journal["prepared_at"],
                    code="ADAPTER_LIFECYCLE_RECOVERY_MISMATCH",
                )
                operation = journal["operation"]
                plan_document = journal["plan"]
                plan, registered = self._verify_plan(
                    journal["adapter_id"],
                    plan_document,
                    operation,
                    evaluated_at=prepared_at,
                )
                approval_document = journal["approval"]
                if approval_document is not None and not isinstance(
                    approval_document, dict
                ):
                    raise ProtocolError(
                        "ADAPTER_LIFECYCLE_RECOVERY_MISMATCH",
                        "stored lifecycle approval is invalid",
                    )
                approval = self._verify_approval(
                    plan_document,
                    plan,
                    approval_document,
                    evaluated_at=prepared_at,
                )
                if document_digest(journal["input"]) != journal["input_digest"]:
                    raise ProtocolError(
                        "ADAPTER_LIFECYCLE_RECOVERY_MISMATCH",
                        "lifecycle input digest changed",
                    )
                expected_key = operation_key(
                    plan.request_digest, document_digest(plan_document)
                )
                deterministic_result_id = self._result_id(expected_key)
                state = journal["state"]
                expected_result_id = (
                    deterministic_result_id
                    if state in {"RESULT_WRITTEN", "TERMINAL"}
                    else None
                )
                if (
                    journal["result_id"] != expected_result_id
                    or (
                        state == "PREPARED"
                        and (
                            journal["claimed_at"] is not None
                            or journal["completed_at"] is not None
                        )
                    )
                    or (
                        state in {"CLAIMED", "RESULT_WRITTEN"}
                        and (
                            not isinstance(journal["claimed_at"], str)
                            or journal["completed_at"] is not None
                        )
                    )
                    or (
                        state == "TERMINAL"
                        and (
                            not isinstance(journal["claimed_at"], str)
                            or not isinstance(journal["completed_at"], str)
                        )
                    )
                ):
                    raise ProtocolError(
                        "ADAPTER_LIFECYCLE_RECOVERY_MISMATCH",
                        "lifecycle journal state metadata changed",
                    )
                if isinstance(journal["claimed_at"], str):
                    _date_time(
                        journal["claimed_at"],
                        code="ADAPTER_LIFECYCLE_RECOVERY_MISMATCH",
                    )
                if isinstance(journal["completed_at"], str):
                    _date_time(
                        journal["completed_at"],
                        code="ADAPTER_LIFECYCLE_RECOVERY_MISMATCH",
                    )
                if (
                    journal["operation_key"] != expected_key
                    or journal_path.stem != plan.plan_id
                    or (
                        operation == "uninstall" and not isinstance(journal["removals"], list)
                    )
                    or (operation != "uninstall" and journal["removals"] is not None)
                ):
                    raise ProtocolError(
                        "ADAPTER_LIFECYCLE_RECOVERY_MISMATCH",
                        "lifecycle journal binding changed",
                    )
                bound_primary, bound_input = self._bind_input(
                    operation,
                    journal["input"],
                    plan,
                    recovery_removals=journal["removals"],
                )
                nonce = approval.nonce if approval is not None else document_digest(
                    plan_document
                )
                claim = self._replay_claim(plan.plan_id, nonce)
                result_path = self.runtime.results / f"{deterministic_result_id}.json"
                if result_path.exists():
                    durable = self._durable_result(
                        deterministic_result_id,
                        plan_document,
                        plan,
                        expected_key,
                        max_output_bytes=registered.manifest.resource_limits[
                            "max_output_bytes"
                        ],
                    )
                    if claim is None:
                        raise ProtocolError(
                            "ADAPTER_LIFECYCLE_RECOVERY_MISMATCH",
                            "durable lifecycle result lacks its replay claim",
                        )
                    if claim["state"] == "PENDING":
                        self.replay.complete(plan.plan_id, nonce)
                    was_terminal = journal["state"] == "TERMINAL"
                    journal["state"] = "TERMINAL"
                    journal["result_id"] = deterministic_result_id
                    journal["completed_at"] = journal.get("completed_at") or utc_now()
                    self._write_journal(journal_path, journal)
                    if not was_terminal:
                        recovered.append(durable)
                    continue
                if journal["state"] == "TERMINAL":
                    raise ProtocolError(
                        "ADAPTER_LIFECYCLE_RECOVERY_MISMATCH",
                        "terminal lifecycle journal lacks its durable result",
                    )
                was_prepared = journal["state"] == "PREPARED"
                if was_prepared:
                    replay_outcome = self.replay.begin(plan.plan_id, nonce)
                    if replay_outcome not in {"NEW", "RESUME"}:
                        raise ProtocolError(
                            "ADAPTER_LIFECYCLE_RECOVERY_MISMATCH",
                            "lifecycle replay claim could not resume",
                        )
                    journal["state"] = "CLAIMED"
                    journal["claimed_at"] = journal.get("claimed_at") or utc_now()
                    self._write_journal(journal_path, journal)
                    claim = self._replay_claim(plan.plan_id, nonce)
                if claim is None or claim["state"] != "PENDING":
                    raise ProtocolError(
                        "ADAPTER_LIFECYCLE_RECOVERY_MISMATCH",
                        "nonterminal lifecycle journal lacks a pending replay claim",
                    )
                try:
                    applied = self._run_operation(
                        operation,
                        registered,
                        bound_primary,
                        bound_input,
                        expected_key,
                        plan,
                        journal,
                        journal_path,
                        recovering=not was_prepared,
                    )
                    signed_result = self._write_result(
                        plan_document,
                        plan,
                        applied,
                        expected_key,
                        max_output_bytes=registered.manifest.resource_limits[
                            "max_output_bytes"
                        ],
                    )
                except Exception as exc:
                    raise ProtocolError(
                        "ADAPTER_EFFECT_STATE_PENDING",
                        "lifecycle effect state remains pending attended recovery",
                    ) from exc
                self._complete(journal_path, journal, nonce, signed_result)
                recovered.append(signed_result)
        return recovered
