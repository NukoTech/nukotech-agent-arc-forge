"""Signed planning runtime for Hive application adapters."""

from __future__ import annotations

import copy
import dataclasses
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping
from uuid import NAMESPACE_URL, uuid4, uuid5

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from hive_protocol.adapters.models import (
    AdapterApproval,
    AdapterOutcome,
    AdapterPlan,
    AdapterRequest,
    AdapterResult,
    validate_adapter_document,
)
from hive_protocol.adapters.execution import execution_deadline, operation_key
from hive_protocol.adapters.policy import InvocationContext, authorize_adapter_request
from hive_protocol.adapters.registry import AdapterRegistry
from hive_protocol.adapters.security import reject_credential_values
from hive_protocol.core import (
    ProtocolError,
    canonical_bytes,
    document_digest,
    public_key_id,
    sign_document as sign_core_document,
    verify_document,
)
from hive_protocol.storage import (
    ReplayLedger,
    atomic_write_json,
    exclusive_lock,
    read_json,
    utc_now,
)


def _date_time(value: str, *, code: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError(code, "date-time value is invalid") from exc
    if parsed.tzinfo is None:
        raise ProtocolError(code, "date-time value must include a timezone")
    return parsed.astimezone(timezone.utc)


_MAX_ADAPTER_DOCUMENT_DEPTH = 64
_ADAPTER_REQUEST_ENVELOPE_OVERHEAD = 64 * 1024
_RECOVERY_JOURNAL_FIELDS = frozenset(
    {
        "schema_version",
        "request",
        "plan",
        "approval",
        "context",
        "adapter_id",
        "operation_key",
        "state",
        "prepared_at",
        "claimed_at",
        "completed_at",
        "result_id",
        "signature",
    }
)


def _enforce_document_bound(
    document: Mapping[str, Any],
    *,
    max_bytes: int,
    size_code: str = "ADAPTER_INPUT_LIMIT_EXCEEDED",
    depth_code: str = "ADAPTER_INPUT_DEPTH_EXCEEDED",
) -> None:
    """Reject oversized or excessively nested input before recursive validators."""

    stack: list[tuple[Any, int]] = [(document, 0)]
    nodes = 0
    approximate_bytes = 0
    max_nodes = max(4096, min(max_bytes * 2, 100_000))
    while stack:
        value, depth = stack.pop()
        if depth > _MAX_ADAPTER_DOCUMENT_DEPTH:
            raise ProtocolError(depth_code, "adapter input exceeds the nesting limit")
        nodes += 1
        if nodes > max_nodes:
            raise ProtocolError(size_code, "adapter input exceeds the structural limit")
        if isinstance(value, Mapping):
            approximate_bytes += 2 + len(value)
            for key, child in value.items():
                if isinstance(key, str):
                    approximate_bytes += len(key.encode("utf-8")) + 3
                stack.append((child, depth + 1))
        elif isinstance(value, (list, tuple)):
            approximate_bytes += 2 + len(value)
            stack.extend((child, depth + 1) for child in value)
        elif isinstance(value, str):
            approximate_bytes += len(value.encode("utf-8")) + 2
        elif value is None or isinstance(value, (bool, int, float)):
            approximate_bytes += len(str(value))
        else:
            approximate_bytes += max_bytes + 1
        if approximate_bytes > max_bytes:
            raise ProtocolError(size_code, "adapter input exceeds the document limit")
    try:
        exact_bytes = len(canonical_bytes(document))
    except (TypeError, ValueError):
        return
    if exact_bytes > max_bytes:
        raise ProtocolError(size_code, "adapter input exceeds the document limit")


class AdapterRuntime:
    def __init__(
        self,
        root: Path,
        registry: AdapterRegistry,
        trusted_request_keys: Mapping[str, Ed25519PublicKey],
        trusted_approver_keys: Mapping[str, Ed25519PublicKey],
        signing_key: Ed25519PrivateKey,
        *,
        trusted_approver_identities: Mapping[str, Mapping[str, str]] | None = None,
    ) -> None:
        raw_root = root.expanduser()
        for candidate in [raw_root, *raw_root.parents]:
            if candidate.is_symlink():
                raise ProtocolError(
                    "ADAPTER_RUNTIME_ROOT_BOUNDARY",
                    "adapter runtime path may not contain symlinks",
                )
        self.root = raw_root.resolve(strict=False)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if (
            self.root.is_symlink()
            or not self.root.is_dir()
            or self.root.resolve() != self.root
            or self.root.stat().st_uid != os.geteuid()
        ):
            raise ProtocolError(
                "ADAPTER_RUNTIME_ROOT_BOUNDARY",
                "adapter runtime root is not an owned canonical directory",
            )
        os.chmod(self.root, 0o700)
        self.registry = registry
        self.trusted_request_keys = dict(trusted_request_keys)
        self.trusted_approver_keys = dict(trusted_approver_keys)
        self.trusted_approver_identities = {
            key_id: copy.deepcopy(dict(identity))
            for key_id, identity in (trusted_approver_identities or {}).items()
        }
        if set(self.trusted_approver_identities) != set(self.trusted_approver_keys):
            raise ProtocolError(
                "ADAPTER_APPROVER_IDENTITY_MISMATCH",
                "every trusted approver key must bind one exact identity",
            )
        self.signing_key = signing_key
        self.key_id = public_key_id(signing_key.public_key())
        # Keys whose verified signatures the credential guard may skip (#23).
        self._signature_keys = {
            **self.trusted_request_keys,
            **self.trusted_approver_keys,
            self.key_id: signing_key.public_key(),
        }
        self.plans = self.root / "plans"
        self.results = self.root / "results"
        self.recovery = self.root / "recovery"
        self.replay = ReplayLedger(self.root / "replay.json", mode=0o600)

    def verification_keys(self) -> dict[str, Ed25519PublicKey]:
        """Return a copy of {key_id: public key} for this runtime's own signatures.

        Public verification keys only; the private signing key is never returned.
        """

        return {self.key_id: self.signing_key.public_key()}

    def signature_keys(self) -> dict[str, Ed25519PublicKey]:
        """Return a copy of the public keys whose verified signatures the guard may skip.

        Trusted request, trusted approver and this runtime's public key. Changing
        the returned dict does not change the runtime.
        """

        return dict(self._signature_keys)

    def sign_document(self, document: Mapping[str, Any]) -> dict[str, Any]:
        """Sign a document with this runtime's key.

        External modules should call this instead of using the signing key.
        """

        return sign_core_document(document, self.signing_key)

    def require_owned_directory(self, path: Path) -> None:
        if path.is_symlink():
            raise ProtocolError(
                "ADAPTER_RUNTIME_ROOT_BOUNDARY",
                "adapter runtime directory must not be a symlink",
            )
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        if (
            path.is_symlink()
            or path.resolve() != path
            or path.stat().st_uid != os.geteuid()
        ):
            raise ProtocolError(
                "ADAPTER_RUNTIME_ROOT_BOUNDARY",
                "adapter runtime directory is not owned and canonical",
            )
        os.chmod(path, 0o700)

    def _write_recovery_journal(
        self, path: Path, journal: dict[str, Any]
    ) -> None:
        unsigned = copy.deepcopy(journal)
        unsigned.pop("signature", None)
        reject_credential_values(
            unsigned,
            location="adapter recovery journal",
            verified_by=self._signature_keys,
        )
        signed = self.sign_document(unsigned)
        verify_document(signed, {self.key_id: self.signing_key.public_key()})
        journal["signature"] = copy.deepcopy(signed["signature"])
        atomic_write_json(path, signed, mode=0o600)

    def read_recovery_journal(self, path: Path) -> dict[str, Any]:
        try:
            journal = read_json(path)
            verify_document(journal, {self.key_id: self.signing_key.public_key()})
            unsigned = copy.deepcopy(journal)
            unsigned.pop("signature", None)
            reject_credential_values(
                unsigned,
                location="adapter recovery journal",
                verified_by=self._signature_keys,
            )
            return journal
        except ProtocolError as exc:
            if exc.code == "ADAPTER_RECOVERY_MISMATCH":
                raise
            raise ProtocolError(
                "ADAPTER_RECOVERY_MISMATCH",
                "adapter recovery journal is not authentic",
            ) from exc

    @staticmethod
    def result_id(invocation_operation_key: str) -> str:
        return str(uuid5(NAMESPACE_URL, f"hive-adapter:{invocation_operation_key}"))

    def plan(
        self,
        request_document: Mapping[str, Any],
        context: InvocationContext,
    ) -> dict[str, Any]:
        raw_adapter_id = request_document.get("adapter_id")
        raw_adapter_version = request_document.get("adapter_version")
        if isinstance(raw_adapter_id, str) and isinstance(raw_adapter_version, str):
            entry = self.registry.require(raw_adapter_id, raw_adapter_version)
            envelope_limit = (
                entry.manifest.resource_limits["max_input_bytes"]
                + _ADAPTER_REQUEST_ENVELOPE_OVERHEAD
            )
        else:
            envelope_limit = _ADAPTER_REQUEST_ENVELOPE_OVERHEAD
        _enforce_document_bound(request_document, max_bytes=envelope_limit)
        validate_adapter_document("adapter-request.v1.schema.json", request_document)
        reject_credential_values(
            request_document,
            location="adapter request",
            verified_by=self._signature_keys,
        )
        verify_document(request_document, self.trusted_request_keys)
        request = AdapterRequest.from_dict(request_document)
        entry = self.registry.require(request.adapter_id, request.adapter_version)
        decision = authorize_adapter_request(
            entry.manifest,
            request,
            context,
            revoked=self.registry.is_revoked(request.adapter_id),
        )
        request_validator = getattr(entry.adapter, "validate_request", None)
        evidence_validator = getattr(entry.adapter, "validate_evidence", None)
        if request_validator is not None and not callable(request_validator):
            raise ProtocolError(
                "ADAPTER_PROTOCOL_INVALID",
                "adapter request validator is not callable",
            )
        if evidence_validator is not None and not callable(evidence_validator):
            raise ProtocolError(
                "ADAPTER_PROTOCOL_INVALID",
                "adapter evidence validator is not callable",
            )
        if len(canonical_bytes(request.payload)) > entry.manifest.resource_limits[
            "max_input_bytes"
        ]:
            raise ProtocolError(
                "ADAPTER_INPUT_LIMIT_EXCEEDED",
                "request payload exceeds the adapter input limit",
            )
        with execution_deadline(entry.manifest.resource_limits["timeout_seconds"]):
            detached_request = AdapterRequest.from_dict(request.as_dict())
            if request_validator is not None:
                request_validator(detached_request)
            if evidence_validator is not None:
                evidence_validator(detached_request)
            planned = entry.adapter.plan(copy.deepcopy(request.payload))
        reject_credential_values(planned, location="adapter plan contribution")
        if not isinstance(planned, dict) or set(planned) != {
            "side_effects",
            "network_destinations",
            "requires_approval",
            "payload",
        }:
            raise ProtocolError(
                "ADAPTER_PLAN_INVALID",
                "adapter plan must return the closed planning object",
            )
        side_effects = planned["side_effects"]
        network_destinations = planned["network_destinations"]
        requires_approval = planned["requires_approval"]
        payload = planned["payload"]
        if (
            not isinstance(side_effects, list)
            or not all(isinstance(item, str) and item for item in side_effects)
            or len(side_effects) != len(set(side_effects))
            or not isinstance(network_destinations, list)
            or not all(isinstance(item, str) and item for item in network_destinations)
            or len(network_destinations) != len(set(network_destinations))
            or not isinstance(requires_approval, bool)
            or not isinstance(payload, dict)
        ):
            raise ProtocolError(
                "ADAPTER_PLAN_INVALID",
                "adapter plan fields have invalid types or duplicate entries",
            )
        if not set(network_destinations) <= set(
            decision.effective_network_destinations
        ):
            raise ProtocolError(
                "ADAPTER_EGRESS_DENIED",
                "planned network destinations exceed effective authority",
            )
        if len(canonical_bytes(payload)) > entry.manifest.resource_limits[
            "max_output_bytes"
        ]:
            raise ProtocolError(
                "ADAPTER_OUTPUT_LIMIT_EXCEEDED",
                "planned payload exceeds the adapter output limit",
            )
        now = datetime.now(timezone.utc)
        request_expiry = _date_time(
            request.expires_at, code="ADAPTER_REQUEST_EXPIRY_INVALID"
        )
        expiry = min(request_expiry, now + timedelta(minutes=15))
        plan = AdapterPlan(
            plan_id=str(uuid4()),
            request_digest=document_digest(request_document),
            manifest_digest=entry.manifest_digest,
            policy_digest=document_digest(dataclasses.asdict(decision)),
            adapter_id=request.adapter_id,
            adapter_version=request.adapter_version,
            capability_id=request.capability_id,
            project_id=request.project_id,
            side_effects=list(side_effects),
            network_destinations=list(network_destinations),
            requires_approval=requires_approval,
            expires_at=expiry.isoformat().replace("+00:00", "Z"),
            payload=copy.deepcopy(payload),
        )
        signed = self.sign_document(plan.as_dict())
        validate_adapter_document("adapter-plan.v1.schema.json", signed)
        reject_credential_values(
            signed,
            location="signed adapter plan",
            verified_by=self._signature_keys,
        )
        self.require_owned_directory(self.plans)
        atomic_write_json(self.plans / f"{plan.plan_id}.json", signed, mode=0o600)
        return signed

    def invoke(
        self,
        request_document: Mapping[str, Any],
        plan_document: Mapping[str, Any],
        context: InvocationContext,
        approval_document: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        raw_adapter_id = request_document.get("adapter_id")
        raw_adapter_version = request_document.get("adapter_version")
        if isinstance(raw_adapter_id, str) and isinstance(raw_adapter_version, str):
            bounded_entry = self.registry.require(
                raw_adapter_id, raw_adapter_version
            )
            _enforce_document_bound(
                request_document,
                max_bytes=(
                    bounded_entry.manifest.resource_limits["max_input_bytes"]
                    + _ADAPTER_REQUEST_ENVELOPE_OVERHEAD
                ),
            )
        else:
            _enforce_document_bound(
                request_document, max_bytes=_ADAPTER_REQUEST_ENVELOPE_OVERHEAD
            )
        validate_adapter_document("adapter-request.v1.schema.json", request_document)
        reject_credential_values(
            request_document,
            location="adapter request",
            verified_by=self._signature_keys,
        )
        verify_document(request_document, self.trusted_request_keys)
        request = AdapterRequest.from_dict(request_document)
        entry = self.registry.require(request.adapter_id, request.adapter_version)
        decision = authorize_adapter_request(
            entry.manifest,
            request,
            context,
            revoked=self.registry.is_revoked(request.adapter_id),
        )

        validate_adapter_document("adapter-plan.v1.schema.json", plan_document)
        reject_credential_values(
            plan_document,
            location="adapter plan",
            verified_by=self._signature_keys,
        )
        verify_document(plan_document, {self.key_id: self.signing_key.public_key()})
        plan = AdapterPlan.from_dict(plan_document)
        expected_policy_digest = document_digest(dataclasses.asdict(decision))
        if plan.request_digest != document_digest(request_document):
            raise ProtocolError(
                "ADAPTER_REQUEST_PLAN_MISMATCH",
                "plan does not bind the exact request document",
            )
        if plan.manifest_digest != entry.manifest_digest:
            raise ProtocolError(
                "ADAPTER_MANIFEST_MISMATCH",
                "plan does not bind the registered manifest",
            )
        if plan.policy_digest != expected_policy_digest:
            raise ProtocolError(
                "ADAPTER_POLICY_MISMATCH",
                "plan does not bind the current policy decision",
            )
        if (
            plan.adapter_id != request.adapter_id
            or plan.adapter_version != request.adapter_version
            or plan.capability_id != request.capability_id
            or plan.project_id != request.project_id
        ):
            raise ProtocolError(
                "ADAPTER_PLAN_SCOPE_MISMATCH",
                "plan scope does not match the request",
            )
        if _date_time(plan.expires_at, code="ADAPTER_PLAN_EXPIRY_INVALID") <= datetime.now(
            timezone.utc
        ):
            raise ProtocolError("ADAPTER_PLAN_EXPIRED", "adapter plan has expired")

        stored_plan_path = self.plans / f"{plan.plan_id}.json"
        stored_plan = read_json(stored_plan_path)
        if canonical_bytes(stored_plan) != canonical_bytes(plan_document):
            raise ProtocolError(
                "ADAPTER_STORED_PLAN_MISMATCH",
                "invocation plan differs from the stored signed plan",
            )

        if plan.requires_approval and approval_document is None:
            raise ProtocolError(
                "ADAPTER_APPROVAL_REQUIRED",
                "the mutating plan requires an exact signed approval",
            )
        if approval_document is not None:
            reject_credential_values(
                approval_document,
                location="adapter approval",
                verified_by=self._signature_keys,
            )
            self._verify_approval(plan_document, plan, context, approval_document)

        self.require_owned_directory(self.recovery)
        journal_path = self.recovery / f"{request.request_id}.json"
        request_digest = document_digest(request_document)
        plan_digest = document_digest(plan_document)
        invocation_key = operation_key(request_digest, plan_digest)
        journal = {
            "schema_version": "hive.adapter-recovery-journal.v2",
            "request": copy.deepcopy(dict(request_document)),
            "plan": copy.deepcopy(dict(plan_document)),
            "approval": (
                copy.deepcopy(dict(approval_document))
                if approval_document is not None
                else None
            ),
            "context": self._context_document(context),
            "adapter_id": request.adapter_id,
            "operation_key": invocation_key,
            "state": "PREPARED",
            "prepared_at": utc_now(),
            "claimed_at": None,
            "completed_at": None,
            "result_id": None,
        }
        reject_credential_values(
            journal,
            location="adapter recovery journal",
            verified_by=self._signature_keys,
        )
        with exclusive_lock(journal_path.with_suffix(".json.lock")):
            if journal_path.exists():
                raise ProtocolError(
                    "REPLAY_MESSAGE_ID", "message ID already has a recovery journal", 3
                )
            self._write_recovery_journal(journal_path, journal)
            claim = self.replay.begin(request.request_id, request.nonce)
            if claim == "RESUME":
                raise ProtocolError(
                    "REPLAY_MESSAGE_ID",
                    "message ID has a pending recovery claim",
                    3,
                )
            journal["state"] = "CLAIMED"
            journal["claimed_at"] = utc_now()
            self._write_recovery_journal(journal_path, journal)

            try:
                with execution_deadline(
                    entry.manifest.resource_limits["timeout_seconds"]
                ):
                    applied = entry.adapter.apply(
                        copy.deepcopy(plan.payload), operation_key=invocation_key
                    )
                reject_credential_values(
                    applied, location="adapter apply contribution"
                )
                validated = self.validate_apply_result(applied, plan)
                signed_result = self._write_result(
                    request_document,
                    plan_document,
                    request,
                    validated,
                    max_output_bytes=entry.manifest.resource_limits[
                        "max_output_bytes"
                    ],
                )
            except Exception as exc:
                try:
                    recovered = entry.adapter.recover(invocation_key)
                    if recovered is None:
                        raise ProtocolError(
                            "ADAPTER_EFFECT_STATE_PENDING",
                            "adapter effect state requires attended recovery",
                        ) from exc
                    reject_credential_values(
                        recovered, location="adapter exception recovery contribution"
                    )
                    validated = self.validate_apply_result(recovered, plan)
                    signed_result = self._write_result(
                        request_document,
                        plan_document,
                        request,
                        validated,
                        max_output_bytes=entry.manifest.resource_limits[
                            "max_output_bytes"
                        ],
                    )
                except ProtocolError as recovery_exc:
                    if recovery_exc.code == "ADAPTER_EFFECT_STATE_PENDING":
                        raise ProtocolError(
                            "ADAPTER_EFFECT_STATE_PENDING",
                            "adapter effect state requires attended recovery",
                        ) from exc
                    raise ProtocolError(
                        "ADAPTER_EFFECT_STATE_PENDING",
                        "adapter effect state failed exact recovery validation",
                    ) from recovery_exc
                except Exception as recovery_exc:
                    raise ProtocolError(
                        "ADAPTER_EFFECT_STATE_PENDING",
                        "adapter effect state requires attended recovery",
                    ) from recovery_exc
            self._complete_invocation(
                journal_path, journal, request, signed_result
            )
            return signed_result

    @staticmethod
    def _context_document(context: InvocationContext) -> dict[str, Any]:
        return {
            "project_id": context.project_id,
            "authorization_ref": context.authorization_ref,
            "identity": copy.deepcopy(context.identity),
            "granted_capabilities": sorted(context.granted_capabilities),
            "granted_permissions": sorted(context.granted_permissions),
            "allowed_data_classifications": sorted(
                context.allowed_data_classifications
            ),
            "allowed_network_destinations": sorted(
                context.allowed_network_destinations
            ),
            "available_credential_references": sorted(
                context.available_credential_references
            ),
        }

    def _complete_invocation(
        self,
        journal_path: Path,
        journal: dict[str, Any],
        request: AdapterRequest,
        signed_result: Mapping[str, Any],
    ) -> None:
        journal["state"] = "RESULT_WRITTEN"
        journal["result_id"] = signed_result["result_id"]
        self._write_recovery_journal(journal_path, journal)
        self.replay.complete(request.request_id, request.nonce)
        journal["state"] = "TERMINAL"
        journal["completed_at"] = utc_now()
        self._write_recovery_journal(journal_path, journal)

    def _verify_approval(
        self,
        plan_document: Mapping[str, Any],
        plan: AdapterPlan,
        context: InvocationContext,
        approval_document: Mapping[str, Any],
        *,
        evaluated_at: datetime | None = None,
    ) -> None:
        validate_adapter_document("adapter-approval.v1.schema.json", approval_document)
        verify_document(approval_document, self.trusted_approver_keys)
        approval = AdapterApproval.from_dict(approval_document)
        signature = approval_document.get("signature")
        key_id = signature.get("key_id") if isinstance(signature, Mapping) else None
        bound_identity = self.trusted_approver_identities.get(str(key_id))
        if approval.decision != "APPROVED":
            raise ProtocolError(
                "ADAPTER_APPROVAL_REJECTED",
                "approval decision is not APPROVED",
            )
        if approval.plan_digest != document_digest(plan_document):
            raise ProtocolError(
                "APPROVAL_PLAN_MISMATCH",
                "approval does not bind the exact signed plan",
            )
        evaluation_time = evaluated_at or datetime.now(timezone.utc)
        if _date_time(
            approval.expires_at, code="ADAPTER_APPROVAL_EXPIRY_INVALID"
        ) <= evaluation_time.astimezone(timezone.utc):
            raise ProtocolError("ADAPTER_APPROVAL_EXPIRED", "approval has expired")
        if (
            bound_identity is None
            or approval.approver != bound_identity
            or approval.approver != context.identity
            or approval.approver.get("project_id") != plan.project_id
        ):
            raise ProtocolError(
                "ADAPTER_APPROVER_IDENTITY_MISMATCH",
                "approval identity does not match the invocation project identity",
            )

    @staticmethod
    def _context_from_document(document: Any) -> InvocationContext:
        expected = {
            "project_id",
            "authorization_ref",
            "identity",
            "granted_capabilities",
            "granted_permissions",
            "allowed_data_classifications",
            "allowed_network_destinations",
            "available_credential_references",
        }
        if not isinstance(document, dict) or set(document) != expected:
            raise ProtocolError(
                "ADAPTER_RECOVERY_MISMATCH", "stored invocation context is invalid"
            )
        identity = document["identity"]
        if not isinstance(identity, dict) or not all(
            isinstance(key, str)
            and isinstance(value, str)
            and key
            and value
            for key, value in identity.items()
        ):
            raise ProtocolError(
                "ADAPTER_RECOVERY_MISMATCH", "stored invocation identity is invalid"
            )

        def values(name: str) -> frozenset[str]:
            raw = document[name]
            if (
                not isinstance(raw, list)
                or not all(isinstance(item, str) and item for item in raw)
                or raw != sorted(set(raw))
            ):
                raise ProtocolError(
                    "ADAPTER_RECOVERY_MISMATCH",
                    f"stored invocation context field {name} is invalid",
                )
            return frozenset(raw)

        if not isinstance(document["project_id"], str) or not isinstance(
            document["authorization_ref"], str
        ):
            raise ProtocolError(
                "ADAPTER_RECOVERY_MISMATCH", "stored invocation scope is invalid"
            )
        return InvocationContext(
            project_id=document["project_id"],
            authorization_ref=document["authorization_ref"],
            identity=copy.deepcopy(identity),
            granted_capabilities=values("granted_capabilities"),
            granted_permissions=values("granted_permissions"),
            allowed_data_classifications=values("allowed_data_classifications"),
            allowed_network_destinations=values("allowed_network_destinations"),
            available_credential_references=values(
                "available_credential_references"
            ),
        )

    def _replay_claim(self, request: AdapterRequest) -> dict[str, Any] | None:
        if not self.replay.ledger_path.exists():
            return None
        with exclusive_lock(self.replay.lock_path):
            replay_document = read_json(self.replay.ledger_path)
            messages = replay_document.get("messages")
            if not isinstance(messages, dict):
                raise ProtocolError(
                    "ADAPTER_RECOVERY_MISMATCH", "replay ledger is malformed"
                )
            claim = messages.get(request.request_id)
        if claim is None:
            return None
        if (
            not isinstance(claim, dict)
            or claim.get("nonce") != request.nonce
            or claim.get("state") not in {"PENDING", "COMPLETE"}
        ):
            raise ProtocolError(
                "ADAPTER_RECOVERY_MISMATCH",
                "replay claim does not match the stored invocation",
            )
        return claim

    def durable_result(
        self,
        result_id: str,
        request_document: Mapping[str, Any],
        plan_document: Mapping[str, Any],
        request: AdapterRequest,
    ) -> dict[str, Any]:
        durable = read_json(self.results / f"{result_id}.json")
        validate_adapter_document("adapter-result.v1.schema.json", durable)
        reject_credential_values(
            durable,
            location="durable adapter result",
            verified_by=self._signature_keys,
        )
        verify_document(durable, {self.key_id: self.signing_key.public_key()})
        parsed = AdapterResult.from_dict(durable)
        if (
            parsed.result_id != result_id
            or parsed.request_digest != document_digest(request_document)
            or parsed.plan_digest != document_digest(plan_document)
            or parsed.adapter_id != request.adapter_id
            or parsed.adapter_version != request.adapter_version
            or parsed.project_id != request.project_id
        ):
            raise ProtocolError(
                "ADAPTER_RECOVERY_MISMATCH",
                "durable result does not match the stored invocation",
            )
        return durable

    def recover_pending(self) -> list[dict[str, Any]]:
        if not self.recovery.exists():
            return []
        self.require_owned_directory(self.recovery)
        recovered: list[dict[str, Any]] = []
        for journal_path in sorted(self.recovery.glob("*.json")):
            with exclusive_lock(journal_path.with_suffix(".json.lock")):
                try:
                    journal = self.read_recovery_journal(journal_path)
                    state = journal.get("state")
                    if (
                        set(journal) != _RECOVERY_JOURNAL_FIELDS
                        or journal.get("schema_version")
                        != "hive.adapter-recovery-journal.v2"
                        or state
                        not in {"PREPARED", "CLAIMED", "RESULT_WRITTEN", "TERMINAL"}
                        or not isinstance(journal.get("prepared_at"), str)
                        or (
                            journal.get("claimed_at") is not None
                            and not isinstance(journal.get("claimed_at"), str)
                        )
                        or (
                            journal.get("completed_at") is not None
                            and not isinstance(journal.get("completed_at"), str)
                        )
                        or (
                            journal.get("result_id") is not None
                            and not isinstance(journal.get("result_id"), str)
                        )
                    ):
                        raise ProtocolError(
                            "ADAPTER_RECOVERY_MISMATCH",
                            "recovery journal shape or state is invalid",
                        )
                    prepared_at = _date_time(
                        journal["prepared_at"], code="ADAPTER_RECOVERY_MISMATCH"
                    )
                    if isinstance(journal.get("claimed_at"), str):
                        _date_time(
                            journal["claimed_at"], code="ADAPTER_RECOVERY_MISMATCH"
                        )
                    if isinstance(journal.get("completed_at"), str):
                        _date_time(
                            journal["completed_at"], code="ADAPTER_RECOVERY_MISMATCH"
                        )
                    request_document = journal.get("request")
                    plan_document = journal.get("plan")
                    approval_document = journal.get("approval")
                    if not isinstance(request_document, dict) or not isinstance(
                        plan_document, dict
                    ):
                        raise ProtocolError(
                            "ADAPTER_RECOVERY_MISMATCH",
                            "recovery journal documents are invalid",
                        )
                    validate_adapter_document(
                        "adapter-request.v1.schema.json", request_document
                    )
                    reject_credential_values(
                        request_document,
                        location="recovery adapter request",
                        verified_by=self._signature_keys,
                    )
                    verify_document(request_document, self.trusted_request_keys)
                    request = AdapterRequest.from_dict(request_document)
                    validate_adapter_document(
                        "adapter-plan.v1.schema.json", plan_document
                    )
                    reject_credential_values(
                        plan_document,
                        location="recovery adapter plan",
                        verified_by=self._signature_keys,
                    )
                    verify_document(
                        plan_document, {self.key_id: self.signing_key.public_key()}
                    )
                    plan = AdapterPlan.from_dict(plan_document)
                    entry = self.registry.require(
                        request.adapter_id, request.adapter_version
                    )
                    context = self._context_from_document(journal.get("context"))
                    decision = authorize_adapter_request(
                        entry.manifest,
                        request,
                        context,
                        revoked=self.registry.is_revoked(request.adapter_id),
                        evaluated_at=prepared_at,
                    )
                    stored_plan = read_json(self.plans / f"{plan.plan_id}.json")
                    request_digest = document_digest(request_document)
                    plan_digest = document_digest(plan_document)
                    expected_operation_key = operation_key(
                        request_digest, plan_digest
                    )
                    if (
                        journal.get("adapter_id") != request.adapter_id
                        or journal.get("operation_key") != expected_operation_key
                        or plan.request_digest != request_digest
                        or plan.manifest_digest != entry.manifest_digest
                        or plan.policy_digest
                        != document_digest(dataclasses.asdict(decision))
                        or plan.adapter_id != request.adapter_id
                        or plan.adapter_version != request.adapter_version
                        or plan.capability_id != request.capability_id
                        or plan.project_id != request.project_id
                        or canonical_bytes(stored_plan)
                        != canonical_bytes(plan_document)
                        or _date_time(
                            plan.expires_at, code="ADAPTER_RECOVERY_MISMATCH"
                        )
                        <= prepared_at
                    ):
                        raise ProtocolError(
                            "ADAPTER_RECOVERY_MISMATCH",
                            "recovery documents do not match their durable bindings",
                        )
                    if plan.requires_approval and not isinstance(
                        approval_document, dict
                    ):
                        raise ProtocolError(
                            "ADAPTER_RECOVERY_MISMATCH",
                            "approval-bound recovery lacks its exact approval",
                        )
                    if approval_document is not None:
                        if not isinstance(approval_document, dict):
                            raise ProtocolError(
                                "ADAPTER_RECOVERY_MISMATCH",
                                "stored adapter approval is invalid",
                            )
                        reject_credential_values(
                            approval_document,
                            location="recovery adapter approval",
                            verified_by=self._signature_keys,
                        )
                        self._verify_approval(
                            plan_document,
                            plan,
                            context,
                            approval_document,
                            evaluated_at=prepared_at,
                        )
                    replay_claim = self._replay_claim(request)
                except ProtocolError as exc:
                    if exc.code == "ADAPTER_RECOVERY_MISMATCH":
                        raise
                    raise ProtocolError(
                        "ADAPTER_RECOVERY_MISMATCH",
                        "recovery documents failed exact verification",
                    ) from exc

                if state == "PREPARED":
                    if replay_claim is None:
                        claim = self.replay.begin(request.request_id, request.nonce)
                        if claim != "NEW":
                            raise ProtocolError(
                                "ADAPTER_RECOVERY_MISMATCH",
                                "prepared recovery could not claim its replay identity",
                            )
                    elif replay_claim["state"] != "PENDING":
                        raise ProtocolError(
                            "ADAPTER_RECOVERY_MISMATCH",
                            "prepared recovery has an incompatible replay state",
                        )
                    journal["state"] = "CLAIMED"
                    journal["claimed_at"] = journal.get("claimed_at") or utc_now()
                    self._write_recovery_journal(journal_path, journal)
                    state = "CLAIMED"
                    replay_claim = self._replay_claim(request)

                result_id = journal.get("result_id")
                if result_id is not None:
                    durable = self.durable_result(
                        result_id, request_document, plan_document, request
                    )
                    if replay_claim is None:
                        raise ProtocolError(
                            "ADAPTER_RECOVERY_MISMATCH",
                            "journaled result has no replay claim",
                        )
                    if replay_claim["state"] == "PENDING":
                        self.replay.complete(request.request_id, request.nonce)
                    journal["state"] = "TERMINAL"
                    journal["completed_at"] = journal.get("completed_at") or utc_now()
                    self._write_recovery_journal(journal_path, journal)
                    if state != "TERMINAL":
                        recovered.append(durable)
                    continue

                if state == "TERMINAL" or replay_claim is None or replay_claim[
                    "state"
                ] != "PENDING":
                    raise ProtocolError(
                        "ADAPTER_RECOVERY_MISMATCH",
                        "nonterminal recovery has no pending replay claim",
                    )

                deterministic_result_id = self.result_id(expected_operation_key)
                deterministic_result_path = (
                    self.results / f"{deterministic_result_id}.json"
                )
                if deterministic_result_path.exists():
                    durable = self.durable_result(
                        deterministic_result_id,
                        request_document,
                        plan_document,
                        request,
                    )
                    self._complete_invocation(
                        journal_path, journal, request, durable
                    )
                    recovered.append(durable)
                    continue

                try:
                    with execution_deadline(
                        entry.manifest.resource_limits["timeout_seconds"]
                    ):
                        applied = entry.adapter.recover(expected_operation_key)
                        if applied is None:
                            applied = entry.adapter.apply(
                                copy.deepcopy(plan.payload),
                                operation_key=expected_operation_key,
                            )
                    reject_credential_values(
                        applied, location="recovered adapter contribution"
                    )
                    validated = self.validate_apply_result(applied, plan)
                    signed_result = self._write_result(
                        request_document,
                        plan_document,
                        request,
                        validated,
                        max_output_bytes=entry.manifest.resource_limits[
                            "max_output_bytes"
                        ],
                    )
                except Exception as exc:
                    raise ProtocolError(
                        "ADAPTER_EFFECT_STATE_PENDING",
                        "adapter effect state remains pending attended recovery",
                    ) from exc
                self._complete_invocation(
                    journal_path, journal, request, signed_result
                )
                recovered.append(signed_result)
        return recovered

    def _write_result(
        self,
        request_document: Mapping[str, Any],
        plan_document: Mapping[str, Any],
        request: AdapterRequest,
        applied: Mapping[str, Any],
        *,
        max_output_bytes: int,
    ) -> dict[str, Any]:
        result_id = self.result_id(
            operation_key(
                document_digest(request_document), document_digest(plan_document)
            )
        )
        self.require_owned_directory(self.results)
        result_path = self.results / f"{result_id}.json"
        if result_path.exists():
            durable = self.durable_result(
                result_id, request_document, plan_document, request
            )
            if len(canonical_bytes(durable)) > max_output_bytes:
                raise ProtocolError(
                    "ADAPTER_OUTPUT_LIMIT_EXCEEDED",
                    "durable adapter result exceeds the manifest output limit",
                )
            return durable
        result = AdapterResult(
            result_id=result_id,
            request_digest=document_digest(request_document),
            plan_digest=document_digest(plan_document),
            adapter_id=request.adapter_id,
            adapter_version=request.adapter_version,
            project_id=request.project_id,
            outcome=applied["outcome"],
            evidence_refs=copy.deepcopy(applied["evidence_refs"]),
            side_effects=list(applied["side_effects"]),
            resource_use=copy.deepcopy(applied["resource_use"]),
            rollback_ref=applied["rollback_ref"],
            detail=copy.deepcopy(applied["detail"]),
        )
        signed = self.sign_document(result.as_dict())
        validate_adapter_document("adapter-result.v1.schema.json", signed)
        reject_credential_values(
            signed,
            location="signed adapter result",
            verified_by=self._signature_keys,
        )
        if len(canonical_bytes(signed)) > max_output_bytes:
            raise ProtocolError(
                "ADAPTER_OUTPUT_LIMIT_EXCEEDED",
                "terminal adapter result exceeds the manifest output limit",
            )
        atomic_write_json(result_path, signed, mode=0o600)
        return signed

    @staticmethod
    def validate_apply_result(
        applied: Any,
        plan: AdapterPlan,
    ) -> dict[str, Any]:
        required = {
            "outcome",
            "evidence_refs",
            "side_effects",
            "resource_use",
            "rollback_ref",
            "detail",
        }
        if not isinstance(applied, dict) or set(applied) != required:
            raise ProtocolError(
                "ADAPTER_APPLY_RESULT_INVALID",
                "adapter apply must return the closed result object",
            )
        if applied["outcome"] not in {item.value for item in AdapterOutcome}:
            raise ProtocolError(
                "ADAPTER_APPLY_OUTCOME_INVALID",
                "adapter apply returned an unsupported outcome",
            )
        evidence_refs = applied["evidence_refs"]
        side_effects = applied["side_effects"]
        resource_use = applied["resource_use"]
        rollback_ref = applied["rollback_ref"]
        detail = applied["detail"]
        if (
            not isinstance(evidence_refs, list)
            or not all(isinstance(item, dict) for item in evidence_refs)
            or not isinstance(side_effects, list)
            or not all(isinstance(item, str) and item for item in side_effects)
            or len(side_effects) != len(set(side_effects))
            or not set(side_effects) <= set(plan.side_effects)
            or not isinstance(resource_use, dict)
            or (rollback_ref is not None and not isinstance(rollback_ref, str))
            or not isinstance(detail, dict)
        ):
            raise ProtocolError(
                "ADAPTER_APPLY_RESULT_INVALID",
                "adapter apply result fields are invalid or exceed the plan",
            )
        return copy.deepcopy(applied)
