"""Attended product control-room facade for immutable local workflows."""

from __future__ import annotations

import copy
import platform
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from hive_protocol.agents import AgentOperations
from hive_protocol.core import (
    ProtocolError,
    document_digest,
    public_key_id,
    sign_document,
)
from hive_protocol.storage import (
    ReplayLedger,
    atomic_write_json,
    read_json,
    require_no_symlink_components,
)
from hive_protocol.workflows.approvals import (
    WorkflowApprovalAuthority,
    build_approval_preview,
)
from hive_protocol.workflows.definitions import WorkflowDefinitionStore
from hive_protocol.workflows.events import WorkflowRunJournal
from hive_protocol.workflows.replay import WorkflowReplay
from hive_protocol.workflows.scheduler import WorkflowScheduler
from hive_protocol.workflows.sessions import WorkflowSessionManager

from .agent_adapter import (
    ADAPTER_PROJECT_ID,
    TENANT_ID,
    WORKSPACE_ID,
    _adapter_private_key,
    _private_key,
    deliver_workflow_step,
    public_pem,
)
from .workspace import HiveWorkspace


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        raise ProtocolError(
            "WORKFLOW_PRODUCT_TIME_INVALID", "workflow time requires timezone"
        )
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ProtocolError(
            "WORKFLOW_PRODUCT_TIME_INVALID", "workflow time is invalid"
        ) from exc
    if parsed.tzinfo is None:
        raise ProtocolError(
            "WORKFLOW_PRODUCT_TIME_INVALID", "workflow time requires timezone"
        )
    return parsed


def _public_key(pem: str) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(pem.encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise ProtocolError(
            "WORKFLOW_PUBLIC_KEY_INVALID", "workflow public key is invalid"
        ) from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ProtocolError(
            "WORKFLOW_PUBLIC_KEY_INVALID", "workflow requires Ed25519 public keys"
        )
    return key


def diff_workflow_documents(
    left: Any, right: Any, path: str = "$"
) -> list[dict[str, Any]]:
    if type(left) is not type(right):
        return [{"path": path, "from": left, "to": right}]
    if isinstance(left, Mapping):
        changes: list[dict[str, Any]] = []
        for key in sorted(set(left).union(right)):
            child = f"{path}.{key}"
            if key not in left:
                changes.append({"path": child, "from": None, "to": right[key]})
            elif key not in right:
                changes.append({"path": child, "from": left[key], "to": None})
            else:
                changes.extend(diff_workflow_documents(left[key], right[key], child))
        return changes
    if isinstance(left, list):
        if left == right:
            return []
        return [{"path": path, "from": left, "to": right}]
    return [] if left == right else [{"path": path, "from": left, "to": right}]


class WorkflowProductService:
    """Expose one-shot attended workflow operations without an executor or daemon."""

    def __init__(self, root: Path) -> None:
        self.workspace = HiveWorkspace.open(root)
        self.root = self.workspace.root
        node = re.sub(r"[^A-Za-z0-9._:-]", "-", platform.node()) or "local-machine"
        self.machine_id = f"machine:{node}"
        key_root = self.root / ".hive" / "keys" / "workflows"
        self.operator_key = _adapter_private_key(key_root, "workflow-operator")
        self.approver_key = _adapter_private_key(key_root, "workflow-approver")
        self.operator_key_id = public_key_id(self.operator_key.public_key())
        self.approver_key_id = public_key_id(self.approver_key.public_key())
        self.operator_identity = {
            "actor_id": "workflow-operator",
            "persona_id": "persona:local-operator",
            "surface_id": "surface:hive-workflow-control",
            "machine_id": self.machine_id,
            "project_id": ADAPTER_PROJECT_ID,
            "app_actor": "app:hive-workflow-control",
            "key_id": self.operator_key_id,
        }
        self.approver_identity = {
            "actor_id": "workflow-approver",
            "persona_id": "persona:human-operator",
            "surface_id": "surface:hive-workflow-approval",
            "machine_id": self.machine_id,
            "project_id": ADAPTER_PROJECT_ID,
            "app_actor": "app:hive-workflow-approval",
            "key_id": self.approver_key_id,
        }
        self.public_key_path = (
            self.root / ".hive" / "workflow-keys" / "public-keys.json"
        )
        self._record_public_keys()
        self.rollback_replay = ReplayLedger(
            self.root
            / ".hive"
            / "runtime"
            / "workflows"
            / "product-rollbacks.json",
            mode=0o600,
        )

    def _record_public_keys(self) -> None:
        require_no_symlink_components(
            self.root,
            self.public_key_path,
            code="WORKFLOW_PUBLIC_KEY_BOUNDARY",
            detail="workflow public-key path contains a symlink",
        )
        if self.public_key_path.is_symlink():
            raise ProtocolError(
                "WORKFLOW_PUBLIC_KEY_BOUNDARY",
                "workflow public-key registry may not be a symlink",
            )
        if self.public_key_path.exists():
            document = read_json(self.public_key_path)
        else:
            document = {
                "schema_version": "hive.workflow-public-keys.v1",
                "keys": {},
            }
        if (
            document.get("schema_version") != "hive.workflow-public-keys.v1"
            or not isinstance(document.get("keys"), dict)
        ):
            raise ProtocolError(
                "WORKFLOW_PUBLIC_KEY_REGISTRY_INVALID",
                "workflow public-key registry is malformed",
            )
        additions = {
            self.operator_key_id: {
                "public_key_pem": public_pem(self.operator_key),
                "roles": ["OPERATOR", "PUBLISHER"],
            },
            self.approver_key_id: {
                "public_key_pem": public_pem(self.approver_key),
                "roles": ["APPROVER"],
            },
        }
        changed = False
        for key_id, record in additions.items():
            existing = document["keys"].get(key_id)
            if existing is not None and existing != record:
                raise ProtocolError(
                    "WORKFLOW_PUBLIC_KEY_CONFLICT",
                    "public key ID is bound to different verification material",
                )
            if existing is None:
                document["keys"][key_id] = record
                changed = True
        if changed or not self.public_key_path.exists():
            self.public_key_path.parent.mkdir(parents=True, exist_ok=True)
            if self.public_key_path.parent.is_symlink():
                raise ProtocolError(
                    "WORKFLOW_PUBLIC_KEY_BOUNDARY",
                    "workflow public-key directory may not be a symlink",
                )
            atomic_write_json(self.public_key_path, document)

    def _key_records(self) -> dict[str, dict[str, Any]]:
        document = read_json(self.public_key_path)
        if (
            document.get("schema_version") != "hive.workflow-public-keys.v1"
            or not isinstance(document.get("keys"), dict)
        ):
            raise ProtocolError(
                "WORKFLOW_PUBLIC_KEY_REGISTRY_INVALID",
                "workflow public-key registry is malformed",
            )
        return copy.deepcopy(document["keys"])

    def _registry(self) -> dict[str, Any]:
        return AgentOperations(
            self.root / ".hive" / "agent-operations"
        ).registry_snapshot()

    def _trusted_keys(self) -> dict[str, Ed25519PublicKey]:
        trusted: dict[str, Ed25519PublicKey] = {}
        for key_id, record in self._key_records().items():
            key = _public_key(record.get("public_key_pem", ""))
            if public_key_id(key) != key_id:
                raise ProtocolError(
                    "WORKFLOW_PUBLIC_KEY_CONFLICT",
                    "public key bytes do not match their key ID",
                )
            roles = record.get("roles")
            if (
                not isinstance(roles, list)
                or roles != sorted(set(roles))
                or not set(roles).issubset({"APPROVER", "OPERATOR", "PUBLISHER"})
            ):
                raise ProtocolError(
                    "WORKFLOW_PUBLIC_KEY_REGISTRY_INVALID",
                    "workflow public-key roles are invalid",
                )
            trusted[key_id] = key
        for record in self._registry()["agents"].values():
            key = _public_key(record["public_key_pem"])
            if public_key_id(key) != record["key_id"]:
                raise ProtocolError(
                    "WORKFLOW_PUBLIC_KEY_CONFLICT",
                    "agent registry key does not bind its key ID",
                )
            trusted[record["key_id"]] = key
        return trusted

    def _approver_keys(self) -> dict[str, Ed25519PublicKey]:
        return {
            key_id: _public_key(record["public_key_pem"])
            for key_id, record in self._key_records().items()
            if "APPROVER" in record["roles"]
        }

    def _definition_store(self) -> WorkflowDefinitionStore:
        return WorkflowDefinitionStore(self.root, self._trusted_keys())

    def _journal(self) -> WorkflowRunJournal:
        return WorkflowRunJournal(self.root, self._trusted_keys())

    def _approval_authority(self) -> WorkflowApprovalAuthority:
        return WorkflowApprovalAuthority(self.root, self._approver_keys())

    def _signed_definition(
        self, document: Mapping[str, Any], *, now: datetime
    ) -> dict[str, Any]:
        candidate = copy.deepcopy(dict(document))
        if "signature" in candidate:
            return candidate
        candidate["publisher"] = copy.deepcopy(self.operator_identity)
        candidate["created_at"] = _iso(now)
        return sign_document(candidate, self.operator_key)

    def definition_preview(
        self, document: Mapping[str, Any], *, now: datetime
    ) -> dict[str, Any]:
        return self._definition_store().preview(
            self._signed_definition(document, now=now)
        )

    def publish_definition(
        self,
        document: Mapping[str, Any],
        *,
        idempotency_key: str,
        now: datetime,
    ) -> dict[str, Any]:
        signed = self._signed_definition(document, now=now)
        store = self._definition_store()
        preview = store.preview(signed)
        receipt = store.publish(signed, idempotency_key=idempotency_key)
        return {
            "outcome": "PUBLISHED",
            "changed": receipt["changed"],
            "definition": signed,
            "preview": preview,
            "receipt": receipt,
            "execution_started": False,
        }

    def list_definitions(self, workflow_id: str) -> dict[str, Any]:
        store = self._definition_store()
        versions = store.list_versions(workflow_id)
        return {
            "workflow_id": workflow_id,
            "versions": versions,
            "digests": {
                str(version): store.load(workflow_id, version).digest
                for version in versions
            },
        }

    def diff_definitions(
        self, workflow_id: str, from_version: int, to_version: int
    ) -> dict[str, Any]:
        store = self._definition_store()
        left = store.load(workflow_id, from_version)
        right = store.load(workflow_id, to_version)
        left_document = left.as_dict()
        right_document = right.as_dict()
        left_document.pop("signature", None)
        right_document.pop("signature", None)
        return {
            "workflow_id": workflow_id,
            "from_version": from_version,
            "to_version": to_version,
            "from_sha256": left.digest,
            "to_sha256": right.digest,
            "changes": diff_workflow_documents(left_document, right_document),
        }

    def launch_run(
        self,
        workflow_id: str,
        version: int,
        *,
        run_id: str,
        source_commit: str,
        input_manifest_sha256: str,
        event_id: str,
        idempotency_key: str,
        now: datetime,
        stale_after_seconds: int = 600,
        max_concurrent_claims: int = 2,
    ) -> dict[str, Any]:
        definition = self._definition_store().load(workflow_id, version)
        run = sign_document(
            {
                "schema_version": "hive.workflow-run.v1",
                "run_id": run_id,
                "workflow_id": workflow_id,
                "workflow_version": version,
                "workflow_sha256": definition.digest,
                "tenant_id": definition.tenant_id,
                "project_id": definition.project_id,
                "source_commit": source_commit,
                "input_manifest_sha256": input_manifest_sha256,
                "policy": {
                    "mode": "ATTENDED",
                    "stale_after_seconds": stale_after_seconds,
                    "allow_claim_release": True,
                    "max_concurrent_claims": max_concurrent_claims,
                },
                "launched_by": copy.deepcopy(self.operator_identity),
                "started_at": _iso(now),
            },
            self.operator_key,
        )
        result = self._journal().start(
            definition.as_dict(),
            run,
            private_key=self.operator_key,
            event_id=event_id,
            idempotency_key=idempotency_key,
        )
        return {**result, "execution_started": False}

    def _run_services(self, run_id: str):
        journal = self._journal()
        run = journal.load_run(run_id)
        definition = self._definition_store().load(
            run.workflow_id, run.workflow_version
        )
        authority = self._approval_authority()
        scheduler = WorkflowScheduler(
            self.root,
            definition.as_dict(),
            run.as_dict(),
            journal=journal,
            registry=self._registry(),
            approval_authority=authority,
        )
        sessions = WorkflowSessionManager(
            self.root,
            definition.as_dict(),
            run.as_dict(),
            journal=journal,
            approval_authority=authority,
        )
        return journal, run, definition, authority, scheduler, sessions

    def run_status(self, run_id: str) -> dict[str, Any]:
        return WorkflowReplay(self.root, self._trusted_keys()).reconstruct(run_id)

    def readiness(self, run_id: str, step_id: str, **arguments: Any) -> dict[str, Any]:
        return self._run_services(run_id)[4].evaluate(step_id, **arguments)

    def conflicts(self, run_id: str, step_id: str, **arguments: Any) -> dict[str, Any]:
        readiness = self.readiness(run_id, step_id, **arguments)
        return {
            "run_id": run_id,
            "step_id": step_id,
            "readiness_sha256": readiness["readiness_sha256"],
            "conflicts": [
                item
                for item in readiness["blockers"]
                if "conflict_id" in item
                or item["code"]
                in {
                    "ACTIVE_BRANCH_CLAIM",
                    "ACTIVE_FILE_CLAIM",
                    "CAPABILITY_ESCALATION",
                    "DUPLICATE_TASK",
                    "MACHINE_TARGET_MISMATCH",
                    "MISSING_EVIDENCE",
                    "PROJECT_TARGET_MISMATCH",
                    "STALE_SOURCE_COMMIT",
                }
            ],
            "mutation_performed": False,
        }

    def step_approval_preview(
        self,
        run_id: str,
        readiness: Mapping[str, Any],
        *,
        action: str,
        destination: str,
        expires_at: datetime,
        now: datetime,
    ) -> dict[str, Any]:
        _, run, definition, _, _, _ = self._run_services(run_id)
        step = next(
            step for step in definition.steps if step["step_id"] == readiness["step_id"]
        )
        return build_approval_preview(
            approval_kind="STEP_APPROVAL",
            run_id=run.run_id,
            workflow_sha256=run.workflow_sha256,
            step_id=readiness["step_id"],
            attempt=readiness["attempt"],
            tenant_id=run.tenant_id,
            project_id=run.project_id,
            action=action,
            destination=destination,
            data_classes=["PROJECT_PRIVATE"],
            side_effects=["WORKFLOW_STEP_RESULT"],
            evidence_refs=[],
            rollback=step["rollback"],
            risk_class=step["approval"]["risk_class"],
            input_sha256=readiness["input_sha256"],
            conflict_ids=sorted(
                item["conflict_id"]
                for item in readiness["blockers"]
                if "conflict_id" in item
            ),
            existing_capabilities=step["required_capabilities"],
            requested_capabilities=step["required_capabilities"],
            created_at=now,
            expires_at=expires_at,
        )

    def approve(
        self,
        preview: Mapping[str, Any],
        *,
        authorization_ref: str,
        approval_id: str,
        idempotency_key: str,
        now: datetime,
    ) -> dict[str, Any]:
        disallowed = {
            record["key_id"] for record in self._registry()["agents"].values()
        }
        result = self._approval_authority().decide(
            preview,
            decision="APPROVED",
            approver=self.approver_identity,
            authorization_ref=authorization_ref,
            private_key=self.approver_key,
            approval_id=approval_id,
            idempotency_key=idempotency_key,
            decided_at=now,
            disallowed_agent_key_ids=disallowed,
        )
        journal = self._journal()
        event = journal.append(
            preview["run_id"],
            event_type="APPROVAL_RECORDED",
            actor=self.approver_identity,
            payload={
                "approval_id": result["approval"]["approval_id"],
                "approval_kind": result["approval"]["approval_kind"],
                "preview_sha256": document_digest(preview),
                "approval_sha256": document_digest(result["approval"]),
                "execution_started": False,
            },
            private_key=self.approver_key,
            event_id=approval_id,
            idempotency_key=f"workflow-approval-event:{approval_id}",
            recorded_at=now,
            step_id=preview["step_id"],
            attempt=preview["attempt"],
        )
        return {**result, "event": event["event"], "execution_started": False}

    def record_conflicts(
        self,
        run_id: str,
        readiness: Mapping[str, Any],
        *,
        event_id: str,
        idempotency_key: str,
        now: datetime,
        attended_confirmation: bool,
        approvals: Sequence[Mapping[str, Any]] = (),
    ) -> dict[str, Any]:
        if not attended_confirmation:
            raise ProtocolError(
                "WORKFLOW_CONFLICT_RECORD_ATTENDANCE_REQUIRED",
                "conflict recording requires attended confirmation",
            )
        try:
            scheduler = self._run_services(run_id)[4]
            refreshed = scheduler.evaluate(
                readiness["step_id"],
                attempt=readiness["attempt"],
                current_source_commit=readiness["source_commit"],
                current_machine_id=readiness["current_machine_id"],
                task_sha256=readiness["task_sha256"],
                existing_task_sha256s=readiness["existing_task_sha256s"],
                required_evidence_refs=readiness["required_evidence_refs"],
                available_evidence_refs=readiness["available_evidence_refs"],
                approvals=approvals,
                now=now,
                explicit_agent_id=readiness["explicit_agent_id"],
            )
        except (KeyError, TypeError, ProtocolError) as exc:
            raise ProtocolError(
                "WORKFLOW_CONFLICT_VIEW_INVALID",
                "conflict recording requires one exact current scheduler view",
            ) from exc
        if refreshed != dict(readiness):
            raise ProtocolError(
                "WORKFLOW_CONFLICT_VIEW_INVALID",
                "conflict recording requires one exact current scheduler view",
            )
        conflicts = [
            item for item in readiness.get("blockers", []) if "conflict_id" in item
        ]
        if not conflicts:
            raise ProtocolError(
                "WORKFLOW_CONFLICT_RECORD_EMPTY",
                "only a current conflict view may be recorded",
            )
        result = self._journal().append(
            run_id,
            event_type="CONFLICT_DETECTED",
            actor=self.operator_identity,
            payload={
                "readiness_sha256": readiness["readiness_sha256"],
                "conflict_ids": sorted(item["conflict_id"] for item in conflicts),
                "codes": sorted(item["code"] for item in conflicts),
                "execution_started": False,
            },
            private_key=self.operator_key,
            event_id=event_id,
            idempotency_key=idempotency_key,
            recorded_at=now,
            step_id=readiness["step_id"],
            attempt=readiness["attempt"],
        )
        return {
            "outcome": "CONFLICT_RECORDED",
            "changed": result["changed"],
            "event": result["event"],
            "execution_started": False,
        }

    @staticmethod
    def _agent_identity(record: Mapping[str, Any]) -> dict[str, Any]:
        return {
            field: record[field]
            for field in (
                "persona_id",
                "surface_id",
                "machine_id",
                "app_actor",
                "key_id",
            )
        } | {
            "actor_id": record["agent_id"],
            "project_id": ADAPTER_PROJECT_ID,
        }

    def claim(
        self,
        run_id: str,
        readiness: Mapping[str, Any],
        *,
        agent_id: str,
        expires_at: datetime,
        event_id: str,
        idempotency_key: str,
        now: datetime,
        approvals: Sequence[Mapping[str, Any]] = (),
    ) -> dict[str, Any]:
        registry = self._registry()
        record = registry["agents"].get(agent_id)
        if not isinstance(record, Mapping):
            raise ProtocolError(
                "WORKFLOW_AGENT_MISSING", "claimed agent is not registered"
            )
        key = _private_key(self.root, agent_id)
        return self._run_services(run_id)[4].claim(
            readiness,
            agent_id=agent_id,
            actor=self._agent_identity(record),
            private_key=key,
            expires_at=expires_at,
            event_id=event_id,
            idempotency_key=idempotency_key,
            now=now,
            approvals=approvals,
        )

    def deliver_claim(
        self,
        run_id: str,
        claim_event_id: str,
        *,
        task_id: str,
        nonce: str,
        issued_at: datetime,
        expires_at: datetime,
        now: datetime,
    ) -> dict[str, Any]:
        journal, run, definition, _, _, _ = self._run_services(run_id)
        events = journal.events(run_id)
        claim_event = next(
            (
                event
                for event in events
                if event.event_id == claim_event_id
                and event.event_type == "STEP_CLAIMED"
            ),
            None,
        )
        if claim_event is None:
            raise ProtocolError(
                "WORKFLOW_DELIVERY_CLAIM_INVALID",
                "delivery requires one exact signed claim event",
            )
        if any(
            event.step_id == claim_event.step_id
            and event.attempt == claim_event.attempt
            and event.event_type
            in {
                "CLAIM_RELEASED",
                "SESSION_ABANDONED",
                "STEP_COMPLETED",
                "STEP_FAILED",
                "RUN_CANCELLED",
            }
            for event in events
        ):
            raise ProtocolError(
                "WORKFLOW_DELIVERY_CLAIM_INACTIVE", "workflow claim is no longer active"
            )
        step = next(
            step for step in definition.steps if step["step_id"] == claim_event.step_id
        )
        claim = claim_event.payload
        if (
            claim["run_id"] != run.run_id
            or claim["workflow_sha256"] != run.workflow_sha256
            or claim["source_commit"] != run.source_commit
            or claim["capabilities"] != step["required_capabilities"]
            or claim["owned_branches"] != step["ownership"]["branches"]
            or claim["owned_files"] != step["ownership"]["files"]
        ):
            raise ProtocolError(
                "WORKFLOW_DELIVERY_CLAIM_INVALID",
                "claim no longer binds the immutable workflow step",
            )
        return deliver_workflow_step(
            self.root,
            agent_id=claim["agent_id"],
            required_capabilities=claim["capabilities"],
            task_id=task_id,
            nonce=nonce,
            issued_at=issued_at,
            expires_at=expires_at,
            now=now,
            payload={
                "run_id": run.run_id,
                "workflow_sha256": run.workflow_sha256,
                "step_id": claim_event.step_id,
                "attempt": claim_event.attempt,
                "claim_event_id": claim_event_id,
                "claim_id": claim["claim_id"],
                "input_sha256": claim["input_sha256"],
                "source_commit": claim["source_commit"],
            },
        )

    def start_session(self, run_id: str, **arguments: Any) -> dict[str, Any]:
        manager = self._run_services(run_id)[5]
        claim_event = manager._claim_event(arguments["claim_event_id"])
        agent_id = claim_event.payload["agent_id"]
        record = self._registry()["agents"].get(agent_id)
        if not isinstance(record, Mapping):
            raise ProtocolError(
                "WORKFLOW_AGENT_MISSING", "session agent is not registered"
            )
        return manager.start(
            agent=self._agent_identity(record),
            private_key=_private_key(self.root, agent_id),
            **arguments,
        )

    def record_session(
        self, run_id: str, session_id: str, **arguments: Any
    ) -> dict[str, Any]:
        manager = self._run_services(run_id)[5]
        status = manager.status(session_id)
        agent_id = status["claim"]["agent_id"]
        record = self._registry()["agents"].get(agent_id)
        if not isinstance(record, Mapping):
            raise ProtocolError(
                "WORKFLOW_AGENT_MISSING", "session agent is not registered"
            )
        return manager.record(
            session_id,
            agent=self._agent_identity(record),
            private_key=_private_key(self.root, agent_id),
            **arguments,
        )

    def session_status(self, run_id: str, session_id: str) -> dict[str, Any]:
        return self._run_services(run_id)[5].status(session_id)

    def stale_preview(self, run_id: str, session_id: str, **arguments: Any):
        return self._run_services(run_id)[5].stale_preview(session_id, **arguments)

    def release_stale(
        self, run_id: str, session_id: str, **arguments: Any
    ) -> dict[str, Any]:
        return self._run_services(run_id)[5].release_stale(
            session_id,
            actor=self.operator_identity,
            private_key=self.operator_key,
            **arguments,
        )

    def create_retry(self, run_id: str, step_id: str, **arguments: Any):
        return self._run_services(run_id)[5].create_retry(
            step_id,
            actor=self.operator_identity,
            private_key=self.operator_key,
            attended_confirmation=True,
            **arguments,
        )

    def compensation_preview(
        self, run_id: str, failed_step_id: str, **arguments: Any
    ):
        return self._run_services(run_id)[5].compensation_preview(
            failed_step_id, **arguments
        )

    def authorize_compensation(
        self, run_id: str, failed_step_id: str, **arguments: Any
    ):
        return self._run_services(run_id)[5].authorize_compensation(
            failed_step_id,
            actor=self.operator_identity,
            private_key=self.operator_key,
            attended_confirmation=True,
            **arguments,
        )

    def rollback_preview(
        self,
        run_id: str,
        step_id: str,
        *,
        attempt: int,
        checkpoint: str,
        now: datetime,
        expires_at: datetime,
    ) -> dict[str, Any]:
        _, run, definition, _, _, _ = self._run_services(run_id)
        step = next(
            (step for step in definition.steps if step["step_id"] == step_id), None
        )
        if not isinstance(step, Mapping) or step["rollback"]["mode"] != "GIT_CHECKPOINT":
            raise ProtocolError(
                "WORKFLOW_ROLLBACK_UNDECLARED",
                "workflow step does not declare Git-checkpoint rollback",
            )
        if not re.fullmatch(r"[0-9a-f]{40}", checkpoint):
            raise ProtocolError(
                "ROLLBACK_TARGET_INVALID", "rollback requires one exact Git commit"
            )
        self.workspace.ensure_git()
        resolved = self.workspace._git(
            "rev-parse", f"{checkpoint}^{{commit}}"
        ).stdout.strip()
        if resolved != checkpoint:
            raise ProtocolError(
                "ROLLBACK_TARGET_INVALID", "rollback checkpoint did not resolve exactly"
            )
        head = self.workspace.git_status()["head"]
        input_sha256 = document_digest(
            {
                "run_id": run_id,
                "workflow_sha256": run.workflow_sha256,
                "step_id": step_id,
                "attempt": attempt,
                "checkpoint": checkpoint,
                "head": head,
            }
        )
        return build_approval_preview(
            approval_kind="ROLLBACK",
            run_id=run_id,
            workflow_sha256=run.workflow_sha256,
            step_id=step_id,
            attempt=attempt,
            tenant_id=run.tenant_id,
            project_id=run.project_id,
            action=f"restore M3.3 portable roots to exact Git checkpoint {checkpoint}",
            destination="portable-vault",
            data_classes=["PORTABLE_HIVE_STATE"],
            side_effects=["GIT_CHECKPOINT_RESTORE"],
            evidence_refs=[f"git:{head}"],
            rollback={"mode": "GIT_CHECKPOINT", "checkpoint": checkpoint},
            risk_class="CRITICAL",
            input_sha256=input_sha256,
            conflict_ids=[],
            existing_capabilities=step["required_capabilities"],
            requested_capabilities=step["required_capabilities"],
            created_at=now,
            expires_at=expires_at,
        )

    def _rollback_replay_state(self, idempotency_key: str, digest: str) -> str | None:
        if not self.rollback_replay.ledger_path.exists():
            return None
        ledger = read_json(self.rollback_replay.ledger_path)
        record = ledger.get("messages", {}).get(idempotency_key)
        if not isinstance(record, Mapping):
            return None
        if record.get("nonce") != digest:
            raise ProtocolError(
                "WORKFLOW_ROLLBACK_REPLAY_CONFLICT",
                "rollback key is bound to a different exact preview",
            )
        return str(record.get("state"))

    def apply_rollback(
        self,
        run_id: str,
        preview: Mapping[str, Any],
        *,
        approval: Mapping[str, Any],
        start_event_id: str,
        complete_event_id: str,
        idempotency_key: str,
        now: datetime,
    ) -> dict[str, Any]:
        digest = document_digest(preview)
        if self._rollback_replay_state(idempotency_key, digest) == "COMPLETE":
            return {
                "outcome": "ROLLBACK_COMPLETED",
                "changed": False,
                "target": preview.get("rollback", {}).get("checkpoint"),
                "execution_started": False,
            }
        expected = self.rollback_preview(
            run_id,
            str(preview.get("step_id")),
            attempt=int(preview.get("attempt", 0)),
            checkpoint=str(preview.get("rollback", {}).get("checkpoint", "")),
            now=_time(str(preview.get("created_at", ""))),
            expires_at=_time(str(preview.get("expires_at", ""))),
        )
        if dict(preview) != expected:
            raise ProtocolError(
                "WORKFLOW_ROLLBACK_BINDING_MISMATCH",
                "rollback does not bind the exact current Git checkpoint preview",
            )
        if not isinstance(approval, Mapping) or not approval:
            raise ProtocolError(
                "WORKFLOW_ROLLBACK_APPROVAL_REQUIRED",
                "portable rollback requires a separate exact approval",
            )
        self._approval_authority().verify(approval, preview, now=now)
        replay_state = self.rollback_replay.begin(idempotency_key, digest)
        if replay_state not in {"NEW", "RESUME"}:
            raise ProtocolError(
                "WORKFLOW_ROLLBACK_REPLAY_CONFLICT", "rollback replay state is invalid"
            )
        target = preview["rollback"]["checkpoint"]
        workspace_result = self.workspace.rollback(target)
        approval_target = (
            self.root
            / ".hive"
            / "receipts"
            / "workflows"
            / run_id
            / "approvals"
            / f"{approval['approval_id']}.json"
        )
        require_no_symlink_components(
            self.root,
            approval_target,
            code="WORKFLOW_ROLLBACK_APPROVAL_BOUNDARY",
            detail="rollback approval path contains a symlink",
        )
        if approval_target.exists():
            if document_digest(read_json(approval_target)) != document_digest(approval):
                raise ProtocolError(
                    "WORKFLOW_ROLLBACK_APPROVAL_CONFLICT",
                    "rollback approval path contains different bytes",
                )
        else:
            approval_target.parent.mkdir(parents=True, exist_ok=True)
            if approval_target.parent.is_symlink():
                raise ProtocolError(
                    "WORKFLOW_ROLLBACK_APPROVAL_BOUNDARY",
                    "rollback approval directory may not be a symlink",
                )
            atomic_write_json(approval_target, dict(approval))
        journal = self._journal()
        run = journal.load_run(run_id)
        payload = {
            "preview_sha256": digest,
            "approval_sha256": document_digest(approval),
            "checkpoint": target,
            "workspace_receipt": workspace_result["receipt"]["receipt_id"],
            "execution_started": False,
        }
        started = journal.append(
            run_id,
            event_type="ROLLBACK_STARTED",
            actor=self.operator_identity,
            payload=payload,
            private_key=self.operator_key,
            event_id=start_event_id,
            idempotency_key=f"{idempotency_key}:started",
            recorded_at=now,
            step_id=preview["step_id"],
            attempt=preview["attempt"],
        )
        completed = journal.append(
            run_id,
            event_type="ROLLBACK_COMPLETED",
            actor=self.operator_identity,
            payload=payload,
            private_key=self.operator_key,
            event_id=complete_event_id,
            idempotency_key=f"{idempotency_key}:completed",
            recorded_at=now,
            step_id=preview["step_id"],
            attempt=preview["attempt"],
        )
        self.rollback_replay.complete(idempotency_key, digest)
        return {
            "outcome": "ROLLBACK_COMPLETED",
            "changed": True,
            "target": target,
            "workspace": workspace_result,
            "start_event": started["event"],
            "complete_event": completed["event"],
            "execution_started": False,
        }

    def cancel_run(
        self,
        run_id: str,
        *,
        event_id: str,
        idempotency_key: str,
        now: datetime,
        attended_confirmation: bool,
    ) -> dict[str, Any]:
        if not attended_confirmation:
            raise ProtocolError(
                "WORKFLOW_CANCELLATION_ATTENDANCE_REQUIRED",
                "run cancellation requires attended confirmation",
            )
        journal, run, _, _, _, _ = self._run_services(run_id)
        if run.launched_by["key_id"] != self.operator_key_id:
            raise ProtocolError(
                "WORKFLOW_CANCELLATION_SIGNER_MISMATCH",
                "historical run launcher key is unavailable for cancellation",
            )
        result = journal.append(
            run_id,
            event_type="RUN_CANCELLED",
            actor=self.operator_identity,
            payload={"reason": "ATTENDED_CANCELLATION", "execution_started": False},
            private_key=self.operator_key,
            event_id=event_id,
            idempotency_key=idempotency_key,
            recorded_at=now,
            step_id=None,
            attempt=None,
        )
        return {
            "outcome": "RUN_CANCELLED",
            "changed": result["changed"],
            "event": result["event"],
            "execution_started": False,
        }

    def complete_run(
        self,
        run_id: str,
        *,
        event_id: str,
        idempotency_key: str,
        now: datetime,
        attended_confirmation: bool,
    ) -> dict[str, Any]:
        if not attended_confirmation:
            raise ProtocolError(
                "WORKFLOW_COMPLETION_ATTENDANCE_REQUIRED",
                "run completion requires attended confirmation",
            )
        journal, run, definition, _, scheduler, _ = self._run_services(run_id)
        if run.launched_by["key_id"] != self.operator_key_id:
            raise ProtocolError(
                "WORKFLOW_COMPLETION_SIGNER_MISMATCH",
                "historical run launcher key is unavailable for completion",
            )
        state = scheduler._state()
        completed_steps = set(state["completed"])
        expected_steps = {step["step_id"] for step in definition.steps}
        if (
            completed_steps != expected_steps
            or state["active_claims"]
            or state["run_terminal"] == "CANCELLED"
        ):
            raise ProtocolError(
                "WORKFLOW_RUN_INCOMPLETE",
                "all immutable workflow steps must complete before the run",
            )
        result = journal.append(
            run_id,
            event_type="RUN_COMPLETED",
            actor=self.operator_identity,
            payload={
                "completed_steps": sorted(completed_steps),
                "result": "SUCCESS",
                "execution_started": False,
            },
            private_key=self.operator_key,
            event_id=event_id,
            idempotency_key=idempotency_key,
            recorded_at=now,
            step_id=None,
            attempt=None,
        )
        return {
            "outcome": "RUN_COMPLETED",
            "changed": result["changed"],
            "event": result["event"],
            "execution_started": False,
        }
