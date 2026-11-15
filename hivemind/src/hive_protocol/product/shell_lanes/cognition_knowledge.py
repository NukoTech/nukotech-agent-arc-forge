"""Approval-separated cognition and version-bound knowledge operator lane."""

from __future__ import annotations

import copy
import hashlib
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Mapping

from hive_protocol.adapters.security import reject_credential_values
from hive_protocol.capture.models import SourceRecord
from hive_protocol.cognition.authority import CognitionAuthority
from hive_protocol.cognition.deletion import CognitionDeletionService
from hive_protocol.cognition.extraction import DeterministicCognitionExtractor
from hive_protocol.cognition.models import CognitionEvent, MemoryDeletionPlan
from hive_protocol.cognition.promotion import (
    CognitionPromotionService,
    load_verified_nodes,
    verify_deletion_receipt,
)
from hive_protocol.cognition.retention import CognitionRetentionService
from hive_protocol.cognition.retrieval import CognitionRetrieval
from hive_protocol.cognition.store import CognitionStore
from hive_protocol.core import ProtocolError, document_digest, verify_document
from hive_protocol.knowledge.editor import KnowledgeEditor
from hive_protocol.knowledge.graph import KnowledgeGraph
from hive_protocol.storage import (
    atomic_write_json,
    ensure_owned_directory,
    read_json,
    require_no_symlink_components,
)

from ..shell_contracts import OperatorRequest, RouteContract
from ..workspace import HiveWorkspace


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MEMORY_ACTIONS = frozenset(
    {
        "memory.propose",
        "memory.review",
        "memory.promote",
        "memory.correct",
        "memory.revoke",
        "memory.retention.scan",
        "memory.deletion.preview",
        "memory.deletion.approve",
        "memory.deletion.apply",
    }
)
_KNOWLEDGE_ACTIONS = frozenset(
    {
        "knowledge.notes.preview",
        "knowledge.notes.approve",
        "knowledge.notes.apply",
        "knowledge.graph.rebuild",
    }
)
_ACTIONS = _MEMORY_ACTIONS | _KNOWLEDGE_ACTIONS
_OPERATION_SCHEMA = "hive.operator-cognition-knowledge-operation.v1"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class CognitionKnowledgeLane:
    """Compose existing authority services without granting the browser new roles."""

    def __init__(
        self,
        workspace: HiveWorkspace,
        *,
        tenant_id: str,
        project_ids: frozenset[str],
        now,
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        self.workspace = workspace
        self.root = workspace.root
        self.tenant_id = tenant_id
        self.project_ids = project_ids
        self.now = now
        self.fault_hook = fault_hook
        self.authority = CognitionAuthority(self.root)
        self.runtime = (
            workspace.runtime / "operator-shell" / "lanes" / "cognition-knowledge"
        )
        self.operations = self.runtime / "operations"

    @staticmethod
    def supports(action: str) -> bool:
        return action in _ACTIONS

    def _fault(self, stage: str) -> None:
        if self.fault_hook is not None:
            self.fault_hook(stage)

    def _domain_fault(self, action: str) -> Callable[[str], None]:
        return lambda stage: self._fault(f"{action}:{stage}")

    def _ensure_runtime(self) -> None:
        ensure_owned_directory(
            self.root,
            self.operations,
            code="OPERATOR_RUNTIME_BOUNDARY",
            detail="cognition/knowledge runtime path is unsafe",
        )

    def _operation_path(self, operation_key: str) -> Path:
        self._ensure_runtime()
        if _SHA256.fullmatch(operation_key) is None:
            raise ProtocolError(
                "OPERATOR_RUNTIME_BOUNDARY", "cognition operation key is invalid"
            )
        path = self.operations / f"{operation_key}.json"
        require_no_symlink_components(
            self.root,
            path,
            code="OPERATOR_RUNTIME_BOUNDARY",
            detail="cognition operation path contains a symlink",
        )
        if path.is_symlink():
            raise ProtocolError(
                "OPERATOR_RUNTIME_BOUNDARY", "cognition operation path is a symlink"
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
        expected = {
            "schema_version",
            "operation_key",
            "action",
            "request_digest",
            "state",
            "result",
            "result_digest",
        }
        if (
            set(document) != expected
            or document.get("schema_version") != _OPERATION_SCHEMA
            or document.get("operation_key") != operation_key
            or document.get("action") != request.action
            or document.get("request_digest") != request.digest
            or document.get("state") not in {"PREPARED", "TERMINAL"}
        ):
            raise ProtocolError(
                "OPERATOR_DOMAIN_RECOVERY_INVALID",
                "cognition/knowledge recovery record changed",
            )
        if document["state"] == "PREPARED":
            return None
        result = document.get("result")
        if not isinstance(result, dict) or document.get(
            "result_digest"
        ) != document_digest(result):
            raise ProtocolError(
                "OPERATOR_DOMAIN_RECOVERY_INVALID",
                "cognition/knowledge recovery result changed",
            )
        return copy.deepcopy(result)

    @staticmethod
    def _result(
        request: OperatorRequest,
        operation_key: str,
        *,
        object_version: str,
        changed: bool,
        data: Mapping[str, Any],
        evidence: list[dict[str, Any]],
        outcome: str = "APPLIED",
    ) -> dict[str, Any]:
        return {
            "operation_key": operation_key,
            "request_digest": request.digest,
            "outcome": outcome,
            "reason_code": None,
            "object_version": object_version,
            "changed": changed,
            "data": copy.deepcopy(dict(data)),
            "technical_evidence": copy.deepcopy(evidence),
        }

    @staticmethod
    def _exact(document: Mapping[str, Any], fields: set[str], *, code: str) -> None:
        if set(document) != fields:
            raise ProtocolError(code, "operator cognition request is not exact")

    def _store(self, action: str, *, faults: bool = False) -> CognitionStore:
        return CognitionStore(
            self.root,
            self.authority,
            fault_hook=self._domain_fault(action) if faults else None,
        )

    def _nodes(self) -> dict[str, Any]:
        return load_verified_nodes(self.root, self.authority)

    def _node(self, node_id: Any, node_sha256: Any | None = None):
        if not isinstance(node_id, str):
            raise ProtocolError("COGNITION_NODE_MISSING", "memory node ID is invalid")
        node = self._nodes().get(node_id)
        if node is None:
            raise ProtocolError("COGNITION_NODE_MISSING", "memory node is absent")
        if node.project_id not in self.project_ids or node.tenant_id != self.tenant_id:
            raise ProtocolError("COGNITION_SCOPE_DENIED", "memory node is outside scope")
        if node_sha256 is not None and node_sha256 != node.digest:
            raise ProtocolError("COGNITION_TARGET_DRIFT", "memory node digest changed")
        return node

    def _source_records(self) -> dict[str, SourceRecord]:
        records: dict[str, SourceRecord] = {}
        if not self.workspace.provenance.exists():
            return records
        for path in sorted(self.workspace.provenance.rglob("*.json")):
            if path.is_symlink() or not path.is_file():
                raise ProtocolError(
                    "COGNITION_EVIDENCE_INVALID", "evidence record path is unsafe"
                )
            document = read_json(path)
            if document.get("schema_version") != "hive.source-record.v1":
                continue
            try:
                record = SourceRecord.from_dict(document)
            except ProtocolError as exc:
                raise ProtocolError(
                    "COGNITION_EVIDENCE_INVALID", "source evidence record is invalid"
                ) from exc
            if record.source_id in records:
                raise ProtocolError(
                    "COGNITION_EVIDENCE_INVALID", "source evidence ID is duplicated"
                )
            records[record.source_id] = record
        return records

    def _event(self, request: OperatorRequest, *, required_action: str | None = None):
        self._exact(request.input, {"event"}, code="COGNITION_EVENT_INVALID")
        try:
            event = CognitionEvent.from_dict(request.input.get("event", {}))
        except ProtocolError:
            raise
        if (
            event.tenant_id != self.tenant_id
            or event.project_id != request.project_id
            or event.project_id not in self.project_ids
            or event.privacy_class != "PROJECT_PRIVATE"
            or event.experience_scope
            != {"kind": "DOMAIN", "owner_id": str(request.project_id)}
        ):
            raise ProtocolError(
                "COGNITION_SCOPE_DENIED", "cognition event is outside project scope"
            )
        if not event.evidence:
            raise ProtocolError(
                "COGNITION_EVIDENCE_INVALID", "cognition proposal requires evidence"
            )
        records = self._source_records()
        for evidence in event.evidence:
            record = records.get(evidence["source_id"])
            anchors = {
                item["anchor_id"] for item in (record.anchors if record is not None else [])
            }
            if (
                record is None
                or record.tenant_id != self.tenant_id
                or record.project_id != request.project_id
                or evidence["anchor_id"] not in anchors
                or evidence["source_sha256"] != record.original_sha256
                or evidence["normalized_sha256"] != record.normalized_sha256
                or event.source_sha256 != record.original_sha256
            ):
                raise ProtocolError(
                    "COGNITION_EVIDENCE_INVALID",
                    "cognition evidence does not bind an admitted project source",
                )
        if required_action is not None:
            if not event.structured_claims or any(
                claim["proposed_action"] != required_action
                for claim in event.structured_claims
            ):
                raise ProtocolError(
                    "COGNITION_ACTION_TARGET_INVALID",
                    "cognition event action does not match its route",
                )
        extraction = DeterministicCognitionExtractor().extract(
            event, now=self.now, current_project_id=str(request.project_id)
        )
        if not extraction.candidates:
            raise ProtocolError(
                "COGNITION_CANDIDATE_ABSENT", "event produced no reviewable candidate"
            )
        return event, extraction

    @staticmethod
    def _batch_version(event, extraction) -> str:
        return document_digest(
            {
                "event_sha256": event.digest,
                "candidates": [candidate.digest for candidate in extraction.candidates],
            }
        )

    def _proposal_head(self, event, extraction) -> str:
        store = self._store("memory.propose")
        present = []
        for candidate in extraction.candidates:
            try:
                stored = store.load_candidate(candidate.candidate_id)
            except (FileNotFoundError, ProtocolError) as exc:
                if isinstance(exc, ProtocolError) and exc.code != "MISSING_DOCUMENT":
                    raise
                present.append(False)
            else:
                if stored.digest != candidate.digest:
                    raise ProtocolError(
                        "COGNITION_STORE_DRIFT", "stored candidate changed"
                    )
                present.append(True)
        if not any(present):
            return "ABSENT"
        return self._batch_version(event, extraction)

    def _candidate_review(self, request: OperatorRequest):
        candidate_id = request.input.get("candidate_id")
        candidate = self._store("memory.review").load_candidate(candidate_id)
        if candidate.tenant_id != self.tenant_id or candidate.project_id != request.project_id:
            raise ProtocolError("COGNITION_SCOPE_DENIED", "candidate is outside scope")
        if request.input.get("candidate_sha256") != candidate.digest:
            raise ProtocolError("COGNITION_CANDIDATE_DRIFT", "candidate digest changed")
        try:
            review = self._store("memory.review").load_review(candidate.candidate_id)
        except (FileNotFoundError, ProtocolError) as exc:
            if isinstance(exc, ProtocolError) and exc.code != "MISSING_DOCUMENT":
                raise
            review = None
        return candidate, review

    def _review_intent(self, request: OperatorRequest):
        self._exact(
            request.input,
            {
                "candidate_id",
                "candidate_sha256",
                "outcome",
                "actor_id",
                "authorization_ref",
                "corrections",
            },
            code="COGNITION_REVIEW_INVALID",
        )
        candidate, review = self._candidate_review(request)
        if request.input.get("actor_id") == candidate.extractor["id"]:
            raise ProtocolError(
                "COGNITION_SELF_REVIEW_DENIED", "candidate extractor cannot review itself"
            )
        decision = self.authority.create_review(
            candidate,
            outcome=request.input.get("outcome"),
            actor_id=request.input.get("actor_id"),
            authorization_ref=request.input.get("authorization_ref"),
            corrections=request.input.get("corrections"),
            now=self.now,
        )
        if review is not None and review.digest != decision.digest:
            raise ProtocolError(
                "COGNITION_REVIEW_ALREADY_DECIDED", "candidate review already differs"
            )
        return candidate, review, decision

    def _promotion_intent(self, request: OperatorRequest):
        self._exact(
            request.input,
            {"candidate_id", "candidate_sha256", "decision_id", "decision_sha256"},
            code="COGNITION_PROMOTION_INVALID",
        )
        candidate, review = self._candidate_review(request)
        if review is None:
            raise ProtocolError(
                "COGNITION_REVIEW_MISSING", "candidate has no review decision"
            )
        if (
            request.input.get("decision_id") != review.decision_id
            or request.input.get("decision_sha256") != review.digest
        ):
            raise ProtocolError(
                "COGNITION_REVIEW_BINDING_MISMATCH", "promotion review binding changed"
            )
        try:
            nodes = self._nodes().values()
        except ProtocolError as exc:
            if exc.code != "COGNITION_PROMOTION_RECEIPT_MISSING":
                raise
            # The signed promotion journal remains the authority for adoption
            # while a crash window has written PRIME bytes but not its receipt.
            nodes = ()
        node = next(
            (value for value in nodes if value.source_candidate_id == candidate.candidate_id),
            None,
        )
        return candidate, review, node

    def _correction_intent(self, request: OperatorRequest, action: str):
        self._exact(
            request.input,
            {"event", "target_id", "target_sha256"},
            code="COGNITION_EVENT_INVALID",
        )
        event_request = copy.deepcopy(request.as_dict())
        event_request["input"] = {"event": copy.deepcopy(request.input["event"])}
        event, extraction = self._event(
            OperatorRequest.from_dict(event_request), required_action=action
        )
        target = self._node(
            request.input.get("target_id"), request.input.get("target_sha256")
        )
        current_ids = {
            item["node_id"]
            for item in CognitionRetrieval(self.root, self.authority).list_nodes(
                project_id=str(request.project_id)
            )
        }
        if target.node_id not in current_ids:
            raise ProtocolError(
                "COGNITION_TARGET_NOT_CURRENT",
                "correction or revocation target is not current knowledge",
            )
        field = "supersedes" if action == "CORRECT" else "revokes"
        if any(getattr(candidate, field) != target.node_id for candidate in extraction.candidates):
            raise ProtocolError(
                "COGNITION_TARGET_BINDING_MISMATCH",
                "correction or revocation event targets another node",
            )
        return event, extraction, target

    def _deletion(self, action: str, *, faults: bool = False):
        return CognitionDeletionService(
            self.root,
            self.authority,
            fault_hook=self._domain_fault(action) if faults else None,
        )

    def _deletion_plan(self, request: OperatorRequest):
        plan_id = request.input.get("plan_id")
        service = self._deletion(request.action)
        plan = service._load_plan(plan_id)
        if (
            plan.tenant_id != self.tenant_id
            or plan.project_id != request.project_id
            or request.input.get("plan_sha256") != plan.digest
        ):
            raise ProtocolError(
                "COGNITION_SCOPE_DENIED", "deletion plan is outside scope or changed"
            )
        return service, plan

    def _deletion_approval_path(self, plan: MemoryDeletionPlan) -> Path:
        return (
            self.workspace.receipts
            / f"cognition-approval-deletion-{plan.plan_id.split(':', 1)[1]}.json"
        )

    def _deletion_approval(self, service, plan, *, enforce_expiry: bool = True):
        path = self._deletion_approval_path(plan)
        if not path.is_file() or path.is_symlink():
            return None
        approval = read_json(path)
        return service._verify_approval(
            plan,
            approval,
            now=self.now,
            enforce_expiry=enforce_expiry,
        )

    def _deletion_receipt(self, plan, approval):
        operation_id = document_digest(
            {"plan_id": plan.plan_id, "approval_id": approval["approval_id"]}
        )
        path = self.workspace.receipts / f"cognition-deletion-{operation_id}.json"
        if not path.is_file() or path.is_symlink():
            return None, path
        receipt = read_json(path)
        verify_deletion_receipt(receipt, self.authority)
        if (
            receipt.get("plan_id") != plan.plan_id
            or receipt.get("plan_sha256") != plan.digest
            or receipt.get("approval_id") != approval["approval_id"]
        ):
            raise ProtocolError(
                "COGNITION_DELETION_RECEIPT_INVALID",
                "deletion receipt binding changed",
            )
        return receipt, path

    def _editor(self, action: str, *, faults: bool = False) -> KnowledgeEditor:
        return KnowledgeEditor(
            self.root,
            self.authority,
            fault_hook=self._domain_fault(action) if faults else None,
        )

    def _knowledge_preview(self, preview_id: Any):
        if not isinstance(preview_id, str):
            raise ProtocolError("KNOWLEDGE_PREVIEW_INVALID", "preview ID is invalid")
        return self._editor("knowledge.notes.preview")._load_preview(preview_id)

    def _knowledge_approval(self, preview, *, enforce_expiry: bool = True):
        path = (
            self.workspace.receipts
            / f"knowledge-approval-edit-{preview['preview_id'][5:]}.json"
        )
        if not path.is_file() or path.is_symlink():
            return None
        approval = read_json(path)
        return self._editor("knowledge.notes.approve")._verify_approval(
            preview,
            approval,
            now=self.now,
            enforce_expiry=enforce_expiry,
        )

    def _knowledge_receipt(self, preview, approval):
        preview_sha256 = document_digest(preview)
        approval_sha256 = (
            document_digest(approval) if approval is not None else None
        )
        if not self.workspace.receipts.exists():
            return None
        for path in sorted(self.workspace.receipts.glob("knowledge-edit-*.json")):
            if path.is_symlink() or not path.is_file():
                raise ProtocolError(
                    "KNOWLEDGE_EDIT_RECEIPT_INVALID",
                    "knowledge edit receipt is unsafe",
                )
            receipt = read_json(path)
            verify_document(
                receipt,
                self.authority.promoter_public_keys,
            )
            if (
                receipt.get("schema_version")
                != "hive.knowledge-edit-receipt.v1"
                or receipt.get("outcome") != "APPLIED"
            ):
                raise ProtocolError(
                    "KNOWLEDGE_EDIT_RECEIPT_INVALID",
                    "knowledge edit receipt is invalid",
                )
            if (
                receipt.get("preview_id") == preview["preview_id"]
                and receipt.get("preview_sha256") == preview_sha256
                and receipt.get("approval_sha256") == approval_sha256
                and receipt.get("relative_path") == preview["relative_path"]
                and receipt.get("before_sha256") == preview["expected_sha256"]
                and receipt.get("after_sha256") == preview["content_sha256"]
            ):
                return receipt
        return None

    def _require_current_preview(self, preview) -> None:
        if self.now >= datetime.fromisoformat(
            preview["expires_at"].replace("Z", "+00:00")
        ):
            raise ProtocolError("KNOWLEDGE_PREVIEW_EXPIRED", "edit preview expired")

    def _note_target(self, preview):
        relative = Path(preview["relative_path"])
        target = self.root.joinpath(*relative.parts)
        return target

    def _find_preview(self, request: OperatorRequest):
        content = request.input.get("content")
        if (
            not isinstance(content, str)
            or "\x00" in content
            or len(content.encode("utf-8")) > 1024 * 1024
        ):
            raise ProtocolError(
                "KNOWLEDGE_CONTENT_INVALID", "Markdown content is invalid or oversized"
            )
        reject_credential_values({"content": content}, location="knowledge note")
        editor = self._editor("knowledge.notes.preview")
        target = editor._target(
            str(request.project_id), request.input.get("relative_path")
        )
        if target.exists() and (target.is_symlink() or not target.is_file()):
            raise ProtocolError("KNOWLEDGE_PATH_INVALID", "note target is unsafe")
        current = _sha256_file(target) if target.is_file() and not target.is_symlink() else None
        if current != request.input.get("expected_sha256"):
            raise ProtocolError("KNOWLEDGE_VERSION_CONFLICT", "expected note digest is stale")
        content_sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if editor.preview_root.exists():
            for path in sorted(editor.preview_root.glob("*.json")):
                preview = editor._load_preview(f"edit:{path.stem}")
                if (
                    preview["project_id"] == request.project_id
                    and preview["relative_path"]
                    == target.relative_to(self.root).as_posix()
                    and preview["expected_sha256"] == current
                    and preview["content_sha256"] == content_sha
                ):
                    return preview, target, current
        return None, target, current

    def object_key(self, route: RouteContract, request: OperatorRequest) -> str:
        action = route.action
        value: Any
        if action in {"memory.propose", "memory.correct", "memory.revoke"}:
            value = document_digest(request.input.get("event", {}))
        elif action in {"memory.review", "memory.promote"}:
            value = request.input.get("candidate_id", "invalid")
        elif action == "memory.retention.scan":
            value = request.project_id
        elif action == "memory.deletion.preview":
            value = request.input.get("node_id", "invalid")
        elif action in {"memory.deletion.approve", "memory.deletion.apply"}:
            value = request.input.get("plan_id", "invalid")
        elif action == "knowledge.notes.preview":
            value = document_digest(
                {
                    "project_id": request.project_id,
                    "relative_path": request.input.get("relative_path"),
                    "content_sha256": hashlib.sha256(
                        str(request.input.get("content", "")).encode("utf-8")
                    ).hexdigest(),
                }
            )
        elif action in {"knowledge.notes.approve", "knowledge.notes.apply"}:
            value = request.input.get("preview_id", "invalid")
        else:
            value = request.project_id
        return f"{request.project_id}:{action}:{value}"

    def current_version(self, route: RouteContract, request: OperatorRequest) -> str:
        action = route.action
        if action == "memory.propose":
            event, extraction = self._event(request)
            return self._proposal_head(event, extraction)
        if action in {"memory.correct", "memory.revoke"}:
            event, extraction, target = self._correction_intent(
                request, "CORRECT" if action.endswith("correct") else "REVOKE"
            )
            head = self._proposal_head(event, extraction)
            return target.digest if head == "ABSENT" else head
        if action == "memory.review":
            candidate, review, _ = self._review_intent(request)
            return review.digest if review is not None else candidate.digest
        if action == "memory.promote":
            _, review, node = self._promotion_intent(request)
            return node.digest if node is not None else review.digest
        if action == "memory.retention.scan":
            self._exact(request.input, {"project_id"}, code="COGNITION_RETENTION_INVALID")
            if request.input.get("project_id") != request.project_id:
                raise ProtocolError("COGNITION_SCOPE_DENIED", "retention project changed")
            nodes = [
                node.as_dict()
                for node in self._nodes().values()
                if node.project_id == request.project_id
                and node.retention_until is not None
                and node.retention_until <= self.now.isoformat().replace("+00:00", "Z")
            ]
            return document_digest(sorted(nodes, key=lambda item: item["node_id"]))
        if action == "memory.deletion.preview":
            self._exact(
                request.input,
                {"node_id", "node_sha256"},
                code="COGNITION_DELETION_PLAN_INVALID",
            )
            node = self._node(
                request.input.get("node_id"), request.input.get("node_sha256")
            )
            plans = self._deletion(action).plans
            if plans.exists():
                for path in sorted(plans.glob("*.json")):
                    plan = MemoryDeletionPlan.from_dict(read_json(path))
                    if plan.node_id == node.node_id and plan.node_sha256 == node.digest:
                        return plan.digest
            return node.digest
        if action == "memory.deletion.approve":
            self._exact(
                request.input,
                {"plan_id", "plan_sha256", "actor_id", "authorization_ref", "confirmation"},
                code="COGNITION_DELETION_APPROVAL_INVALID",
            )
            service, plan = self._deletion_plan(request)
            if request.input.get("confirmation") != f"DELETE {plan.node_id}":
                raise ProtocolError(
                    "COGNITION_DELETION_CONFIRMATION_INVALID",
                    "typed deletion confirmation is not exact",
                )
            if request.input.get("actor_id") not in self.authority.trusted_reviewer_actors:
                raise ProtocolError(
                    "COGNITION_REVIEWER_UNTRUSTED",
                    "deletion reviewer is not trusted",
                )
            approval = self._deletion_approval(service, plan)
            return document_digest(approval) if approval is not None else plan.digest
        if action == "memory.deletion.apply":
            self._exact(
                request.input,
                {"plan_id", "plan_sha256", "approval_id", "approval_sha256"},
                code="COGNITION_DELETION_APPROVAL_INVALID",
            )
            service, plan = self._deletion_plan(request)
            approval = self._deletion_approval(
                service, plan, enforce_expiry=False
            )
            if (
                approval is None
                or request.input.get("approval_id") != approval["approval_id"]
                or request.input.get("approval_sha256") != document_digest(approval)
            ):
                raise ProtocolError(
                    "COGNITION_DELETION_APPROVAL_INVALID",
                    "deletion approval binding changed",
                )
            receipt, _ = self._deletion_receipt(plan, approval)
            if receipt is not None:
                return document_digest(receipt)
            if service.has_started_journal(plan, approval, now=self.now):
                return document_digest(approval)
            service._verify_approval(plan, approval, now=self.now)
            return document_digest(approval)
        if action == "knowledge.notes.preview":
            self._exact(
                request.input,
                {"relative_path", "content", "expected_sha256"},
                code="KNOWLEDGE_PREVIEW_INVALID",
            )
            preview, _, current = self._find_preview(request)
            return document_digest(preview) if preview is not None else (current or "ABSENT")
        if action == "knowledge.notes.approve":
            self._exact(
                request.input,
                {"preview_id", "preview_sha256", "actor_id", "authorization_ref"},
                code="KNOWLEDGE_APPROVAL_INVALID",
            )
            preview = self._knowledge_preview(request.input.get("preview_id"))
            if request.input.get("preview_sha256") != document_digest(preview):
                raise ProtocolError("KNOWLEDGE_PREVIEW_INVALID", "preview digest changed")
            if (
                preview["operation"] != "UPDATE"
                or request.input.get("actor_id")
                not in self.authority.trusted_reviewer_actors
            ):
                raise ProtocolError(
                    "KNOWLEDGE_APPROVAL_INVALID", "edit approval is not authorized"
                )
            approval = self._knowledge_approval(preview)
            return document_digest(approval) if approval is not None else document_digest(preview)
        if action == "knowledge.notes.apply":
            self._exact(
                request.input,
                {"preview_id", "preview_sha256", "content", "approval_id", "approval_sha256"},
                code="KNOWLEDGE_EDIT_INVALID",
            )
            preview = self._knowledge_preview(request.input.get("preview_id"))
            content = request.input.get("content")
            if not isinstance(content, str):
                raise ProtocolError(
                    "KNOWLEDGE_CONTENT_INVALID", "Markdown content must be text"
                )
            reject_credential_values({"content": content}, location="knowledge note")
            if (
                request.input.get("preview_sha256") != document_digest(preview)
                or hashlib.sha256(content.encode("utf-8")).hexdigest()
                != preview["content_sha256"]
            ):
                raise ProtocolError("KNOWLEDGE_CONTENT_DRIFT", "content or preview changed")
            approval = self._knowledge_approval(preview, enforce_expiry=False)
            if preview["operation"] == "UPDATE":
                if (
                    approval is None
                    or request.input.get("approval_id") != approval["approval_id"]
                    or request.input.get("approval_sha256") != document_digest(approval)
                ):
                    raise ProtocolError("KNOWLEDGE_APPROVAL_INVALID", "edit approval changed")
                before = document_digest(approval)
            else:
                if request.input.get("approval_id") is not None or request.input.get("approval_sha256") is not None:
                    raise ProtocolError("KNOWLEDGE_APPROVAL_INVALID", "create cannot use edit approval")
                before = document_digest(preview)
            target = self._note_target(preview)
            current = _sha256_file(target) if target.is_file() and not target.is_symlink() else None
            receipt = self._knowledge_receipt(preview, approval)
            if receipt is not None:
                if current == preview["content_sha256"]:
                    return current
                raise ProtocolError(
                    "KNOWLEDGE_VERSION_CONFLICT",
                    "note changed after the recorded edit",
                )
            self._require_current_preview(preview)
            if preview["operation"] == "UPDATE":
                self._knowledge_approval(preview)
            if current != preview["expected_sha256"]:
                raise ProtocolError("KNOWLEDGE_VERSION_CONFLICT", "note changed after preview")
            return before
        if action == "knowledge.graph.rebuild":
            self._graph_input(request)
            projection = KnowledgeGraph(self.root, self.authority).projection
            if projection.is_file() and not projection.is_symlink():
                document = read_json(projection)
                self._require_graph_node_scope(request, document.get("nodes"))
                return _sha256_file(projection)
            return "ABSENT"
        raise ProtocolError("OPERATOR_DOMAIN_UNAVAILABLE", "lane action is unavailable")

    def graph_version(self) -> str:
        """Return the exact disposable graph projection version for UI rebinding."""

        projection = KnowledgeGraph(self.root, self.authority).projection
        return (
            _sha256_file(projection)
            if projection.is_file() and not projection.is_symlink()
            else "ABSENT"
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
        result = self._apply(route.action, request, operation_key)
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
        existing = self._read_operation(operation_key, request)
        if existing is not None:
            return existing
        result = self._apply(route.action, request, operation_key)
        self._write_operation(operation_key, request, result)
        return result

    def _apply(self, action: str, request: OperatorRequest, operation_key: str):
        if action == "memory.propose":
            return self._propose(request, operation_key)
        if action in {"memory.correct", "memory.revoke"}:
            return self._correct_revoke(request, operation_key, action)
        if action == "memory.review":
            return self._review(request, operation_key)
        if action == "memory.promote":
            return self._promote(request, operation_key)
        if action == "memory.retention.scan":
            return self._retention(request, operation_key)
        if action == "memory.deletion.preview":
            return self._delete_preview(request, operation_key)
        if action == "memory.deletion.approve":
            return self._delete_approve(request, operation_key)
        if action == "memory.deletion.apply":
            return self._delete_apply(request, operation_key)
        if action == "knowledge.notes.preview":
            return self._note_preview(request, operation_key)
        if action == "knowledge.notes.approve":
            return self._note_approve(request, operation_key)
        if action == "knowledge.notes.apply":
            return self._note_apply(request, operation_key)
        if action == "knowledge.graph.rebuild":
            return self._graph_rebuild(request, operation_key)
        raise ProtocolError("OPERATOR_DOMAIN_UNAVAILABLE", "lane action is unavailable")

    def _stage(self, request, operation_key, event, extraction, *, action):
        store = self._store(action, faults=True)
        results = [store.stage(event, candidate) for candidate in extraction.candidates]
        version = self._batch_version(event, extraction)
        return self._result(
            request,
            operation_key,
            object_version=version,
            changed=any(item["outcome"] == "STAGED" for item in results),
            data={
                "event_id": event.event_id,
                "event_sha256": event.digest,
                "candidates": [candidate.as_dict() for candidate in extraction.candidates],
                "candidate_sha256": [candidate.digest for candidate in extraction.candidates],
                "provider_state": extraction.provider_state,
                "warnings": list(extraction.warnings),
                "stage_results": results,
                "prime_write": False,
            },
            evidence=[
                {"kind": "memory-proposal", "ref": item["receipt_path"], "sha256": candidate.digest}
                for item, candidate in zip(results, extraction.candidates, strict=True)
            ],
        )

    def _propose(self, request, operation_key):
        event, extraction = self._event(request)
        return self._stage(request, operation_key, event, extraction, action="memory.propose")

    def _correct_revoke(self, request, operation_key, route_action):
        action = "CORRECT" if route_action.endswith("correct") else "REVOKE"
        event, extraction, target = self._correction_intent(request, action)
        result = self._stage(request, operation_key, event, extraction, action=route_action)
        result["data"]["target_id"] = target.node_id
        result["data"]["target_sha256"] = target.digest
        return result

    def _review(self, request, operation_key):
        candidate, _, decision = self._review_intent(request)
        result = self._store("memory.review").record_review(decision, now=self.now)
        return self._result(
            request,
            operation_key,
            object_version=decision.digest,
            changed=result["outcome"] == "RECORDED",
            data={**result, "decision": decision.as_dict(), "prime_write": False},
            evidence=[{"kind": "memory-review", "ref": result["review_path"], "sha256": decision.digest}],
        )

    def _promote(self, request, operation_key):
        candidate, review, _ = self._promotion_intent(request)
        result = CognitionPromotionService(
            self.root,
            self._store("memory.promote"),
            self.authority,
            fault_hook=self._domain_fault("memory.promote"),
        ).promote(candidate.candidate_id, now=self.now)
        node = result["node"]
        return self._result(
            request,
            operation_key,
            object_version=document_digest(node),
            changed=True,
            data=result,
            evidence=[{"kind": "memory-promotion", "ref": result["receipt_path"], "sha256": document_digest(node)}],
        )

    def _retention(self, request, operation_key):
        before = set()
        root = self._retention_root()
        if root.exists():
            before = {path.name for path in root.glob("*.json") if path.is_file() and not path.is_symlink()}
        items = CognitionRetentionService(self.root, self.authority).scan(
            now=self.now, project_id=str(request.project_id)
        )
        after = {Path(item["request_path"]).name for item in items}
        version = document_digest(
            sorted(
                [node.as_dict() for node in self._nodes().values() if node.project_id == request.project_id and node.retention_until is not None and node.retention_until <= self.now.isoformat().replace("+00:00", "Z")],
                key=lambda item: item["node_id"],
            )
        )
        return self._result(
            request,
            operation_key,
            object_version=version,
            changed=bool(after - before),
            data={"reviews": items, "automatic_delete": False},
            evidence=[{"kind": "retention-review", "ref": item["request_path"], "sha256": document_digest({k: v for k, v in item.items() if k != "request_path"})} for item in items],
        )

    def _retention_root(self) -> Path:
        return self.root / "staging" / "memory" / "reviews" / "retention"

    def _delete_preview(self, request, operation_key):
        self.current_version(RouteContract("POST", "", request.action, True, "NONE"), request)
        plan = self._deletion(request.action).create_plan(request.input["node_id"], now=self.now)
        path = self._deletion(request.action).plans / f"{plan.plan_id.split(':', 1)[1]}.json"
        return self._result(
            request,
            operation_key,
            object_version=plan.digest,
            changed=True,
            data={"plan": plan.as_dict(), "requires_approval": True},
            evidence=[{"kind": "memory-deletion-plan", "ref": path.relative_to(self.root).as_posix(), "sha256": plan.digest}],
        )

    def _delete_approve(self, request, operation_key):
        service, plan = self._deletion_plan(request)
        approval = service.approve(
            plan.plan_id,
            actor_id=request.input["actor_id"],
            authorization_ref=request.input["authorization_ref"],
            confirmation=request.input["confirmation"],
            now=self.now,
        )
        path = self._deletion_approval_path(plan)
        return self._result(
            request,
            operation_key,
            object_version=document_digest(approval),
            changed=True,
            data={"approval_id": approval["approval_id"], "approval": approval},
            evidence=[{"kind": "memory-deletion-approval", "ref": path.relative_to(self.root).as_posix(), "sha256": document_digest(approval)}],
        )

    def _delete_apply(self, request, operation_key):
        service, plan = self._deletion_plan(request)
        approval = self._deletion_approval(
            service, plan, enforce_expiry=False
        )
        if approval is None:
            raise ProtocolError("COGNITION_DELETION_APPROVAL_INVALID", "deletion approval is absent")
        result = self._deletion(request.action, faults=True).apply(plan.plan_id, approval, now=self.now)
        receipt = read_json(self.root / result["receipt_path"])
        if not result.get("checkpoint"):
            raise ProtocolError("COGNITION_DELETION_CHECKPOINT_MISSING", "deletion checkpoint is absent")
        return self._result(
            request,
            operation_key,
            object_version=document_digest(receipt),
            changed=True,
            data=result,
            evidence=[{"kind": "memory-deletion", "ref": result["receipt_path"], "sha256": document_digest(receipt)}],
        )

    def _note_preview(self, request, operation_key):
        preview, _, _ = self._find_preview(request)
        if preview is None:
            preview = self._editor(request.action).preview(
                project_id=str(request.project_id),
                relative_path=request.input["relative_path"],
                content=request.input["content"],
                expected_sha256=request.input["expected_sha256"],
                now=self.now,
            )
        digest = document_digest(preview)
        path = self._editor(request.action).preview_root / f"{preview['preview_id'][5:]}.json"
        return self._result(
            request,
            operation_key,
            object_version=digest,
            changed=True,
            data={"preview_id": preview["preview_id"], "preview": preview, "requires_approval": preview["operation"] == "UPDATE"},
            evidence=[{"kind": "knowledge-preview", "ref": path.relative_to(self.root).as_posix(), "sha256": digest}],
        )

    def _note_approve(self, request, operation_key):
        preview = self._knowledge_preview(request.input["preview_id"])
        approval = self._editor(request.action).approve(
            preview["preview_id"],
            actor_id=request.input["actor_id"],
            authorization_ref=request.input["authorization_ref"],
            now=self.now,
        )
        path = self.workspace.receipts / f"knowledge-approval-edit-{preview['preview_id'][5:]}.json"
        return self._result(
            request,
            operation_key,
            object_version=document_digest(approval),
            changed=True,
            data={"approval_id": approval["approval_id"], "approval": approval},
            evidence=[{"kind": "knowledge-approval", "ref": path.relative_to(self.root).as_posix(), "sha256": document_digest(approval)}],
        )

    def _note_apply(self, request, operation_key):
        preview = self._knowledge_preview(request.input["preview_id"])
        approval = self._knowledge_approval(preview, enforce_expiry=False)
        result = self._editor(request.action, faults=True).apply(
            preview["preview_id"],
            content=request.input["content"],
            idempotency_key=operation_key,
            approval=approval,
            now=self.now,
        )
        return self._result(
            request,
            operation_key,
            object_version=result["sha256"],
            changed=True,
            data=result,
            evidence=[{"kind": "knowledge-edit", "ref": result["receipt_path"], "sha256": result["sha256"]}],
        )

    def _graph_input(self, request: OperatorRequest) -> None:
        fields = {"project_id", "relation", "tag", "trust_state", "lifecycle_state", "node_id", "direction"}
        self._exact(request.input, fields, code="KNOWLEDGE_GRAPH_FILTER_INVALID")
        if request.input.get("project_id") != request.project_id:
            raise ProtocolError("COGNITION_SCOPE_DENIED", "knowledge graph project changed")
        for name in fields - {"project_id"}:
            value = request.input.get(name)
            if value is not None and (not isinstance(value, str) or not value or len(value) > 256):
                raise ProtocolError("KNOWLEDGE_GRAPH_FILTER_INVALID", "knowledge graph filter is invalid")
        if (request.input.get("node_id") is None) != (request.input.get("direction") is None):
            raise ProtocolError("KNOWLEDGE_GRAPH_FILTER_INVALID", "neighbor ID and direction must be paired")

    def _require_graph_node_scope(self, request: OperatorRequest, nodes) -> None:
        node_id = request.input.get("node_id")
        if node_id is None:
            return
        if not isinstance(nodes, list) or any(
            not isinstance(node, dict) for node in nodes
        ):
            raise ProtocolError(
                "KNOWLEDGE_GRAPH_PROJECTION_INVALID",
                "knowledge graph projection is malformed",
            )
        selected = next((node for node in nodes if node.get("id") == node_id), None)
        if selected is not None and selected.get("project_id") != request.project_id:
            raise ProtocolError(
                "COGNITION_SCOPE_DENIED",
                "knowledge graph node is outside project scope",
            )

    def _graph_rebuild(self, request, operation_key):
        self._graph_input(request)
        graph = KnowledgeGraph(self.root, self.authority)
        rebuilt = graph.rebuild()
        node_by_id = {node["id"]: node for node in rebuilt["nodes"]}
        authorized_ids = {
            node_id
            for node_id, node in node_by_id.items()
            if node["project_id"] == request.project_id
        }
        if request.input["node_id"] is not None:
            self._require_graph_node_scope(request, rebuilt["nodes"])
            selected = graph.neighbors(request.input["node_id"], direction=request.input["direction"])
        else:
            selected = graph.filter(
                project_id=str(request.project_id),
                relation=request.input["relation"],
                tag=request.input["tag"],
                trust_state=request.input["trust_state"],
                lifecycle_state=request.input["lifecycle_state"],
            )
        all_node_ids = set(node_by_id)
        selected_nodes = [
            node for node in selected["nodes"] if node["id"] in authorized_ids
        ]
        selected_edges = [
            edge
            for edge in selected["edges"]
            if edge["source_id"] in authorized_ids
            and (
                edge["target_id"] is None
                or edge["target_id"] in authorized_ids
                or edge["target_id"] not in all_node_ids
            )
        ]
        backlinks = {}
        for target_id, entries in rebuilt["backlinks"].items():
            if target_id in all_node_ids and target_id not in authorized_ids:
                continue
            authorized_entries = [
                entry
                for entry in entries
                if entry["source_id"] in authorized_ids
            ]
            if authorized_entries:
                backlinks[target_id] = authorized_entries
        return self._result(
            request,
            operation_key,
            object_version=rebuilt["sha256"],
            changed=True,
            data={
                "nodes": selected_nodes,
                "edges": selected_edges,
                "backlinks": backlinks,
                "projection_path": Path(rebuilt["projection_path"])
                .relative_to(self.root)
                .as_posix(),
            },
            evidence=[{"kind": "knowledge-graph", "ref": Path(rebuilt["projection_path"]).relative_to(self.root).as_posix(), "sha256": rebuilt["sha256"]}],
        )
