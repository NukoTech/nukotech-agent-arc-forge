from __future__ import annotations

import hashlib
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.capture.admission import CaptureAdmissionService
from hive_protocol.capture.models import SourceRecord
from hive_protocol.capture.normalizers import NormalizerRegistry
from hive_protocol.cognition.authority import CognitionAuthority
from hive_protocol.cognition.extraction import DeterministicCognitionExtractor
from hive_protocol.cognition.models import CognitionEvent, MemoryCandidate
from hive_protocol.cognition.promotion import CognitionPromotionService
from hive_protocol.cognition.retrieval import CognitionRetrieval
from hive_protocol.cognition.store import CognitionStore
from hive_protocol.knowledge.editor import KnowledgeEditor
from hive_protocol.knowledge.graph import KnowledgeGraph
from hive_protocol.product.api import OperatorAPI
from hive_protocol.product.shell_contracts import OperatorRequest, route_for
from hive_protocol.product.shell_service import ShellService
from hive_protocol.product.workspace import HiveWorkspace
from hive_protocol.storage import read_json


NOW = datetime(2026, 9, 1, 13, 0, tzinfo=timezone.utc)
SESSION_DIGEST = "e" * 64


def _request(
    action: str,
    input_document: dict,
    *,
    expected_version: str,
    key: str,
) -> dict:
    return {
        "schema_version": "hive.operator-request.v1",
        "request_id": str(uuid4()),
        "tenant_id": "local-user",
        "project_id": "HiveMind",
        "action": action,
        "expected_version": expected_version,
        "idempotency_key": key,
        "input": input_document,
    }


def _dispatch(api: OperatorAPI, path: str, request: dict):
    return api.dispatch_mutation(
        "POST",
        path,
        request,
        session_digest=SESSION_DIGEST,
        idempotency_key=request["idempotency_key"],
        expected_version=request["expected_version"],
    )


def _document(result) -> dict:
    return result.response.as_dict()


def _shell(tmp_path: Path, *, fault_hook=None):
    workspace = HiveWorkspace.create(tmp_path / "hive")
    workspace.configure_provider("retrieval-only")
    service = ShellService(
        workspace,
        tenant_id="local-user",
        project_ids={"HiveMind"},
        now=NOW,
        cognition_knowledge_fault_hook=fault_hook,
    )
    api = OperatorAPI(
        workspace.root,
        service,
        tenant_id="local-user",
        project_ids={"HiveMind"},
    )
    return workspace, service, api


def _source(workspace: HiveWorkspace) -> SourceRecord:
    payload = b"Decision: reviewed shell memory remains evidence-bound.\n"
    nonce = uuid4().hex
    capture = CaptureAdmissionService(
        workspace,
        workspace.root.parent / f"capture-state-{nonce}",
        registry=NormalizerRegistry(),
        signing_key=Ed25519PrivateKey.generate(),
    )
    plan = capture.plan_bytes(
        payload,
        tenant_id="local-user",
        project_id="HiveMind",
        privacy_class="PROJECT_PRIVATE",
        channel="MARKDOWN",
        source_owner="Owner",
        rights_assertion="USER_PROVIDED",
        media_type="text/markdown",
        filename="memory-evidence.md",
        destination="RESEARCH",
    )
    result = capture.apply(plan, hashlib.sha256(nonce.encode()).hexdigest())
    return SourceRecord.from_dict(read_json(workspace.root / result["source_record_path"]))


def _event(record: SourceRecord, *, action: str = "CREATE", target: str | None = None) -> dict:
    anchor = record.anchors[0]
    return {
        "schema_version": "hive.cognition-event.v1",
        "event_id": str(uuid4()),
        "tenant_id": "local-user",
        "project_id": "HiveMind",
        "event_type": "PROJECT_EVENT",
        "privacy_class": "PROJECT_PRIVATE",
        "experience_scope": {"kind": "DOMAIN", "owner_id": "HiveMind"},
        "title": "Shell memory proposal",
        "text": "",
        "structured_claims": [
            {
                "candidate_type": "CORRECTION" if action != "CREATE" else "DECISION",
                "subject_id": "project:HiveMind",
                "key": "shell.memory.decision",
                "value": "Review remains separate from promotion.",
                "narrative": "Review remains separate from promotion.",
                "proposed_action": action,
                "supersedes": target if action == "CORRECT" else None,
                "revokes": target if action == "REVOKE" else None,
            }
        ],
        "evidence": [
            {
                "source_id": record.source_id,
                "anchor_id": anchor["anchor_id"],
                "source_sha256": record.original_sha256,
                "normalized_sha256": record.normalized_sha256,
            }
        ],
        "source_ref": f"operator-shell:{uuid4().hex}",
        "source_sha256": record.original_sha256,
        "occurred_at": NOW.isoformat().replace("+00:00", "Z"),
        "recorded_at": NOW.isoformat().replace("+00:00", "Z"),
    }


def _propose_review_promote(workspace: HiveWorkspace, api: OperatorAPI) -> tuple[dict, dict, dict]:
    event = _event(_source(workspace))
    proposed = _document(
        _dispatch(
            api,
            "/api/v1/memory/propose",
            _request(
                "memory.propose",
                {"event": event},
                expected_version="ABSENT",
                key="memory-propose-0001",
            ),
        )
    )
    assert proposed["outcome"] == "APPLIED", proposed
    assert proposed["data"]["provider_state"] == {"status": "ABSENT", "used": False}
    assert not workspace.prime.exists()
    candidate = proposed["data"]["candidates"][0]
    candidate_sha256 = proposed["data"]["candidate_sha256"][0]

    reviewed = _document(
        _dispatch(
            api,
            "/api/v1/memory/review",
            _request(
                "memory.review",
                {
                    "candidate_id": candidate["candidate_id"],
                    "candidate_sha256": candidate_sha256,
                    "outcome": "APPROVED",
                    "actor_id": "Owner",
                    "authorization_ref": "attended:m4-shell-review",
                    "corrections": [],
                },
                expected_version=candidate_sha256,
                key="memory-review-00001",
            ),
        )
    )
    assert reviewed["outcome"] == "APPLIED"
    assert not workspace.prime.exists()

    promote_request = _request(
                "memory.promote",
                {
                    "candidate_id": candidate["candidate_id"],
                    "candidate_sha256": candidate_sha256,
                    "decision_id": reviewed["data"]["decision_id"],
                    "decision_sha256": reviewed["object_version"],
                },
                expected_version=reviewed["object_version"],
                key="memory-promote-0001",
            )
    promoted = _document(
        _dispatch(api, "/api/v1/memory/promote", promote_request)
    )
    assert promoted["outcome"] == "APPLIED"
    assert promoted["data"]["node"]["trust_state"] == "REVIEWED"
    replay = _dispatch(api, "/api/v1/memory/promote", promote_request)
    assert replay.status == 200
    assert _document(replay)["changed"] is False
    return proposed, reviewed, promoted


def test_memory_proposal_review_and_promotion_are_separate_and_replay_safe(tmp_path: Path) -> None:
    workspace, _, api = _shell(tmp_path)

    _, _, promoted = _propose_review_promote(workspace, api)
    assert promoted["changed"] is True


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"project_id": "OtherProject"}, "COGNITION_SCOPE_DENIED"),
        ({"tenant_id": "other-user"}, "COGNITION_SCOPE_DENIED"),
        ({"evidence": []}, "COGNITION_EVIDENCE_INVALID"),
        ({"approval": "forbidden"}, "COGNITION_DOCUMENT_SCHEMA_INVALID"),
    ],
)
def test_memory_proposal_refuses_scope_missing_evidence_and_authority_fields(
    tmp_path: Path, change: dict, reason: str
) -> None:
    workspace, _, api = _shell(tmp_path)
    event = _event(_source(workspace))
    event.update(change)
    result = _dispatch(
        api,
        "/api/v1/memory/propose",
        _request(
            "memory.propose",
            {"event": event},
            expected_version="ABSENT",
            key=f"memory-refuse-{uuid4().hex}",
        ),
    )
    assert result.status in {400, 403}
    assert _document(result)["reason_code"] == reason
    assert not workspace.prime.exists()


def test_correction_revocation_retention_and_deletion_remain_exact_and_checkpointed(
    tmp_path: Path,
) -> None:
    workspace, _, api = _shell(tmp_path)
    _, _, promoted = _propose_review_promote(workspace, api)
    node = promoted["data"]["node"]
    sentinel = workspace.sources / "unrelated-sentinel.md"
    sentinel.write_text("# untouched\n", encoding="utf-8")

    wrong = _event(_source(workspace), action="CORRECT", target=node["node_id"])
    wrong["structured_claims"][0]["supersedes"] = "node:" + "0" * 64
    refused = _dispatch(
        api,
        "/api/v1/memory/correct",
        _request(
            "memory.correct",
            {"event": wrong, "target_id": node["node_id"], "target_sha256": promoted["object_version"]},
            expected_version=promoted["object_version"],
            key="memory-correct-refuse",
        ),
    )
    assert _document(refused)["reason_code"] == "COGNITION_TARGET_BINDING_MISMATCH"

    correction_event = _event(
        _source(workspace), action="CORRECT", target=node["node_id"]
    )
    correction = _document(
        _dispatch(
            api,
            "/api/v1/memory/correct",
            _request(
                "memory.correct",
                {
                    "event": correction_event,
                    "target_id": node["node_id"],
                    "target_sha256": promoted["object_version"],
                },
                expected_version=promoted["object_version"],
                key="memory-correct-propose",
            ),
        )
    )
    corrected_candidate = correction["data"]["candidates"][0]
    corrected_sha = correction["data"]["candidate_sha256"][0]
    correction_review = _document(
        _dispatch(
            api,
            "/api/v1/memory/review",
            _request(
                "memory.review",
                {
                    "candidate_id": corrected_candidate["candidate_id"],
                    "candidate_sha256": corrected_sha,
                    "outcome": "APPROVED",
                    "actor_id": "Owner",
                    "authorization_ref": "attended:m4-correction",
                    "corrections": [],
                },
                expected_version=corrected_sha,
                key="memory-correct-review",
            ),
        )
    )
    corrected = _document(
        _dispatch(
            api,
            "/api/v1/memory/promote",
            _request(
                "memory.promote",
                {
                    "candidate_id": corrected_candidate["candidate_id"],
                    "candidate_sha256": corrected_sha,
                    "decision_id": correction_review["data"]["decision_id"],
                    "decision_sha256": correction_review["object_version"],
                },
                expected_version=correction_review["object_version"],
                key="memory-correct-promote",
            ),
        )
    )
    corrected_node = corrected["data"]["node"]

    revocation = _document(
        _dispatch(
            api,
            "/api/v1/memory/revoke",
            _request(
                "memory.revoke",
                {
                    "event": _event(
                        _source(workspace),
                        action="REVOKE",
                        target=corrected_node["node_id"],
                    ),
                    "target_id": corrected_node["node_id"],
                    "target_sha256": corrected["object_version"],
                },
                expected_version=corrected["object_version"],
                key="memory-revoke-propose",
            ),
        )
    )
    revoked_candidate = revocation["data"]["candidates"][0]
    revoked_sha = revocation["data"]["candidate_sha256"][0]
    revocation_review = _document(
        _dispatch(
            api,
            "/api/v1/memory/review",
            _request(
                "memory.review",
                {
                    "candidate_id": revoked_candidate["candidate_id"],
                    "candidate_sha256": revoked_sha,
                    "outcome": "APPROVED",
                    "actor_id": "Owner",
                    "authorization_ref": "attended:m4-revocation",
                    "corrections": [],
                },
                expected_version=revoked_sha,
                key="memory-revoke-review",
            ),
        )
    )
    revoked = _document(
        _dispatch(
            api,
            "/api/v1/memory/promote",
            _request(
                "memory.promote",
                {
                    "candidate_id": revoked_candidate["candidate_id"],
                    "candidate_sha256": revoked_sha,
                    "decision_id": revocation_review["data"]["decision_id"],
                    "decision_sha256": revocation_review["object_version"],
                },
                expected_version=revocation_review["object_version"],
                key="memory-revoke-promote",
            ),
        )
    )
    assert revoked["data"]["node"]["node_type"] == "REVOCATION"
    authority = CognitionAuthority(workspace.root)
    visible = CognitionRetrieval(workspace.root, authority).list_nodes(
        project_id="HiveMind"
    )
    assert all(item["node_id"] not in {node["node_id"], corrected_node["node_id"]} for item in visible)

    preview = _document(
        _dispatch(
            api,
            "/api/v1/memory/deletion/preview",
            _request(
                "memory.deletion.preview",
                {"node_id": node["node_id"], "node_sha256": promoted["object_version"]},
                expected_version=promoted["object_version"],
                key="memory-delete-preview",
            ),
        )
    )
    plan = preview["data"]["plan"]
    unconfirmed = _dispatch(
        api,
        "/api/v1/memory/deletion/approve",
        _request(
            "memory.deletion.approve",
            {
                "plan_id": plan["plan_id"],
                "plan_sha256": preview["object_version"],
                "actor_id": "Owner",
                "authorization_ref": "attended:m4-delete",
                "confirmation": "DELETE something-else",
            },
            expected_version=preview["object_version"],
            key="memory-delete-unconfirmed",
        ),
    )
    assert _document(unconfirmed)["reason_code"] == "COGNITION_DELETION_CONFIRMATION_INVALID"

    approved = _document(
        _dispatch(
            api,
            "/api/v1/memory/deletion/approve",
            _request(
                "memory.deletion.approve",
                {
                    "plan_id": plan["plan_id"],
                    "plan_sha256": preview["object_version"],
                    "actor_id": "Owner",
                    "authorization_ref": "attended:m4-delete",
                    "confirmation": f"DELETE {node['node_id']}",
                },
                expected_version=preview["object_version"],
                key="memory-delete-approve",
            ),
        )
    )
    deleted = _document(
        _dispatch(
            api,
            "/api/v1/memory/deletion/apply",
            _request(
                "memory.deletion.apply",
                {
                    "plan_id": plan["plan_id"],
                    "plan_sha256": preview["object_version"],
                    "approval_id": approved["data"]["approval_id"],
                    "approval_sha256": approved["object_version"],
                },
                expected_version=approved["object_version"],
                key="memory-delete-apply01",
            ),
        )
    )
    assert deleted["outcome"] == "APPLIED"
    assert len(deleted["data"]["checkpoint"]) == 40
    assert sentinel.read_text(encoding="utf-8") == "# untouched\n"


def test_knowledge_create_update_approval_graph_and_stale_preview(tmp_path: Path) -> None:
    workspace, service, api = _shell(tmp_path)
    content = "---\ntype: moc\n---\n# MOC Shell\n\n#local\n"
    preview = _document(
        _dispatch(
            api,
            "/api/v1/knowledge/notes/preview",
            _request(
                "knowledge.notes.preview",
                {"relative_path": "MOC Shell.md", "content": content, "expected_sha256": None},
                expected_version="ABSENT",
                key="knowledge-preview-create",
            ),
        )
    )
    applied = _document(
        _dispatch(
            api,
            "/api/v1/knowledge/notes/apply",
            _request(
                "knowledge.notes.apply",
                {
                    "preview_id": preview["data"]["preview_id"],
                    "preview_sha256": preview["object_version"],
                    "content": content,
                    "approval_id": None,
                    "approval_sha256": None,
                },
                expected_version=preview["object_version"],
                key="knowledge-apply-create1",
            ),
        )
    )
    assert applied["data"]["sha256"] == hashlib.sha256(content.encode()).hexdigest()

    updated_content = content + "\n- supports [[Architecture]]\n"
    update_preview = _document(
        _dispatch(
            api,
            "/api/v1/knowledge/notes/preview",
            _request(
                "knowledge.notes.preview",
                {
                    "relative_path": "MOC Shell.md",
                    "content": updated_content,
                    "expected_sha256": applied["object_version"],
                },
                expected_version=applied["object_version"],
                key="knowledge-preview-update",
            ),
        )
    )
    approval = _document(
        _dispatch(
            api,
            "/api/v1/knowledge/notes/approve",
            _request(
                "knowledge.notes.approve",
                {
                    "preview_id": update_preview["data"]["preview_id"],
                    "preview_sha256": update_preview["object_version"],
                    "actor_id": "Owner",
                    "authorization_ref": "attended:m4-note-edit",
                },
                expected_version=update_preview["object_version"],
                key="knowledge-approve-update",
            ),
        )
    )
    updated = _document(
        _dispatch(
            api,
            "/api/v1/knowledge/notes/apply",
            _request(
                "knowledge.notes.apply",
                {
                    "preview_id": update_preview["data"]["preview_id"],
                    "preview_sha256": update_preview["object_version"],
                    "content": updated_content,
                    "approval_id": approval["data"]["approval_id"],
                    "approval_sha256": approval["object_version"],
                },
                expected_version=approval["object_version"],
                key="knowledge-apply-update1",
            ),
        )
    )
    assert updated["object_version"] == hashlib.sha256(updated_content.encode()).hexdigest()

    graph = _document(
        _dispatch(
            api,
            "/api/v1/knowledge/graph/rebuild",
            _request(
                "knowledge.graph.rebuild",
                {
                    "project_id": "HiveMind",
                    "relation": None,
                    "tag": "local",
                    "trust_state": None,
                    "lifecycle_state": None,
                    "node_id": None,
                    "direction": None,
                },
                expected_version="ABSENT",
                key="knowledge-graph-rebuild",
            ),
        )
    )
    assert graph["data"]["nodes"][0]["kind"] == "MOC"
    assert graph["data"]["nodes"][0]["tags"] == ["local"]
    projected = service.read(
        route_for("GET", "/api/v1/knowledge"),
        tenant_id="local-user",
        project_id="HiveMind",
        query={"project_id": "HiveMind"},
    )
    assert projected["data"]["action_versions"]["knowledge.graph.rebuild"] == graph[
        "object_version"
    ]

    stale = _dispatch(
        api,
        "/api/v1/knowledge/notes/apply",
        _request(
            "knowledge.notes.apply",
            {
                "preview_id": preview["data"]["preview_id"],
                "preview_sha256": preview["object_version"],
                "content": content,
                "approval_id": None,
                "approval_sha256": None,
            },
            expected_version=preview["object_version"],
            key="knowledge-stale-apply",
        ),
    )
    assert _document(stale)["reason_code"] in {
        "KNOWLEDGE_VERSION_CONFLICT",
        "OPERATOR_VERSION_STALE",
    }


def test_retention_scan_creates_review_work_only_and_never_deletes(tmp_path: Path) -> None:
    workspace, service, api = _shell(tmp_path)
    record = _source(workspace)
    event = CognitionEvent.from_dict(_event(record))
    extracted = DeterministicCognitionExtractor().extract(event, now=NOW).candidates[0]
    candidate_document = extracted.as_dict()
    candidate_document["retention_until"] = (NOW - timedelta(days=1)).isoformat().replace(
        "+00:00", "Z"
    )
    candidate = MemoryCandidate.from_dict(candidate_document)
    store = CognitionStore(workspace.root, service.cognition_knowledge.authority)
    store.stage(event, candidate)
    decision = service.cognition_knowledge.authority.create_review(
        candidate,
        outcome="APPROVED",
        actor_id="Owner",
        authorization_ref="attended:m4-retention-seed",
        corrections=[],
        now=NOW,
    )
    store.record_review(decision, now=NOW)
    node = CognitionPromotionService(
        workspace.root, store, service.cognition_knowledge.authority
    ).promote(candidate.candidate_id, now=NOW)["node"]
    target = workspace.root / node["relative_path"]

    version = service.cognition_knowledge.current_version(
        route_for("POST", "/api/v1/memory/retention/scan"),
        OperatorRequest.from_dict(
            _request(
                "memory.retention.scan",
                {"project_id": "HiveMind"},
                expected_version="0" * 64,
                key="retention-version-probe",
            )
        ),
    )
    scan = _document(
        _dispatch(
            api,
            "/api/v1/memory/retention/scan",
            _request(
                "memory.retention.scan",
                {"project_id": "HiveMind"},
                expected_version=version,
                key="memory-retention-scan",
            ),
        )
    )
    assert scan["outcome"] == "APPLIED"
    assert scan["data"]["automatic_delete"] is False
    assert scan["data"]["reviews"][0]["node_id"] == node["node_id"]
    assert target.is_file()


@pytest.mark.parametrize(
    "content,reason",
    [
        ("# Note\n\nAuthorization: Bearer secret-value\n", "ADAPTER_CREDENTIAL_VALUE_DENIED"),
        ("\x00", "KNOWLEDGE_CONTENT_INVALID"),
    ],
)
def test_knowledge_note_refuses_credentials_and_invalid_content_before_preview(
    tmp_path: Path, content: str, reason: str
) -> None:
    workspace, _, api = _shell(tmp_path)
    result = _dispatch(
        api,
        "/api/v1/knowledge/notes/preview",
        _request(
            "knowledge.notes.preview",
            {"relative_path": "Denied.md", "content": content, "expected_sha256": None},
            expected_version="ABSENT",
            key=f"knowledge-denied-{uuid4().hex}",
        ),
    )
    assert _document(result)["reason_code"] == reason
    assert not (workspace.prime / "knowledge" / "HiveMind" / "Denied.md").exists()


class CrashOnce:
    def __init__(self, target: str) -> None:
        self.target = target
        self.fired = False

    def __call__(self, stage: str) -> None:
        if stage == self.target and not self.fired:
            self.fired = True
            raise RuntimeError("simulated crash")


def _create_note(
    workspace: HiveWorkspace,
    *,
    project_id: str,
    relative_path: str,
    content: str,
    idempotency_key: str,
) -> None:
    authority = CognitionAuthority(workspace.root)
    editor = KnowledgeEditor(workspace.root, authority)
    preview = editor.preview(
        project_id=project_id,
        relative_path=relative_path,
        content=content,
        expected_sha256=None,
        now=NOW,
    )
    editor.apply(
        preview["preview_id"],
        content=content,
        idempotency_key=idempotency_key,
        approval=None,
        now=NOW,
    )


def test_graph_refuses_a_neighbor_node_from_another_project(tmp_path: Path) -> None:
    workspace, _, api = _shell(tmp_path)
    _create_note(
        workspace,
        project_id="OtherProject",
        relative_path="Foreign.md",
        content="# Foreign\n",
        idempotency_key="4" * 64,
    )
    rebuilt = KnowledgeGraph(
        workspace.root, CognitionAuthority(workspace.root)
    ).rebuild()
    foreign_node = next(
        node for node in rebuilt["nodes"] if node["project_id"] == "OtherProject"
    )

    result = _dispatch(
        api,
        "/api/v1/knowledge/graph/rebuild",
        _request(
            "knowledge.graph.rebuild",
            {
                "project_id": "HiveMind",
                "relation": None,
                "tag": None,
                "trust_state": None,
                "lifecycle_state": None,
                "node_id": foreign_node["id"],
                "direction": "outbound",
            },
            expected_version=rebuilt["sha256"],
            key="knowledge-graph-foreign-neighbor",
        ),
    )
    assert result.status == 403
    assert _document(result)["reason_code"] == "COGNITION_SCOPE_DENIED"
    ledger = workspace.root / ".hive" / "runtime" / "operator-shell" / "api-replay" / "ledger"
    assert not ledger.exists() or not list(ledger.glob("*.json"))


def test_graph_response_contains_only_the_authorized_project(tmp_path: Path) -> None:
    workspace, _, api = _shell(tmp_path)
    _create_note(
        workspace,
        project_id="HiveMind",
        relative_path="Local.md",
        content="# Local\n\n- links_to [[Foreign]]\n",
        idempotency_key="5" * 64,
    )
    _create_note(
        workspace,
        project_id="OtherProject",
        relative_path="Foreign.md",
        content="# Foreign\n\n- links_to [[Local]]\n",
        idempotency_key="6" * 64,
    )

    result = _document(
        _dispatch(
            api,
            "/api/v1/knowledge/graph/rebuild",
            _request(
                "knowledge.graph.rebuild",
                {
                    "project_id": "HiveMind",
                    "relation": None,
                    "tag": None,
                    "trust_state": None,
                    "lifecycle_state": None,
                    "node_id": None,
                    "direction": None,
                },
                expected_version="ABSENT",
                key="knowledge-graph-project-projection",
            ),
        )
    )
    authorized_ids = {node["id"] for node in result["data"]["nodes"]}
    assert authorized_ids
    assert {node["project_id"] for node in result["data"]["nodes"]} == {"HiveMind"}
    assert all(
        edge["source_id"] in authorized_ids
        and (edge["target_id"] is None or edge["target_id"] in authorized_ids)
        for edge in result["data"]["edges"]
    )
    assert set(result["data"]["backlinks"]) <= authorized_ids
    assert all(
        backlink["source_id"] in authorized_ids
        for backlinks in result["data"]["backlinks"].values()
        for backlink in backlinks
    )


def test_shell_refreshes_time_before_authorizing_a_new_effect(tmp_path: Path) -> None:
    workspace, service, api = _shell(tmp_path)
    content = "# Original\n"
    preview = _document(
        _dispatch(
            api,
            "/api/v1/knowledge/notes/preview",
            _request(
                "knowledge.notes.preview",
                {
                    "relative_path": "Expiring.md",
                    "content": content,
                    "expected_sha256": None,
                },
                expected_version="ABSENT",
                key="knowledge-expiring-create-preview",
            ),
        )
    )
    created = _document(
        _dispatch(
            api,
            "/api/v1/knowledge/notes/apply",
            _request(
                "knowledge.notes.apply",
                {
                    "preview_id": preview["data"]["preview_id"],
                    "preview_sha256": preview["object_version"],
                    "content": content,
                    "approval_id": None,
                    "approval_sha256": None,
                },
                expected_version=preview["object_version"],
                key="knowledge-expiring-create-apply",
            ),
        )
    )
    replacement = "# Replacement\n"
    update_preview = _document(
        _dispatch(
            api,
            "/api/v1/knowledge/notes/preview",
            _request(
                "knowledge.notes.preview",
                {
                    "relative_path": "Expiring.md",
                    "content": replacement,
                    "expected_sha256": created["object_version"],
                },
                expected_version=created["object_version"],
                key="knowledge-expiring-update-preview",
            ),
        )
    )
    approval = _document(
        _dispatch(
            api,
            "/api/v1/knowledge/notes/approve",
            _request(
                "knowledge.notes.approve",
                {
                    "preview_id": update_preview["data"]["preview_id"],
                    "preview_sha256": update_preview["object_version"],
                    "actor_id": "Owner",
                    "authorization_ref": "attended:m4-expiry",
                },
                expected_version=update_preview["object_version"],
                key="knowledge-expiring-update-approve",
            ),
        )
    )
    service._clock = lambda: NOW + timedelta(minutes=20)
    refused = _dispatch(
        api,
        "/api/v1/knowledge/notes/apply",
        _request(
            "knowledge.notes.apply",
            {
                "preview_id": update_preview["data"]["preview_id"],
                "preview_sha256": update_preview["object_version"],
                "content": replacement,
                "approval_id": approval["data"]["approval_id"],
                "approval_sha256": approval["object_version"],
            },
            expected_version=approval["object_version"],
            key="knowledge-expiring-update-apply",
        ),
    )
    assert refused.status in {400, 403}
    assert _document(refused)["reason_code"] in {
        "KNOWLEDGE_APPROVAL_INVALID",
        "KNOWLEDGE_PREVIEW_EXPIRED",
    }


def test_exact_knowledge_receipt_survives_promoter_key_rotation(
    tmp_path: Path,
) -> None:
    workspace, _, api = _shell(tmp_path)
    content = "# Rotated receipt\n"
    preview = _document(
        _dispatch(
            api,
            "/api/v1/knowledge/notes/preview",
            _request(
                "knowledge.notes.preview",
                {
                    "relative_path": "Rotated.md",
                    "content": content,
                    "expected_sha256": None,
                },
                expected_version="ABSENT",
                key="knowledge-rotation-preview",
            ),
        )
    )
    applied_request = _request(
        "knowledge.notes.apply",
        {
            "preview_id": preview["data"]["preview_id"],
            "preview_sha256": preview["object_version"],
            "content": content,
            "approval_id": None,
            "approval_sha256": None,
        },
        expected_version=preview["object_version"],
        key="knowledge-rotation-apply",
    )
    applied = _document(
        _dispatch(api, "/api/v1/knowledge/notes/apply", applied_request)
    )

    shutil.rmtree(workspace.root / ".hive" / "keys" / "cognition")
    api.service = ShellService(
        workspace,
        tenant_id="local-user",
        project_ids={"HiveMind"},
        now=NOW,
    )
    replay_as_new_request = _request(
        "knowledge.notes.apply",
        applied_request["input"],
        expected_version=applied["object_version"],
        key="knowledge-rotation-apply-new-request",
    )
    result = _dispatch(
        api,
        "/api/v1/knowledge/notes/apply",
        replay_as_new_request,
    )
    assert result.status == 200
    assert _document(result)["object_version"] == applied["object_version"]


def test_shell_recovers_started_deletion_after_approval_expiry(tmp_path: Path) -> None:
    crash = CrashOnce("memory.deletion.apply:first-path-deleted")
    workspace, service, api = _shell(tmp_path)
    _, _, promoted = _propose_review_promote(workspace, api)
    node = promoted["data"]["node"]
    preview = _document(
        _dispatch(
            api,
            "/api/v1/memory/deletion/preview",
            _request(
                "memory.deletion.preview",
                {"node_id": node["node_id"], "node_sha256": promoted["object_version"]},
                expected_version=promoted["object_version"],
                key="memory-expiring-delete-preview",
            ),
        )
    )
    plan = preview["data"]["plan"]
    approval = _document(
        _dispatch(
            api,
            "/api/v1/memory/deletion/approve",
            _request(
                "memory.deletion.approve",
                {
                    "plan_id": plan["plan_id"],
                    "plan_sha256": preview["object_version"],
                    "actor_id": "Owner",
                    "authorization_ref": "attended:m4-expiry-recovery",
                    "confirmation": f"DELETE {node['node_id']}",
                },
                expected_version=preview["object_version"],
                key="memory-expiring-delete-approve",
            ),
        )
    )
    request = _request(
        "memory.deletion.apply",
        {
            "plan_id": plan["plan_id"],
            "plan_sha256": preview["object_version"],
            "approval_id": approval["data"]["approval_id"],
            "approval_sha256": approval["object_version"],
        },
        expected_version=approval["object_version"],
        key="memory-expiring-delete-apply",
    )
    service.cognition_knowledge.fault_hook = crash
    first = _dispatch(api, "/api/v1/memory/deletion/apply", request)
    assert first.status == 500

    api.service = ShellService(
        workspace,
        tenant_id="local-user",
        project_ids={"HiveMind"},
        now=NOW + timedelta(hours=1),
    )
    recovered = _dispatch(api, "/api/v1/memory/deletion/apply", request)
    assert recovered.status == 200
    assert _document(recovered)["changed"] is False


@pytest.mark.parametrize(
    "fault",
    [
        "memory.propose:receipt-written",
        "memory.promote:sidecar-written",
        "knowledge.notes.apply:note-written",
    ],
)
def test_cognition_and_knowledge_exactly_recover_domain_crash(
    tmp_path: Path, fault: str
) -> None:
    crash = CrashOnce(fault)
    workspace, service, api = _shell(tmp_path, fault_hook=crash)
    source = _source(workspace)
    if fault.startswith("memory.propose"):
        request = _request(
            "memory.propose",
            {"event": _event(source)},
            expected_version="ABSENT",
            key=f"crash-{fault}",
        )
        path = "/api/v1/memory/propose"
    else:
        service.cognition_knowledge.fault_hook = None
        proposed, reviewed, _ = _propose_review_promote(workspace, api)
        candidate = proposed["data"]["candidates"][0]
        if fault.startswith("memory.promote"):
            # A second exact approved proposal gives the promotion crash its own object.
            event = _event(source)
            event["structured_claims"][0]["key"] = "shell.memory.crash-decision"
            proposed2 = _document(_dispatch(api, "/api/v1/memory/propose", _request(
                "memory.propose", {"event": event}, expected_version="ABSENT", key="crash-propose-two"
            )))
            candidate = proposed2["data"]["candidates"][0]
            reviewed2 = _document(_dispatch(api, "/api/v1/memory/review", _request(
                "memory.review",
                {"candidate_id": candidate["candidate_id"], "candidate_sha256": proposed2["data"]["candidate_sha256"][0], "outcome": "APPROVED", "actor_id": "Owner", "authorization_ref": "attended:crash", "corrections": []},
                expected_version=proposed2["data"]["candidate_sha256"][0], key="crash-review-two"
            )))
            request = _request(
                "memory.promote",
                {"candidate_id": candidate["candidate_id"], "candidate_sha256": proposed2["data"]["candidate_sha256"][0], "decision_id": reviewed2["data"]["decision_id"], "decision_sha256": reviewed2["object_version"]},
                expected_version=reviewed2["object_version"], key=f"crash-{fault}"
            )
            path = "/api/v1/memory/promote"
        else:
            content = "# Recoverable\n"
            note_preview = _document(_dispatch(api, "/api/v1/knowledge/notes/preview", _request(
                "knowledge.notes.preview", {"relative_path": "Recoverable.md", "content": content, "expected_sha256": None}, expected_version="ABSENT", key="crash-note-preview"
            )))
            request = _request(
                "knowledge.notes.apply",
                {"preview_id": note_preview["data"]["preview_id"], "preview_sha256": note_preview["object_version"], "content": content, "approval_id": None, "approval_sha256": None},
                expected_version=note_preview["object_version"], key=f"crash-{fault}"
            )
            path = "/api/v1/knowledge/notes/apply"
        service.cognition_knowledge.fault_hook = crash

    first = _dispatch(api, path, request)
    assert first.status == 500
    api.service = ShellService(
        workspace,
        tenant_id="local-user",
        project_ids={"HiveMind"},
        now=NOW,
    )
    recovered = _dispatch(api, path, request)
    assert recovered.status == 200
    assert _document(recovered)["changed"] is False
