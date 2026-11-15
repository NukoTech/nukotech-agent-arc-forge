from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.capture.admission import CaptureAdmissionService
from hive_protocol.capture.models import SourceRecord
from hive_protocol.capture.normalizers import NormalizerRegistry
from hive_protocol.cognition.authority import CognitionAuthority
from hive_protocol.cognition.deletion import CognitionDeletionService
from hive_protocol.cognition.extraction import DeterministicCognitionExtractor
from hive_protocol.cognition.models import CognitionEvent, KnowledgeNode, MemoryCandidate
from hive_protocol.cognition.promotion import CognitionPromotionService
from hive_protocol.cognition.retention import CognitionRetentionService
from hive_protocol.cognition.retrieval import CognitionRetrieval
from hive_protocol.cognition.store import CognitionStore
from hive_protocol.core import public_key_id
from hive_protocol.knowledge.editor import KnowledgeEditor
from hive_protocol.knowledge.graph import KnowledgeGraph
from hive_protocol.product.agent_adapter import product_adapter_services
from hive_protocol.product.workspace import HiveWorkspace
from hive_protocol.storage import read_json


NOW = datetime(2026, 9, 1, 6, 45, tzinfo=timezone.utc)


def _event(
    record: SourceRecord,
    *,
    event_type: str,
    key: str,
    narrative: str,
    action: str = "CREATE",
    supersedes: str | None = None,
    revokes: str | None = None,
) -> CognitionEvent:
    anchor = record.anchors[0]
    return CognitionEvent.from_dict(
        {
            "schema_version": "hive.cognition-event.v1",
            "event_id": str(uuid4()),
            "tenant_id": "local-user",
            "project_id": "HiveMind",
            "event_type": event_type,
            "privacy_class": "PROJECT_PRIVATE",
            "experience_scope": {"kind": "DOMAIN", "owner_id": "HiveMind"},
            "title": f"{event_type} cognition event",
            "text": "",
            "structured_claims": [
                {
                    "candidate_type": (
                        "CORRECTION" if action != "CREATE" else "DECISION"
                    ),
                    "subject_id": "project:HiveMind",
                    "key": key,
                    "value": narrative,
                    "narrative": narrative,
                    "proposed_action": action,
                    "supersedes": supersedes,
                    "revokes": revokes,
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
            "source_ref": f"{event_type.lower()}:{uuid4().hex}",
            "source_sha256": record.original_sha256,
            "occurred_at": NOW.isoformat().replace("+00:00", "Z"),
            "recorded_at": NOW.isoformat().replace("+00:00", "Z"),
        }
    )


def _review_promote(
    root: Path,
    authority: CognitionAuthority,
    event: CognitionEvent,
    *,
    retention_until: datetime | None = None,
) -> KnowledgeNode:
    store = CognitionStore(root, authority)
    candidate = DeterministicCognitionExtractor().extract(event, now=NOW).candidates[0]
    if retention_until is not None:
        document = candidate.as_dict()
        document["retention_until"] = retention_until.isoformat().replace(
            "+00:00", "Z"
        )
        candidate = MemoryCandidate.from_dict(document)
    store.stage(event, candidate)
    decision = authority.create_review(
        candidate,
        outcome="APPROVED",
        actor_id="Owner",
        authorization_ref="attended:m32-e2e",
        corrections=[],
        now=NOW,
    )
    store.record_review(decision, now=NOW)
    return KnowledgeNode.from_dict(
        CognitionPromotionService(root, store, authority).promote(
            candidate.candidate_id, now=NOW
        )["node"]
    )


def _create_note(
    editor: KnowledgeEditor,
    *,
    relative_path: str,
    content: str,
    key: str,
) -> dict:
    preview = editor.preview(
        project_id="HiveMind",
        relative_path=relative_path,
        content=content,
        expected_sha256=None,
        now=NOW,
    )
    return editor.apply(
        preview["preview_id"],
        content=content,
        idempotency_key=key * 64,
        approval=None,
        now=NOW,
    )


def _portable_bytes(workspace: HiveWorkspace) -> dict[str, bytes]:
    roots = (
        workspace.sources,
        workspace.assets,
        workspace.staging,
        workspace.research,
        workspace.prime,
        workspace.provenance,
        workspace.receipts,
    )
    return {
        path.relative_to(workspace.root).as_posix(): path.read_bytes()
        for root in roots
        if root.exists()
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


def _canonical_bytes(workspace: HiveWorkspace) -> dict[str, bytes]:
    portable = _portable_bytes(workspace)
    return {
        relative: payload
        for relative, payload in portable.items()
        if not relative.startswith(".hive/receipts/")
    }


def test_m32_complete_cognition_knowledge_portability_and_recovery_path(
    tmp_path: Path,
) -> None:
    workspace = HiveWorkspace.create(tmp_path / "hive", privacy_mode="local-only")
    sentinel = workspace.sources / "unrelated-sentinel.md"
    sentinel.write_bytes(b"# Unrelated sentinel\n")
    capture = CaptureAdmissionService(
        workspace,
        tmp_path / "capture-state",
        registry=NormalizerRegistry(),
        signing_key=Ed25519PrivateKey.generate(),
    )
    source = b"Decision: evidence remains anchored and local.\n"
    plan = capture.plan_bytes(
        source,
        tenant_id="local-user",
        project_id="HiveMind",
        privacy_class="PROJECT_PRIVATE",
        channel="MARKDOWN",
        source_owner="Owner",
        rights_assertion="USER_PROVIDED",
        media_type="text/markdown",
        filename="m32-evidence.md",
        destination="RESEARCH",
    )
    admitted = capture.apply(plan, "a" * 64)
    record = SourceRecord.from_dict(
        read_json(workspace.root / admitted["source_record_path"])
    )
    assert record.anchors
    assert (workspace.root / record.original_asset_path).read_bytes() == source

    authority = CognitionAuthority(
        workspace.root, trusted_reviewer_actors={"Owner"}
    )
    store = CognitionStore(workspace.root, authority)
    events = [
        _event(
            record,
            event_type=event_type,
            key=f"{event_type.lower()}.decision",
            narrative=f"{event_type} remains reviewable.",
        )
        for event_type in (
            "CAPTURE_ADMITTED",
            "RESEARCH_ARTIFACT",
            "TASK_EVENT",
            "PROJECT_EVENT",
        )
    ]
    staged: list[MemoryCandidate] = []
    for event in events:
        extraction = DeterministicCognitionExtractor().extract(event, now=NOW)
        assert extraction.provider_state == {"status": "ABSENT", "used": False}
        candidate = extraction.candidates[0]
        assert set(candidate.score["features"]) == {
            "evidence_quality",
            "repetition",
            "recency",
            "project_relevance",
            "source_trust",
            "contradiction",
            "sensitivity",
        }
        store.stage(event, candidate)
        staged.append(candidate)
    assert not workspace.prime.exists()

    selected = staged[-1]
    decision = authority.create_review(
        selected,
        outcome="APPROVED",
        actor_id="Owner",
        authorization_ref="attended:m32-e2e",
        corrections=[],
        now=NOW,
    )
    store.record_review(decision, now=NOW)
    original = KnowledgeNode.from_dict(
        CognitionPromotionService(workspace.root, store, authority).promote(
            selected.candidate_id, now=NOW
        )["node"]
    )
    corrected = _review_promote(
        workspace.root,
        authority,
        _event(
            record,
            event_type="PROJECT_EVENT",
            key=selected.claim["key"],
            narrative="PROJECT_EVENT remains reviewed and portable.",
            action="CORRECT",
            supersedes=original.node_id,
        ),
    )
    revocation = _review_promote(
        workspace.root,
        authority,
        _event(
            record,
            event_type="PROJECT_EVENT",
            key=selected.claim["key"],
            narrative="The corrected project claim is revoked.",
            action="REVOKE",
            revokes=corrected.node_id,
        ),
    )
    retained = _review_promote(
        workspace.root,
        authority,
        _event(
            record,
            event_type="TASK_EVENT",
            key="retention.review",
            narrative="Expired knowledge requires attended review.",
        ),
        retention_until=NOW - timedelta(days=1),
    )
    retention = CognitionRetentionService(workspace.root, authority).scan(
        now=NOW, project_id="HiveMind"
    )
    assert [item["node_id"] for item in retention] == [retained.node_id]
    assert retention[0]["automatic_delete"] is False
    assert (workspace.root / retained.relative_path).is_file()

    historical = CognitionRetrieval(workspace.root, authority).list_nodes(
        project_id="HiveMind", include_historical=True
    )
    states = {item["node_id"]: item["derived_state"] for item in historical}
    assert states[original.node_id] == "SUPERSEDED"
    assert states[corrected.node_id] == "REVOKED"
    assert states[revocation.node_id] == "AUDIT"
    assert states[retained.node_id] == "CURRENT"
    assert [
        item["node_id"]
        for item in CognitionRetrieval(workspace.root, authority).list_nodes(
            project_id="HiveMind"
        )
    ] == [retained.node_id]

    editor = KnowledgeEditor(workspace.root, authority)
    first = _create_note(
        editor,
        relative_path="Architecture.md",
        content="# Architecture\n\n#local\n\n- supports [[MOC HiveMind]]\n",
        key="b",
    )
    updated_content = (
        "# Architecture\n\n#local #reviewed\n\n"
        "- supports [[MOC HiveMind]]\n- depends_on [[Missing Note]]\n"
    )
    update = editor.preview(
        project_id="HiveMind",
        relative_path="Architecture.md",
        content=updated_content,
        expected_sha256=first["sha256"],
        now=NOW,
    )
    edit_approval = editor.approve(
        update["preview_id"],
        actor_id="Owner",
        authorization_ref="attended:m32-e2e-edit",
        now=NOW,
    )
    editor.apply(
        update["preview_id"],
        content=updated_content,
        idempotency_key="c" * 64,
        approval=edit_approval,
        now=NOW,
    )
    _create_note(
        editor,
        relative_path="mocs/MOC HiveMind.md",
        content=(
            "---\ntype: moc\n---\n# MOC HiveMind\n\n"
            "- contains [[Architecture]]\n"
        ),
        key="d",
    )
    graph_service = KnowledgeGraph(workspace.root, authority)
    before_graph = graph_service.rebuild()
    architecture = next(
        node for node in before_graph["nodes"] if node["title"] == "Architecture"
    )
    assert architecture["tags"] == ["local", "reviewed"]
    assert graph_service.neighbors(
        architecture["id"], direction="outbound"
    )["edges"]
    assert graph_service.neighbors(
        next(node["id"] for node in before_graph["nodes"] if node["kind"] == "MOC"),
        direction="inbound",
    )["edges"]

    bundle = tmp_path / "m32-hive.tar.gz"
    workspace.export(bundle)
    reopened = HiveWorkspace.reopen_export(bundle, tmp_path / "reopened")
    reopened_authority = CognitionAuthority(
        reopened.root, trusted_reviewer_actors={"Owner"}
    )
    reopened_graph = KnowledgeGraph(reopened.root, reopened_authority).rebuild()
    assert reopened_graph["nodes"] == before_graph["nodes"]
    assert reopened_graph["edges"] == before_graph["edges"]
    assert reopened_graph["backlinks"] == before_graph["backlinks"]
    assert CognitionRetrieval(reopened.root, reopened_authority).list_nodes(
        project_id="HiveMind", include_historical=True
    ) == historical

    workspace.snapshot("M3.2 pre-deletion portable checkpoint")
    deletion = CognitionDeletionService(workspace.root, authority)
    deletion_plan = deletion.create_plan(retained.node_id, now=NOW)
    deletion_approval = deletion.approve(
        deletion_plan.plan_id,
        actor_id="Owner",
        authorization_ref="attended:m32-e2e-delete",
        confirmation=f"DELETE {retained.node_id}",
        now=NOW,
    )
    before_deletion = _canonical_bytes(workspace)
    deleted = deletion.apply(deletion_plan.plan_id, deletion_approval, now=NOW)
    assert not (workspace.root / retained.relative_path).exists()
    assert sentinel.read_bytes() == b"# Unrelated sentinel\n"
    workspace.rollback(deleted["checkpoint"])
    assert _canonical_bytes(workspace) == before_deletion
    assert (workspace.root / retained.relative_path).is_file()

    services = product_adapter_services(workspace.root)
    owned_root = tmp_path / "adapter-owned"
    owned_root.mkdir()
    owned = owned_root / "owned.txt"
    owned.write_bytes(b"adapter-owned")
    unrelated = owned_root / "sentinel.txt"
    unrelated.write_bytes(b"unrelated")
    ownership = {
        "schema_version": "hive.adapter-ownership-manifest.v1",
        "installation_id": "m32-e2e-install",
        "adapter_id": "nukotech.hive.local-capture",
        "adapter_version": services.manifests["nukotech.hive.local-capture"]["version"],
        "root": str(owned_root.resolve()),
        "created_at": NOW.isoformat().replace("+00:00", "Z"),
        "paths": [
            {
                "path": owned.name,
                "kind": "file",
                "sha256": hashlib.sha256(owned.read_bytes()).hexdigest(),
            }
        ],
    }
    grant = services.authority.resolve(
        public_key_id(services.request_key.public_key()),
        "nukotech.hive.local-capture",
    )
    uninstall_plan = services.lifecycle.plan(
        "nukotech.hive.local-capture", "uninstall", ownership, grant.project_id
    )
    uninstall_approval = services.lifecycle.approve(
        uninstall_plan, grant.identity, services.approver_key
    )
    before_uninstall = _portable_bytes(workspace)
    result = services.lifecycle.uninstall(
        "nukotech.hive.local-capture",
        ownership,
        uninstall_plan,
        uninstall_approval,
    )
    assert result["outcome"] == "APPLIED"
    assert not owned.exists()
    assert unrelated.read_bytes() == b"unrelated"
    assert _portable_bytes(workspace) == before_uninstall
