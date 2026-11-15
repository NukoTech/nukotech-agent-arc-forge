from __future__ import annotations

import json
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from hive_protocol.cognition.authority import CognitionAuthority
from hive_protocol.cognition.extraction import DeterministicCognitionExtractor
from hive_protocol.cognition.models import CognitionEvent, KnowledgeNode
from hive_protocol.cognition.promotion import CognitionPromotionService
from hive_protocol.cognition.retrieval import CognitionRetrieval
from hive_protocol.cognition.store import CognitionStore
from hive_protocol.knowledge.editor import KnowledgeEditor
from hive_protocol.knowledge.graph import KnowledgeGraph
from hive_protocol.product.cli import main
from hive_protocol.product.workspace import HiveWorkspace


def _event(
    *,
    key: str,
    narrative: str,
    action: str = "CREATE",
    supersedes: str | None = None,
    revokes: str | None = None,
) -> CognitionEvent:
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return CognitionEvent.from_dict(
        {
            "schema_version": "hive.cognition-event.v1",
            "event_id": str(uuid4()),
            "tenant_id": "local-user",
            "project_id": "HiveMind",
            "event_type": "PROJECT_EVENT",
            "privacy_class": "PROJECT_PRIVATE",
            "experience_scope": {"kind": "DOMAIN", "owner_id": "HiveMind"},
            "title": "Portable cognition event",
            "text": "",
            "structured_claims": [
                {
                    "candidate_type": "CORRECTION" if action != "CREATE" else "DECISION",
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
                    "source_id": "source:portable",
                    "anchor_id": "anchor:" + uuid4().hex,
                    "source_sha256": "a" * 64,
                    "normalized_sha256": "b" * 64,
                }
            ],
            "source_ref": "project-event:" + uuid4().hex,
            "source_sha256": "a" * 64,
            "occurred_at": timestamp,
            "recorded_at": timestamp,
        }
    )


def _promote(
    root: Path,
    authority: CognitionAuthority,
    event: CognitionEvent,
) -> KnowledgeNode:
    now = datetime.now(timezone.utc)
    store = CognitionStore(root, authority)
    candidate = DeterministicCognitionExtractor().extract(event, now=now).candidates[0]
    store.stage(event, candidate)
    decision = authority.create_review(
        candidate,
        outcome="APPROVED",
        actor_id="Owner",
        authorization_ref="attended:m32-portable-test",
        corrections=[],
        now=now,
    )
    store.record_review(decision, now=now)
    result = CognitionPromotionService(root, store, authority).promote(
        candidate.candidate_id,
        now=now,
    )
    return KnowledgeNode.from_dict(result["node"])


def _create_note(editor: KnowledgeEditor, relative_path: str, content: str, token: str) -> None:
    now = datetime.now(timezone.utc)
    preview = editor.preview(
        project_id="HiveMind",
        relative_path=relative_path,
        content=content,
        expected_sha256=None,
        now=now,
    )
    editor.apply(
        preview["preview_id"],
        content=content,
        idempotency_key=token * 64,
        approval=None,
        now=now,
    )


def test_whole_hive_export_reopens_cognition_and_rebuilds_all_knowledge_views(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source-hive"
    workspace = HiveWorkspace.create(source_root)
    authority = CognitionAuthority(
        source_root, trusted_reviewer_actors={"Owner"}
    )
    editor = KnowledgeEditor(source_root, authority)
    _create_note(
        editor,
        "mocs/MOC HiveMind.md",
        "---\ntype: moc\n---\n# MOC HiveMind\n\n- contains [[Architecture]]\n",
        "1",
    )
    _create_note(
        editor,
        "Architecture.md",
        "# Architecture\n\n#portable\n\n- supports [[MOC HiveMind]]\n",
        "2",
    )
    original = _promote(
        source_root,
        authority,
        _event(key="storage.canonical", narrative="Markdown is canonical."),
    )
    corrected = _promote(
        source_root,
        authority,
        _event(
            key="storage.canonical",
            narrative="Markdown plus signed sidecars are canonical.",
            action="CORRECT",
            supersedes=original.node_id,
        ),
    )
    _promote(
        source_root,
        authority,
        _event(
            key="storage.canonical",
            narrative="The corrected claim is revoked.",
            action="REVOKE",
            revokes=corrected.node_id,
        ),
    )
    current = _promote(
        source_root,
        authority,
        _event(key="operation.attended", narrative="Mutation remains attended."),
    )
    before_graph = KnowledgeGraph(source_root, authority).rebuild()
    before_history = CognitionRetrieval(source_root, authority).list_nodes(
        project_id="HiveMind", include_historical=True
    )
    old_keys = {
        "proposer": authority.proposer_key_id,
        "reviewer": authority.reviewer_key_id,
        "promoter": authority.promoter_key_id,
    }

    bundle = tmp_path / "hive.tar.gz"
    workspace.export(bundle)
    with tarfile.open(bundle, "r:gz") as archive:
        names = {member.name for member in archive.getmembers()}
    assert any(name.startswith("hive-export/prime/") for name in names)
    assert any("cognition-public-keys" in name for name in names)
    assert not any("/.hive/keys/" in f"/{name}" for name in names)
    assert not any("/.hive/runtime/" in f"/{name}" for name in names)
    assert not any("/.hive/derived/" in f"/{name}" for name in names)
    assert not any(name.endswith((".sqlite3", ".sqlite3-wal", ".sqlite3-shm")) for name in names)

    reopened_root = tmp_path / "reopened-hive"
    reopened = HiveWorkspace.reopen_export(bundle, reopened_root)
    reopened_authority = CognitionAuthority(
        reopened_root, trusted_reviewer_actors={"Owner"}
    )
    assert reopened_authority.proposer_key_id != old_keys["proposer"]
    assert reopened_authority.reviewer_key_id != old_keys["reviewer"]
    assert reopened_authority.promoter_key_id != old_keys["promoter"]
    assert old_keys["proposer"] in reopened_authority.proposer_public_keys
    assert old_keys["reviewer"] in reopened_authority.reviewer_public_keys
    assert old_keys["promoter"] in reopened_authority.promoter_public_keys

    after_graph = KnowledgeGraph(reopened_root, reopened_authority).rebuild()
    after_history = CognitionRetrieval(reopened_root, reopened_authority).list_nodes(
        project_id="HiveMind", include_historical=True
    )
    assert after_graph["nodes"] == before_graph["nodes"]
    assert after_graph["edges"] == before_graph["edges"]
    assert after_graph["backlinks"] == before_graph["backlinks"]
    assert after_history == before_history
    assert CognitionRetrieval(reopened_root, reopened_authority).list_nodes(
        project_id="HiveMind"
    ) == [next(item for item in after_history if item["node_id"] == current.node_id)]
    assert len(CognitionStore(reopened_root, reopened_authority).list_candidates()) == 4
    assert reopened.rebuild_index()["outcome"] == "INDEX_REBUILT"


def _invoke(capsys, *arguments: str) -> tuple[int, dict]:
    status = main(list(arguments))
    payload = json.loads(capsys.readouterr().out)
    return status, payload


def test_attended_cli_exposes_review_promotion_notes_graph_and_deletion(
    tmp_path: Path, capsys
) -> None:
    vault = tmp_path / "hive"
    assert _invoke(capsys, "init", "--vault", str(vault))[0] == 0
    event_path = tmp_path / "event.json"
    event_path.write_text(
        json.dumps(_event(key="cli.attended", narrative="CLI mutation is attended.").as_dict()),
        encoding="utf-8",
    )

    status, proposed = _invoke(
        capsys,
        "memory-propose-event",
        "--vault",
        str(vault),
        "--event",
        str(event_path),
    )
    assert status == 0
    candidate_id = proposed["candidates"][0]["candidate_id"]
    assert proposed["outcome"] == "PROPOSED"
    assert _invoke(capsys, "memory-candidates", "--vault", str(vault))[1][
        "candidates"
    ][0]["candidate"]["candidate_id"] == candidate_id

    status, reviewed = _invoke(
        capsys,
        "memory-review",
        "--vault",
        str(vault),
        "--candidate-id",
        candidate_id,
        "--outcome",
        "APPROVED",
        "--actor-id",
        "Owner",
        "--authorization-ref",
        "attended:cli-test",
    )
    assert status == 0 and reviewed["outcome"] == "RECORDED"
    status, promoted = _invoke(
        capsys,
        "memory-promote",
        "--vault",
        str(vault),
        "--candidate-id",
        candidate_id,
    )
    assert status == 0 and promoted["outcome"] == "PROMOTED"
    node_id = promoted["node"]["node_id"]

    secret = "api_" + "key=examplevalue12345"
    secret_note = tmp_path / "secret-note.md"
    secret_note.write_text(f"# Secret\n\n{secret}\n", encoding="utf-8")
    refusal_status, refusal = _invoke(
        capsys,
        "knowledge-note-preview",
        "--vault",
        str(vault),
        "--project-id",
        "HiveMind",
        "--relative-path",
        "Secret.md",
        "--content",
        str(secret_note),
    )
    assert refusal_status != 0
    assert refusal["reason_code"] == "ADAPTER_CREDENTIAL_VALUE_DENIED"
    assert secret not in json.dumps(refusal)
    assert secret.encode("utf-8") not in b"".join(
        path.read_bytes()
        for path in vault.rglob("*")
        if path.is_file() and not path.is_symlink()
    )

    content_path = tmp_path / "note.md"
    content_path.write_text(
        "# CLI Note\n\n#attended\n\n- supports [[CLI Note]]\n", encoding="utf-8"
    )
    status, preview = _invoke(
        capsys,
        "knowledge-note-preview",
        "--vault",
        str(vault),
        "--project-id",
        "HiveMind",
        "--relative-path",
        "CLI Note.md",
        "--content",
        str(content_path),
    )
    assert status == 0 and preview["operation"] == "CREATE"
    status, applied = _invoke(
        capsys,
        "knowledge-note-apply",
        "--vault",
        str(vault),
        "--preview-id",
        preview["preview_id"],
        "--content",
        str(content_path),
        "--idempotency-key",
        "c" * 64,
    )
    assert status == 0 and applied["outcome"] == "APPLIED"
    status_payload = _invoke(capsys, "status", "--vault", str(vault))[1]
    assert status_payload["memory_candidates"] == 1
    assert status_payload["reviewed_memory"] == 1
    assert status_payload["knowledge_notes"] == 1
    status, graph = _invoke(
        capsys,
        "knowledge-graph",
        "--vault",
        str(vault),
        "--tag",
        "attended",
    )
    assert status == 0
    assert [node["title"] for node in graph["nodes"]] == ["CLI Note"]
    assert _invoke(
        capsys,
        "memory-retention-scan",
        "--vault",
        str(vault),
        "--project-id",
        "HiveMind",
    )[1] == {"outcome": "SCANNED", "requests": []}

    status, plan = _invoke(
        capsys,
        "memory-deletion-plan",
        "--vault",
        str(vault),
        "--node-id",
        node_id,
    )
    assert status == 0 and plan["risk_class"] == "HIGH"
    refusal_status, refusal = _invoke(
        capsys,
        "memory-deletion-approve",
        "--vault",
        str(vault),
        "--plan-id",
        plan["plan_id"],
        "--actor-id",
        "Owner",
        "--authorization-ref",
        "attended:cli-delete",
        "--confirmation",
        "DELETE wrong-node",
        "--output",
        str(tmp_path / "wrong-approval.json"),
    )
    assert refusal_status != 0 and refusal["outcome"] == "REFUSED"
    approval_path = tmp_path / "approval.json"
    status, approval = _invoke(
        capsys,
        "memory-deletion-approve",
        "--vault",
        str(vault),
        "--plan-id",
        plan["plan_id"],
        "--actor-id",
        "Owner",
        "--authorization-ref",
        "attended:cli-delete",
        "--confirmation",
        f"DELETE {node_id}",
        "--output",
        str(approval_path),
    )
    assert status == 0 and approval_path.is_file()
    assert approval["confirmation"] == f"DELETE {node_id}"
    status, deleted = _invoke(
        capsys,
        "memory-deletion-apply",
        "--vault",
        str(vault),
        "--plan-id",
        plan["plan_id"],
        "--approval",
        str(approval_path),
    )
    assert status == 0 and deleted["outcome"] == "DELETED"
