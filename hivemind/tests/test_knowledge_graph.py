from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from hive_protocol.cognition.authority import CognitionAuthority
from hive_protocol.cognition.models import KnowledgeNode
from hive_protocol.cognition.promotion import CognitionPromotionService
from hive_protocol.cognition.store import CognitionStore
from hive_protocol.core import ProtocolError
from hive_protocol.knowledge.editor import KnowledgeEditor
from hive_protocol.knowledge.graph import KnowledgeGraph
from hive_protocol.product.workspace import HiveWorkspace

from test_cognition_promotion import NOW, _event, _stage_review


def _apply_note(editor: KnowledgeEditor, path: str, content: str, key: str) -> dict:
    preview = editor.preview(
        project_id="HiveMind",
        relative_path=path,
        content=content,
        expected_sha256=None,
        now=NOW,
    )
    return editor.apply(
        preview["preview_id"], content=content, idempotency_key=key * 64, approval=None, now=NOW
    )


def _graph_fixture(root: Path):
    workspace = HiveWorkspace.create(root)
    source = root / "sources" / "source-note.md"
    source.write_text("# Source Note\n\n#evidence\n", encoding="utf-8")
    workspace.rebuild_index()
    authority = CognitionAuthority(root, trusted_reviewer_actors={"Owner"})
    editor = KnowledgeEditor(root, authority)
    _apply_note(
        editor,
        "mocs/MOC HiveMind.md",
        "---\ntype: moc\n---\n# MOC HiveMind\n\n- contains [[Architecture]]\n",
        "1",
    )
    _apply_note(
        editor,
        "Architecture.md",
        "# Architecture\n\n#systems #local\n\n- supports [[MOC HiveMind]]\n- depends_on [[Missing Note]]\n\n[anchor:alpha]\n",
        "2",
    )
    research = root / "research" / "manual"
    research.mkdir(parents=True)
    (research / "brief.md").write_text("# Research Brief\n\n- cites [[Source Note]]\n", encoding="utf-8")
    event = _event()
    store, candidate, _ = _stage_review(root, authority, event)
    promoted = KnowledgeNode.from_dict(
        CognitionPromotionService(root, store, authority).promote(candidate.candidate_id, now=NOW)["node"]
    )
    return authority, source, promoted


def test_rebuild_projects_all_portable_lanes_with_links_tags_trust_and_breakage(tmp_path: Path) -> None:
    authority, source, promoted = _graph_fixture(tmp_path)
    before = source.read_bytes()
    service = KnowledgeGraph(tmp_path, authority)
    graph = service.rebuild()
    kinds = {node["kind"] for node in graph["nodes"]}
    assert {"SOURCE", "RESEARCH", "STAGING", "PRIME", "NOTE", "MOC"}.issubset(kinds)
    architecture = next(node for node in graph["nodes"] if node["title"] == "Architecture")
    assert architecture["tags"] == ["local", "systems"]
    assert architecture["citation_anchor_ids"] == ["anchor:alpha"]
    assert architecture["trust_state"] == "HUMAN_AUTHORED"
    assert next(node for node in graph["nodes"] if node["id"] == promoted.node_id)["trust_state"] == "REVIEWED"
    broken = [edge for edge in graph["edges"] if edge["broken"]]
    assert any(edge["target_ref"] == "Missing Note" for edge in broken)
    assert source.read_bytes() == before
    assert Path(graph["projection_path"]).is_relative_to(tmp_path / ".hive" / "derived" / "knowledge")


def test_backlinks_neighbors_and_filters_are_exact(tmp_path: Path) -> None:
    authority, _, _ = _graph_fixture(tmp_path)
    service = KnowledgeGraph(tmp_path, authority)
    graph = service.rebuild()
    architecture = next(node for node in graph["nodes"] if node["title"] == "Architecture")
    moc = next(node for node in graph["nodes"] if node["title"] == "MOC HiveMind")
    outgoing = service.neighbors(architecture["id"], direction="outbound")
    incoming = service.neighbors(moc["id"], direction="inbound")
    assert {edge["relation"] for edge in outgoing["edges"]} == {"DEPENDS_ON", "SUPPORTS", "CITES"}
    assert any(edge["source_id"] == architecture["id"] for edge in incoming["edges"])
    assert [node["title"] for node in service.filter(tag="systems")["nodes"]] == ["Architecture"]
    assert all(node["project_id"] == "HiveMind" for node in service.filter(project_id="HiveMind")["nodes"])
    assert all(node["trust_state"] == "REVIEWED" for node in service.filter(trust_state="REVIEWED")["nodes"])


def test_correction_and_revocation_states_are_visible_in_graph(tmp_path: Path) -> None:
    authority, _, original = _graph_fixture(tmp_path)
    store = CognitionStore(tmp_path, authority)
    promotion = CognitionPromotionService(tmp_path, store, authority)
    _, correction_candidate, _ = _stage_review(
        tmp_path,
        authority,
        _event(action="CORRECT", supersedes=original.node_id, value="corrected", narrative="Corrected claim."),
    )
    corrected = KnowledgeNode.from_dict(promotion.promote(correction_candidate.candidate_id, now=NOW)["node"])
    _, revoke_candidate, _ = _stage_review(
        tmp_path,
        authority,
        _event(action="REVOKE", revokes=corrected.node_id, value=False, narrative="Revoked claim."),
    )
    promotion.promote(revoke_candidate.candidate_id, now=NOW)
    graph = KnowledgeGraph(tmp_path, authority).rebuild()
    states = {node["id"]: node["lifecycle_state"] for node in graph["nodes"]}
    assert states[original.node_id] == "SUPERSEDED"
    assert states[corrected.node_id] == "REVOKED"
    assert any(edge["relation"] == "SUPERSEDES" for edge in graph["edges"])
    assert any(edge["relation"] == "REVOKES" for edge in graph["edges"])


def test_rebuild_is_byte_deterministic_without_prior_projection(tmp_path: Path) -> None:
    authority, _, _ = _graph_fixture(tmp_path)
    service = KnowledgeGraph(tmp_path, authority)
    first = service.rebuild()
    path = Path(first["projection_path"])
    first_bytes = path.read_bytes()
    path.unlink()
    second = service.rebuild()
    assert Path(second["projection_path"]).read_bytes() == first_bytes
    assert first["sha256"] == second["sha256"] == hashlib.sha256(first_bytes).hexdigest()


def test_case_colliding_titles_or_paths_refuse(tmp_path: Path) -> None:
    authority = CognitionAuthority(tmp_path)
    first = tmp_path / "sources" / "Alpha.md"
    second = tmp_path / "sources" / "alpha.md"
    first.parent.mkdir(parents=True)
    first.write_text("# Alpha\n", encoding="utf-8")
    second.write_text("# alpha\n", encoding="utf-8")
    with pytest.raises(ProtocolError, match="collision"):
        KnowledgeGraph(tmp_path, authority).rebuild()


def test_projection_tamper_is_replaced_from_canonical_sources(tmp_path: Path) -> None:
    authority, _, _ = _graph_fixture(tmp_path)
    service = KnowledgeGraph(tmp_path, authority)
    graph = service.rebuild()
    path = Path(graph["projection_path"])
    path.write_text('{"tampered":true}', encoding="utf-8")
    rebuilt = service.rebuild()
    assert "tampered" not in Path(rebuilt["projection_path"]).read_text(encoding="utf-8")
