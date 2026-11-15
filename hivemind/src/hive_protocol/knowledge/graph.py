"""Deterministic graph projection over every portable knowledge lane."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, Iterable

from hive_protocol.cognition.authority import CognitionAuthority
from hive_protocol.cognition.models import MemoryCandidate
from hive_protocol.cognition.promotion import load_verified_nodes
from hive_protocol.core import ProtocolError, canonical_bytes, document_digest
from hive_protocol.storage import atomic_write_bytes, read_json

from .models import GraphEdge, GraphNode


_TEXT_SUFFIXES = {".md", ".markdown", ".txt"}
_WIKILINK = re.compile(r"\[\[([^\]|#]+)(?:#[^\]|]+)?(?:\|[^\]]+)?\]\]")
_TYPED = re.compile(r"^\s*(?:[-*]\s+)?([A-Za-z][A-Za-z0-9_-]{0,63})\s+\[\[([^\]|#]+)", re.MULTILINE)
_TAG = re.compile(r"(?<![\w#])#([A-Za-z][A-Za-z0-9_-]*)")
_CITATION = re.compile(r"\b(anchor:[A-Za-z0-9._:-]{1,192})\b")


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _title(path: Path, text: str) -> str:
    for line in text.splitlines():
        if line.startswith("# ") and line[2:].strip():
            return " ".join(line[2:].split())
    return path.stem


def _parsed(path: Path, text: str) -> dict[str, Any]:
    typed = sorted({(relation.upper(), " ".join(target.split())) for relation, target in _TYPED.findall(text)})
    typed_targets = {target for _, target in typed}
    wikilinks = sorted({" ".join(value.split()) for value in _WIKILINK.findall(text)})
    is_moc = path.stem.lower().startswith("moc ") or bool(
        re.search(r"(?mi)^type:\s*moc\s*$", text.split("\n---\n", 1)[0] if text.startswith("---\n") else "")
    )
    return {
        "typed": typed,
        "wikilinks": [value for value in wikilinks if value not in typed_targets],
        "tags": sorted(set(_TAG.findall(text))),
        "citations": sorted(set(_CITATION.findall(text))),
        "is_moc": is_moc,
    }


class KnowledgeGraph:
    def __init__(self, root: Path, authority: CognitionAuthority) -> None:
        self.root = root.expanduser().resolve(strict=True)
        if self.root != authority.root:
            raise ProtocolError("KNOWLEDGE_GRAPH_BOUNDARY", "authority belongs to another Hive")
        self.authority = authority
        self.derived = self.root / ".hive" / "derived" / "knowledge"
        self.projection = self.derived / "graph.json"

    def _portable_markdown(self, root: Path) -> Iterable[Path]:
        if not root.exists():
            return ()
        if root.is_symlink() or not root.is_dir():
            raise ProtocolError("KNOWLEDGE_GRAPH_BOUNDARY", "portable graph root is unsafe")
        paths = []
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                raise ProtocolError("KNOWLEDGE_GRAPH_BOUNDARY", "portable graph path is a symlink")
            if path.is_file() and path.suffix.lower() in _TEXT_SUFFIXES:
                paths.append(path)
        return paths

    def rebuild(self) -> dict[str, Any]:
        nodes: list[GraphNode] = []
        texts: dict[str, str] = {}
        path_keys: dict[str, str] = {}

        def add_node(document: dict[str, Any], text: str) -> None:
            relative = document["path"]
            folded = relative.casefold()
            if folded in path_keys and path_keys[folded] != relative:
                raise ProtocolError("KNOWLEDGE_GRAPH_COLLISION", "portable path collision by case")
            path_keys[folded] = relative
            if any(existing.as_dict()["id"] == document["id"] for existing in nodes):
                raise ProtocolError("KNOWLEDGE_GRAPH_COLLISION", "duplicate graph node ID")
            nodes.append(GraphNode(document))
            texts[document["id"]] = text

        reviewed = load_verified_nodes(self.root, self.authority)
        superseded = {node.supersedes for node in reviewed.values() if node.supersedes}
        revoked = {node.revokes for node in reviewed.values() if node.revokes}
        reviewed_paths = {node.relative_path: node for node in reviewed.values()}

        for relative, node in sorted(reviewed_paths.items()):
            path = self.root / relative
            text = path.read_text(encoding="utf-8")
            parsed = _parsed(path, text)
            if node.node_type == "REVOCATION":
                state = "AUDIT"
            elif node.node_id in revoked:
                state = "REVOKED"
            elif node.node_id in superseded:
                state = "SUPERSEDED"
            else:
                state = "CURRENT"
            add_node(
                {
                    "id": node.node_id,
                    "path": relative,
                    "title": node.title,
                    "kind": "PRIME",
                    "project_id": node.project_id,
                    "experience_scope": node.experience_scope,
                    "trust_state": "REVIEWED",
                    "lifecycle_state": state,
                    "tags": parsed["tags"],
                    "citation_anchor_ids": sorted({item["anchor_id"] for item in node.evidence} | set(parsed["citations"])),
                    "sha256": node.markdown_sha256,
                    "provenance_refs": [node.source_candidate_id, node.review_decision_id],
                },
                text,
            )

        for path in self._portable_markdown(self.root / "prime" / "knowledge"):
            relative = path.relative_to(self.root).as_posix()
            if relative in reviewed_paths:
                continue
            text = path.read_text(encoding="utf-8")
            parsed = _parsed(path, text)
            parts = path.relative_to(self.root / "prime" / "knowledge").parts
            project_id = parts[0] if parts else "HiveMind"
            add_node(
                {
                    "id": "note:" + document_digest({"path": relative, "sha256": _sha(path.read_bytes())}),
                    "path": relative,
                    "title": _title(path, text),
                    "kind": "MOC" if parsed["is_moc"] else "NOTE",
                    "project_id": project_id,
                    "experience_scope": {"kind": "DOMAIN", "owner_id": project_id},
                    "trust_state": "HUMAN_AUTHORED",
                    "lifecycle_state": "CURRENT",
                    "tags": parsed["tags"],
                    "citation_anchor_ids": parsed["citations"],
                    "sha256": _sha(path.read_bytes()),
                    "provenance_refs": [],
                },
                text,
            )

        candidate_root = self.root / "staging" / "memory" / "candidates"
        if candidate_root.exists():
            for sidecar in sorted(candidate_root.glob("*.json")):
                if sidecar.is_symlink():
                    raise ProtocolError("KNOWLEDGE_GRAPH_BOUNDARY", "candidate sidecar is unsafe")
                candidate = MemoryCandidate.from_dict(read_json(sidecar))
                markdown = sidecar.with_suffix(".md")
                text = markdown.read_text(encoding="utf-8")
                parsed = _parsed(markdown, text)
                add_node(
                    {
                        "id": "candidate:" + candidate.candidate_id.split(":", 1)[1],
                        "path": markdown.relative_to(self.root).as_posix(),
                        "title": candidate.claim["key"],
                        "kind": "STAGING",
                        "project_id": candidate.project_id,
                        "experience_scope": candidate.experience_scope,
                        "trust_state": "UNREVIEWED",
                        "lifecycle_state": "PROPOSED",
                        "tags": parsed["tags"],
                        "citation_anchor_ids": sorted(item["anchor_id"] for item in candidate.evidence),
                        "sha256": _sha(markdown.read_bytes()),
                        "provenance_refs": candidate.source_event_ids,
                    },
                    text,
                )

        for lane, kind, trust in (
            (self.root / "sources", "SOURCE", "CANONICAL_SOURCE"),
            (self.root / "research", "RESEARCH", "CITED_RESEARCH"),
        ):
            for path in self._portable_markdown(lane):
                relative = path.relative_to(self.root).as_posix()
                text = path.read_text(encoding="utf-8")
                parsed = _parsed(path, text)
                add_node(
                    {
                        "id": kind.lower() + ":" + document_digest({"path": relative, "sha256": _sha(path.read_bytes())}),
                        "path": relative,
                        "title": _title(path, text),
                        "kind": kind,
                        "project_id": "HiveMind",
                        "experience_scope": {"kind": "DOMAIN", "owner_id": "HiveMind"},
                        "trust_state": trust,
                        "lifecycle_state": "CANONICAL",
                        "tags": parsed["tags"],
                        "citation_anchor_ids": parsed["citations"],
                        "sha256": _sha(path.read_bytes()),
                        "provenance_refs": [],
                    },
                    text,
                )

        node_documents = sorted((node.as_dict() for node in nodes), key=lambda item: (item["path"], item["id"]))
        title_index: dict[str, list[str]] = {}
        for node in node_documents:
            title_index.setdefault(node["title"].casefold(), []).append(node["id"])
        edges: list[GraphEdge] = []
        for node in node_documents:
            parsed = _parsed(self.root / node["path"], texts[node["id"]])
            for relation, target_ref in parsed["typed"]:
                targets = title_index.get(target_ref.casefold(), [])
                target_id = targets[0] if len(targets) == 1 else None
                edges.append(GraphEdge({"source_id": node["id"], "target_id": target_id, "target_ref": target_ref, "relation": relation, "broken": target_id is None}))
            for target_ref in parsed["wikilinks"]:
                targets = title_index.get(target_ref.casefold(), [])
                target_id = targets[0] if len(targets) == 1 else None
                edges.append(GraphEdge({"source_id": node["id"], "target_id": target_id, "target_ref": target_ref, "relation": "LINKS_TO", "broken": target_id is None}))
            for anchor_id in node["citation_anchor_ids"]:
                edges.append(GraphEdge({"source_id": node["id"], "target_id": anchor_id, "target_ref": anchor_id, "relation": "CITES", "broken": False}))
            reviewed_node = reviewed.get(node["id"])
            if reviewed_node is not None and reviewed_node.supersedes:
                edges.append(GraphEdge({"source_id": node["id"], "target_id": reviewed_node.supersedes, "target_ref": reviewed_node.supersedes, "relation": "SUPERSEDES", "broken": reviewed_node.supersedes not in reviewed}))
            if reviewed_node is not None and reviewed_node.revokes:
                edges.append(GraphEdge({"source_id": node["id"], "target_id": reviewed_node.revokes, "target_ref": reviewed_node.revokes, "relation": "REVOKES", "broken": reviewed_node.revokes not in reviewed}))
        edge_documents = sorted((edge.as_dict() for edge in edges), key=lambda item: (item["source_id"], item["relation"], item["target_ref"]))
        backlinks: dict[str, list[dict[str, Any]]] = {}
        for edge in edge_documents:
            if edge["target_id"] is not None:
                backlinks.setdefault(edge["target_id"], []).append({"source_id": edge["source_id"], "relation": edge["relation"]})
        backlinks = {key: sorted(value, key=lambda item: (item["source_id"], item["relation"])) for key, value in sorted(backlinks.items())}
        projection = {"schema_version": "hive.knowledge-graph-projection.v1", "nodes": node_documents, "edges": edge_documents, "backlinks": backlinks}
        payload = canonical_bytes(projection) + b"\n"
        self.derived.mkdir(parents=True, exist_ok=True)
        atomic_write_bytes(self.projection, payload)
        result = dict(projection)
        result["projection_path"] = str(self.projection)
        result["sha256"] = _sha(payload)
        return result

    def _load(self) -> dict[str, Any]:
        return self.rebuild() if not self.projection.is_file() else read_json(self.projection)

    def filter(
        self,
        *,
        project_id: str | None = None,
        relation: str | None = None,
        tag: str | None = None,
        trust_state: str | None = None,
        lifecycle_state: str | None = None,
    ) -> dict[str, Any]:
        graph = self._load()
        nodes = [
            node for node in graph["nodes"]
            if (project_id is None or node["project_id"] == project_id)
            and (tag is None or tag in node["tags"])
            and (trust_state is None or node["trust_state"] == trust_state)
            and (lifecycle_state is None or node["lifecycle_state"] == lifecycle_state)
        ]
        node_ids = {node["id"] for node in nodes}
        edges = [edge for edge in graph["edges"] if edge["source_id"] in node_ids and (relation is None or edge["relation"] == relation)]
        return {"nodes": nodes, "edges": edges}

    def neighbors(self, node_id: str, *, direction: str) -> dict[str, Any]:
        if direction not in {"inbound", "outbound"}:
            raise ProtocolError("KNOWLEDGE_GRAPH_DIRECTION_INVALID", "graph direction is invalid")
        graph = self._load()
        if not any(node["id"] == node_id for node in graph["nodes"]):
            raise ProtocolError("KNOWLEDGE_GRAPH_NODE_MISSING", "graph node is absent")
        edges = [
            edge for edge in graph["edges"]
            if (direction == "outbound" and edge["source_id"] == node_id)
            or (direction == "inbound" and edge["target_id"] == node_id)
        ]
        related_ids = {edge["target_id"] if direction == "outbound" else edge["source_id"] for edge in edges}
        return {"nodes": [node for node in graph["nodes"] if node["id"] in related_ids], "edges": edges}
