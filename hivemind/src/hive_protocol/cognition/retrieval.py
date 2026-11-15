"""Verified current and historical retrieval over reviewed PRIME nodes."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hive_protocol.core import ProtocolError

from .authority import CognitionAuthority
from .promotion import load_verified_nodes


class CognitionRetrieval:
    def __init__(self, root: Path, authority: CognitionAuthority) -> None:
        self.root = root.expanduser().resolve(strict=True)
        if self.root != authority.root:
            raise ProtocolError(
                "COGNITION_RETRIEVAL_BOUNDARY", "authority belongs to another Hive"
            )
        self.authority = authority

    def list_nodes(
        self,
        *,
        project_id: str,
        scope_kind: str | None = None,
        scope_owner: str | None = None,
        include_historical: bool = False,
    ) -> list[dict[str, Any]]:
        nodes = load_verified_nodes(self.root, self.authority)
        superseded = {
            node.supersedes for node in nodes.values() if node.supersedes is not None
        }
        revoked = {node.revokes for node in nodes.values() if node.revokes is not None}
        results: list[dict[str, Any]] = []
        for node in nodes.values():
            if node.project_id != project_id:
                continue
            scope = node.experience_scope
            if scope_kind is not None and scope["kind"] != scope_kind:
                continue
            if scope_owner is not None and scope["owner_id"] != scope_owner:
                continue
            if node.node_type == "REVOCATION":
                state = "AUDIT"
            elif node.node_id in revoked:
                state = "REVOKED"
            elif node.node_id in superseded:
                state = "SUPERSEDED"
            else:
                state = "CURRENT"
            if not include_historical and state != "CURRENT":
                continue
            document = node.as_dict()
            document["derived_state"] = state
            results.append(document)
        return sorted(results, key=lambda item: (item["relative_path"], item["node_id"]))

    def search(
        self,
        query: str,
        *,
        project_id: str,
        scope_kind: str | None = None,
        scope_owner: str | None = None,
        include_historical: bool = False,
    ) -> list[dict[str, Any]]:
        if not isinstance(query, str) or not query.strip() or len(query) > 4096:
            raise ProtocolError(
                "COGNITION_QUERY_INVALID", "memory query must be bounded non-empty text"
            )
        needle = query.casefold()
        return [
            node
            for node in self.list_nodes(
                project_id=project_id,
                scope_kind=scope_kind,
                scope_owner=scope_owner,
                include_historical=include_historical,
            )
            if needle
            in " ".join(
                (
                    node["title"],
                    node["claim"]["key"],
                    node["claim"]["narrative"],
                    str(node["claim"]["value"]),
                )
            ).casefold()
        ]

    def get_node(self, node_id: str) -> dict[str, Any]:
        nodes = load_verified_nodes(self.root, self.authority)
        if node_id not in nodes:
            raise ProtocolError("COGNITION_NODE_MISSING", "knowledge node is absent")
        return nodes[node_id].as_dict()
