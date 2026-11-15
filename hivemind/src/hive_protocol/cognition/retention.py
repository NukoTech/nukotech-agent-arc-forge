"""Retention expiry creates review work; it never deletes automatically."""

from __future__ import annotations

import copy
from datetime import datetime
from pathlib import Path
from typing import Any

from hive_protocol.core import ProtocolError, canonical_bytes, document_digest, sign_document, verify_document
from hive_protocol.storage import read_json

from .authority import CognitionAuthority
from .promotion import load_verified_nodes
from .store import _ensure_directory, _token, _write_exact


class CognitionRetentionService:
    def __init__(self, root: Path, authority: CognitionAuthority) -> None:
        self.root = root.expanduser().resolve(strict=True)
        if self.root != authority.root:
            raise ProtocolError(
                "COGNITION_RETENTION_BOUNDARY", "authority belongs to another Hive"
            )
        self.authority = authority
        self.requests = (
            self.root / "staging" / "memory" / "reviews" / "retention"
        )

    def scan(self, *, now, project_id: str | None = None) -> list[dict[str, Any]]:
        if now.tzinfo is None:
            raise ProtocolError(
                "COGNITION_RETENTION_TIME_INVALID", "retention time lacks timezone"
            )
        _ensure_directory(self.requests, self.root)
        results: list[dict[str, Any]] = []
        for node in load_verified_nodes(self.root, self.authority).values():
            if project_id is not None and node.project_id != project_id:
                continue
            if node.retention_until is None:
                continue
            expires = datetime.fromisoformat(node.retention_until.replace("Z", "+00:00"))
            if now < expires:
                continue
            path = self.requests / f"{_token(node.node_id, 'node')}.json"
            if path.exists():
                request = read_json(path)
                verify_document(
                    request,
                    self.authority.proposer_public_keys,
                )
                if request.get("node_id") != node.node_id or request.get("node_sha256") != node.digest:
                    raise ProtocolError(
                        "COGNITION_RETENTION_REQUEST_DRIFT",
                        "retention request no longer binds its node",
                    )
            else:
                unsigned = {
                    "schema_version": "hive.memory-retention-review.v1",
                    "request_id": "retention:placeholder",
                    "node_id": node.node_id,
                    "node_sha256": node.digest,
                    "tenant_id": node.tenant_id,
                    "project_id": node.project_id,
                    "experience_scope": node.experience_scope,
                    "retention_until": node.retention_until,
                    "detected_at": now.isoformat().replace("+00:00", "Z"),
                    "action": "REVIEW_REQUIRED",
                    "automatic_delete": False,
                }
                unsigned["request_id"] = "retention:" + document_digest(
                    {key: value for key, value in unsigned.items() if key != "request_id"}
                )
                request = sign_document(unsigned, self.authority.proposer_private_key)
                _write_exact(path, canonical_bytes(request) + b"\n")
            result = copy.deepcopy(request)
            result["request_path"] = path.relative_to(self.root).as_posix()
            results.append(result)
        return sorted(results, key=lambda item: item["node_id"])
