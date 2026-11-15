"""Approval-bound, replay-safe promotion into scoped portable PRIME nodes."""

from __future__ import annotations

import copy
import hashlib
import os
import re
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

import yaml

from hive_protocol.core import (
    ProtocolError,
    canonical_bytes,
    document_digest,
    sign_document,
    verify_document,
)
from hive_protocol.storage import atomic_write_json, exclusive_lock, read_json

from .authority import CognitionAuthority
from .models import KnowledgeEdge, KnowledgeNode, MemoryCandidate
from .store import CognitionStore, _ensure_directory, _token, _write_exact


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")


def _markdown(candidate: MemoryCandidate, review_id: str) -> bytes:
    metadata = {
        "type": "hive-reviewed-knowledge",
        "project_id": candidate.project_id,
        "scope": candidate.experience_scope,
        "candidate_id": candidate.candidate_id,
        "review_decision_id": review_id,
        "candidate_type": candidate.candidate_type,
        "action": candidate.proposed_action,
        "trust_state": "REVIEWED",
        "evidence": [item["anchor_id"] for item in candidate.evidence],
        "supersedes": candidate.supersedes,
        "revokes": candidate.revokes,
    }
    frontmatter = yaml.safe_dump(metadata, allow_unicode=False, sort_keys=True)
    evidence = "\n".join(
        f"- cites [{item['anchor_id']}]" for item in candidate.evidence
    )
    relation = ""
    if candidate.supersedes is not None:
        relation = f"\n\n## Lifecycle\n\n- supersedes {candidate.supersedes}"
    if candidate.revokes is not None:
        relation = f"\n\n## Lifecycle\n\n- revokes {candidate.revokes}"
    return (
        f"---\n{frontmatter}---\n\n# {candidate.claim['key']}\n\n"
        f"{candidate.claim['narrative']}\n\n## Evidence\n\n{evidence}{relation}\n"
    ).encode("utf-8")


def verify_promotion_receipt(
    document: Mapping[str, Any], authority: CognitionAuthority
) -> dict[str, Any]:
    candidate = copy.deepcopy(dict(document))
    expected = {
        "schema_version",
        "operation_id",
        "candidate_id",
        "candidate_sha256",
        "review_decision_id",
        "review_decision_sha256",
        "node_id",
        "node_sha256",
        "owned_paths",
        "outcome",
        "promoted_at",
        "signature",
    }
    if (
        set(candidate) != expected
        or candidate.get("schema_version")
        != "hive.memory-promotion-receipt.v1"
        or _SHA256.fullmatch(str(candidate.get("operation_id", ""))) is None
        or candidate.get("outcome") != "PROMOTED"
        or not isinstance(candidate.get("owned_paths"), list)
    ):
        raise ProtocolError(
            "COGNITION_PROMOTION_RECEIPT_INVALID",
            "promotion receipt structure is invalid",
        )
    for value in candidate["owned_paths"]:
        path = PurePosixPath(value)
        if (
            not isinstance(value, str)
            or path.is_absolute()
            or not path.parts
            or any(part in {"", ".", ".."} for part in path.parts)
            or path.parts[0] not in {"prime", ".hive"}
        ):
            raise ProtocolError(
                "COGNITION_PROMOTION_RECEIPT_INVALID",
                "promotion receipt contains an unsafe owned path",
            )
    verify_document(candidate, authority.promoter_public_keys)
    if candidate["signature"]["key_id"] not in authority.promoter_public_keys:
        raise ProtocolError(
            "COGNITION_PROMOTION_RECEIPT_INVALID", "promotion signer changed"
        )
    return candidate


def verify_deletion_receipt(
    document: Mapping[str, Any], authority: CognitionAuthority
) -> dict[str, Any]:
    candidate = copy.deepcopy(dict(document))
    expected = {
        "schema_version",
        "operation_id",
        "plan_id",
        "plan_sha256",
        "approval_id",
        "approval_sha256",
        "node_id",
        "node_sha256",
        "deleted_paths",
        "checkpoint",
        "outcome",
        "deleted_at",
        "signature",
    }
    if (
        set(candidate) != expected
        or candidate.get("schema_version") != "hive.memory-deletion-receipt.v1"
        or candidate.get("outcome") != "DELETED"
        or _SHA256.fullmatch(str(candidate.get("operation_id", ""))) is None
        or _GIT_COMMIT.fullmatch(str(candidate.get("checkpoint", ""))) is None
        or not isinstance(candidate.get("deleted_paths"), list)
    ):
        raise ProtocolError(
            "COGNITION_DELETION_RECEIPT_INVALID", "deletion receipt structure is invalid"
        )
    for entry in candidate["deleted_paths"]:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"path", "sha256"}
            or _SHA256.fullmatch(str(entry.get("sha256", ""))) is None
        ):
            raise ProtocolError(
                "COGNITION_DELETION_RECEIPT_INVALID",
                "deleted path evidence is invalid",
            )
        path = PurePosixPath(str(entry.get("path", "")))
        if (
            path.is_absolute()
            or not path.parts
            or any(part in {"", ".", ".."} for part in path.parts)
            or path.parts[0] != "prime"
        ):
            raise ProtocolError(
                "COGNITION_DELETION_RECEIPT_INVALID",
                "deleted path evidence escapes PRIME",
            )
    verify_document(candidate, authority.promoter_public_keys)
    return candidate


def load_verified_nodes(
    root: Path,
    authority: CognitionAuthority,
    *,
    allowed_pending_node_ids: frozenset[str] = frozenset(),
) -> dict[str, KnowledgeNode]:
    prime = root / "prime"
    receipts_root = root / ".hive" / "receipts"
    if not prime.exists():
        return {}
    if prime.is_symlink() or not prime.is_dir():
        raise ProtocolError("COGNITION_PRIME_BOUNDARY", "PRIME root is unsafe")
    nodes: dict[str, KnowledgeNode] = {}
    for path in sorted(prime.rglob("*.json")):
        if path.is_symlink() or not path.is_file():
            raise ProtocolError("COGNITION_PRIME_BOUNDARY", "PRIME sidecar is unsafe")
        node = KnowledgeNode.from_dict(read_json(path))
        markdown = root / node.relative_path
        if (
            markdown.is_symlink()
            or not markdown.is_file()
            or hashlib.sha256(markdown.read_bytes()).hexdigest()
            != node.markdown_sha256
        ):
            raise ProtocolError(
                "COGNITION_NODE_DRIFT", "knowledge Markdown does not match its sidecar"
            )
        if node.node_id in nodes:
            raise ProtocolError("COGNITION_NODE_COLLISION", "duplicate knowledge node ID")
        nodes[node.node_id] = node
    deleted: set[str] = set()
    if receipts_root.exists():
        for path in sorted(receipts_root.glob("cognition-deletion-*.json")):
            deleted.add(verify_deletion_receipt(read_json(path), authority)["node_id"])
    authenticated: set[str] = set()
    if receipts_root.exists():
        for path in sorted(receipts_root.glob("cognition-promotion-*.json")):
            receipt = verify_promotion_receipt(read_json(path), authority)
            node = nodes.get(receipt["node_id"])
            if node is None and receipt["node_id"] in deleted:
                continue
            if node is None or receipt["node_sha256"] != node.digest:
                raise ProtocolError(
                    "COGNITION_PROMOTION_RECEIPT_INVALID",
                    "promotion receipt does not bind a current sidecar",
                )
            authenticated.add(node.node_id)
    unauthenticated = set(nodes) - authenticated
    if not unauthenticated.issubset(allowed_pending_node_ids):
        raise ProtocolError(
            "COGNITION_PROMOTION_RECEIPT_MISSING",
            "one or more PRIME nodes lack authenticated promotion receipts",
        )
    return nodes


class CognitionPromotionService:
    def __init__(
        self,
        root: Path,
        store: CognitionStore,
        authority: CognitionAuthority,
        *,
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        self.root = root.expanduser().resolve(strict=True)
        if self.root != store.root or self.root != authority.root:
            raise ProtocolError(
                "COGNITION_PROMOTION_BOUNDARY", "promotion services belong to different Hives"
            )
        self.store = store
        self.authority = authority
        self.fault_hook = fault_hook
        self.prime = self.root / "prime"
        self.edges = self.root / ".hive" / "provenance" / "memory" / "edges"
        self.receipts = self.root / ".hive" / "receipts"
        self.journals = self.root / ".hive" / "runtime" / "cognition-journals"
        self.locks = self.root / ".hive" / "runtime" / "locks"

    def _fault(self, point: str) -> None:
        if self.fault_hook is not None:
            self.fault_hook(point)

    def _prepare(self) -> None:
        for path in (self.prime, self.edges, self.receipts, self.journals, self.locks):
            _ensure_directory(path, self.root)

    def _write_journal(self, path: Path, document: dict[str, Any]) -> None:
        if path.is_symlink():
            raise ProtocolError(
                "COGNITION_PROMOTION_BOUNDARY", "promotion journal is unsafe"
            )
        atomic_write_json(
            path,
            sign_document(document, self.authority.promoter_private_key),
            mode=0o600,
        )

    def _read_journal(self, path: Path) -> dict[str, Any]:
        document = read_json(path)
        verify_document(
            document,
            {self.authority.promoter_key_id: self.authority.promoter_public_key},
        )
        if document.get("schema_version") != "hive.cognition-promotion-journal.v1":
            raise ProtocolError(
                "COGNITION_PROMOTION_JOURNAL_INVALID", "promotion journal version changed"
            )
        return document

    def promote(self, candidate_id: str, *, now) -> dict[str, Any]:
        candidate = self.store.load_candidate(candidate_id)
        review = self.store.load_review(candidate_id)
        proposal_receipts = self.store.proposal_receipts(candidate_id)
        if not proposal_receipts:
            raise ProtocolError(
                "COGNITION_PROPOSAL_RECEIPT_MISSING", "candidate has no proposal receipt"
            )
        self.authority.verify_review(
            candidate, review, proposal_receipts[0], now=now
        )
        if review.outcome != "APPROVED":
            raise ProtocolError(
                "COGNITION_PROMOTION_NOT_APPROVED", "candidate review is not approved"
            )
        target_id = candidate.supersedes or candidate.revokes
        self._prepare()
        operation_id = document_digest(
            {
                "candidate_id": candidate.candidate_id,
                "candidate_sha256": candidate.digest,
                "review_decision_id": review.decision_id,
                "review_decision_sha256": review.digest,
            }
        )
        journal_path = self.journals / f"promote-{operation_id}.json"
        with exclusive_lock(self.locks / "cognition-promotion.lock"):
            if journal_path.exists():
                journal = self._read_journal(journal_path)
                if (
                    journal.get("operation_id") != operation_id
                    or journal.get("candidate_id") != candidate.candidate_id
                    or journal.get("review_decision_id") != review.decision_id
                    or journal.get("state") not in {"PREPARED", "TERMINAL"}
                ):
                    raise ProtocolError(
                        "COGNITION_PROMOTION_JOURNAL_INVALID",
                        "promotion journal input binding changed",
                    )
                if journal["state"] == "TERMINAL":
                    return copy.deepcopy(journal["result"])
                pending_node = KnowledgeNode.from_dict(journal["node"])
                if target_id is not None:
                    target = load_verified_nodes(
                        self.root,
                        self.authority,
                        allowed_pending_node_ids=frozenset({pending_node.node_id}),
                    ).get(target_id)
                    if target is None or (
                        target.tenant_id != candidate.tenant_id
                        or target.project_id != candidate.project_id
                        or target.experience_scope != candidate.experience_scope
                    ):
                        raise ProtocolError(
                            "COGNITION_TARGET_SCOPE_MISMATCH",
                            "correction or revocation target is absent or changed scope",
                        )
            else:
                target: KnowledgeNode | None = None
                if target_id is not None:
                    target = load_verified_nodes(self.root, self.authority).get(target_id)
                    if target is None:
                        raise ProtocolError(
                            "COGNITION_TARGET_MISSING",
                            "correction or revocation target is absent",
                        )
                    if (
                        target.tenant_id != candidate.tenant_id
                        or target.project_id != candidate.project_id
                        or target.experience_scope != candidate.experience_scope
                    ):
                        raise ProtocolError(
                            "COGNITION_TARGET_SCOPE_MISMATCH",
                            "correction or revocation cannot cross project or scope",
                        )
                scope = candidate.experience_scope
                scope_root = self.prime / scope["kind"].lower() / scope["owner_id"]
                _ensure_directory(scope_root, self.root)
                token = _token(candidate.candidate_id, "memory")
                relative_markdown = (
                    scope_root / f"{token}.md"
                ).relative_to(self.root).as_posix()
                markdown = _markdown(candidate, review.decision_id)
                node_document: dict[str, Any] = {
                    "schema_version": "hive.knowledge-node.v1",
                    "node_id": "node:placeholder",
                    "tenant_id": candidate.tenant_id,
                    "project_id": candidate.project_id,
                    "experience_scope": candidate.experience_scope,
                    "node_type": (
                        "REVOCATION"
                        if candidate.proposed_action == "REVOKE"
                        else candidate.candidate_type
                    ),
                    "title": candidate.claim["key"],
                    "relative_path": relative_markdown,
                    "markdown_sha256": hashlib.sha256(markdown).hexdigest(),
                    "claim": candidate.claim,
                    "evidence": candidate.evidence,
                    "trust_state": "REVIEWED",
                    "source_candidate_id": candidate.candidate_id,
                    "review_decision_id": review.decision_id,
                    "supersedes": candidate.supersedes,
                    "revokes": candidate.revokes,
                    "retention_until": candidate.retention_until,
                    "created_at": now.isoformat().replace("+00:00", "Z"),
                }
                node_document["node_id"] = KnowledgeNode.identity_for(node_document)
                node = KnowledgeNode.from_dict(node_document)
                edge: KnowledgeEdge | None = None
                if target is not None:
                    edge_document: dict[str, Any] = {
                        "schema_version": "hive.knowledge-edge.v1",
                        "edge_id": "edge:placeholder",
                        "tenant_id": candidate.tenant_id,
                        "project_id": candidate.project_id,
                        "source_node_id": node.node_id,
                        "target_node_id": target.node_id,
                        "relation": (
                            "SUPERSEDES"
                            if candidate.supersedes is not None
                            else "REVOKES"
                        ),
                        "evidence_anchor_ids": sorted(
                            item["anchor_id"] for item in candidate.evidence
                        ),
                        "created_at": node.created_at,
                    }
                    edge_document["edge_id"] = KnowledgeEdge.identity_for(edge_document)
                    edge = KnowledgeEdge.from_dict(edge_document)
                journal = {
                    "schema_version": "hive.cognition-promotion-journal.v1",
                    "operation_id": operation_id,
                    "candidate_id": candidate.candidate_id,
                    "review_decision_id": review.decision_id,
                    "state": "PREPARED",
                    "node": node.as_dict(),
                    "markdown": markdown.decode("utf-8"),
                    "edge": edge.as_dict() if edge is not None else None,
                    "result": None,
                }
                self._write_journal(journal_path, journal)
            self._fault("journal-written")

            node = KnowledgeNode.from_dict(journal["node"])
            markdown_path = self.root / node.relative_path
            sidecar_path = markdown_path.with_suffix(".json")
            _ensure_directory(markdown_path.parent, self.root)
            _write_exact(markdown_path, journal["markdown"].encode("utf-8"))
            self._fault("markdown-written")
            _write_exact(sidecar_path, canonical_bytes(node.as_dict()) + b"\n")
            self._fault("sidecar-written")

            edge_document = journal["edge"]
            edge_path: Path | None = None
            if edge_document is not None:
                edge = KnowledgeEdge.from_dict(edge_document)
                edge_path = self.edges / f"{_token(edge.edge_id, 'edge')}.json"
                _write_exact(edge_path, canonical_bytes(edge.as_dict()) + b"\n")
            self._fault("edge-written")

            owned_paths = [
                markdown_path.relative_to(self.root).as_posix(),
                sidecar_path.relative_to(self.root).as_posix(),
            ]
            if edge_path is not None:
                owned_paths.append(edge_path.relative_to(self.root).as_posix())
            receipt_path = self.receipts / f"cognition-promotion-{operation_id}.json"
            receipt = sign_document(
                {
                    "schema_version": "hive.memory-promotion-receipt.v1",
                    "operation_id": operation_id,
                    "candidate_id": candidate.candidate_id,
                    "candidate_sha256": candidate.digest,
                    "review_decision_id": review.decision_id,
                    "review_decision_sha256": review.digest,
                    "node_id": node.node_id,
                    "node_sha256": node.digest,
                    "owned_paths": sorted(owned_paths),
                    "outcome": "PROMOTED",
                    "promoted_at": node.created_at,
                },
                self.authority.promoter_private_key,
            )
            verify_promotion_receipt(receipt, self.authority)
            _write_exact(receipt_path, canonical_bytes(receipt) + b"\n")
            self._fault("receipt-written")
            result = {
                "outcome": "PROMOTED",
                "node": node.as_dict(),
                "sidecar_path": sidecar_path.relative_to(self.root).as_posix(),
                "edge": copy.deepcopy(edge_document),
                "edge_path": (
                    edge_path.relative_to(self.root).as_posix()
                    if edge_path is not None
                    else None
                ),
                "receipt_path": receipt_path.relative_to(self.root).as_posix(),
            }
            terminal = {
                "schema_version": "hive.cognition-promotion-journal.v1",
                "operation_id": operation_id,
                "candidate_id": candidate.candidate_id,
                "review_decision_id": review.decision_id,
                "state": "TERMINAL",
                "node": node.as_dict(),
                "markdown": journal["markdown"],
                "edge": copy.deepcopy(edge_document),
                "result": result,
            }
            self._write_journal(journal_path, terminal)
            return result
