"""Replay-safe STAGING storage for immutable memory candidates and reviews."""

from __future__ import annotations

import copy
import json
import os
import re
from pathlib import Path
from typing import Any, Callable

import yaml

from hive_protocol.core import (
    ProtocolError,
    canonical_bytes,
    document_digest,
    sign_document,
    verify_document,
)
from hive_protocol.storage import atomic_write_bytes, atomic_write_json, exclusive_lock, read_json

from .authority import CognitionAuthority
from .models import CognitionEvent, MemoryCandidate, MemoryReviewDecision


_TOKEN = re.compile(r"^[0-9a-f]{64}$")


def _token(identifier: str, prefix: str) -> str:
    expected = f"{prefix}:"
    value = identifier[len(expected) :] if identifier.startswith(expected) else ""
    if _TOKEN.fullmatch(value) is None:
        raise ProtocolError("COGNITION_ID_INVALID", "cognition identifier is unsafe")
    return value


def _ensure_directory(path: Path, boundary: Path) -> None:
    if path != boundary and boundary not in path.parents:
        raise ProtocolError("COGNITION_STORE_BOUNDARY", "store path escapes Hive root")
    current = boundary
    if current.is_symlink() or not current.is_dir():
        raise ProtocolError("COGNITION_STORE_BOUNDARY", "Hive root is unsafe")
    for part in path.relative_to(boundary).parts:
        current /= part
        if current.is_symlink():
            raise ProtocolError("COGNITION_STORE_BOUNDARY", "store path contains a symlink")
        if current.exists() and not current.is_dir():
            raise ProtocolError("COGNITION_STORE_BOUNDARY", "store path is not a directory")
        current.mkdir(exist_ok=True, mode=0o700)
        if current.is_symlink() or current.stat().st_uid != os.geteuid():
            raise ProtocolError("COGNITION_STORE_BOUNDARY", "store directory is not owned")


def _write_exact(path: Path, payload: bytes, *, mode: int = 0o644) -> None:
    if path.is_symlink():
        raise ProtocolError("COGNITION_STORE_BOUNDARY", "store file cannot be a symlink")
    if path.exists():
        if not path.is_file() or path.read_bytes() != payload:
            raise ProtocolError("COGNITION_STORE_DRIFT", f"stored file changed: {path.name}")
        return
    atomic_write_bytes(path, payload, mode=mode)


def _candidate_markdown(candidate: MemoryCandidate) -> bytes:
    metadata = {
        "type": "hive-memory-candidate",
        "status": "PROPOSED",
        "candidate_id": candidate.candidate_id,
        "candidate_type": candidate.candidate_type,
        "project_id": candidate.project_id,
        "scope": candidate.experience_scope,
        "score": candidate.score["total"],
        "evidence": [item["anchor_id"] for item in candidate.evidence],
    }
    frontmatter = yaml.safe_dump(metadata, allow_unicode=False, sort_keys=True)
    title = candidate.claim["key"]
    narrative = candidate.claim["narrative"]
    return f"---\n{frontmatter}---\n\n# {title}\n\n{narrative}\n".encode("utf-8")


class CognitionStore:
    def __init__(
        self,
        root: Path,
        authority: CognitionAuthority,
        *,
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        raw = root.expanduser()
        for candidate in (raw, *raw.parents):
            if candidate.is_symlink():
                raise ProtocolError(
                    "COGNITION_STORE_BOUNDARY", "Hive path contains a symlink"
                )
        raw.mkdir(parents=True, exist_ok=True)
        self.root = raw.resolve(strict=True)
        if self.root != authority.root:
            raise ProtocolError(
                "COGNITION_STORE_BOUNDARY", "authority belongs to another Hive"
            )
        self.authority = authority
        self.fault_hook = fault_hook
        self.candidates = self.root / "staging" / "memory" / "candidates"
        self.reviews = self.root / "staging" / "memory" / "reviews"
        self.provenance = self.root / ".hive" / "provenance" / "memory"
        self.receipts = self.root / ".hive" / "receipts"
        self.journals = self.root / ".hive" / "runtime" / "cognition-journals"
        self.locks = self.root / ".hive" / "runtime" / "locks"

    def _fault(self, point: str) -> None:
        if self.fault_hook is not None:
            self.fault_hook(point)

    def _prepare(self) -> None:
        for path in (
            self.candidates,
            self.reviews,
            self.provenance,
            self.receipts,
            self.journals,
            self.locks,
        ):
            _ensure_directory(path, self.root)

    def _journal_path(self, operation_id: str) -> Path:
        if _TOKEN.fullmatch(operation_id) is None:
            raise ProtocolError("COGNITION_OPERATION_INVALID", "operation ID is invalid")
        return self.journals / f"stage-{operation_id}.json"

    def _read_journal(self, path: Path) -> dict[str, Any]:
        document = read_json(path)
        verify_document(
            document,
            {self.authority.proposer_key_id: self.authority.proposer_public_key},
        )
        if document.get("schema_version") != "hive.cognition-stage-journal.v1":
            raise ProtocolError("COGNITION_JOURNAL_INVALID", "journal version is invalid")
        return document

    def _write_journal(self, path: Path, document: dict[str, Any]) -> None:
        if path.is_symlink():
            raise ProtocolError("COGNITION_STORE_BOUNDARY", "journal cannot be a symlink")
        atomic_write_json(
            path,
            sign_document(document, self.authority.proposer_private_key),
            mode=0o600,
        )

    def stage(self, event: CognitionEvent, candidate: MemoryCandidate) -> dict[str, Any]:
        if (
            event.event_id not in candidate.source_event_ids
            or event.tenant_id != candidate.tenant_id
            or event.project_id != candidate.project_id
            or event.experience_scope != candidate.experience_scope
        ):
            raise ProtocolError(
                "COGNITION_EVENT_BINDING_MISMATCH",
                "candidate does not bind the exact event project and scope",
            )
        self._prepare()
        candidate_token = _token(candidate.candidate_id, "memory")
        event_digest = event.digest
        operation_id = document_digest(
            {
                "candidate_id": candidate.candidate_id,
                "event_id": event.event_id,
                "event_sha256": event_digest,
            }
        )
        journal_path = self._journal_path(operation_id)
        with exclusive_lock(self.locks / "cognition-stage.lock"):
            candidate_path = self.candidates / f"{candidate_token}.json"
            markdown_path = self.candidates / f"{candidate_token}.md"
            if journal_path.exists():
                journal = self._read_journal(journal_path)
                if (
                    journal.get("operation_id") != operation_id
                    or journal.get("candidate") != candidate.as_dict()
                    or journal.get("event") != event.as_dict()
                    or journal.get("state") not in {"PREPARED", "TERMINAL"}
                    or journal.get("initial_outcome")
                    not in {"STAGED", "DUPLICATE_PROVENANCE"}
                ):
                    raise ProtocolError(
                        "COGNITION_JOURNAL_INVALID", "journal input binding changed"
                    )
                if journal["state"] == "TERMINAL":
                    return copy.deepcopy(journal["result"])
            else:
                journal = {
                    "schema_version": "hive.cognition-stage-journal.v1",
                    "operation_id": operation_id,
                    "state": "PREPARED",
                    "initial_outcome": (
                        "DUPLICATE_PROVENANCE"
                        if candidate_path.exists()
                        else "STAGED"
                    ),
                    "candidate": candidate.as_dict(),
                    "event": event.as_dict(),
                    "result": None,
                }
                self._write_journal(journal_path, journal)
            self._fault("journal-written")

            already_present = candidate_path.exists()
            if already_present:
                canonical_candidate = MemoryCandidate.from_dict(read_json(candidate_path))
                if canonical_candidate.candidate_id != candidate.candidate_id:
                    raise ProtocolError(
                        "COGNITION_STORE_DRIFT", "candidate identity collision"
                    )
            else:
                canonical_candidate = candidate
                _write_exact(
                    candidate_path, canonical_bytes(candidate.as_dict()) + b"\n"
                )
            self._fault("candidate-written")
            if not markdown_path.exists():
                _write_exact(markdown_path, _candidate_markdown(canonical_candidate))
            elif not markdown_path.is_file() or markdown_path.is_symlink():
                raise ProtocolError(
                    "COGNITION_STORE_BOUNDARY", "candidate Markdown path is unsafe"
                )
            self._fault("markdown-written")

            event_root = self.provenance / candidate_token / "events"
            _ensure_directory(event_root, self.root)
            provenance_path = event_root / f"{event.event_id}.json"
            _write_exact(provenance_path, canonical_bytes(event.as_dict()) + b"\n")
            self._fault("provenance-written")

            outcome = journal["initial_outcome"]
            receipt_path = self.receipts / f"cognition-proposal-{candidate_token}-{operation_id}.json"
            owned_paths = sorted(
                {
                    candidate_path.relative_to(self.root).as_posix(),
                    markdown_path.relative_to(self.root).as_posix(),
                    provenance_path.relative_to(self.root).as_posix(),
                }
            )
            receipt = self.authority.sign_proposal(
                {
                    "schema_version": "hive.memory-candidate-receipt.v1",
                    "operation_id": operation_id,
                    "candidate_id": candidate.candidate_id,
                    "candidate_sha256": canonical_candidate.digest,
                    "proposed_candidate_sha256": candidate.digest,
                    "event_id": event.event_id,
                    "event_sha256": event_digest,
                    "outcome": outcome,
                    "owned_paths": owned_paths,
                    "prime_write": False,
                    "recorded_at": event.recorded_at,
                }
            )
            _write_exact(receipt_path, canonical_bytes(receipt) + b"\n")
            self._fault("receipt-written")
            result = {
                "outcome": outcome,
                "candidate_id": candidate.candidate_id,
                "candidate_sha256": canonical_candidate.digest,
                "candidate_path": candidate_path.relative_to(self.root).as_posix(),
                "markdown_path": markdown_path.relative_to(self.root).as_posix(),
                "provenance_path": provenance_path.relative_to(self.root).as_posix(),
                "receipt_path": receipt_path.relative_to(self.root).as_posix(),
            }
            terminal = {
                "schema_version": "hive.cognition-stage-journal.v1",
                "operation_id": operation_id,
                "state": "TERMINAL",
                "initial_outcome": outcome,
                "candidate": candidate.as_dict(),
                "event": event.as_dict(),
                "result": result,
            }
            self._write_journal(journal_path, terminal)
            return result

    def load_candidate(self, candidate_id: str) -> MemoryCandidate:
        self._prepare()
        path = self.candidates / f"{_token(candidate_id, 'memory')}.json"
        return MemoryCandidate.from_dict(read_json(path))

    def proposal_receipts(self, candidate_id: str) -> list[dict[str, Any]]:
        self._prepare()
        candidate_token = _token(candidate_id, "memory")
        documents: list[dict[str, Any]] = []
        for path in sorted(
            self.receipts.glob(f"cognition-proposal-{candidate_token}-*.json")
        ):
            document = read_json(path)
            self.authority.verify_proposal(document)
            documents.append(document)
        return documents

    def record_review(
        self, decision: MemoryReviewDecision, *, now
    ) -> dict[str, Any]:
        self._prepare()
        candidate = self.load_candidate(decision.candidate_id)
        receipts = self.proposal_receipts(candidate.candidate_id)
        if not receipts:
            raise ProtocolError(
                "COGNITION_PROPOSAL_RECEIPT_MISSING",
                "candidate has no authenticated proposal receipt",
            )
        verified = self.authority.verify_review(
            candidate, decision, receipts[0], now=now
        )
        path = self.reviews / f"{_token(candidate.candidate_id, 'memory')}.json"
        payload = canonical_bytes(verified.as_dict()) + b"\n"
        with exclusive_lock(self.locks / "cognition-review.lock"):
            if path.exists():
                if path.is_symlink() or not path.is_file():
                    raise ProtocolError(
                        "COGNITION_STORE_BOUNDARY", "review path is unsafe"
                    )
                if path.read_bytes() == payload:
                    return {
                        "outcome": "REPLAYED",
                        "candidate_id": candidate.candidate_id,
                        "decision_id": verified.decision_id,
                        "review_path": path.relative_to(self.root).as_posix(),
                    }
                raise ProtocolError(
                    "COGNITION_REVIEW_ALREADY_DECIDED",
                    "candidate review was already recorded",
                )
            _write_exact(path, payload)
        return {
            "outcome": "RECORDED",
            "candidate_id": candidate.candidate_id,
            "decision_id": verified.decision_id,
            "review_path": path.relative_to(self.root).as_posix(),
        }

    def load_review(self, candidate_id: str) -> MemoryReviewDecision:
        self._prepare()
        path = self.reviews / f"{_token(candidate_id, 'memory')}.json"
        return MemoryReviewDecision.from_dict(
            read_json(path), verified_by=self.authority.reviewer_public_keys
        )

    def list_candidates(self) -> list[dict[str, Any]]:
        self._prepare()
        results = []
        for path in sorted(self.candidates.glob("*.json")):
            candidate = MemoryCandidate.from_dict(read_json(path))
            review_path = self.reviews / f"{_token(candidate.candidate_id, 'memory')}.json"
            results.append(
                {
                    "candidate": candidate.as_dict(),
                    "review": read_json(review_path) if review_path.is_file() else None,
                }
            )
        return results
