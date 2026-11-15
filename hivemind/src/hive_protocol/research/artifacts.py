"""Verified, source-set-bound research artifact persistence."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
from pathlib import Path, PurePosixPath
from typing import Any, Mapping
from uuid import NAMESPACE_URL, uuid5

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.adapters.security import reject_credential_values
from hive_protocol.capture.models import CitationAnchor
from hive_protocol.core import (
    ProtocolError,
    canonical_bytes,
    document_digest,
    public_key_id,
    sign_document,
    verify_document,
)
from hive_protocol.storage import (
    atomic_write_bytes,
    atomic_write_json,
    exclusive_lock,
    read_json,
    utc_now,
)

from .models import ResearchArtifact
from .workspace import BoundedResearchWorkspaceStore


_SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REASON = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_CLAIM_TOKEN = re.compile(r"[A-Za-z0-9_-]{2,}")
_CITATION = re.compile(r"\[cite:(anchor:[A-Za-z0-9._:-]+)\]")
_CLAIM_STOP = frozenset(
    {
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "by",
        "for",
        "from",
        "is",
        "it",
        "of",
        "on",
        "or",
        "the",
        "to",
        "was",
        "were",
    }
)
ARTIFACT_TYPES = frozenset(
    {
        "CITED_ANSWER",
        "SOURCE_SUMMARY",
        "COMPARISON",
        "TIMELINE",
        "BRIEF",
        "QUESTIONS",
        "OUTLINE",
        "STUDY_GUIDE",
        "ACTION_ITEMS",
    }
)
ARTIFACT_STATUSES = frozenset(
    {
        "NO_EVIDENCE",
        "RETRIEVAL_ONLY",
        "MODEL_OUTPUT_REJECTED",
        "ANSWERED",
        "DEGRADED",
        "FAILED",
    }
)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _encode(payload: bytes | None) -> str | None:
    return None if payload is None else base64.b64encode(payload).decode("ascii")


def _decode(payload: Any) -> bytes | None:
    if payload is None:
        return None
    if not isinstance(payload, str):
        raise ProtocolError(
            "RESEARCH_ARTIFACT_JOURNAL_INVALID",
            "artifact recovery bytes are malformed",
        )
    try:
        return base64.b64decode(payload, validate=True)
    except ValueError as exc:
        raise ProtocolError(
            "RESEARCH_ARTIFACT_JOURNAL_INVALID",
            "artifact recovery bytes are malformed",
        ) from exc


def _reason(value: Any, fallback: str) -> str:
    return value if isinstance(value, str) and _REASON.fullmatch(value) else fallback


class ResearchArtifactStore:
    """Persist only independently verified artifacts under signed recovery state."""

    def __init__(
        self,
        store: BoundedResearchWorkspaceStore,
        state_root: Path,
        *,
        signing_key: Ed25519PrivateKey,
    ) -> None:
        self.store = store
        raw_state = state_root.expanduser()
        for candidate in [raw_state, *raw_state.parents]:
            if candidate.is_symlink():
                raise ProtocolError(
                    "RESEARCH_ARTIFACT_STATE_BOUNDARY",
                    "artifact state path may not contain symlinks",
                )
        self.state_root = raw_state.resolve(strict=False)
        self.signing_key = signing_key
        self.key_id = public_key_id(signing_key.public_key())
        self.trusted_keys = {self.key_id: signing_key.public_key()}

    def _ensure_state_root(self) -> None:
        if self.state_root.is_symlink():
            raise ProtocolError(
                "RESEARCH_ARTIFACT_STATE_BOUNDARY",
                "artifact state root is a symlink",
            )
        self.state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if (
            self.state_root.is_symlink()
            or not self.state_root.is_dir()
            or self.state_root.resolve() != self.state_root
            or self.state_root.stat().st_uid != os.geteuid()
        ):
            raise ProtocolError(
                "RESEARCH_ARTIFACT_STATE_BOUNDARY",
                "artifact state root changed identity",
            )
        os.chmod(self.state_root, 0o700)

    @staticmethod
    def _validate_operation_key(operation_key: str) -> None:
        if not isinstance(operation_key, str) or _SHA256.fullmatch(operation_key) is None:
            raise ProtocolError(
                "RESEARCH_ARTIFACT_OPERATION_KEY_INVALID",
                "artifact operation key must be an exact SHA-256",
            )

    def _operation_path(self, operation_key: str) -> Path:
        self._validate_operation_key(operation_key)
        self._ensure_state_root()
        operations = self.state_root / "operations"
        if operations.is_symlink():
            raise ProtocolError(
                "RESEARCH_ARTIFACT_STATE_BOUNDARY",
                "artifact operation root is a symlink",
            )
        operations.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(operations, 0o700)
        return operations / f"{operation_key}.json"

    def _lock_path(self, operation_key: str) -> Path:
        self._ensure_state_root()
        locks = self.state_root / "locks"
        if locks.is_symlink():
            raise ProtocolError(
                "RESEARCH_ARTIFACT_STATE_BOUNDARY", "artifact lock root is a symlink"
            )
        locks.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(locks, 0o700)
        return locks / f"{operation_key}.lock"

    def _write_journal(self, path: Path, document: dict[str, Any]) -> None:
        signed = sign_document(document, self.signing_key)
        verify_document(signed, self.trusted_keys)
        atomic_write_json(path, signed, mode=0o600)

    def _read_journal(self, path: Path) -> dict[str, Any]:
        try:
            document = read_json(path)
            verify_document(document, self.trusted_keys)
        except ProtocolError as exc:
            raise ProtocolError(
                "RESEARCH_ARTIFACT_JOURNAL_INVALID",
                "artifact recovery journal is not authentic",
            ) from exc
        signature = document.get("signature")
        if not isinstance(signature, dict) or signature.get("key_id") != self.key_id:
            raise ProtocolError(
                "RESEARCH_ARTIFACT_JOURNAL_INVALID",
                "artifact recovery signer changed",
            )
        if (
            document.get("schema_version") != "hive.research-artifact-operation.v1"
            or document.get("state")
            not in {
                "PREPARED",
                "MARKDOWN_WRITTEN",
                "SIDECAR_WRITTEN",
                "RECEIPT_WRITTEN",
                "TERMINAL",
                "ROLLING_BACK",
                "ROLLED_BACK",
            }
            or not isinstance(document.get("effects"), list)
            or not isinstance(document.get("result"), dict)
        ):
            raise ProtocolError(
                "RESEARCH_ARTIFACT_JOURNAL_INVALID",
                "artifact recovery journal is malformed",
            )
        return document

    def _portable_path(self, relative: str) -> Path:
        candidate = PurePosixPath(relative)
        if (
            candidate.is_absolute()
            or candidate.as_posix() != relative
            or not candidate.parts
            or any(part in {"", ".", ".."} for part in candidate.parts)
            or not (
                candidate.parts[:2] == ("research", "workspaces")
                or candidate.parts[:2] == (".hive", "receipts")
            )
        ):
            raise ProtocolError(
                "RESEARCH_ARTIFACT_BOUNDARY", "artifact path exceeds its portable roots"
            )
        current = self.store.workspace.root
        for part in candidate.parts:
            current /= part
            if current.is_symlink():
                raise ProtocolError(
                    "RESEARCH_ARTIFACT_BOUNDARY",
                    "artifact path may not contain symlinks",
                )
        return current

    def _ensure_artifact_directory(self, workspace_id: str) -> Path:
        directory = self.store.workspace_path(workspace_id).parent / "artifacts"
        try:
            directory.relative_to(self.store.workspace.root)
        except ValueError as exc:
            raise ProtocolError(
                "RESEARCH_ARTIFACT_BOUNDARY", "artifact directory escapes the Hive root"
            ) from exc
        if directory.is_symlink():
            raise ProtocolError(
                "RESEARCH_ARTIFACT_BOUNDARY", "artifact directory is a symlink"
            )
        directory.mkdir(parents=True, exist_ok=True)
        if not directory.is_dir() or directory.stat().st_uid != os.geteuid():
            raise ProtocolError(
                "RESEARCH_ARTIFACT_BOUNDARY",
                "artifact directory is not an owned regular directory",
            )
        return directory

    def _anchor_map(
        self, workspace_id: str, source_set_digest: str
    ) -> dict[str, dict[str, Any]]:
        source_set = self.store.verify_source_set(workspace_id, source_set_digest)
        anchors: dict[str, dict[str, Any]] = {}
        for source in source_set.sources:
            record, _ = self.store.load_source_record_snapshot(
                workspace_id, source["source_record_digest"]
            )
            for raw_anchor in record.anchors:
                anchor = CitationAnchor.from_dict(raw_anchor)
                if anchor.anchor_id in anchors:
                    raise ProtocolError(
                        "RESEARCH_ARTIFACT_ANCHOR_INVALID",
                        "source set contains a duplicate citation anchor",
                    )
                anchors[anchor.anchor_id] = {
                    "anchor_id": anchor.anchor_id,
                    "source_id": record.source_id,
                    "source_record_digest": source["source_record_digest"],
                    "source_sha256": record.original_sha256,
                    "normalized_sha256": record.normalized_sha256,
                    "source_path": record.normalized_text_path,
                    "quote": anchor.quote,
                    "quote_sha256": anchor.quote_sha256,
                    "locator": copy.deepcopy(anchor.locator),
                }
        return anchors

    @staticmethod
    def _validate_claim_support(
        claim: Mapping[str, Any], citations: Mapping[str, dict[str, Any]]
    ) -> None:
        if set(claim) != {"text", "citation_anchor_ids", "uncertainty"}:
            raise ProtocolError(
                "RESEARCH_ARTIFACT_CLAIM_INVALID", "artifact claim shape is invalid"
            )
        text = claim.get("text")
        anchor_ids = claim.get("citation_anchor_ids")
        uncertainty = claim.get("uncertainty")
        if (
            not isinstance(text, str)
            or not text.strip()
            or text != text.strip()
            or len(text) > 16_384
            or not isinstance(anchor_ids, list)
            or not anchor_ids
            or len(anchor_ids) != len(set(anchor_ids))
            or not all(isinstance(item, str) and item in citations for item in anchor_ids)
            or not (uncertainty is None or isinstance(uncertainty, str))
        ):
            raise ProtocolError(
                "RESEARCH_ARTIFACT_CLAIM_INVALID",
                "artifact claim is not bound to exact result citations",
            )
        claim_tokens = {
            token.lower()
            for token in _CLAIM_TOKEN.findall(text)
            if token.lower() not in _CLAIM_STOP
        }
        evidence_tokens = {
            token.lower()
            for anchor_id in anchor_ids
            for token in _CLAIM_TOKEN.findall(citations[anchor_id]["quote"])
            if token.lower() not in _CLAIM_STOP
        }
        if not claim_tokens or not claim_tokens.issubset(evidence_tokens):
            raise ProtocolError(
                "RESEARCH_ARTIFACT_CLAIM_UNSUPPORTED",
                "artifact claim exceeds its cited evidence",
            )

    @staticmethod
    def _validate_record_references(
        records: list[dict[str, Any]], allowed: frozenset[str], label: str
    ) -> list[dict[str, Any]]:
        if not isinstance(records, list) or not all(
            isinstance(record, dict) for record in records
        ):
            raise ProtocolError(
                "RESEARCH_ARTIFACT_RECORD_INVALID",
                f"artifact {label} records are invalid",
            )
        retained = copy.deepcopy(records)
        for record in retained:
            anchor_ids = record.get("citation_anchor_ids")
            if anchor_ids is not None and (
                not isinstance(anchor_ids, list)
                or len(anchor_ids) != len(set(anchor_ids))
                or not all(isinstance(item, str) and item in allowed for item in anchor_ids)
            ):
                raise ProtocolError(
                    "RESEARCH_ARTIFACT_ANCHOR_INVALID",
                    f"artifact {label} references an unknown citation anchor",
                )
        return retained

    def _verify_result(
        self,
        workspace_id: str,
        source_set_digest: str,
        research_result: Mapping[str, Any],
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        if not isinstance(research_result, Mapping):
            raise ProtocolError(
                "RESEARCH_ARTIFACT_RESULT_INVALID", "research result must be an object"
            )
        result = copy.deepcopy(dict(research_result))
        reject_credential_values(result, location="research artifact result")
        if result.get("source_set_digest") != source_set_digest:
            raise ProtocolError(
                "RESEARCH_ARTIFACT_SOURCE_SET_MISMATCH",
                "research result is not bound to the requested source set",
            )
        status = result.get("status")
        if status not in ARTIFACT_STATUSES:
            raise ProtocolError(
                "RESEARCH_ARTIFACT_STATUS_INVALID", "research result status is invalid"
            )
        source_anchors = self._anchor_map(workspace_id, source_set_digest)
        raw_citations = result.get("citations")
        if not isinstance(raw_citations, list) or len(raw_citations) > 10_000:
            raise ProtocolError(
                "RESEARCH_ARTIFACT_CITATION_INVALID", "artifact citations are invalid"
            )
        citations: dict[str, dict[str, Any]] = {}
        verified_citations: list[dict[str, Any]] = []
        exact_fields = (
            "anchor_id",
            "source_id",
            "source_record_digest",
            "source_sha256",
            "normalized_sha256",
            "source_path",
            "quote",
            "quote_sha256",
            "locator",
        )
        for raw_citation in raw_citations:
            if not isinstance(raw_citation, dict):
                raise ProtocolError(
                    "RESEARCH_ARTIFACT_CITATION_INVALID", "artifact citation is invalid"
                )
            anchor_id = raw_citation.get("anchor_id")
            expected = source_anchors.get(anchor_id)
            if (
                expected is None
                or anchor_id in citations
                or any(raw_citation.get(field) != expected[field] for field in exact_fields)
            ):
                raise ProtocolError(
                    "RESEARCH_ARTIFACT_CITATION_INVALID",
                    "artifact citation does not match its exact source-set anchor",
                )
            citation = copy.deepcopy(raw_citation)
            citations[anchor_id] = citation
            verified_citations.append(citation)
        answer = result.get("answer")
        provider_called = result.get("provider_called")
        raw_claims = result.get("claims")
        if not isinstance(provider_called, bool) or not isinstance(raw_claims, list):
            raise ProtocolError(
                "RESEARCH_ARTIFACT_RESULT_INVALID", "research result shape is invalid"
            )
        if status == "ANSWERED":
            if (
                not provider_called
                or not isinstance(answer, str)
                or not answer.strip()
                or not raw_claims
                or len(answer.encode("utf-8")) > 32_768
            ):
                raise ProtocolError(
                    "RESEARCH_ARTIFACT_RESULT_INVALID",
                    "answered artifact lacks bounded model output and claims",
                )
            marker_ids = set(_CITATION.findall(answer))
            claims = copy.deepcopy(raw_claims)
            for claim in claims:
                if not isinstance(claim, dict):
                    raise ProtocolError(
                        "RESEARCH_ARTIFACT_CLAIM_INVALID", "artifact claim is invalid"
                    )
                self._validate_claim_support(claim, citations)
                if claim["text"] not in answer or not set(
                    claim["citation_anchor_ids"]
                ).issubset(marker_ids):
                    raise ProtocolError(
                        "RESEARCH_ARTIFACT_CLAIM_INVALID",
                        "artifact answer and structured claims disagree",
                    )
        elif status == "RETRIEVAL_ONLY":
            if provider_called or answer is not None or raw_claims or not verified_citations:
                raise ProtocolError(
                    "RESEARCH_ARTIFACT_RESULT_INVALID",
                    "retrieval-only artifact must contain evidence without model output",
                )
            claims = [
                {
                    "text": citation["quote"],
                    "citation_anchor_ids": [citation["anchor_id"]],
                    "uncertainty": "RETRIEVAL_ONLY_EVIDENCE",
                }
                for citation in verified_citations
            ]
        elif status == "NO_EVIDENCE":
            if verified_citations or answer is not None or raw_claims:
                raise ProtocolError(
                    "RESEARCH_ARTIFACT_RESULT_INVALID",
                    "no-evidence artifact may not contain model claims or citations",
                )
            claims = []
        else:
            if answer is not None or raw_claims:
                raise ProtocolError(
                    "RESEARCH_ARTIFACT_RESULT_INVALID",
                    "failed or rejected model output may not be persisted as claims",
                )
            claims = []
        allowed = frozenset(citations)
        contradictions = self._validate_record_references(
            result.get("contradictions", []), allowed, "contradiction"
        )
        uncertainties = self._validate_record_references(
            result.get("uncertainties", []), allowed, "uncertainty"
        )
        if status in {"MODEL_OUTPUT_REJECTED", "DEGRADED", "FAILED"}:
            rejection = {
                "reason": _reason(result.get("reason"), status),
                "status": status,
            }
            if rejection not in uncertainties:
                uncertainties.append(rejection)
        verified = {
            "status": status,
            "answer": copy.deepcopy(answer),
            "provider_called": provider_called,
            "provider_reason": _reason(
                result.get("provider_reason"),
                _reason(result.get("reason"), status)
                if provider_called and status in {"DEGRADED", "FAILED"}
                else "AVAILABLE"
                if provider_called
                else "NO_PROVIDER_CONFIGURED",
            ),
            "claims": claims,
            "contradictions": contradictions,
            "uncertainties": uncertainties,
        }
        return verified, verified_citations

    @staticmethod
    def _markdown(
        *,
        title: str,
        artifact_type: str,
        source_set_digest: str,
        verified: dict[str, Any],
        citations: list[dict[str, Any]],
    ) -> bytes:
        lines = [
            f"# {title}",
            "",
            f"> Status: `{verified['status']}`",
            f"> Artifact type: `{artifact_type}`",
            f"> Source set: `{source_set_digest}`",
            "",
        ]
        if verified["status"] == "RETRIEVAL_ONLY":
            lines.extend(
                ["**RETRIEVAL ONLY — no model answer generated.**", ""]
            )
        if verified["answer"] is not None:
            lines.extend(["## Answer", "", verified["answer"].strip(), ""])
        lines.extend(["## Verified evidence", ""])
        if citations:
            for citation in citations:
                lines.append(
                    f"### `{citation['source_id']}` `[cite:{citation['anchor_id']}]`"
                )
                lines.append("")
                lines.extend(
                    f"> {line}" if line else ">"
                    for line in citation["quote"].splitlines()
                )
                lines.append("")
        else:
            lines.extend(["No verified evidence was available.", ""])
        lines.extend(["## Claims", ""])
        if verified["claims"]:
            for claim in verified["claims"]:
                markers = " ".join(
                    f"[cite:{anchor_id}]"
                    for anchor_id in claim["citation_anchor_ids"]
                )
                lines.append(f"- {claim['text']} {markers}".rstrip())
                if claim["uncertainty"] is not None:
                    lines.append(f"  - Uncertainty: `{claim['uncertainty']}`")
        else:
            lines.append("- None.")
        for heading, key in (
            ("Contradictions", "contradictions"),
            ("Uncertainties", "uncertainties"),
        ):
            lines.extend(["", f"## {heading}", ""])
            records = verified[key]
            if records:
                for record in records:
                    lines.append(
                        "- `" + json.dumps(record, ensure_ascii=False, sort_keys=True) + "`"
                    )
            else:
                lines.append("- None.")
        return ("\n".join(lines).rstrip() + "\n").encode("utf-8")

    def _prepare(
        self,
        *,
        workspace_id: str,
        source_set_digest: str,
        artifact_type: str,
        title: str,
        research_result: Mapping[str, Any],
        operation_key: str,
        created_at: str | None,
        generator_id: str,
        payload_digest: str,
    ) -> dict[str, Any]:
        research_workspace = self.store.open_workspace(workspace_id)
        self.store.verify_source_set(workspace_id, source_set_digest)
        if artifact_type not in ARTIFACT_TYPES:
            raise ProtocolError(
                "RESEARCH_ARTIFACT_TYPE_INVALID", "research artifact type is invalid"
            )
        if (
            not isinstance(title, str)
            or not title.strip()
            or title != title.strip()
            or "\n" in title
            or len(title) > 256
            or _SAFE_ID.fullmatch(generator_id) is None
        ):
            raise ProtocolError(
                "RESEARCH_ARTIFACT_INPUT_INVALID", "artifact title or generator is invalid"
            )
        reject_credential_values(
            {"title": title, "generator_id": generator_id},
            location="research artifact metadata",
        )
        verified, citations = self._verify_result(
            workspace_id, source_set_digest, research_result
        )
        moment = created_at or utc_now()
        markdown = self._markdown(
            title=title,
            artifact_type=artifact_type,
            source_set_digest=source_set_digest,
            verified=verified,
            citations=citations,
        )
        provider_called = bool(verified["provider_called"])
        provider_available = provider_called and verified["status"] not in {
            "DEGRADED",
            "FAILED",
        }
        generator = {
            "kind": "LOCAL_PROVIDER"
            if provider_called
            else "DETERMINISTIC_RETRIEVAL",
            "id": generator_id if provider_called else "bounded-retrieval",
        }
        provider_state = {
            "available": provider_available,
            "reason": verified["provider_reason"],
        }
        verification_state = {
            "ANSWERED": "VERIFIED",
            "RETRIEVAL_ONLY": "RETRIEVAL_VERIFIED",
            "NO_EVIDENCE": "RETRIEVAL_VERIFIED",
        }.get(verified["status"], "REJECTED")
        identity = document_digest(
            {
                "workspace_id": workspace_id,
                "tenant_id": research_workspace.tenant_id,
                "project_id": research_workspace.project_id,
                "source_set_digest": source_set_digest,
                "artifact_type": artifact_type,
                "status": verified["status"],
                "markdown_sha256": _sha256(markdown),
                "generator": generator,
                "provider_state": provider_state,
                "claims": verified["claims"],
                "contradictions": verified["contradictions"],
                "uncertainties": verified["uncertainties"],
                "verification_state": verification_state,
                "created_at": moment,
            }
        )
        artifact_id = f"artifact:{identity}"
        directory = self._ensure_artifact_directory(workspace_id)
        markdown_path = directory / f"{identity}.md"
        sidecar_path = directory / f"{identity}.json"
        receipt_path = self.store.workspace.receipts / f"research-artifact-{identity}.json"
        for directory_path in (directory, receipt_path.parent):
            if directory_path.is_symlink():
                raise ProtocolError(
                    "RESEARCH_ARTIFACT_BOUNDARY", "artifact output root is a symlink"
                )
            directory_path.mkdir(parents=True, exist_ok=True)
        relative_markdown = markdown_path.relative_to(
            self.store.workspace.root
        ).as_posix()
        relative_sidecar = sidecar_path.relative_to(
            self.store.workspace.root
        ).as_posix()
        relative_receipt = receipt_path.relative_to(
            self.store.workspace.root
        ).as_posix()
        model = ResearchArtifact(
            artifact_id=artifact_id,
            workspace_id=workspace_id,
            tenant_id=research_workspace.tenant_id,
            project_id=research_workspace.project_id,
            source_set_digest=source_set_digest,
            artifact_type=artifact_type,
            status=verified["status"],
            markdown_path=relative_markdown,
            markdown_sha256=_sha256(markdown),
            generator=generator,
            provider_state=provider_state,
            claims=verified["claims"],
            contradictions=verified["contradictions"],
            uncertainties=verified["uncertainties"],
            verification_state=verification_state,
            created_at=moment,
        )
        sidecar_document = model.as_dict()
        model = ResearchArtifact.from_dict(sidecar_document)
        sidecar = canonical_bytes(sidecar_document) + b"\n"
        artifact_digest = document_digest(sidecar_document)
        receipt_document = {
            "schema_version": "nukotech.hive-local.receipt.v1",
            "receipt_id": str(
                uuid5(NAMESPACE_URL, f"research-artifact-created:{artifact_digest}")
            ),
            "kind": "research-artifact-created",
            "recorded_at": moment,
            "detail": {
                "artifact_id": model.artifact_id,
                "artifact_digest": artifact_digest,
                "workspace_id": workspace_id,
                "source_set_digest": source_set_digest,
                "markdown_path": relative_markdown,
                "sidecar_path": relative_sidecar,
            },
        }
        receipt = canonical_bytes(receipt_document) + b"\n"
        result = {
            "outcome": "APPLIED",
            "artifact_id": artifact_id,
            "artifact_digest": artifact_digest,
            "markdown_path": relative_markdown,
            "sidecar_path": relative_sidecar,
            "receipt_path": relative_receipt,
            "markdown_sha256": model.markdown_sha256,
            "source_set_digest": source_set_digest,
            "status": model.status,
            "rollback_ref": f"research-artifact:{operation_key}",
        }
        effects = []
        for name, relative, payload in (
            ("MARKDOWN", relative_markdown, markdown),
            ("SIDECAR", relative_sidecar, sidecar),
            ("RECEIPT", relative_receipt, receipt),
        ):
            path = self._portable_path(relative)
            before = path.read_bytes() if path.exists() and not path.is_symlink() else None
            if path.is_symlink():
                raise ProtocolError(
                    "RESEARCH_ARTIFACT_BOUNDARY", "artifact output path is a symlink"
                )
            effects.append(
                {
                    "name": name,
                    "path": relative,
                    "before": _encode(before),
                    "after": _encode(payload),
                }
            )
        return {
            "schema_version": "hive.research-artifact-operation.v1",
            "operation_key": operation_key,
            "payload_digest": payload_digest,
            "state": "PREPARED",
            "effects": effects,
            "result": result,
            "rollback_result": None,
        }

    def _validate_journal_binding(
        self, journal: dict[str, Any], operation_key: str, payload_digest: str
    ) -> None:
        if (
            journal.get("operation_key") != operation_key
            or journal.get("payload_digest") != payload_digest
            or set(journal)
            != {
                "schema_version",
                "operation_key",
                "payload_digest",
                "state",
                "effects",
                "result",
                "rollback_result",
                "signature",
            }
        ):
            raise ProtocolError(
                "RESEARCH_ARTIFACT_OPERATION_KEY_MISMATCH",
                "artifact operation key is bound to different input",
            )

    def _verify_terminal_effects(self, journal: Mapping[str, Any]) -> None:
        for effect in journal["effects"]:
            path = self._portable_path(effect["path"])
            after = _decode(effect["after"])
            if after is None or not path.is_file() or path.read_bytes() != after:
                raise ProtocolError(
                    "RESEARCH_ARTIFACT_DRIFT", "completed artifact bytes changed"
                )

    def _apply_effect(self, effect: Mapping[str, Any]) -> None:
        path = self._portable_path(effect["path"])
        before = _decode(effect.get("before"))
        after = _decode(effect.get("after"))
        if after is None:
            raise ProtocolError(
                "RESEARCH_ARTIFACT_JOURNAL_INVALID", "artifact effect is incomplete"
            )
        current = path.read_bytes() if path.exists() and not path.is_symlink() else None
        if path.is_symlink():
            raise ProtocolError(
                "RESEARCH_ARTIFACT_BOUNDARY", "artifact output path is a symlink"
            )
        if current == after:
            return
        if current != before:
            raise ProtocolError(
                "RESEARCH_ARTIFACT_DRIFT", "artifact path has unexpected bytes"
            )
        atomic_write_bytes(path, after)

    def _after_stage(self, stage: str) -> None:
        """Deterministic crash seam used by recovery tests."""

    def create_artifact(
        self,
        *,
        workspace_id: str,
        source_set_digest: str,
        artifact_type: str,
        title: str,
        research_result: Mapping[str, Any],
        operation_key: str,
        created_at: str | None = None,
        generator_id: str = "bounded-research",
    ) -> dict[str, Any]:
        self._validate_operation_key(operation_key)
        if not isinstance(research_result, Mapping):
            raise ProtocolError(
                "RESEARCH_ARTIFACT_RESULT_INVALID", "research result must be an object"
            )
        payload = {
            "workspace_id": workspace_id,
            "source_set_digest": source_set_digest,
            "artifact_type": artifact_type,
            "title": title,
            "research_result": copy.deepcopy(dict(research_result)),
            "created_at": created_at,
            "generator_id": generator_id,
        }
        payload_digest = document_digest(payload)
        path = self._operation_path(operation_key)
        with exclusive_lock(self._lock_path(operation_key)):
            if path.exists():
                journal = self._read_journal(path)
                self._validate_journal_binding(journal, operation_key, payload_digest)
            else:
                journal = self._prepare(
                    workspace_id=workspace_id,
                    source_set_digest=source_set_digest,
                    artifact_type=artifact_type,
                    title=title,
                    research_result=research_result,
                    operation_key=operation_key,
                    created_at=created_at,
                    generator_id=generator_id,
                    payload_digest=payload_digest,
                )
                self._write_journal(path, journal)
                journal = self._read_journal(path)
            if journal["state"] == "ROLLED_BACK":
                raise ProtocolError(
                    "RESEARCH_ARTIFACT_ROLLED_BACK",
                    "rolled-back artifact operation cannot be replayed",
                )
            if journal["state"] == "ROLLING_BACK":
                raise ProtocolError(
                    "RESEARCH_ARTIFACT_ROLLBACK_PENDING",
                    "artifact rollback must finish before replay",
                )
            if journal["state"] == "TERMINAL":
                self._verify_terminal_effects(journal)
                return copy.deepcopy(journal["result"])
            stages = ("MARKDOWN_WRITTEN", "SIDECAR_WRITTEN", "RECEIPT_WRITTEN")
            for effect, stage in zip(journal["effects"], stages, strict=True):
                self._apply_effect(effect)
                journal["state"] = stage
                journal.pop("signature", None)
                self._write_journal(path, journal)
                journal = self._read_journal(path)
                self._after_stage(stage)
            journal["state"] = "TERMINAL"
            journal.pop("signature", None)
            self._write_journal(path, journal)
            terminal = self._read_journal(path)
            self._verify_terminal_effects(terminal)
            return copy.deepcopy(terminal["result"])

    def rollback(self, operation_key: str) -> dict[str, Any]:
        self._validate_operation_key(operation_key)
        path = self._operation_path(operation_key)
        with exclusive_lock(self._lock_path(operation_key)):
            if not path.exists():
                raise ProtocolError(
                    "RESEARCH_ARTIFACT_ROLLBACK_UNKNOWN",
                    "artifact operation does not exist",
                )
            journal = self._read_journal(path)
            if journal.get("operation_key") != operation_key:
                raise ProtocolError(
                    "RESEARCH_ARTIFACT_JOURNAL_INVALID",
                    "artifact operation identity changed",
                )
            if journal["state"] == "ROLLED_BACK":
                rollback_result = journal.get("rollback_result")
                if not isinstance(rollback_result, dict):
                    raise ProtocolError(
                        "RESEARCH_ARTIFACT_JOURNAL_INVALID",
                        "artifact rollback result is absent",
                    )
                return copy.deepcopy(rollback_result)
            journal["state"] = "ROLLING_BACK"
            journal.pop("signature", None)
            self._write_journal(path, journal)
            journal = self._read_journal(path)
            removed: list[str] = []
            restored: list[str] = []
            for effect in reversed(journal["effects"]):
                target = self._portable_path(effect["path"])
                before = _decode(effect.get("before"))
                after = _decode(effect.get("after"))
                current = (
                    target.read_bytes()
                    if target.exists() and not target.is_symlink()
                    else None
                )
                if target.is_symlink():
                    raise ProtocolError(
                        "RESEARCH_ARTIFACT_BOUNDARY", "artifact rollback path is a symlink"
                    )
                if current == before:
                    continue
                if current != after:
                    raise ProtocolError(
                        "RESEARCH_ARTIFACT_ROLLBACK_DRIFT",
                        "artifact rollback found unexpected bytes",
                    )
                if before is None:
                    target.unlink()
                    directory_fd = os.open(target.parent, os.O_RDONLY)
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
                    removed.append(effect["path"])
                else:
                    atomic_write_bytes(target, before)
                    restored.append(effect["path"])
            rollback_result = {
                "outcome": "ROLLED_BACK",
                "removed": sorted(removed),
                "restored": sorted(restored),
                "canonical_sources_preserved": True,
            }
            journal["state"] = "ROLLED_BACK"
            journal["rollback_result"] = rollback_result
            journal.pop("signature", None)
            self._write_journal(path, journal)
            return copy.deepcopy(rollback_result)

    def recover(self, operation_key: str) -> dict[str, Any] | None:
        path = self._operation_path(operation_key)
        if not path.exists():
            return None
        journal = self._read_journal(path)
        if journal.get("operation_key") != operation_key:
            raise ProtocolError(
                "RESEARCH_ARTIFACT_JOURNAL_INVALID", "artifact operation identity changed"
            )
        if journal["state"] == "TERMINAL":
            self._verify_terminal_effects(journal)
            return copy.deepcopy(journal["result"])
        return None

    def verify_artifact(self, workspace_id: str, artifact_id: str) -> ResearchArtifact:
        self.store.open_workspace(workspace_id)
        if not isinstance(artifact_id, str) or not artifact_id.startswith("artifact:"):
            raise ProtocolError(
                "RESEARCH_ARTIFACT_ID_INVALID", "artifact ID is invalid"
            )
        digest = artifact_id.removeprefix("artifact:")
        if _SHA256.fullmatch(digest) is None:
            raise ProtocolError(
                "RESEARCH_ARTIFACT_ID_INVALID", "artifact ID is invalid"
            )
        directory = self.store.workspace_path(workspace_id).parent / "artifacts"
        if directory.is_symlink() or not directory.is_dir():
            raise ProtocolError(
                "RESEARCH_ARTIFACT_ABSENT", "artifact directory is absent or unsafe"
            )
        sidecar_path = directory / f"{digest}.json"
        if sidecar_path.is_symlink() or not sidecar_path.is_file():
            raise ProtocolError(
                "RESEARCH_ARTIFACT_ABSENT", "artifact sidecar is absent"
            )
        model = ResearchArtifact.from_dict(read_json(sidecar_path))
        if model.artifact_id != artifact_id or model.workspace_id != workspace_id:
            raise ProtocolError(
                "RESEARCH_ARTIFACT_DRIFT", "artifact identity changed"
            )
        identity = document_digest(
            {
                "workspace_id": model.workspace_id,
                "tenant_id": model.tenant_id,
                "project_id": model.project_id,
                "source_set_digest": model.source_set_digest,
                "artifact_type": model.artifact_type,
                "status": model.status,
                "markdown_sha256": model.markdown_sha256,
                "generator": model.generator,
                "provider_state": model.provider_state,
                "claims": model.claims,
                "contradictions": model.contradictions,
                "uncertainties": model.uncertainties,
                "verification_state": model.verification_state,
                "created_at": model.created_at,
            }
        )
        if identity != digest:
            raise ProtocolError(
                "RESEARCH_ARTIFACT_DRIFT", "artifact sidecar changed"
            )
        self.store.verify_source_set(workspace_id, model.source_set_digest)
        expected_markdown = (directory / f"{digest}.md").relative_to(
            self.store.workspace.root
        ).as_posix()
        if model.markdown_path != expected_markdown:
            raise ProtocolError(
                "RESEARCH_ARTIFACT_DRIFT", "artifact Markdown path changed"
            )
        anchors = self._anchor_map(workspace_id, model.source_set_digest)
        for claim in model.claims:
            self._validate_claim_support(claim, anchors)
        allowed = frozenset(anchors)
        self._validate_record_references(
            model.contradictions, allowed, "contradiction"
        )
        self._validate_record_references(model.uncertainties, allowed, "uncertainty")
        markdown_path = self._portable_path(model.markdown_path)
        if (
            markdown_path.is_symlink()
            or not markdown_path.is_file()
            or _sha256(markdown_path.read_bytes()) != model.markdown_sha256
        ):
            raise ProtocolError(
                "RESEARCH_ARTIFACT_DRIFT", "artifact Markdown changed"
            )
        try:
            markdown = markdown_path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ProtocolError(
                "RESEARCH_ARTIFACT_DRIFT", "artifact Markdown is not UTF-8"
            ) from exc
        if (
            f"> Status: `{model.status}`" not in markdown
            or f"> Source set: `{model.source_set_digest}`" not in markdown
        ):
            raise ProtocolError(
                "RESEARCH_ARTIFACT_DRIFT", "artifact Markdown metadata changed"
            )
        for claim in model.claims:
            if claim["text"] not in markdown or any(
                f"[cite:{anchor_id}]" not in markdown
                for anchor_id in claim["citation_anchor_ids"]
            ):
                raise ProtocolError(
                    "RESEARCH_ARTIFACT_DRIFT",
                    "artifact Markdown no longer contains its verified claims",
                )
        for records in (model.contradictions, model.uncertainties):
            if any(
                json.dumps(record, ensure_ascii=False, sort_keys=True) not in markdown
                for record in records
            ):
                raise ProtocolError(
                    "RESEARCH_ARTIFACT_DRIFT",
                    "artifact Markdown no longer contains its evidence records",
                )
        return model

    def list_artifacts(
        self, workspace_id: str, *, source_set_digest: str | None = None
    ) -> list[ResearchArtifact]:
        self.store.open_workspace(workspace_id)
        directory = self.store.workspace_path(workspace_id).parent / "artifacts"
        if not directory.exists() and not directory.is_symlink():
            return []
        if directory.is_symlink() or not directory.is_dir():
            raise ProtocolError(
                "RESEARCH_ARTIFACT_BOUNDARY", "artifact directory is unsafe"
            )
        artifacts: list[ResearchArtifact] = []
        for path in sorted(directory.glob("*.json")):
            if path.is_symlink() or _SHA256.fullmatch(path.stem) is None:
                raise ProtocolError(
                    "RESEARCH_ARTIFACT_BOUNDARY", "artifact sidecar path is invalid"
                )
            artifact = self.verify_artifact(workspace_id, f"artifact:{path.stem}")
            if source_set_digest is None or artifact.source_set_digest == source_set_digest:
                artifacts.append(artifact)
        return artifacts
