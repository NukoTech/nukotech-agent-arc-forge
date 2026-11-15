"""Previewed, version-bound, replay-safe Markdown editing."""

from __future__ import annotations

import copy
import hashlib
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

from hive_protocol.adapters.security import reject_credential_values
from hive_protocol.cognition.authority import CognitionAuthority
from hive_protocol.cognition.store import _ensure_directory, _write_exact
from hive_protocol.core import ProtocolError, canonical_bytes, document_digest, sign_document, verify_document
from hive_protocol.storage import atomic_write_bytes, atomic_write_json, exclusive_lock, read_json


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PROJECT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_WIKILINK = re.compile(r"\[\[([^\]|#]+)(?:#[^\]|]+)?(?:\|[^\]]+)?\]\]")
_TYPED = re.compile(r"^\s*(?:[-*]\s+)?([A-Za-z][A-Za-z0-9_-]{0,63})\s+\[\[([^\]|#]+)", re.MULTILINE)
_TAG = re.compile(r"(?<![\w#])#([A-Za-z][A-Za-z0-9_-]*)")
_CITATION = re.compile(r"\b(anchor:[A-Za-z0-9._:-]{1,192})\b")


def _time(value) -> str:
    if value.tzinfo is None:
        raise ProtocolError("KNOWLEDGE_TIME_INVALID", "knowledge edit time lacks timezone")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse(content: str, relative_path: str) -> dict[str, Any]:
    typed = sorted(
        {(" ".join(target.split()), relation.lower()) for relation, target in _TYPED.findall(content)}
    )
    wikilinks = sorted({" ".join(value.split()) for value in _WIKILINK.findall(content)})
    frontmatter = content.startswith("---\n") and "\n---\n" in content[4:]
    frontmatter_text = content[4:].split("\n---\n", 1)[0] if frontmatter else ""
    is_moc = bool(re.search(r"(?mi)^type:\s*moc\s*$", frontmatter_text)) or Path(relative_path).stem.lower().startswith("moc ")
    return {
        "wikilinks": wikilinks,
        "typed_links": [
            {"relation": relation, "target": target} for target, relation in typed
        ],
        "tags": sorted(set(_TAG.findall(content))),
        "citation_anchor_ids": sorted(set(_CITATION.findall(content))),
        "is_moc": is_moc,
    }


class KnowledgeEditor:
    def __init__(
        self,
        root: Path,
        authority: CognitionAuthority,
        *,
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        self.root = root.expanduser().resolve(strict=True)
        if self.root != authority.root:
            raise ProtocolError("KNOWLEDGE_EDIT_BOUNDARY", "authority belongs to another Hive")
        self.authority = authority
        self.fault_hook = fault_hook
        self.preview_root = self.root / ".hive" / "runtime" / "knowledge-previews"
        self.journals = self.root / ".hive" / "runtime" / "knowledge-journals"
        self.locks = self.root / ".hive" / "runtime" / "locks"
        self.receipts = self.root / ".hive" / "receipts"

    def _prepare(self) -> None:
        for path in (self.preview_root, self.journals, self.locks, self.receipts):
            _ensure_directory(path, self.root)

    def _fault(self, point: str) -> None:
        if self.fault_hook is not None:
            self.fault_hook(point)

    def _target(self, project_id: str, relative_path: str) -> Path:
        if _PROJECT.fullmatch(project_id) is None or not isinstance(relative_path, str):
            raise ProtocolError("KNOWLEDGE_PATH_INVALID", "project or note path is invalid")
        pure = PurePosixPath(relative_path)
        if (
            pure.is_absolute()
            or not pure.parts
            or any(part in {"", ".", ".."} or part.startswith(".") for part in pure.parts)
            or pure.suffix.lower() != ".md"
            or pure.as_posix() != relative_path
        ):
            raise ProtocolError("KNOWLEDGE_PATH_INVALID", "note must be a safe relative Markdown path")
        target = self.root / "prime" / "knowledge" / project_id / Path(*pure.parts)
        current = self.root
        for part in target.relative_to(self.root).parts:
            current /= part
            if current.is_symlink():
                raise ProtocolError("KNOWLEDGE_PATH_INVALID", "note path contains a symlink")
        return target

    def preview(
        self,
        *,
        project_id: str,
        relative_path: str,
        content: str,
        expected_sha256: str | None,
        now,
        ttl: timedelta = timedelta(minutes=10),
    ) -> dict[str, Any]:
        if not isinstance(content, str) or "\x00" in content or len(content.encode("utf-8")) > 1024 * 1024:
            raise ProtocolError("KNOWLEDGE_CONTENT_INVALID", "Markdown content is invalid or oversized")
        reject_credential_values({"content": content}, location="knowledge note")
        if ttl <= timedelta(0) or ttl > timedelta(hours=1):
            raise ProtocolError("KNOWLEDGE_PREVIEW_EXPIRY_INVALID", "preview TTL is invalid")
        target = self._target(project_id, relative_path)
        if target.exists():
            if target.is_symlink() or not target.is_file():
                raise ProtocolError("KNOWLEDGE_PATH_INVALID", "note target is unsafe")
            current_sha = hashlib.sha256(target.read_bytes()).hexdigest()
            if expected_sha256 != current_sha:
                raise ProtocolError("KNOWLEDGE_VERSION_CONFLICT", "expected note digest is stale")
            operation = "UPDATE"
        else:
            if expected_sha256 is not None:
                raise ProtocolError("KNOWLEDGE_VERSION_CONFLICT", "new note cannot have an expected digest")
            operation = "CREATE"
        relative = target.relative_to(self.root).as_posix()
        unsigned: dict[str, Any] = {
            "schema_version": "hive.knowledge-edit-preview.v1",
            "preview_id": "edit:placeholder",
            "project_id": project_id,
            "relative_path": relative,
            "operation": operation,
            "expected_sha256": expected_sha256,
            "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            "size_bytes": len(content.encode("utf-8")),
            "parsed": _parse(content, relative_path),
            "risk_class": "HIGH" if operation == "UPDATE" else "NORMAL",
            "created_at": _time(now),
            "expires_at": _time(now + ttl),
        }
        unsigned["preview_id"] = "edit:" + document_digest(
            {key: value for key, value in unsigned.items() if key != "preview_id"}
        )
        preview = sign_document(unsigned, self.authority.proposer_private_key)
        self._prepare()
        path = self.preview_root / f"{preview['preview_id'].split(':', 1)[1]}.json"
        _write_exact(path, canonical_bytes(preview) + b"\n", mode=0o600)
        return preview

    def _load_preview(self, preview_id: str) -> dict[str, Any]:
        if not isinstance(preview_id, str) or not preview_id.startswith("edit:") or _SHA256.fullmatch(preview_id[5:]) is None:
            raise ProtocolError("KNOWLEDGE_PREVIEW_INVALID", "preview ID is invalid")
        preview = read_json(self.preview_root / f"{preview_id[5:]}.json")
        verify_document(preview, self.authority.proposer_public_keys)
        expected = {
            "schema_version", "preview_id", "project_id", "relative_path", "operation",
            "expected_sha256", "content_sha256", "size_bytes", "parsed", "risk_class",
            "created_at", "expires_at", "signature",
        }
        identity = "edit:" + document_digest(
            {key: value for key, value in preview.items() if key not in {"preview_id", "signature"}}
        )
        if set(preview) != expected or preview.get("preview_id") != preview_id or identity != preview_id:
            raise ProtocolError("KNOWLEDGE_PREVIEW_INVALID", "preview identity changed")
        return preview

    def approve(
        self,
        preview_id: str,
        *,
        actor_id: str,
        authorization_ref: str,
        now,
        ttl: timedelta = timedelta(minutes=5),
    ) -> dict[str, Any]:
        preview = self._load_preview(preview_id)
        if preview["operation"] != "UPDATE" or actor_id not in self.authority.trusted_reviewer_actors:
            raise ProtocolError("KNOWLEDGE_APPROVAL_INVALID", "edit approval is not authorized")
        if now >= datetime.fromisoformat(preview["expires_at"].replace("Z", "+00:00")):
            raise ProtocolError("KNOWLEDGE_PREVIEW_EXPIRED", "edit preview expired")
        if ttl <= timedelta(0) or ttl > timedelta(minutes=15):
            raise ProtocolError("KNOWLEDGE_APPROVAL_INVALID", "edit approval TTL is invalid")
        unsigned: dict[str, Any] = {
            "schema_version": "hive.knowledge-edit-approval.v1",
            "approval_id": "approval:placeholder",
            "preview_id": preview_id,
            "preview_sha256": document_digest(preview),
            "actor_id": actor_id,
            "authorization_ref": authorization_ref,
            "key_id": self.authority.reviewer_key_id,
            "approved_at": _time(now),
            "expires_at": _time(now + ttl),
        }
        unsigned["approval_id"] = "approval:" + document_digest(
            {key: value for key, value in unsigned.items() if key != "approval_id"}
        )
        approval = sign_document(unsigned, self.authority.reviewer_private_key)
        path = self.receipts / f"knowledge-approval-edit-{preview_id[5:]}.json"
        _write_exact(path, canonical_bytes(approval) + b"\n")
        return approval

    def _verify_approval(
        self,
        preview: Mapping[str, Any],
        approval: Mapping[str, Any] | None,
        *,
        now,
        enforce_expiry: bool = True,
    ) -> dict[str, Any] | None:
        if preview["operation"] == "CREATE":
            if approval is not None:
                raise ProtocolError("KNOWLEDGE_APPROVAL_INVALID", "create preview does not accept replacement approval")
            return None
        if approval is None:
            raise ProtocolError("KNOWLEDGE_APPROVAL_REQUIRED", "replacement approval is required")
        document = copy.deepcopy(dict(approval))
        verify_document(document, self.authority.reviewer_public_keys)
        expected = {
            "schema_version", "approval_id", "preview_id", "preview_sha256", "actor_id",
            "authorization_ref", "key_id", "approved_at", "expires_at", "signature",
        }
        identity = "approval:" + document_digest(
            {key: value for key, value in document.items() if key not in {"approval_id", "signature"}}
        )
        if (
            set(document) != expected
            or document.get("schema_version") != "hive.knowledge-edit-approval.v1"
            or document.get("approval_id") != identity
            or document.get("preview_id") != preview["preview_id"]
            or document.get("preview_sha256") != document_digest(preview)
            or document.get("actor_id") not in self.authority.trusted_reviewer_actors
            or document.get("key_id") != document.get("signature", {}).get("key_id")
            or document.get("key_id") not in self.authority.reviewer_public_keys
        ):
            raise ProtocolError("KNOWLEDGE_APPROVAL_INVALID", "replacement approval binding is invalid")
        if enforce_expiry and now >= datetime.fromisoformat(
            document["expires_at"].replace("Z", "+00:00")
        ):
            raise ProtocolError(
                "KNOWLEDGE_APPROVAL_INVALID",
                "replacement approval binding is invalid",
            )
        return document

    def apply(
        self,
        preview_id: str,
        *,
        content: str,
        idempotency_key: str,
        approval: Mapping[str, Any] | None,
        now,
    ) -> dict[str, Any]:
        if _SHA256.fullmatch(idempotency_key) is None:
            raise ProtocolError("KNOWLEDGE_IDEMPOTENCY_INVALID", "idempotency key must be SHA-256")
        preview = self._load_preview(preview_id)
        if not isinstance(content, str):
            raise ProtocolError("KNOWLEDGE_CONTENT_INVALID", "Markdown content must be text")
        reject_credential_values({"content": content}, location="knowledge note")
        if hashlib.sha256(content.encode("utf-8")).hexdigest() != preview["content_sha256"]:
            raise ProtocolError("KNOWLEDGE_CONTENT_DRIFT", "content differs from preview")
        preview_expired = now >= datetime.fromisoformat(
            preview["expires_at"].replace("Z", "+00:00")
        )
        approval_document = self._verify_approval(
            preview, approval, now=now, enforce_expiry=False
        )
        operation_id = document_digest({"preview_id": preview_id, "idempotency_key": idempotency_key})
        journal_path = self.journals / f"edit-{operation_id}.json"
        self._prepare()
        with exclusive_lock(self.locks / "knowledge-edit.lock"):
            if journal_path.exists():
                journal = read_json(journal_path)
                verify_document(journal, {self.authority.promoter_key_id: self.authority.promoter_public_key})
                if (
                    journal.get("preview") != preview
                    or journal.get("idempotency_key") != idempotency_key
                    or journal.get("approval") != approval_document
                ):
                    raise ProtocolError("KNOWLEDGE_EDIT_JOURNAL_INVALID", "edit journal binding changed")
                if journal.get("state") == "TERMINAL":
                    return copy.deepcopy(journal["result"])
            else:
                if preview_expired:
                    raise ProtocolError(
                        "KNOWLEDGE_PREVIEW_EXPIRED", "edit preview expired"
                    )
                approval_document = self._verify_approval(
                    preview, approval_document, now=now
                )
                journal = {
                    "schema_version": "hive.knowledge-edit-journal.v1",
                    "operation_id": operation_id,
                    "state": "PREPARED",
                    "preview": preview,
                    "idempotency_key": idempotency_key,
                    "approval": approval_document,
                    "recorded_at": _time(now),
                    "result": None,
                }
                atomic_write_json(journal_path, sign_document(journal, self.authority.promoter_private_key), mode=0o600)
            self._fault("journal-written")
            target = self.root / preview["relative_path"]
            self._target(
                preview["project_id"],
                PurePosixPath(preview["relative_path"])
                .relative_to(PurePosixPath("prime") / "knowledge" / preview["project_id"])
                .as_posix(),
            )
            current_sha = hashlib.sha256(target.read_bytes()).hexdigest() if target.is_file() and not target.is_symlink() else None
            if current_sha == preview["content_sha256"]:
                pass
            elif current_sha != preview["expected_sha256"]:
                raise ProtocolError("KNOWLEDGE_VERSION_CONFLICT", "note changed after preview")
            else:
                _ensure_directory(target.parent, self.root)
                if target.is_symlink():
                    raise ProtocolError("KNOWLEDGE_PATH_INVALID", "note target is a symlink")
                atomic_write_bytes(target, content.encode("utf-8"))
            self._fault("note-written")
            receipt_path = self.receipts / f"knowledge-edit-{operation_id}.json"
            receipt = sign_document(
                {
                    "schema_version": "hive.knowledge-edit-receipt.v1",
                    "operation_id": operation_id,
                    "preview_id": preview_id,
                    "preview_sha256": document_digest(preview),
                    "approval_sha256": document_digest(approval_document) if approval_document is not None else None,
                    "idempotency_key": idempotency_key,
                    "relative_path": preview["relative_path"],
                    "before_sha256": preview["expected_sha256"],
                    "after_sha256": preview["content_sha256"],
                    "outcome": "APPLIED",
                    "recorded_at": journal["recorded_at"],
                },
                self.authority.promoter_private_key,
            )
            _write_exact(receipt_path, canonical_bytes(receipt) + b"\n")
            self._fault("receipt-written")
            result = {
                "outcome": "APPLIED",
                "relative_path": preview["relative_path"],
                "sha256": preview["content_sha256"],
                "receipt_path": receipt_path.relative_to(self.root).as_posix(),
            }
            terminal = copy.deepcopy(journal)
            terminal["state"] = "TERMINAL"
            terminal["result"] = result
            atomic_write_json(journal_path, sign_document(terminal, self.authority.promoter_private_key), mode=0o600)
            return result
