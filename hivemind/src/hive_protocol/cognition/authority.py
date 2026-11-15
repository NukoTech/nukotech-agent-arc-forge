"""Separate signed proposer, reviewer, and promoter roles for product memory."""

from __future__ import annotations

import copy
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from hive_protocol.core import (
    ProtocolError,
    generate_keypair,
    load_private_key,
    load_public_key,
    public_key_id,
    sign_document,
    verify_document,
)
from hive_protocol.storage import atomic_write_bytes, exclusive_lock

from .models import MemoryCandidate, MemoryReviewDecision, cognition_document_digest


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _format_time(value: datetime) -> str:
    if value.tzinfo is None:
        raise ProtocolError("COGNITION_REVIEW_TIME_INVALID", "review time lacks timezone")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _secure_directory(path: Path, boundary: Path, *, mode: int = 0o700) -> Path:
    if path != boundary and boundary not in path.parents:
        raise ProtocolError("COGNITION_KEY_BOUNDARY", "key directory escapes Hive root")
    current = boundary
    if current.is_symlink() or not current.is_dir():
        raise ProtocolError("COGNITION_KEY_BOUNDARY", "Hive root is not a safe directory")
    for part in path.relative_to(boundary).parts:
        current /= part
        if current.is_symlink():
            raise ProtocolError("COGNITION_KEY_BOUNDARY", "key path contains a symlink")
        if current.exists() and not current.is_dir():
            raise ProtocolError("COGNITION_KEY_BOUNDARY", "key path contains a non-directory")
        current.mkdir(exist_ok=True, mode=mode)
        if current.is_symlink() or current.stat().st_uid != os.geteuid():
            raise ProtocolError("COGNITION_KEY_BOUNDARY", "key directory is not owned")
        os.chmod(current, mode)
    return path


class CognitionAuthority:
    """Bootstraps and enforces distinct local attended cognition roles."""

    def __init__(
        self,
        root: Path,
        *,
        trusted_reviewer_actors: Iterable[str] | None = None,
    ) -> None:
        raw = root.expanduser()
        for candidate in (raw, *raw.parents):
            if candidate.is_symlink():
                raise ProtocolError(
                    "COGNITION_KEY_BOUNDARY", "Hive or key path contains a symlink"
                )
        raw.mkdir(parents=True, exist_ok=True)
        self.root = raw.resolve(strict=True)
        self.key_root = self.root / ".hive" / "keys" / "cognition"
        _secure_directory(self.key_root, self.root)
        self.trusted_reviewer_actors = frozenset(
            trusted_reviewer_actors or {"local-operator", "Owner"}
        )
        if not self.trusted_reviewer_actors or any(
            _ID.fullmatch(value) is None for value in self.trusted_reviewer_actors
        ):
            raise ProtocolError(
                "COGNITION_REVIEWER_INVALID", "trusted reviewer actor set is invalid"
            )
        with exclusive_lock(self.key_root / ".bootstrap.lock"):
            self._proposer_private, self._proposer_public = self._load_role("proposer")
            self._reviewer_private, self._reviewer_public = self._load_role("reviewer")
            self._promoter_private, self._promoter_public = self._load_role("promoter")
        self.public_trust_root = (
            self.root / ".hive" / "provenance" / "cognition-public-keys"
        )
        _secure_directory(self.public_trust_root, self.root)
        self._persist_public_role("proposer", self._proposer_public)
        self._persist_public_role("reviewer", self._reviewer_public)
        self._persist_public_role("promoter", self._promoter_public)
        self.proposer_public_keys = self._load_public_role("proposer")
        self.reviewer_public_keys = self._load_public_role("reviewer")
        self.promoter_public_keys = self._load_public_role("promoter")
        if (
            set(self.proposer_public_keys) & set(self.reviewer_public_keys)
            or set(self.proposer_public_keys) & set(self.promoter_public_keys)
            or set(self.reviewer_public_keys) & set(self.promoter_public_keys)
        ):
            raise ProtocolError(
                "COGNITION_ROLE_REUSE",
                "portable proposer, reviewer, and promoter trust sets must differ",
            )
        key_ids = {
            self.proposer_key_id,
            self.reviewer_key_id,
            self.promoter_key_id,
        }
        if len(key_ids) != 3:
            raise ProtocolError(
                "COGNITION_ROLE_REUSE", "proposer, reviewer, and promoter keys must differ"
            )

    def _public_role_path(self, role: str, key_id: str) -> Path:
        return self.public_trust_root / f"{role}-{key_id.replace(':', '-')}.public.pem"

    def _persist_public_role(self, role: str, public_key: Ed25519PublicKey) -> None:
        from cryptography.hazmat.primitives import serialization

        key_id = public_key_id(public_key)
        path = self._public_role_path(role, key_id)
        payload = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if path.exists():
            if path.is_symlink() or not path.is_file() or path.read_bytes() != payload:
                raise ProtocolError(
                    "COGNITION_KEY_MISMATCH", "portable public cognition key changed"
                )
            return
        atomic_write_bytes(path, payload, mode=0o644)

    def _load_public_role(self, role: str) -> dict[str, Ed25519PublicKey]:
        trusted: dict[str, Ed25519PublicKey] = {}
        for path in sorted(self.public_trust_root.glob(f"{role}-ed25519-*.public.pem")):
            if (
                path.is_symlink()
                or not path.is_file()
                or path.stat().st_uid != os.geteuid()
            ):
                raise ProtocolError(
                    "COGNITION_KEY_BOUNDARY", "portable public cognition key is unsafe"
                )
            public = load_public_key(path)
            key_id = public_key_id(public)
            if path != self._public_role_path(role, key_id):
                raise ProtocolError(
                    "COGNITION_KEY_MISMATCH", "portable public cognition key name changed"
                )
            trusted[key_id] = public
        return trusted

    def _load_role(
        self, label: str
    ) -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
        private_path = self.key_root / f"{label}.private.pem"
        public_path = self.key_root / f"{label}.public.pem"
        if private_path.exists() != public_path.exists():
            raise ProtocolError(
                "COGNITION_KEY_BOUNDARY", f"incomplete cognition keypair: {label}"
            )
        if not private_path.exists():
            generate_keypair(self.key_root, label)
        private = load_private_key(private_path)
        public = load_public_key(public_path)
        if public_key_id(private.public_key()) != public_key_id(public):
            raise ProtocolError(
                "COGNITION_KEY_MISMATCH", f"cognition keypair does not match: {label}"
            )
        return private, public

    @property
    def proposer_private_key(self) -> Ed25519PrivateKey:
        return self._proposer_private

    @property
    def reviewer_private_key(self) -> Ed25519PrivateKey:
        return self._reviewer_private

    @property
    def promoter_private_key(self) -> Ed25519PrivateKey:
        return self._promoter_private

    @property
    def proposer_public_key(self) -> Ed25519PublicKey:
        return self._proposer_public

    @property
    def reviewer_public_key(self) -> Ed25519PublicKey:
        return self._reviewer_public

    @property
    def promoter_public_key(self) -> Ed25519PublicKey:
        return self._promoter_public

    @property
    def proposer_key_id(self) -> str:
        return public_key_id(self._proposer_public)

    @property
    def reviewer_key_id(self) -> str:
        return public_key_id(self._reviewer_public)

    @property
    def promoter_key_id(self) -> str:
        return public_key_id(self._promoter_public)

    def sign_proposal(self, document: Mapping[str, Any]) -> dict[str, Any]:
        signed = sign_document(document, self._proposer_private)
        self.verify_proposal(signed)
        return signed

    def verify_proposal(self, document: Mapping[str, Any]) -> dict[str, Any]:
        candidate = copy.deepcopy(dict(document))
        expected_fields = {
            "schema_version",
            "operation_id",
            "candidate_id",
            "candidate_sha256",
            "proposed_candidate_sha256",
            "event_id",
            "event_sha256",
            "outcome",
            "owned_paths",
            "prime_write",
            "recorded_at",
            "signature",
        }
        if (
            set(candidate) != expected_fields
            or candidate.get("schema_version")
            != "hive.memory-candidate-receipt.v1"
            or _SHA256.fullmatch(str(candidate.get("operation_id", ""))) is None
            or not isinstance(candidate.get("candidate_id"), str)
            or not candidate["candidate_id"].startswith("memory:")
            or _SHA256.fullmatch(str(candidate.get("candidate_sha256", ""))) is None
            or _SHA256.fullmatch(
                str(candidate.get("proposed_candidate_sha256", ""))
            )
            is None
            or candidate.get("outcome") not in {"STAGED", "DUPLICATE_PROVENANCE"}
            or candidate.get("prime_write") is not False
            or not isinstance(candidate.get("owned_paths"), list)
        ):
            raise ProtocolError(
                "COGNITION_PROPOSAL_RECEIPT_INVALID",
                "proposal receipt structure is invalid",
            )
        for value in candidate["owned_paths"]:
            path = PurePosixPath(value)
            if (
                not isinstance(value, str)
                or path.is_absolute()
                or not path.parts
                or any(part in {"", ".", ".."} for part in path.parts)
                or path.parts[0] not in {"staging", ".hive"}
            ):
                raise ProtocolError(
                    "COGNITION_PROPOSAL_RECEIPT_INVALID",
                    "proposal receipt owns an unsafe path",
                )
        verify_document(candidate, self.proposer_public_keys)
        if candidate["signature"]["key_id"] not in self.proposer_public_keys:
            raise ProtocolError(
                "COGNITION_ROLE_REUSE", "proposal signer is not the proposer role"
            )
        return candidate

    def create_review(
        self,
        candidate: MemoryCandidate,
        *,
        outcome: str,
        actor_id: str,
        authorization_ref: str,
        corrections: list[str],
        now: datetime,
        ttl: timedelta = timedelta(minutes=15),
    ) -> MemoryReviewDecision:
        if actor_id not in self.trusted_reviewer_actors:
            raise ProtocolError(
                "COGNITION_REVIEWER_UNTRUSTED", "reviewer actor is not authorized"
            )
        if outcome not in {"APPROVED", "REJECTED", "CHANGES_REQUESTED"}:
            raise ProtocolError("COGNITION_REVIEW_OUTCOME_INVALID", "review outcome is invalid")
        if not isinstance(ttl, timedelta) or ttl <= timedelta(0) or ttl > timedelta(hours=1):
            raise ProtocolError("COGNITION_REVIEW_EXPIRY_INVALID", "review TTL is invalid")
        if outcome == "APPROVED" and corrections:
            raise ProtocolError(
                "COGNITION_REVIEW_CORRECTION_INVALID",
                "approved review cannot contain requested corrections",
            )
        document: dict[str, Any] = {
            "schema_version": "hive.memory-review-decision.v1",
            "decision_id": "review:placeholder",
            "candidate_id": candidate.candidate_id,
            "candidate_sha256": candidate.digest,
            "tenant_id": candidate.tenant_id,
            "project_id": candidate.project_id,
            "experience_scope": candidate.experience_scope,
            "outcome": outcome,
            "corrections": list(corrections),
            "reviewer": {
                "actor_id": actor_id,
                "authorization_ref": authorization_ref,
                "key_id": self.reviewer_key_id,
            },
            "reviewed_at": _format_time(now),
            "expires_at": _format_time(now + ttl),
        }
        document["decision_id"] = MemoryReviewDecision.identity_for(document)
        return MemoryReviewDecision.from_dict(
            sign_document(document, self._reviewer_private),
            verified_by=self.reviewer_public_keys,
        )

    def verify_review(
        self,
        candidate: MemoryCandidate,
        decision: MemoryReviewDecision | Mapping[str, Any],
        proposal_receipt: Mapping[str, Any],
        *,
        now: datetime,
    ) -> MemoryReviewDecision:
        review = (
            decision
            if isinstance(decision, MemoryReviewDecision)
            else MemoryReviewDecision.from_dict(
                decision, verified_by=self.reviewer_public_keys
            )
        )
        proposal = self.verify_proposal(proposal_receipt)
        if proposal["signature"]["key_id"] == review.signature["key_id"]:
            raise ProtocolError(
                "COGNITION_ROLE_REUSE", "proposal and review use the same signing role"
            )
        verify_document(review.as_dict(), self.reviewer_public_keys)
        if (
            review.reviewer["key_id"] != review.signature["key_id"]
            or review.signature["key_id"] not in self.reviewer_public_keys
        ):
            raise ProtocolError(
                "COGNITION_ROLE_REUSE", "review signer is not the declared reviewer role"
            )
        if review.reviewer["actor_id"] not in self.trusted_reviewer_actors:
            raise ProtocolError(
                "COGNITION_REVIEWER_UNTRUSTED", "reviewer actor is not authorized"
            )
        if (
            review.candidate_id != candidate.candidate_id
            or review.candidate_sha256 != candidate.digest
            or review.tenant_id != candidate.tenant_id
            or review.project_id != candidate.project_id
            or review.experience_scope != candidate.experience_scope
            or proposal["candidate_id"] != candidate.candidate_id
            or proposal["candidate_sha256"] != candidate.digest
        ):
            raise ProtocolError(
                "COGNITION_REVIEW_BINDING_MISMATCH",
                "review or proposal does not bind the exact candidate and scope",
            )
        if now.tzinfo is None:
            raise ProtocolError("COGNITION_REVIEW_TIME_INVALID", "review time lacks timezone")
        expires = datetime.fromisoformat(review.expires_at.replace("Z", "+00:00"))
        if now >= expires:
            raise ProtocolError("COGNITION_REVIEW_EXPIRED", "review decision expired")
        return review
