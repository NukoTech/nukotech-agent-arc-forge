"""Validation, canonicalization, hashing, and Ed25519 signatures."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from jsonschema import Draft202012Validator, FormatChecker


SCHEMA_BY_KIND = {
    "work-envelope": "work-envelope.v2.schema.json",
    "acknowledgment": "acknowledgment.v1.schema.json",
    "turn-receipt": "turn-receipt.v1.schema.json",
    "repository-roster": "repository-roster.v1.schema.json",
    "identity-context": "identity-context.v1.schema.json",
    "memory-proposal": "memory-proposal.v1.schema.json",
    "promotion-decision": "promotion-decision.v1.schema.json",
    "promotion-receipt": "promotion-receipt.v1.schema.json",
    "governance-release": "governance-release.v1.schema.json",
    "node-pin": "node-pin.v1.schema.json",
    "distribution-receipt": "distribution-receipt.v1.schema.json",
}


@dataclass(frozen=True)
class ProtocolError(Exception):
    """A fail-closed protocol result with a stable machine-readable code."""

    code: str
    detail: str
    exit_status: int = 2

    def __str__(self) -> str:
        return f"{self.code}: {self.detail}"


_B64URL_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def b64url_encode(raw: bytes) -> str:
    """Encode bytes as unpadded base64url."""

    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode_strict(value: str, *, expected_len: int | None = None) -> bytes:
    """Decode unpadded canonical base64url.

    Rejects padding, whitespace, non-alphabet characters, and encodings whose
    trailing bits are not the canonical re-encoding of the decoded bytes.
    When ``expected_len`` is set, also rejects a decoded payload of any other
    length. Fail closed with ``INVALID_BASE64URL``.
    """

    if not isinstance(value, str) or not all(ch in _B64URL_ALPHABET for ch in value):
        raise ProtocolError("INVALID_BASE64URL", "signature is not valid base64url")
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        raw = base64.urlsafe_b64decode(value + padding)
    except Exception as exc:  # pragma: no cover - exact decoder errors vary
        raise ProtocolError("INVALID_BASE64URL", "signature is not valid base64url") from exc
    if b64url_encode(raw) != value:
        raise ProtocolError("INVALID_BASE64URL", "signature is not valid base64url")
    if expected_len is not None and len(raw) != expected_len:
        raise ProtocolError("INVALID_BASE64URL", "signature is not valid base64url")
    return raw


# Public names are the API. These aliases keep existing private imports working.
_b64url_encode = b64url_encode
_b64url_decode = b64url_decode_strict


def canonical_bytes(document: Mapping[str, Any]) -> bytes:
    """Return RFC-8785-like stable JSON bytes for the supported data model."""

    return json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def unsigned_document(document: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(document)
    payload.pop("signature", None)
    return payload


def document_digest(document: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(document)).hexdigest()


def validate_identity_context(document: Mapping[str, Any]) -> None:
    """Validate structural and cross-dimension identity bindings."""

    validate_document(document, "identity-context")
    persona = document["persona"]
    surface = document["surface"]
    worker = document["agent_worker"]
    if persona["continuity_id"] != surface["persona_continuity_id"]:
        raise ProtocolError("IDENTITY_CONTINUITY_INVALID", "surface continuity does not bind its persona")
    if worker["acts_for_persona"] != persona["id"]:
        raise ProtocolError("IDENTITY_DELEGATION_INVALID", "worker does not name the persona it acts for")
    if persona["id"] in {
        worker["id"],
        document["model_runtime"]["runtime"],
        document["machine_node"]["machine"],
    }:
        raise ProtocolError("IDENTITY_DIMENSION_COLLAPSE", "persona cannot be worker, runtime, or machine")


def _is_unassigned_persona_value(value: object) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.strip().upper()
    if normalized.startswith("PERSONA:"):
        normalized = normalized.split(":", 1)[1]
    return normalized == "UNASSIGNED"


def require_assigned_persona(document: Mapping[str, Any]) -> None:
    """Refuse to route or sign when a governance role has no assigned persona."""

    persona = document["persona"]
    surface = document["surface"]
    worker = document["agent_worker"]
    if any(
        _is_unassigned_persona_value(value)
        for value in (
            persona["id"],
            persona["continuity_id"],
            surface["persona_continuity_id"],
            worker["acts_for_persona"],
        )
    ):
        raise ProtocolError(
            "PERSONA_UNASSIGNED",
            "governance role has no assigned persona; run `hive-local persona assign <name>`",
        )


def public_key_id(public_key: Ed25519PublicKey, *, full: bool = False) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return f"ed25519:{hashlib.sha256(raw).hexdigest()[: None if full else 24]}"


def generate_keypair(directory: Path, label: str) -> tuple[Path, Path, str]:
    """Create a disposable keypair with a mode-0600 private key."""

    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    key_id = public_key_id(public_key)

    private_path = directory / f"{label}.private.pem"
    public_path = directory / f"{label}.public.pem"
    _secure_create(
        private_path,
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        mode=0o600,
    )
    _secure_create(
        public_path,
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
        mode=0o644,
    )
    return private_path, public_path, key_id


def _secure_create(path: Path, payload: bytes, *, mode: int) -> None:
    """Create one regular file without following or replacing an existing path."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def load_private_key(path: Path) -> Ed25519PrivateKey:
    if path.is_symlink() or not path.is_file():
        raise ProtocolError("PRIVATE_KEY_BOUNDARY", "private key must be a regular file")
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise ProtocolError("PRIVATE_KEY_MODE", "private key permissions must be 0600")
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ProtocolError("PRIVATE_KEY_TYPE", "private key must be Ed25519")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    if path.is_symlink() or not path.is_file():
        raise ProtocolError("PUBLIC_KEY_BOUNDARY", "public key must be a regular file")
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ProtocolError("PUBLIC_KEY_TYPE", "public key must be Ed25519")
    return key


def sign_document(
    document: Mapping[str, Any], private_key: Ed25519PrivateKey
) -> dict[str, Any]:
    signed = unsigned_document(document)
    signature = private_key.sign(canonical_bytes(signed))
    signed["signature"] = {
        "algorithm": "Ed25519",
        "key_id": public_key_id(private_key.public_key()),
        "value": b64url_encode(signature),
    }
    return signed


def verify_document(
    document: Mapping[str, Any], public_keys: Mapping[str, Ed25519PublicKey]
) -> None:
    trusted = index_trusted_keys(public_keys)
    signature = document.get("signature")
    if not isinstance(signature, Mapping):
        raise ProtocolError("MISSING_SIGNATURE", "document has no signature object")
    if signature.get("algorithm") != "Ed25519":
        raise ProtocolError("UNSUPPORTED_SIGNATURE", "only Ed25519 is accepted")
    key_id = signature.get("key_id")
    if not isinstance(key_id, str) or key_id not in trusted:
        raise ProtocolError("UNKNOWN_SIGNING_KEY", "signature key is not trusted")
    value = signature.get("value")
    if not isinstance(value, str):
        raise ProtocolError("MISSING_SIGNATURE_VALUE", "signature value is absent")
    try:
        trusted[key_id].verify(
            b64url_decode_strict(value, expected_len=64),
            canonical_bytes(unsigned_document(document)),
        )
    except InvalidSignature as exc:
        raise ProtocolError("SIGNATURE_INVALID", "document signature does not verify") from exc


def validate_document(document: Mapping[str, Any], kind: str) -> None:
    schema_name = SCHEMA_BY_KIND.get(kind)
    if schema_name is None:
        raise ProtocolError("UNKNOWN_SCHEMA_KIND", f"unsupported document kind: {kind}")
    schema_path = files("hive_protocol.schemas").joinpath(schema_name)
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.path))
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.absolute_path) or "$"
        raise ProtocolError("SCHEMA_INVALID", f"{location}: {first.message}")


def _public_key_digest(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


def public_key_id_legacy(public_key: Ed25519PublicKey) -> str:
    return public_key_id(public_key, full=False)


def index_trusted_keys(
    public_keys: Mapping[str, Ed25519PublicKey],
) -> dict[str, Ed25519PublicKey]:
    """Index each trusted key under both the 24-hex and full fingerprints.

    ``public_key_id`` keeps the 24-hex default used by existing registries
    and already-signed protocol documents. ``full=True`` returns the
    untruncated ``ed25519:<64 hex>`` fingerprint used by new workspace
    integrity signatures. ``verify_document`` accepts both forms.
    """

    expanded = dict(public_keys)
    for key in public_keys.values():
        expanded[public_key_id(key, full=False)] = key
        expanded[public_key_id(key, full=True)] = key
    return expanded
