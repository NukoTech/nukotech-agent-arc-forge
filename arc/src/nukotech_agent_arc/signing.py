"""Optional detached Ed25519 signatures for package manifests and receipts.

Signing depends on the optional extra ``nukotech-agent-arc[signing]`` (the
``cryptography`` library). Compose, package, and unsigned verify stay on the
standard library.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import zipfile
from pathlib import Path
from typing import Any, Iterable, Mapping

from .digests import digests_equal
from .receipts import canonical_json_bytes


SIGNATURE_SCHEMA = "nukotech.agent_arc.package_signature.v1"
TRUSTED_KEYS_SCHEMA = "nukotech.agent_arc.trusted_keys.v1"
SIGNATURE_ALGORITHM = "Ed25519"
SIGNATURE_SUFFIX = ".SIGNATURE.json"
REQUIRED_RECEIPT_ENTRY = "composition-receipt.json"
KEY_ID_PATTERN = re.compile(r"^ed25519:[0-9a-f]{64}$")
HEX64_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_BEGIN_PUBLIC = "-----BEGIN PUBLIC KEY-----"
_END_PUBLIC = "-----END PUBLIC KEY-----"


class SigningError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def default_signature_path(package_path: Path) -> Path:
    path = Path(package_path)
    return path.with_name(f"{path.stem}{SIGNATURE_SUFFIX}")


def _require_crypto():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:
        raise SigningError(
            "signing_dependency_missing",
            "package signing requires the optional extra nukotech-agent-arc[signing]",
        ) from exc
    return InvalidSignature, serialization, Ed25519PrivateKey, Ed25519PublicKey


def generate_private_key():
    """Generate an Ed25519 private key. Requires the signing extra."""

    _, _, Ed25519PrivateKey, _ = _require_crypto()
    return Ed25519PrivateKey.generate()


def _raw_public_bytes(public_key) -> bytes:
    _, serialization, _, _ = _require_crypto()
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def key_id_for(public_key) -> str:
    """Return ``ed25519:`` plus the full SHA-256 of the raw 32-byte public key."""

    return "ed25519:" + hashlib.sha256(_raw_public_bytes(public_key)).hexdigest()


def public_key_pem_bytes(public_key) -> bytes:
    _, serialization, _, _ = _require_crypto()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def private_key_pem_bytes(private_key) -> bytes:
    _, serialization, _, _ = _require_crypto()
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_private_key(path: Path):
    _, serialization, Ed25519PrivateKey, _ = _require_crypto()
    try:
        data = Path(path).read_bytes()
        key = serialization.load_pem_private_key(data, None)
    except SigningError:
        raise
    except Exception as exc:
        raise SigningError("private_key_unreadable", "private signing key could not be loaded") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise SigningError("private_key_invalid", "signing key must be an Ed25519 private key")
    return key


def load_public_key(path: Path):
    keys = load_public_keys_from_pem_file(path)
    if len(keys) != 1:
        raise SigningError("public_key_invalid", "pubkey file must contain exactly one Ed25519 public key")
    return next(iter(keys.values()))


def _load_public_key_from_pem(data: bytes):
    _, serialization, _, Ed25519PublicKey = _require_crypto()
    try:
        key = serialization.load_pem_public_key(data)
    except Exception as exc:
        raise SigningError("public_key_invalid", "public signing key could not be loaded") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise SigningError("public_key_invalid", "trusted key must be an Ed25519 public key")
    return key


def _iter_pem_blocks(text: str) -> Iterable[bytes]:
    start = 0
    while True:
        begin = text.find(_BEGIN_PUBLIC, start)
        if begin < 0:
            return
        end = text.find(_END_PUBLIC, begin)
        if end < 0:
            raise SigningError("public_key_invalid", "public key PEM block is truncated")
        end += len(_END_PUBLIC)
        yield text[begin:end].encode("utf-8") + b"\n"
        start = end


def load_public_keys_from_pem_file(path: Path) -> dict[str, Any]:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise SigningError("public_key_unreadable", "public key file could not be read") from exc
    keys: dict[str, Any] = {}
    for block in _iter_pem_blocks(text):
        key = _load_public_key_from_pem(block)
        ident = key_id_for(key)
        if ident in keys:
            raise SigningError("duplicate_trusted_key", "trusted key list contains a duplicate key id")
        keys[ident] = key
    if not keys:
        raise SigningError("public_key_invalid", "public key file did not contain an Ed25519 public key")
    return keys


def load_trusted_keys(path: Path) -> dict[str, Any]:
    """Load a PEM bundle or a ``trusted_keys.v1`` JSON map of public keys."""

    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise SigningError("trusted_keys_unreadable", "trusted keys file could not be read") from exc
    stripped = raw.lstrip()
    if stripped.startswith(b"{") or stripped.startswith(b"["):
        return _load_trusted_keys_json(raw)
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise SigningError("trusted_keys_unreadable", "trusted keys file could not be read") from exc
    return _keys_from_pem_text(text, source_code="trusted_keys_invalid")


def _keys_from_pem_text(text: str, *, source_code: str) -> dict[str, Any]:
    keys: dict[str, Any] = {}
    blocks = list(_iter_pem_blocks(text))
    if not blocks:
        raise SigningError(source_code, "trusted keys file did not contain an Ed25519 public key")
    for block in blocks:
        key = _load_public_key_from_pem(block)
        ident = key_id_for(key)
        if ident in keys:
            raise SigningError("duplicate_trusted_key", "trusted key list contains a duplicate key id")
        keys[ident] = key
    return keys


def _load_trusted_keys_json(raw: bytes) -> dict[str, Any]:
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SigningError("trusted_keys_unreadable", "trusted keys file could not be parsed") from exc
    if not isinstance(document, Mapping):
        raise SigningError("trusted_keys_invalid", "trusted keys file must be an object")
    schema = document.get("schema")
    entries = document.get("keys")
    if schema != TRUSTED_KEYS_SCHEMA or not isinstance(entries, list) or not entries:
        raise SigningError("trusted_keys_invalid", "trusted keys file is not a valid key list")
    if set(document) - {"schema", "keys"}:
        raise SigningError("trusted_keys_invalid", "trusted keys file has unexpected fields")
    keys: dict[str, Any] = {}
    for item in entries:
        if not isinstance(item, Mapping) or "public_key_pem" not in item:
            raise SigningError("trusted_keys_invalid", "trusted keys entry is invalid")
        if set(item) - {"key_id", "public_key_pem"}:
            raise SigningError("trusted_keys_invalid", "trusted keys entry has unexpected fields")
        pem = item["public_key_pem"]
        if not isinstance(pem, str):
            raise SigningError("trusted_keys_invalid", "trusted keys entry is invalid")
        key = _load_public_key_from_pem(pem.encode("utf-8"))
        ident = key_id_for(key)
        declared = item.get("key_id")
        if declared is not None and (not isinstance(declared, str) or not digests_equal(declared, ident)):
            raise SigningError("trusted_keys_invalid", "declared key id does not match the public key")
        if ident in keys:
            raise SigningError("duplicate_trusted_key", "trusted key list contains a duplicate key id")
        keys[ident] = key
    return keys


def _signature_payload(key_id: str, manifest_sha256: str, receipt_sha256: str) -> dict[str, str]:
    return {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "manifest_sha256": manifest_sha256,
        "receipt_sha256": receipt_sha256,
        "schema": SIGNATURE_SCHEMA,
    }


def _manifest_digest(manifest_path: Path) -> str:
    try:
        data = Path(manifest_path).read_bytes()
    except OSError as exc:
        raise SigningError("manifest_unreadable", "package manifest could not be read") from exc
    return hashlib.sha256(data).hexdigest()


def _receipt_bytes(package_path: Path) -> bytes:
    try:
        with zipfile.ZipFile(package_path) as archive:
            if REQUIRED_RECEIPT_ENTRY not in archive.namelist():
                raise SigningError("receipt_missing", "package is missing composition-receipt.json")
            return archive.read(REQUIRED_RECEIPT_ENTRY)
    except SigningError:
        raise
    except (OSError, zipfile.BadZipFile) as exc:
        raise SigningError("package_unreadable", "package could not be read") from exc


def sign_package(
    package_path: Path,
    manifest_path: Path,
    private_key_path: Path,
    signature_path: Path | None = None,
) -> Path:
    """Write a detached signature receipt over the manifest and composition receipt."""

    private_key = load_private_key(private_key_path)
    public_key = private_key.public_key()
    ident = key_id_for(public_key)
    payload = _signature_payload(
        ident,
        _manifest_digest(manifest_path),
        hashlib.sha256(_receipt_bytes(package_path)).hexdigest(),
    )
    signature = private_key.sign(canonical_json_bytes(payload))
    document = {
        **payload,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    destination = Path(signature_path) if signature_path is not None else default_signature_path(package_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(canonical_json_bytes(document))
    return destination


def _collect_trusted_keys(
    public_key_path: Path | None,
    trusted_keys_path: Path | None,
) -> dict[str, Any]:
    keys: dict[str, Any] = {}
    if public_key_path is not None:
        keys.update(load_public_keys_from_pem_file(public_key_path))
    if trusted_keys_path is not None:
        loaded = load_trusted_keys(trusted_keys_path)
        overlap = set(keys) & set(loaded)
        if overlap:
            raise SigningError("duplicate_trusted_key", "trusted key list contains a duplicate key id")
        keys.update(loaded)
    return keys


def verify_package_signature_issues(
    package_path: Path,
    manifest_path: Path,
    *,
    signature_path: Path | None = None,
    public_key_path: Path | None = None,
    trusted_keys_path: Path | None = None,
    require_signature: bool = False,
) -> tuple[str, ...]:
    """Return issue codes for a detached signature. Fail closed on any defect."""

    required = require_signature or public_key_path is not None or trusted_keys_path is not None
    resolved = Path(signature_path) if signature_path is not None else default_signature_path(package_path)
    if not required and signature_path is None:
        return ()
    if not required and signature_path is not None and public_key_path is None and trusted_keys_path is None:
        return ("trusted_keys_required",)
    try:
        trusted = _collect_trusted_keys(public_key_path, trusted_keys_path)
    except SigningError as exc:
        return (exc.code,)
    if not trusted:
        return ("trusted_keys_required",)
    if not resolved.is_file():
        return ("signature_missing",)
    try:
        _verify_signature_document(resolved, package_path, manifest_path, trusted)
    except SigningError as exc:
        return (exc.code,)
    return ()


def _verify_signature_document(
    signature_path: Path,
    package_path: Path,
    manifest_path: Path,
    trusted: Mapping[str, Any],
) -> None:
    InvalidSignature, _, _, _ = _require_crypto()
    try:
        raw = Path(signature_path).read_bytes()
        document = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SigningError("signature_unreadable", "signature receipt could not be read") from exc
    if not isinstance(document, Mapping):
        raise SigningError("signature_invalid", "signature receipt is not a valid object")
    allowed = {"algorithm", "key_id", "manifest_sha256", "receipt_sha256", "schema", "signature"}
    if set(document) != allowed:
        raise SigningError("signature_invalid", "signature receipt fields are invalid")
    payload = _signature_payload(
        str(document.get("key_id", "")),
        str(document.get("manifest_sha256", "")),
        str(document.get("receipt_sha256", "")),
    )
    if (
        document.get("schema") != SIGNATURE_SCHEMA
        or document.get("algorithm") != SIGNATURE_ALGORITHM
        or not KEY_ID_PATTERN.fullmatch(payload["key_id"])
        or not HEX64_PATTERN.fullmatch(payload["manifest_sha256"])
        or not HEX64_PATTERN.fullmatch(payload["receipt_sha256"])
        or not isinstance(document.get("signature"), str)
    ):
        raise SigningError("signature_invalid", "signature receipt fields are invalid")

    actual_manifest = _manifest_digest(manifest_path)
    if not digests_equal(payload["manifest_sha256"], actual_manifest):
        raise SigningError("signature_manifest_mismatch", "signature does not cover this manifest")
    try:
        actual_receipt = hashlib.sha256(_receipt_bytes(package_path)).hexdigest()
    except SigningError:
        raise
    if not digests_equal(payload["receipt_sha256"], actual_receipt):
        raise SigningError("signature_receipt_mismatch", "signature does not cover this composition receipt")

    public_key = trusted.get(payload["key_id"])
    if public_key is None:
        raise SigningError("untrusted_signing_key", "signature key id is not in the trusted key set")
    try:
        signature = base64.b64decode(document["signature"], validate=True)
    except (ValueError, TypeError) as exc:
        raise SigningError("signature_invalid", "signature value is not valid base64") from exc
    try:
        public_key.verify(signature, canonical_json_bytes(payload))
    except InvalidSignature as exc:
        raise SigningError("signature_invalid", "signature verification failed") from exc
