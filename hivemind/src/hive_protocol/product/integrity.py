"""Workspace integrity helpers: Ed25519 signing for receipts and export manifests.

Kept small and importable after a no-history export (paths may later move from
``src/hive_protocol/product`` to ``hive/...``). Private keys stay under
``.hive/workspace-keys/`` (gitignored, not exported). ``.hive/keys/`` remains the agent/cognition key root so existing tests can still create that directory after ``create()``. Public keys used to verify historical receipts
live in the portable ``.hive/integrity-keys/`` keyring.
"""

from __future__ import annotations

import hmac
import json
import warnings
from pathlib import Path
from typing import Any, Iterable, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from hive_protocol.core import (
    ProtocolError,
    canonical_bytes,
    document_digest,
    generate_keypair,
    index_trusted_keys,
    load_private_key,
    load_public_key,
    public_key_id,
    sign_document,
    unsigned_document,
    verify_document,
)
from hive_protocol.storage import atomic_write_json, read_json


WORKSPACE_KEY_LABEL = "workspace"
WORKSPACE_PRIVATE_DIR = Path(".hive") / "workspace-keys"
INTEGRITY_KEYRING_RELATIVE = Path(".hive") / "integrity-keys" / "public-keys.json"
EXPORT_SIGNATURE_MEMBER = "manifest.sig.json"
EXPORT_SIGNATURE_SCHEMA = "nukotech.hive-local.export-signature.v1"
INTEGRITY_KEYRING_SCHEMA = "nukotech.hive-local.integrity-keys.v1"
MAX_EXPORT_SIGNATURE_BYTES = 64 * 1024
COGNITION_RECEIPT_SCHEMAS = frozenset(
    {
        "hive.memory-candidate-receipt.v1",
        "hive.memory-promotion-receipt.v1",
        "hive.memory-deletion-approval.v1",
        "hive.memory-deletion-receipt.v1",
        "hive.knowledge-edit-approval.v1",
        "hive.knowledge-edit-receipt.v1",
    }
)
PRODUCT_RECEIPT_SCHEMA = "nukotech.hive-local.receipt.v1"


def digests_equal(left: str, right: object) -> bool:
    """Constant-time hex (or other string) digest compare; length mismatch is False."""

    if not isinstance(right, str) or len(left) != len(right):
        return False
    return hmac.compare_digest(left, right)


def full_public_key_id(public_key: Ed25519PublicKey) -> str:
    """Full SHA-256 fingerprint; used for new workspace/export signatures."""

    return public_key_id(public_key, full=True)


def sign_integrity_document(
    document: Mapping[str, Any], signer: Ed25519PrivateKey
) -> dict[str, Any]:
    """Like ``sign_document``, but the key id is the full public-key fingerprint."""

    signed = unsigned_document(document)
    signature = signer.sign(canonical_bytes(signed))
    signed["signature"] = {
        "algorithm": "Ed25519",
        "key_id": full_public_key_id(signer.public_key()),
        "value": _b64url_encode(signature),
    }
    return signed


def _b64url_encode(raw: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def public_key_pem(public_key: Ed25519PublicKey) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def public_key_from_pem(pem: str | bytes) -> Ed25519PublicKey:
    payload = pem.encode("ascii") if isinstance(pem, str) else pem
    key = serialization.load_pem_public_key(payload)
    if not isinstance(key, Ed25519PublicKey):
        raise ProtocolError("PUBLIC_KEY_TYPE", "public key must be Ed25519")
    return key


def workspace_private_dir(root: Path) -> Path:
    return root.expanduser().resolve() / WORKSPACE_PRIVATE_DIR


def integrity_keyring_path(root: Path) -> Path:
    return root.expanduser().resolve() / INTEGRITY_KEYRING_RELATIVE


def ensure_workspace_keypair(root: Path) -> tuple[Ed25519PrivateKey, Ed25519PublicKey, str]:
    """Create or load the workspace signing key. Private material stays under keys/."""

    directory = workspace_private_dir(root)
    private_path = directory / f"{WORKSPACE_KEY_LABEL}.private.pem"
    public_path = directory / f"{WORKSPACE_KEY_LABEL}.public.pem"
    if private_path.exists() or public_path.exists():
        if not private_path.is_file() or not public_path.is_file():
            raise ProtocolError(
                "WORKSPACE_KEY_BOUNDARY",
                "workspace signing keypair is incomplete",
            )
        private_key = load_private_key(private_path)
        public_key = load_public_key(public_path)
        if full_public_key_id(private_key.public_key()) != full_public_key_id(public_key):
            raise ProtocolError(
                "WORKSPACE_KEY_MISMATCH",
                "workspace signing keypair does not match",
            )
        return private_key, public_key, full_public_key_id(public_key)
    directory.parent.mkdir(parents=True, exist_ok=True)
    generate_keypair(directory, WORKSPACE_KEY_LABEL)
    private_key = load_private_key(private_path)
    public_key = load_public_key(public_path)
    return private_key, public_key, full_public_key_id(public_key)


def publish_workspace_public_key(root: Path) -> None:
    """Add the current workspace public key to the portable integrity keyring."""

    _, public_key, key_id = ensure_workspace_keypair(root)
    path = integrity_keyring_path(root)
    if path.exists():
        document = read_json(path)
    else:
        document = {"schema_version": INTEGRITY_KEYRING_SCHEMA, "keys": {}}
    if (
        document.get("schema_version") != INTEGRITY_KEYRING_SCHEMA
        or not isinstance(document.get("keys"), dict)
    ):
        raise ProtocolError(
            "INTEGRITY_KEYRING_INVALID",
            "workspace integrity keyring is malformed",
        )
    record = {"public_key_pem": public_key_pem(public_key)}
    existing = document["keys"].get(key_id)
    if existing is not None and existing != record:
        raise ProtocolError(
            "INTEGRITY_KEYRING_CONFLICT",
            "workspace public key id is bound to different material",
        )
    # Also index the legacy 24-hex id so older verifiers can look it up.
    legacy_id = public_key_id(public_key)
    if key_id not in document["keys"] or legacy_id not in document["keys"]:
        document["keys"][key_id] = record
        document["keys"].setdefault(legacy_id, record)
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(path, document)


def _keys_from_keyring(path: Path) -> dict[str, Ed25519PublicKey]:
    trusted: dict[str, Ed25519PublicKey] = {}
    if not path.exists():
        return trusted
    document = read_json(path)
    if (
        document.get("schema_version") != INTEGRITY_KEYRING_SCHEMA
        or not isinstance(document.get("keys"), dict)
    ):
        raise ProtocolError(
            "INTEGRITY_KEYRING_INVALID",
            "workspace integrity keyring is malformed",
        )
    for key_id, record in document["keys"].items():
        if not isinstance(key_id, str) or not isinstance(record, dict):
            raise ProtocolError(
                "INTEGRITY_KEYRING_INVALID",
                "workspace integrity keyring entry is invalid",
            )
        key = public_key_from_pem(str(record.get("public_key_pem", "")))
        if key_id not in {public_key_id(key), full_public_key_id(key)}:
            raise ProtocolError(
                "INTEGRITY_KEYRING_CONFLICT",
                "workspace public key bytes do not match their key id",
            )
        trusted[key_id] = key
    return trusted


def _load_pem_dir(directory: Path, pattern: str = "*.public.pem") -> dict[str, Ed25519PublicKey]:
    trusted: dict[str, Ed25519PublicKey] = {}
    if not directory.exists():
        return trusted
    if directory.is_symlink() or not directory.is_dir():
        raise ProtocolError("PUBLIC_KEY_BOUNDARY", f"public key directory is unsafe: {directory}")
    for path in sorted(directory.rglob(pattern)):
        if path.is_symlink() or not path.is_file():
            raise ProtocolError("PUBLIC_KEY_BOUNDARY", f"public key is unsafe: {path}")
        key = load_public_key(path)
        trusted[full_public_key_id(key)] = key
        trusted[public_key_id(key)] = key
    return trusted


def trusted_workspace_keys(root: Path) -> dict[str, Ed25519PublicKey]:
    """Public keys that may sign product receipts and export manifests."""

    root = root.expanduser().resolve()
    trusted = _keys_from_keyring(integrity_keyring_path(root))
    public_path = workspace_private_dir(root) / f"{WORKSPACE_KEY_LABEL}.public.pem"
    if public_path.is_file() and not public_path.is_symlink():
        key = load_public_key(public_path)
        trusted[full_public_key_id(key)] = key
        trusted[public_key_id(key)] = key
    return index_trusted_keys(trusted)


def trusted_agent_public_keys(root: Path) -> dict[str, Ed25519PublicKey]:
    """Workspace, cognition, workflow, and agent public keys used at index rebuild."""

    root = root.expanduser().resolve()
    trusted = trusted_workspace_keys(root)
    trusted.update(_load_pem_dir(root / ".hive" / "provenance" / "cognition-public-keys"))
    trusted.update(_load_pem_dir(root / ".hive" / "keys" / "cognition"))
    trusted.update(_load_pem_dir(root / ".hive" / "keys" / "agents"))
    workflow_path = root / ".hive" / "workflow-keys" / "public-keys.json"
    if workflow_path.exists():
        document = read_json(workflow_path)
        keys = document.get("keys") if isinstance(document, dict) else None
        if document.get("schema_version") != "hive.workflow-public-keys.v1" or not isinstance(keys, dict):
            raise ProtocolError(
                "WORKFLOW_PUBLIC_KEY_REGISTRY_INVALID",
                "workflow public-key registry is malformed",
            )
        for key_id, record in keys.items():
            if not isinstance(record, dict):
                raise ProtocolError(
                    "WORKFLOW_PUBLIC_KEY_REGISTRY_INVALID",
                    "workflow public-key registry is malformed",
                )
            key = public_key_from_pem(str(record.get("public_key_pem", "")))
            trusted[str(key_id)] = key
            trusted[public_key_id(key)] = key
            trusted[full_public_key_id(key)] = key
    return index_trusted_keys(trusted)


def sign_product_receipt(
    receipt: Mapping[str, Any], signer: Ed25519PrivateKey
) -> dict[str, Any]:
    if receipt.get("schema_version") != PRODUCT_RECEIPT_SCHEMA:
        raise ProtocolError("PRODUCT_RECEIPT_INVALID", "cannot sign an unsupported receipt")
    return sign_integrity_document(receipt, signer)


def verify_product_receipt(
    receipt: Mapping[str, Any],
    trusted_keys: Mapping[str, Ed25519PublicKey],
    *,
    require_signature: bool = False,
) -> None:
    signature = receipt.get("signature")
    if signature is None:
        if require_signature:
            raise ProtocolError(
                "MISSING_SIGNATURE",
                "product receipt signature is required",
            )
        return
    verify_document(receipt, trusted_keys)


def verify_cognition_receipt(
    receipt: Mapping[str, Any], trusted_keys: Mapping[str, Ed25519PublicKey]
) -> None:
    """Fail closed: cognition receipts must have a valid, trusted signature."""

    if receipt.get("schema_version") not in COGNITION_RECEIPT_SCHEMAS:
        raise ProtocolError("PRODUCT_RECEIPT_INVALID", "not a cognition receipt")
    try:
        verify_document(receipt, trusted_keys)
    except ProtocolError as exc:
        raise ProtocolError(
            "COGNITION_RECEIPT_SIGNATURE_INVALID",
            exc.detail,
        ) from exc


def sign_export_manifest(
    manifest: Mapping[str, Any], signer: Ed25519PrivateKey
) -> dict[str, Any]:
    payload = {
        "schema_version": EXPORT_SIGNATURE_SCHEMA,
        "manifest_sha256": document_digest(manifest),
        "public_key_pem": public_key_pem(signer.public_key()),
    }
    return sign_integrity_document(payload, signer)


def parse_export_signature(payload: bytes) -> dict[str, Any]:
    if len(payload) > MAX_EXPORT_SIGNATURE_BYTES:
        raise ProtocolError("EXPORT_LIMIT", "portable export signature is oversized")
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(
            "EXPORT_SIGNATURE_INVALID",
            "portable export signature is invalid",
        ) from exc
    if not isinstance(document, dict) or document.get("schema_version") != EXPORT_SIGNATURE_SCHEMA:
        raise ProtocolError(
            "EXPORT_SIGNATURE_INVALID",
            "portable export signature shape is invalid",
        )
    return document


EXPORT_SIGNATURE_STATUS_VERIFIED = "verified"
EXPORT_SIGNATURE_STATUS_SELF_SIGNED_UNTRUSTED = "self_signed_untrusted"
EXPORT_SIGNATURE_STATUS_UNSIGNED = "unsigned"

EXPORT_SIGNATURE_STATUS_TEXT = {
    EXPORT_SIGNATURE_STATUS_VERIFIED: "verified",
    EXPORT_SIGNATURE_STATUS_SELF_SIGNED_UNTRUSTED: "self-signed (untrusted key)",
    EXPORT_SIGNATURE_STATUS_UNSIGNED: "unsigned",
}


def export_signature_status_text(status: str) -> str:
    """Human-readable label for an export-signature verification status."""

    try:
        return EXPORT_SIGNATURE_STATUS_TEXT[status]
    except KeyError as exc:
        raise ValueError(f"unknown export signature status: {status}") from exc


def verify_export_signature(
    manifest: Mapping[str, Any],
    signature_document: Mapping[str, Any] | None,
    trusted_keys: Mapping[str, Ed25519PublicKey] | None = None,
    *,
    require_signature: bool = False,
) -> str:
    """Verify a detached export signature and return how it was checked.

    A result of ``verified`` means the signature matched a caller-supplied
    trusted key. When no trusted keys are given and a signature is not
    required, the embedded ``public_key_pem`` is used only as an integrity
    check and the status is ``self_signed_untrusted``. Fail closed when a
    signature is required.
    """

    if signature_document is None:
        if require_signature:
            raise ProtocolError(
                "EXPORT_SIGNATURE_MISSING",
                "portable export signature is required",
            )
        return EXPORT_SIGNATURE_STATUS_UNSIGNED
    declared = signature_document.get("manifest_sha256")
    actual = document_digest(manifest)
    if not isinstance(declared, str) or not digests_equal(declared, actual):
        raise ProtocolError(
            "EXPORT_SIGNATURE_MISMATCH",
            "portable export signature does not cover this manifest",
        )
    keys: dict[str, Ed25519PublicKey]
    if trusted_keys:
        keys = index_trusted_keys(dict(trusted_keys))
        status = EXPORT_SIGNATURE_STATUS_VERIFIED
    elif require_signature:
        raise ProtocolError(
            "EXPORT_SIGNATURE_TRUST_REQUIRED",
            "a trusted export public key is required",
        )
    else:
        pem = signature_document.get("public_key_pem")
        if not isinstance(pem, str):
            raise ProtocolError(
                "EXPORT_SIGNATURE_INVALID",
                "portable export signature has no public key",
            )
        embedded = public_key_from_pem(pem)
        keys = index_trusted_keys(
            {
                full_public_key_id(embedded): embedded,
                public_key_id(embedded): embedded,
            }
        )
        status = EXPORT_SIGNATURE_STATUS_SELF_SIGNED_UNTRUSTED
    try:
        verify_document(signature_document, keys)
    except ProtocolError as exc:
        raise ProtocolError(
            "EXPORT_SIGNATURE_INVALID",
            exc.detail,
        ) from exc
    return status


def load_trusted_keys_from_pems(paths: Iterable[Path]) -> dict[str, Ed25519PublicKey]:
    trusted: dict[str, Ed25519PublicKey] = {}
    for path in paths:
        key = load_public_key(path)
        trusted[full_public_key_id(key)] = key
        trusted[public_key_id(key)] = key
    return index_trusted_keys(trusted)


CHECKPOINT_SCHEMA = "nukotech.hive-local.checkpoint.v1"
CHECKPOINT_RELATIVE = Path(".hive") / "checkpoints"
PORTABLE_MANIFEST_SCHEMA = "hive.operator-portable-manifest.v1"


class UnsignedCheckpointWarning(UserWarning):
    """A rollback proceeded against an unsigned or legacy Git checkpoint."""


def checkpoint_path(root: Path, commit: str) -> Path:
    return root.expanduser().resolve() / CHECKPOINT_RELATIVE / f"{commit}.json"


def inventory_digest(inventory: list[dict[str, Any]]) -> str:
    return document_digest({"schema_version": PORTABLE_MANIFEST_SCHEMA, "files": inventory})


def sign_checkpoint(
    *,
    commit: str,
    tree: str,
    message: str,
    tenant_id: str,
    project_id: str,
    inventory: list[dict[str, Any]],
    receipt_id: str,
    signer: Ed25519PrivateKey,
) -> dict[str, Any]:
    document = {
        "schema_version": CHECKPOINT_SCHEMA,
        "commit": commit,
        "tree": tree,
        "message": message,
        "tenant_id": tenant_id,
        "project_id": project_id,
        "inventory_sha256": inventory_digest(inventory),
        "inventory": inventory,
        "receipt_id": receipt_id,
    }
    return sign_integrity_document(document, signer)


def write_signed_checkpoint(root: Path, document: Mapping[str, Any]) -> Path:
    path = checkpoint_path(root, str(document["commit"]))
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(path, dict(document), mode=0o644)
    return path


def load_checkpoint(root: Path, commit: str) -> dict[str, Any] | None:
    path = checkpoint_path(root, commit)
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise ProtocolError(
            "CHECKPOINT_BOUNDARY",
            "snapshot checkpoint must be a regular file",
        )
    document = read_json(path)
    if document.get("schema_version") != CHECKPOINT_SCHEMA:
        raise ProtocolError(
            "CHECKPOINT_INVALID",
            "snapshot checkpoint schema is invalid",
        )
    return document


def verify_checkpoint(
    document: Mapping[str, Any],
    *,
    commit: str,
    tree: str,
    inventory: list[dict[str, Any]],
    trusted_keys: Mapping[str, Ed25519PublicKey],
) -> None:
    if document.get("schema_version") != CHECKPOINT_SCHEMA:
        raise ProtocolError("CHECKPOINT_INVALID", "snapshot checkpoint schema is invalid")
    if document.get("commit") != commit:
        raise ProtocolError("CHECKPOINT_COMMIT_MISMATCH", "snapshot checkpoint commit does not match")
    if document.get("tree") != tree:
        raise ProtocolError("CHECKPOINT_TREE_MISMATCH", "snapshot checkpoint tree does not match")
    if not digests_equal(str(document.get("inventory_sha256", "")), inventory_digest(inventory)):
        raise ProtocolError(
            "CHECKPOINT_INVENTORY_MISMATCH",
            "snapshot checkpoint inventory digest does not match",
        )
    if document.get("inventory") != inventory:
        raise ProtocolError(
            "CHECKPOINT_INVENTORY_MISMATCH",
            "snapshot checkpoint inventory does not match the commit",
        )
    try:
        verify_document(document, trusted_keys)
    except ProtocolError as exc:
        raise ProtocolError(
            "CHECKPOINT_SIGNATURE_INVALID",
            exc.detail,
        ) from exc


def warn_unsigned_checkpoint(commit: str) -> None:
    warnings.warn(
        f"Rolling back to unsigned or legacy checkpoint {commit}; "
        "authenticity was not verified.",
        UnsignedCheckpointWarning,
        stacklevel=3,
    )
