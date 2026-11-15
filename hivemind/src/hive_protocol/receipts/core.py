"""Receipt construction with explicit identity and immutable references."""

from __future__ import annotations

import json
import re
from importlib.resources import files
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ..core import ProtocolError, document_digest, sign_document, verify_document


_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _schema() -> dict[str, Any]:
    return json.loads(files("hive_protocol.schemas").joinpath("cycle2-receipt.v1.schema.json").read_text())


def _validate(receipt: Mapping[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(_schema(), format_checker=FormatChecker()).iter_errors(receipt),
        key=lambda error: list(error.path),
    )
    if errors:
        error = errors[0]
        where = ".".join(str(part) for part in error.absolute_path) or "$"
        raise ProtocolError("RECEIPT_SCHEMA_INVALID", f"{where}: {error.message}")


def _identity(value: Mapping[str, Any], label: str) -> None:
    required = ("persona_id", "surface_id", "machine_id", "project_id", "app_actor")
    if any(not isinstance(value.get(key), str) or not _ID.fullmatch(value[key]) for key in required):
        raise ProtocolError("RECEIPT_IDENTITY_INVALID", f"{label} must contain five safe identity dimensions")
    dimensions = [value[key] for key in required]
    if len(set(dimensions)) != len(dimensions):
        raise ProtocolError("RECEIPT_IDENTITY_COLLAPSE", f"{label} dimensions must remain distinct")


def build_receipt(
    *,
    receipt_id: str,
    task_id: str,
    event: str,
    actor: Mapping[str, Any],
    recipient: Mapping[str, Any],
    state_before: str,
    state_after: str,
    version: int,
    nonce: str,
    artifact_refs: list[Mapping[str, Any]],
    result: Mapping[str, Any] | None,
    private_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    if not _ID.fullmatch(receipt_id) or not _ID.fullmatch(task_id) or not _ID.fullmatch(event):
        raise ProtocolError("RECEIPT_ID_INVALID", "receipt, task, and event identifiers are unsafe")
    if version < 1 or not isinstance(nonce, str) or len(nonce) < 16:
        raise ProtocolError("RECEIPT_METADATA_INVALID", "version and nonce are invalid")
    _identity(actor, "actor")
    _identity(recipient, "recipient")
    if actor["project_id"] != recipient["project_id"]:
        raise ProtocolError("RECEIPT_PROJECT_MISMATCH", "actor and recipient projects differ")
    for ref in artifact_refs:
        if not isinstance(ref, Mapping) or not _SHA256.fullmatch(str(ref.get("sha256", ""))):
            raise ProtocolError("RECEIPT_REFERENCE_INVALID", "every artifact reference requires a SHA-256 digest")
    receipt: dict[str, Any] = {
        "schema_version": "hive.cycle2.receipt.v1",
        "receipt_id": receipt_id,
        "task_id": task_id,
        "event": event,
        "actor": dict(actor),
        "recipient": dict(recipient),
        "state_before": state_before,
        "state_after": state_after,
        "version": version,
        "nonce": nonce,
        "artifact_refs": [dict(ref) for ref in artifact_refs],
        "result": dict(result or {}),
    }
    signed = sign_document(receipt, private_key)
    _validate(signed)
    return signed


def verify_receipt(receipt: Mapping[str, Any], trusted_keys: Mapping[str, Ed25519PublicKey]) -> None:
    _validate(receipt)
    _identity(receipt["actor"], "actor")
    _identity(receipt["recipient"], "recipient")
    if receipt["actor"]["project_id"] != receipt["recipient"]["project_id"]:
        raise ProtocolError("RECEIPT_PROJECT_MISMATCH", "receipt crosses project boundary")
    verify_document(receipt, trusted_keys)


def receipt_digest(receipt: Mapping[str, Any]) -> str:
    return document_digest(receipt)
