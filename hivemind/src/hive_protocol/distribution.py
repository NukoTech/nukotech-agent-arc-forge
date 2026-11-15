"""Signed LAB governance release and non-activating Node pin demonstration."""

from __future__ import annotations

import os
import re
import shutil
from importlib.resources import files
from pathlib import Path
from typing import Any
from uuid import uuid4

from .core import (
    ProtocolError,
    document_digest,
    load_private_key,
    load_public_key,
    sign_document,
    validate_document,
    verify_document,
)
from .memory import BASE_NAMES
from .release_identity import require_matching_repository, require_release_repository
from .storage import atomic_write_bytes, atomic_write_json, exclusive_lock, read_json, utc_now


def _sha256_bytes(payload: bytes) -> str:
    import hashlib

    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ProtocolError("RELEASE_ARTIFACT_MISSING", f"not a regular release artifact: {path}")
    return _sha256_bytes(path.read_bytes())


def _trusted_key(run_dir: Path, label: str, key_id: str) -> dict[str, Any]:
    return {key_id: load_public_key(run_dir / "keys" / f"{label}.public.pem")}


def _release_artifacts() -> list[tuple[str, bytes]]:
    result: list[tuple[str, bytes]] = []
    schema_root = files("hive_protocol").joinpath("schemas")
    for item in sorted(schema_root.iterdir(), key=lambda value: value.name):
        if item.name.endswith(".schema.json"):
            result.append((f"schemas/{item.name}", item.read_bytes()))
    base_root = files("hive_protocol").joinpath("bases")
    for name in BASE_NAMES:
        result.append((f"bases/{name}", base_root.joinpath(name).read_bytes()))
    return result


def build_governance_release(
    run_dir: Path,
    marker: dict[str, Any],
    version: str,
    tree: str,
    process_namespace: str,
) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+-lab\.[0-9]+", version):
        raise ProtocolError("RELEASE_VERSION_INVALID", "only versioned LAB releases are accepted")
    if not re.fullmatch(r"[0-9a-f]{40}", tree):
        raise ProtocolError("TREE_INVALID", "release tree must be a full Git SHA-1")
    outbox = run_dir / "distribution" / "outbox" / version
    if outbox.exists():
        raise ProtocolError("RELEASE_EXISTS", "release version already exists in this run")

    artifacts: list[dict[str, Any]] = []
    for relative, payload in _release_artifacts():
        artifact_path = outbox / "artifacts" / relative
        atomic_write_bytes(artifact_path, payload)
        artifacts.append(
            {
                "path": relative,
                "sha256": _sha256_bytes(payload),
                "size": len(payload),
                "classification": "NON_PRIVATE_GOVERNANCE",
            }
        )
    release = {
        "schema_version": "hive.governance-release.v1",
        "release_id": str(uuid4()),
        "version": version,
        "channel": "LAB",
        "repository": require_release_repository(),
        "commit": marker["commit"],
        "tree": tree,
        "issued_at": utc_now(),
        "review": {
            "status": "APPROVED_FOR_LAB_STAGING",
            "reviewer_key_id": marker["reviewer_key_id"],
            "authorization_ref": marker["authorization_ref"],
        },
        "artifacts": artifacts,
        "rollback": {
            "previous_version": None,
            "action": "RESTORE_PREVIOUS_PIN_AND_REMOVE_STAGED_RELEASE",
        },
        "contains_raw_memory": False,
        "contains_credentials": False,
    }
    signed_release = sign_document(
        release,
        load_private_key(run_dir / "keys" / "issuer.private.pem"),
    )
    validate_document(signed_release, "governance-release")
    atomic_write_json(outbox / "release.json", signed_release)
    release_sha256 = document_digest(signed_release)

    pin = {
        "schema_version": "hive.node-pin.v1",
        "node_id": marker["identity"]["machine_node"]["node_id"],
        "environment": "LAB",
        "version": version,
        "release_sha256": release_sha256,
        "release_key_id": marker["issuer_key_id"],
        "activation": False,
        "authorization_ref": marker["authorization_ref"],
    }
    signed_pin = sign_document(
        pin,
        load_private_key(run_dir / "keys" / "reviewer.private.pem"),
    )
    validate_document(signed_pin, "node-pin")
    atomic_write_json(outbox / "node-pin.json", signed_pin)
    return {
        "outcome": "RELEASE_BUILT",
        "version": version,
        "artifact_count": len(artifacts),
        "release_sha256": release_sha256,
        "pin_sha256": document_digest(signed_pin),
        "activation": False,
        "process_id": os.getpid(),
        "process_namespace": process_namespace,
    }


def stage_governance_release(
    run_dir: Path,
    marker: dict[str, Any],
    version: str,
    process_namespace: str,
) -> dict[str, Any]:
    outbox = run_dir / "distribution" / "outbox" / version
    release = read_json(outbox / "release.json")
    pin = read_json(outbox / "node-pin.json")
    validate_document(release, "governance-release")
    validate_document(pin, "node-pin")
    require_matching_repository(release["repository"])
    verify_document(release, _trusted_key(run_dir, "issuer", marker["issuer_key_id"]))
    verify_document(pin, _trusted_key(run_dir, "reviewer", marker["reviewer_key_id"]))
    if release["version"] != version or pin["version"] != version:
        raise ProtocolError("NODE_PIN_MISMATCH", "release and pin versions differ")
    if pin["release_sha256"] != document_digest(release):
        raise ProtocolError("NODE_PIN_MISMATCH", "pin does not bind the release manifest")
    if pin["node_id"] != marker["identity"]["machine_node"]["node_id"]:
        raise ProtocolError("NODE_PIN_MISMATCH", "pin targets another Node Hive")
    if release["contains_raw_memory"] or release["contains_credentials"] or pin["activation"]:
        raise ProtocolError("RELEASE_CONTENT_DENIED", "release violates GitHub or activation boundaries")

    node_root = run_dir / "node-staging"
    if node_root.is_symlink():
        raise ProtocolError("NODE_BOUNDARY", "node staging root cannot be a symlink")
    release_root = node_root / "releases" / version
    current_pin = node_root / "current-pin.json"
    previous_pin = node_root / "previous-pin.json"
    with exclusive_lock(run_dir / "locks" / "release-stage.lock"):
        if release_root.exists():
            raise ProtocolError("RELEASE_EXISTS", "release is already staged")
        if current_pin.exists():
            atomic_write_bytes(previous_pin, current_pin.read_bytes())
        for artifact in release["artifacts"]:
            relative = artifact["path"]
            if not re.fullmatch(r"(schemas|bases)/[A-Za-z0-9._/-]+", relative) or ".." in Path(relative).parts:
                raise ProtocolError("RELEASE_PATH_DENIED", f"unsafe release path: {relative}")
            source = outbox / "artifacts" / relative
            if _sha256_file(source) != artifact["sha256"] or source.stat().st_size != artifact["size"]:
                raise ProtocolError("RELEASE_ARTIFACT_DRIFT", f"artifact mismatch: {relative}")
            atomic_write_bytes(release_root / relative, source.read_bytes())
        atomic_write_json(release_root / "release.json", release)
        atomic_write_json(current_pin, pin)

        receipt = {
            "schema_version": "hive.distribution-receipt.v1",
            "receipt_id": str(uuid4()),
            "node_id": pin["node_id"],
            "version": version,
            "release_sha256": document_digest(release),
            "pin_sha256": document_digest(pin),
            "outcome": "STAGED_NOT_ACTIVATED",
            "activation": False,
            "recorded_at": utc_now(),
            "process_id": os.getpid(),
            "process_namespace": process_namespace,
        }
        signed = sign_document(
            receipt,
            load_private_key(run_dir / "keys" / "node.private.pem"),
        )
        validate_document(signed, "distribution-receipt")
        atomic_write_json(run_dir / "receipts" / "distribution-stage.json", signed)
    return {
        "outcome": "STAGED_NOT_ACTIVATED",
        "version": version,
        "artifact_count": len(release["artifacts"]),
        "activation": False,
        "process_id": os.getpid(),
        "process_namespace": process_namespace,
        "receipt_sha256": document_digest(signed),
    }


def rollback_governance_release(
    run_dir: Path,
    marker: dict[str, Any],
    version: str,
    process_namespace: str,
) -> dict[str, Any]:
    stage_receipt = read_json(run_dir / "receipts" / "distribution-stage.json")
    validate_document(stage_receipt, "distribution-receipt")
    verify_document(stage_receipt, _trusted_key(run_dir, "node", marker["node_key_id"]))
    if stage_receipt["version"] != version or stage_receipt["outcome"] != "STAGED_NOT_ACTIVATED":
        raise ProtocolError("RELEASE_ROLLBACK_DENIED", "stage receipt does not authorize this rollback")
    node_root = run_dir / "node-staging"
    release_root = node_root / "releases" / version
    if release_root.is_symlink() or release_root.resolve().parent != (node_root / "releases").resolve():
        raise ProtocolError("NODE_BOUNDARY", "release rollback target is outside node staging")
    current_pin = node_root / "current-pin.json"
    previous_pin = node_root / "previous-pin.json"
    with exclusive_lock(run_dir / "locks" / "release-stage.lock"):
        if release_root.is_dir():
            shutil.rmtree(release_root)
        restored_previous = previous_pin.is_file() and not previous_pin.is_symlink()
        if restored_previous:
            os.replace(previous_pin, current_pin)
        elif current_pin.is_file() and not current_pin.is_symlink():
            current_pin.unlink()
        residue = release_root.exists() or (
            current_pin.exists()
            and (not restored_previous or read_json(current_pin).get("version") == version)
        )
        if residue:
            raise ProtocolError("RELEASE_ROLLBACK_RESIDUE", "staged release or pin remains")
        receipt = {
            "schema_version": "hive.distribution-receipt.v1",
            "receipt_id": str(uuid4()),
            "node_id": stage_receipt["node_id"],
            "version": version,
            "release_sha256": stage_receipt["release_sha256"],
            "pin_sha256": stage_receipt["pin_sha256"],
            "outcome": "ROLLED_BACK",
            "activation": False,
            "recorded_at": utc_now(),
            "process_id": os.getpid(),
            "process_namespace": process_namespace,
        }
        signed = sign_document(
            receipt,
            load_private_key(run_dir / "keys" / "node.private.pem"),
        )
        validate_document(signed, "distribution-receipt")
        atomic_write_json(run_dir / "receipts" / "distribution-rollback.json", signed)
    return {
        "outcome": "ROLLED_BACK",
        "version": version,
        "activation": False,
        "residue": "NONE",
        "process_id": os.getpid(),
        "process_namespace": process_namespace,
        "receipt_sha256": document_digest(signed),
    }
