#!/usr/bin/env python3
"""Fail-closed verification for GitHub identity-bound Hive Sigstore bundles."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
# Cosign is the cryptographic verifier; its path and digest are checked first.
import subprocess  # nosec B404
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hive_protocol.core import ProtocolError as HiveProtocolError
from hive_protocol.release_identity import require_release_repository


LEDGER_SCHEMA = "nukotech.hive.attestation-replay-ledger.v1"


class VerificationError(RuntimeError):
    """Policy or provenance verification refused the artifact."""



UNBOUND_PLACEHOLDER = re.compile(r"<[A-Z][A-Z0-9_]+>")
IDENTITY_FIELDS = (
    "certificate_identity",
    "oidc_issuer",
    "repository",
    "source_ref",
    "workflow_name",
    "workflow_trigger",
)
WORKFLOW_PATH = re.compile(r"[A-Za-z0-9._-]+\.ya?ml")


def require_bound_identity(identity: dict[str, Any]) -> None:
    """Refuse a policy whose signer identity is still a launch placeholder."""

    for key in IDENTITY_FIELDS:
        value = identity.get(key)
        if not isinstance(value, str) or not value.strip() or UNBOUND_PLACEHOLDER.search(value):
            raise VerificationError("POLICY_IDENTITY_UNBOUND")


def workflow_path_for_ref(
    certificate_identity: str, repository: str, source_ref: str
) -> str:
    prefix = f"https://github.com/{repository}/.github/workflows/"
    suffix = f"@{source_ref}"
    if not certificate_identity.startswith(prefix) or not certificate_identity.endswith(suffix):
        raise VerificationError("POLICY_CERTIFICATE_IDENTITY_MISMATCH")
    workflow_path = certificate_identity[len(prefix) : len(certificate_identity) - len(suffix)]
    if WORKFLOW_PATH.fullmatch(workflow_path) is None:
        raise VerificationError("POLICY_WORKFLOW_PATH_INVALID")
    return workflow_path



def bind_policy_repository(identity: dict[str, Any]) -> dict[str, Any]:
    """Fill <REPO_SLUG> from the shared release-identity source, then fail closed."""

    try:
        repository = require_release_repository()
    except HiveProtocolError as exc:
        raise VerificationError(exc.code) from exc
    bound = {
        key: (
            value.replace("<REPO_SLUG>", repository)
            if isinstance(value, str)
            else value
        )
        for key, value in identity.items()
    }
    if bound.get("repository") != repository:
        raise VerificationError("RELEASE_IDENTITY_MISMATCH")
    require_bound_identity(bound)
    return bound


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_version(raw: str) -> tuple[int, int, int]:
    token = raw.strip().lstrip("v").split("-", 1)[0]
    parts = token.split(".")
    if len(parts) != 3 or any(not part.isdigit() for part in parts):
        raise VerificationError(f"COSIGN_VERSION_UNPARSEABLE:{raw}")
    return tuple(int(part) for part in parts)  # type: ignore[return-value]


def checked_executable(path: Path, expected_sha256: str) -> str:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise VerificationError("COSIGN_BINARY_MISSING_OR_UNSAFE")
    if not os.access(path, os.X_OK):
        raise VerificationError("COSIGN_BINARY_NOT_EXECUTABLE")
    actual = sha256_file(path)
    if actual != expected_sha256.lower():
        raise VerificationError("COSIGN_BINARY_DIGEST_MISMATCH")
    return str(path)


def cosign_version(binary: str) -> tuple[int, int, int]:
    # The executable is absolute, regular, executable, and hash-pinned.
    result = subprocess.run(  # nosec B603
        [binary, "version", "--json"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        try:
            payload = json.loads(result.stdout)
            raw = payload.get("gitVersion") or payload.get("GitVersion") or payload.get("version")
            return parse_version(str(raw))
        except (KeyError, TypeError, json.JSONDecodeError, VerificationError):
            pass
    # The executable is absolute, regular, executable, and hash-pinned.
    fallback = subprocess.run(  # nosec B603
        [binary, "--version"], check=False, capture_output=True, text=True
    )
    if fallback.returncode != 0:
        raise VerificationError("COSIGN_BINARY_UNAVAILABLE")
    for line in fallback.stdout.splitlines():
        if line.strip().startswith("GitVersion:"):
            return parse_version(line.split(":", 1)[1].strip())
    raise VerificationError("COSIGN_VERSION_UNPARSEABLE")


def load_json_object(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise VerificationError(f"{label}_MISSING_OR_UNSAFE")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"{label}_INVALID") from exc
    if not isinstance(value, dict):
        raise VerificationError(f"{label}_INVALID")
    return value


def load_ledger(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"schema": LEDGER_SCHEMA, "entries": []}
    ledger = load_json_object(path, "LEDGER")
    if ledger.get("schema") != LEDGER_SCHEMA or not isinstance(ledger.get("entries"), list):
        raise VerificationError("LEDGER_SCHEMA_INVALID")
    return ledger


def atomic_write_ledger(path: Path, ledger: dict[str, Any]) -> None:
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    if parent.is_symlink() or path.is_symlink():
        raise VerificationError("LEDGER_PATH_UNSAFE")
    temp = parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    payload = (json.dumps(ledger, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd = os.open(temp, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        directory_fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temp.exists():
            temp.unlink()


def verify(args: argparse.Namespace) -> dict[str, Any]:
    artifact = args.artifact.resolve()
    if not artifact.is_file() or artifact.is_symlink():
        raise VerificationError("ARTIFACT_MISSING_OR_UNSAFE")
    policy = load_json_object(args.policy.resolve(), "POLICY")
    if policy.get("schema") != "nukotech.hive.release-attestation-policy.v1":
        raise VerificationError("POLICY_SCHEMA_INVALID")
    identity = policy.get("identity")
    verification_policy = policy.get("verification")
    if not isinstance(identity, dict) or not isinstance(verification_policy, dict):
        raise VerificationError("POLICY_FIELDS_INVALID")
    identity = bind_policy_repository(identity)
    policy["identity"] = identity

    actual_digest = sha256_file(artifact)
    if actual_digest != args.expected_sha256.lower():
        raise VerificationError("EXPECTED_DIGEST_MISMATCH")
    if args.bundle is None:
        raise VerificationError("SIGSTORE_BUNDLE_REQUIRED")
    bundle = args.bundle.resolve()
    if not bundle.is_file() or bundle.is_symlink():
        raise VerificationError("SIGSTORE_BUNDLE_MISSING_OR_UNSAFE")
    cosign_binary = checked_executable(args.cosign_binary, args.cosign_binary_sha256)
    minimum = parse_version(str(verification_policy["minimum_cosign_version"]))
    installed = cosign_version(cosign_binary)
    if installed < minimum:
        raise VerificationError(
            f"COSIGN_VERSION_TOO_OLD:{'.'.join(map(str, installed))}:requires:{'.'.join(map(str, minimum))}"
        )

    command = [
        cosign_binary,
        "verify-blob",
        "--bundle",
        str(bundle),
        "--certificate-identity",
        str(identity["certificate_identity"]),
        "--certificate-oidc-issuer",
        str(identity["oidc_issuer"]),
        "--certificate-github-workflow-repository",
        str(identity["repository"]),
        "--certificate-github-workflow-name",
        str(identity["workflow_name"]),
        "--certificate-github-workflow-ref",
        str(identity["source_ref"]),
        "--certificate-github-workflow-sha",
        args.expected_source_digest,
        "--certificate-github-workflow-trigger",
        str(identity["workflow_trigger"]),
        str(artifact),
    ]
    # The executable is absolute, regular, executable, and hash-pinned.
    result = subprocess.run(  # nosec B603
        command, check=False, capture_output=True, text=True
    )
    if result.returncode != 0:
        raise VerificationError("SIGSTORE_VERIFICATION_FAILED")
    fingerprint = sha256_file(bundle)

    ledger_path = args.ledger.resolve()
    ledger = load_ledger(ledger_path)
    entries = ledger["entries"]
    for entry in entries:
        if not isinstance(entry, dict):
            raise VerificationError("LEDGER_ENTRY_INVALID")
        if entry.get("claim_id") == args.claim_id:
            raise VerificationError("REPLAY_CLAIM_ID")
        if entry.get("bundle_fingerprint") == fingerprint:
            raise VerificationError("REPLAY_BUNDLE")
    accepted = {
        "artifact_name": artifact.name,
        "artifact_sha256": actual_digest,
        "bundle_fingerprint": fingerprint,
        "claim_id": args.claim_id,
        "repository": identity["repository"],
        "signer_workflow": identity["certificate_identity"],
        "source_digest": args.expected_source_digest,
        "source_ref": identity["source_ref"],
        "verified_at": datetime.now(UTC).isoformat(),
    }
    entries.append(accepted)
    atomic_write_ledger(ledger_path, ledger)
    return {"outcome": "ACCEPTED", **accepted, "ledger": str(ledger_path)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--expected-source-digest", required=True)
    parser.add_argument("--claim-id", required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--cosign-binary", type=Path, required=True)
    parser.add_argument("--cosign-binary-sha256", required=True)
    args = parser.parse_args()
    try:
        receipt = verify(args)
    except (KeyError, OSError, VerificationError) as exc:
        print(json.dumps({"outcome": "REJECTED", "reason": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
