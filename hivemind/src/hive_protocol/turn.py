"""Disposable reference implementation of one organizational turn."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import stat
import sys
from datetime import datetime, timedelta, timezone
from importlib.resources import files
from pathlib import Path
from typing import Any
from uuid import uuid4

from .core import (
    ProtocolError,
    document_digest,
    generate_keypair,
    load_private_key,
    load_public_key,
    sign_document,
    require_assigned_persona,
    validate_document,
    validate_identity_context,
    verify_document,
)
from .release_identity import require_matching_repository, require_release_repository
from .lab_context import load_lab_identity
from .storage import (
    ReplayLedger,
    atomic_write_bytes,
    atomic_write_json,
    exclusive_lock,
    read_json,
    utc_now,
)


MASTER_RECORD_SHA256 = "b78a16acef307f117a444b7cbd3136c01d6be3906593318833e2ee8903b75589"
AUTHORIZED_PLAN_SHA256 = "e582ac2552f871fb0864b40b6401f3561e0e55e8c83182492e08d21e31b224b4"
CURRENT_PLAN_COPY_SHA256 = "c93bc29304fda1401674c1f0f2fc860daf3a186d2de58311757ee07c43ad6f73"
AUTHORIZATION_REF = "urn:hive:authorization:sample-001"
BRANCH = "main"
REQUIRED_CAPABILITIES = {
    "mailbox:route",
    "memory:retrieve",
    "state:compare-and-set",
    "vault:stage",
    "vault:propose",
    "vault:promote",
    "graph:link",
}
EXPECTED_IDENTITY = json.loads(
    files("hive_protocol")
    .joinpath("reference", "sample-lab-context.json")
    .read_text(encoding="utf-8")
)


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError("TIME_INVALID", f"invalid timestamp: {value}") from exc
    if parsed.tzinfo is None:
        raise ProtocolError("TIME_INVALID", "timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def _sha256_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ProtocolError("MISSING_ARTIFACT", f"expected regular file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_marker(run_dir: Path) -> dict[str, Any]:
    if run_dir.is_symlink() or not run_dir.is_dir():
        raise ProtocolError("RUN_BOUNDARY", "run directory must be a real directory")
    marker = read_json(run_dir / ".hive-lab-run.json")
    expected_name = f"turn-{marker.get('run_id', '')}"
    if run_dir.name != expected_name:
        raise ProtocolError("RUN_BOUNDARY", "run directory name does not match marker")
    expected_parent = Path(marker.get("lab_root", "")) / "runs"
    if run_dir.resolve().parent != expected_parent.resolve():
        raise ProtocolError("RUN_BOUNDARY", "run directory is outside its marked LAB root")
    return marker


def _trusted_key(run_dir: Path, label: str, expected_key_id: str) -> dict[str, Any]:
    public_key = load_public_key(run_dir / "keys" / f"{label}.public.pem")
    return {expected_key_id: public_key}


def _validate_policy(envelope: dict[str, Any], marker: dict[str, Any]) -> None:
    now = datetime.now(timezone.utc)
    if _parse_time(envelope["issued_at"]) > now + timedelta(seconds=30):
        raise ProtocolError("NOT_YET_VALID", "envelope issue time is in the future")
    if _parse_time(envelope["expires_at"]) <= now:
        raise ProtocolError("EXPIRED", "envelope has expired")
    authority = envelope["authority"]
    if authority["environment"] not in marker["allowed_environments"]:
        raise ProtocolError("ENVIRONMENT_DENIED", "environment is outside LAB/STAGING")
    if authority["authorization_ref"] != marker["authorization_ref"]:
        raise ProtocolError("AUTHORITY_REF_DENIED", "authorization reference is not allowed")
    capabilities = set(authority["capabilities"])
    if not REQUIRED_CAPABILITIES.issubset(capabilities):
        missing = sorted(REQUIRED_CAPABILITIES - capabilities)
        raise ProtocolError("CAPABILITY_DENIED", f"missing capabilities: {missing}")
    unexpected = sorted(capabilities - REQUIRED_CAPABILITIES)
    if unexpected:
        raise ProtocolError(
            "CAPABILITY_ESCALATION",
            f"unapproved capabilities requested: {unexpected}",
        )
    recipient = envelope["recipient"]
    expected = marker["recipient"]
    if recipient != expected:
        raise ProtocolError("RECIPIENT_DENIED", "recipient does not match this run")
    if socket.gethostname() != expected["machine"]:
        raise ProtocolError("MACHINE_DENIED", "consumer host does not match the envelope")
    if envelope["identity"] != marker["identity"]:
        raise ProtocolError("IDENTITY_DENIED", "identity tuple does not match the authorized run")
    validate_identity_context(envelope["identity"])
    require_assigned_persona(envelope["identity"])
    if envelope["identity"]["domain_product_project"]["project"] != recipient["project"]:
        raise ProtocolError("PROJECT_BINDING_DENIED", "identity project does not match recipient project")
    identity_authority = envelope["identity"]["capability_authority"]
    if (
        identity_authority["authorization_ref"] != authority["authorization_ref"]
        or set(identity_authority["capabilities"]) != capabilities
        or _parse_time(identity_authority["expires_at"]) < _parse_time(envelope["expires_at"])
    ):
        raise ProtocolError("CAPABILITY_BINDING_DENIED", "identity authority does not bind the envelope grant")
    provenance = envelope["provenance"]
    require_matching_repository(provenance["repository"])
    if (
        provenance["branch"] != BRANCH
        or provenance["commit"] != marker["commit"]
        or provenance["issue"] != marker["authorization_ref"]
    ):
        raise ProtocolError("PROVENANCE_DENIED", "repository provenance does not match the run")


def _process_namespace() -> str:
    namespace = os.environ.get("HIVE_PROCESS_NAMESPACE", "")
    if not namespace.startswith("HIVE-LAB-"):
        raise ProtocolError("PROCESS_NAMESPACE_DENIED", "HIVE-LAB process namespace is required")
    return namespace


def prepare_turn(lab_root: Path, commit: str) -> dict[str, Any]:
    _process_namespace()
    identity = load_lab_identity()
    validate_identity_context(identity)
    require_assigned_persona(identity)
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ProtocolError("COMMIT_INVALID", "provenance commit must be a full SHA-1")
    if lab_root.is_symlink():
        raise ProtocolError("LAB_ROOT_BOUNDARY", "LAB root cannot be a symlink")
    if lab_root.exists() and any(lab_root.iterdir()) and not (lab_root / ".hive-lab-root.json").is_file():
        raise ProtocolError("LAB_ROOT_BOUNDARY", "existing non-empty LAB root is not marked")
    lab_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(lab_root, 0o700)
    root_marker_path = lab_root / ".hive-lab-root.json"
    if root_marker_path.exists():
        root_marker = read_json(root_marker_path)
        if root_marker.get("schema_version") != "hive.lab-root.v1":
            raise ProtocolError("LAB_ROOT_BOUNDARY", "LAB root marker is invalid")
    else:
        atomic_write_json(
            root_marker_path,
            {"schema_version": "hive.lab-root.v1", "created_at": utc_now()},
            mode=0o600,
        )
    runs_root = lab_root / "runs"
    runs_root.mkdir(exist_ok=True, mode=0o700)

    run_id = str(uuid4())
    message_id = str(uuid4())
    run_dir = runs_root / f"turn-{run_id}"
    run_dir.mkdir(mode=0o700)

    issuer_private, _, issuer_key_id = generate_keypair(run_dir / "keys", "issuer")
    _, _, consumer_key_id = generate_keypair(run_dir / "keys", "consumer")
    _, _, reviewer_key_id = generate_keypair(run_dir / "keys", "reviewer")
    _, _, promoter_key_id = generate_keypair(run_dir / "keys", "promoter")
    _, _, node_key_id = generate_keypair(run_dir / "keys", "node")
    now = datetime.now(timezone.utc)
    identity = json.loads(json.dumps(identity))
    identity["capability_authority"]["expires_at"] = (
        now + timedelta(minutes=15)
    ).isoformat().replace("+00:00", "Z")
    validate_identity_context(identity)
    require_assigned_persona(identity)
    marker = {
        "schema_version": "hive.lab-run.v1",
        "run_id": run_id,
        "message_id": message_id,
        "created_at": utc_now(),
        "lab_root": str(lab_root.resolve()),
        "authorization_ref": AUTHORIZATION_REF,
        "allowed_environments": ["LAB", "STAGING"],
        "issuer_key_id": issuer_key_id,
        "consumer_key_id": consumer_key_id,
        "reviewer_key_id": reviewer_key_id,
        "promoter_key_id": promoter_key_id,
        "node_key_id": node_key_id,
        "commit": commit,
        "sender_surface": identity["surface"]["id"],
        "identity": identity,
        "recipient": {
            "surface": "HIVE-SURFACE",
            "machine": "hive-lab-host",
            "project": "HIVE-LAB",
        },
    }
    atomic_write_json(run_dir / ".hive-lab-run.json", marker, mode=0o600)

    state = {
        "schema_version": "hive.task-state.v1",
        "version": 0,
        "values": {"organizational-turn.status": "pending"},
        "last_message_id": None,
    }
    atomic_write_json(run_dir / "state" / "task-state.json", state)

    envelope = {
        "schema_version": "hive.work-envelope.v2",
        "message_id": message_id,
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(minutes=15)).isoformat().replace("+00:00", "Z"),
        "nonce": secrets.token_urlsafe(32),
        "identity": marker["identity"],
        "recipient": marker["recipient"],
        "authority": {
            "environment": "LAB",
            "authorization_ref": AUTHORIZATION_REF,
            "capabilities": sorted(REQUIRED_CAPABILITIES),
        },
        "task": {
            "kind": "state-transition",
            "operation": "compare-and-set",
            "key": "organizational-turn.status",
            "expected": "pending",
            "value": "acknowledged",
        },
        "provenance": {
            "repository": require_release_repository(),
            "branch": BRANCH,
            "commit": commit,
            "issue": AUTHORIZATION_REF,
            "source_records": [
                {
                    "ref": "gdrive:1L569QLkJdGd9FBAcABFL9r0OjLQ90t_0lVAe6RDR3JY",
                    "sha256": MASTER_RECORD_SHA256,
                    "status": "VERIFIED",
                },
                {
                    "ref": "authorized:PLAN_0_Hive_Mind_V2_Foundation_v1.2.md",
                    "sha256": AUTHORIZED_PLAN_SHA256,
                    "status": "CONFLICT",
                },
                {
                    "ref": "gdrive-current-copy:PLAN_0_Hive_Mind_V2_Foundation_v1.2.md",
                    "sha256": CURRENT_PLAN_COPY_SHA256,
                    "status": "CONFLICT",
                },
            ],
        },
    }
    signed = sign_document(envelope, load_private_key(issuer_private))
    validate_document(signed, "work-envelope")
    outbox = run_dir / "mailbox" / "outbox" / marker["sender_surface"]
    envelope_path = outbox / f"{message_id}.json"
    atomic_write_json(envelope_path, signed)
    return {
        "outcome": "PREPARED",
        "run_id": run_id,
        "message_id": message_id,
        "run_dir": str(run_dir),
        "envelope_sha256": document_digest(signed),
    }


def route_turn(run_dir: Path) -> dict[str, Any]:
    process_namespace = _process_namespace()
    marker = _load_marker(run_dir)
    message_id = marker["message_id"]
    outbox_path = run_dir / "mailbox" / "outbox" / marker["sender_surface"] / f"{message_id}.json"
    inbox_path = run_dir / "mailbox" / "inbox" / marker["recipient"]["surface"] / outbox_path.name
    archive_path = run_dir / "mailbox" / "archive" / marker["sender_surface"] / outbox_path.name
    transaction_lock = run_dir / "locks" / "router-transaction.lock"
    with exclusive_lock(transaction_lock):
        source_path = outbox_path if outbox_path.is_file() else inbox_path
        envelope = read_json(source_path)
        validate_document(envelope, "work-envelope")
        verify_document(envelope, _trusted_key(run_dir, "issuer", marker["issuer_key_id"]))
        _validate_policy(envelope, marker)
        if envelope["identity"]["surface"]["id"] != marker["sender_surface"]:
            raise ProtocolError("SENDER_DENIED", "identity surface does not own this outbox")

        ledger = ReplayLedger(run_dir / "replay" / "router.json")
        ledger.begin(envelope["message_id"], envelope["nonce"])
        envelope_sha256 = document_digest(envelope)

        if archive_path.exists():
            if document_digest(read_json(archive_path)) != envelope_sha256:
                raise ProtocolError("DELIVERY_COLLISION", "archive contains another document")
        else:
            atomic_write_bytes(archive_path, source_path.read_bytes())

        if inbox_path.exists():
            if document_digest(read_json(inbox_path)) != envelope_sha256:
                raise ProtocolError("DELIVERY_COLLISION", "inbox contains another document")
        elif outbox_path.exists():
            inbox_path.parent.mkdir(parents=True, exist_ok=True)
            os.replace(outbox_path, inbox_path)
        else:
            raise ProtocolError("DELIVERY_RECOVERY_MISSING", "no outbox or inbox document exists")

        delivery = {
            "schema_version": "hive.delivery.v1",
            "message_id": message_id,
            "delivered_at": utc_now(),
            "sender_surface": marker["sender_surface"],
            "recipient_surface": marker["recipient"]["surface"],
            "machine": socket.gethostname(),
            "process_id": os.getpid(),
            "process_namespace": process_namespace,
            "envelope_sha256": envelope_sha256,
            "archive_sha256": _sha256_file(archive_path),
            "inbox_sha256": _sha256_file(inbox_path),
        }
        atomic_write_json(run_dir / "receipts" / "delivery.json", delivery)
        ledger.complete(envelope["message_id"], envelope["nonce"])
        return {"outcome": "DELIVERED", **delivery}


def consume_turn(run_dir: Path) -> tuple[dict[str, Any], int]:
    process_namespace = _process_namespace()
    marker = _load_marker(run_dir)
    message_id = marker["message_id"]
    inbox_path = run_dir / "mailbox" / "inbox" / marker["recipient"]["surface"] / f"{message_id}.json"
    envelope = read_json(inbox_path)
    validate_document(envelope, "work-envelope")
    verify_document(envelope, _trusted_key(run_dir, "issuer", marker["issuer_key_id"]))
    _validate_policy(envelope, marker)
    ReplayLedger(run_dir / "replay" / "consumer.json").claim(
        envelope["message_id"], envelope["nonce"]
    )

    state_path = run_dir / "state" / "task-state.json"
    before_state = read_json(state_path)
    values = before_state.get("values")
    if not isinstance(values, dict) or not isinstance(before_state.get("version"), int):
        raise ProtocolError("STATE_INVALID", "task state is malformed")
    task = envelope["task"]
    before_value = values.get(task["key"])
    version_before = before_state["version"]
    before_sha256 = document_digest(before_state)

    if before_value != task["expected"]:
        outcome, reason_code, exit_status = "REFUSED", "STATE_PRECONDITION_FAILED", 5
        after_state = before_state
    elif before_value == task["value"]:
        outcome, reason_code, exit_status = "NOOP", "ALREADY_APPLIED", 4
        after_state = before_state
    else:
        outcome, reason_code, exit_status = "APPLIED", "STATE_CHANGED", 0
        after_state = {
            **before_state,
            "version": version_before + 1,
            "values": {**values, task["key"]: task["value"]},
            "last_message_id": message_id,
        }
        atomic_write_json(state_path, after_state)

    after_value = after_state["values"].get(task["key"])
    acknowledgment = {
        "schema_version": "hive.acknowledgment.v1",
        "ack_id": str(uuid4()),
        "message_id": message_id,
        "consumed_at": utc_now(),
        "consumer": {
            "surface": marker["recipient"]["surface"],
            "runtime": "hive-protocol-reference",
            "machine": socket.gethostname(),
            "project": marker["recipient"]["project"],
            "process_id": os.getpid(),
            "process_namespace": process_namespace,
        },
        "outcome": outcome,
        "reason_code": reason_code,
        "state": {
            "key": task["key"],
            "before": before_value,
            "after": after_value,
            "before_sha256": before_sha256,
            "after_sha256": document_digest(after_state),
            "changed": outcome == "APPLIED",
            "version_before": version_before,
            "version_after": after_state["version"],
        },
    }
    signed = sign_document(
        acknowledgment, load_private_key(run_dir / "keys" / "consumer.private.pem")
    )
    validate_document(signed, "acknowledgment")
    atomic_write_json(run_dir / "receipts" / "acknowledgment.json", signed)
    return signed, exit_status


def _safe_note_name(value: str) -> str:
    if not value.isascii() or not re.fullmatch(r"[A-Za-z0-9 ._-]+", value):
        raise ProtocolError("NOTE_NAME_DENIED", f"unsafe Obsidian note name: {value}")
    return value


def _backlink_note(entity: str, relation: str, turn_stem: str, existing: str = "") -> str:
    backlink = f"- {relation} [[{turn_stem}]]"
    if backlink in existing:
        return existing
    if existing:
        return existing.rstrip() + "\n" + backlink + "\n"
    return (
        "---\n"
        "type: hive-entity\n"
        f"entity: {entity}\n"
        "---\n\n"
        f"# {entity}\n\n"
        "## Typed backlinks\n\n"
        f"{backlink}\n"
    )


FLEET_FOLDER = "70-Agent-Fleet"
# Folder name used by earlier vaults; migrated atomically, never written fresh.
LEGACY_FLEET_FOLDER = "70-Hive-Fleet"
_DIRECTORY_NOFOLLOW = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
_RENAME_NOREPLACE = 1
_renameat2_fn = None
_renameat2_probed = False


def _open_owned_directory(path: Path) -> int:
    try:
        fd = os.open(path, _DIRECTORY_NOFOLLOW)
    except OSError as exc:
        raise ProtocolError(
            "VAULT_FOLDER_UNSAFE",
            "vault root is not an owned directory",
        ) from exc
    try:
        st = os.fstat(fd)
    except OSError as exc:
        os.close(fd)
        raise ProtocolError(
            "VAULT_FOLDER_UNSAFE",
            "vault root is not an owned directory",
        ) from exc
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid():
        os.close(fd)
        raise ProtocolError(
            "VAULT_FOLDER_UNSAFE",
            "vault root is not an owned directory",
        )
    return fd


def _lstat_at(dir_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _linux_renameat2(
    src_dir_fd: int, src: str, dst_dir_fd: int, dst: str, flags: int
) -> None:
    global _renameat2_fn, _renameat2_probed
    if not _renameat2_probed:
        _renameat2_probed = True
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            fn = getattr(libc, "renameat2", None)
        except OSError:
            fn = None
        if fn is not None:
            fn.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            fn.restype = ctypes.c_int
            _renameat2_fn = fn
    if _renameat2_fn is None:
        raise OSError(errno.ENOSYS, "renameat2 is not available")
    ctypes.set_errno(0)
    rc = _renameat2_fn(
        src_dir_fd,
        os.fsencode(src),
        dst_dir_fd,
        os.fsencode(dst),
        flags,
    )
    if rc != 0:
        err = ctypes.get_errno() or errno.ENOSYS
        raise OSError(err, os.strerror(err))


def _renameat2_available() -> bool:
    if not sys.platform.startswith("linux"):
        return False
    try:
        _linux_renameat2(-1, "a", -1, "b", _RENAME_NOREPLACE)
    except OSError as exc:
        return exc.errno not in (errno.ENOSYS, errno.EINVAL)
    return True


def _rename_legacy_fleet(dir_fd: int) -> None:
    if sys.platform.startswith("linux"):
        try:
            _linux_renameat2(
                dir_fd,
                LEGACY_FLEET_FOLDER,
                dir_fd,
                FLEET_FOLDER,
                _RENAME_NOREPLACE,
            )
            return
        except OSError as exc:
            if exc.errno in (errno.EEXIST, errno.ENOTEMPTY):
                raise ProtocolError(
                    "VAULT_FOLDER_CONFLICT",
                    "both legacy and current fleet folders exist; leaving both untouched",
                ) from exc
            if exc.errno not in (errno.ENOSYS, errno.EINVAL):
                raise
            # renameat2 is missing or unsupported on this kernel; fall through.
    # Fallback: os.replace can still replace an empty destination directory
    # that appears in the race window after the lstat checks.
    os.replace(
        LEGACY_FLEET_FOLDER,
        FLEET_FOLDER,
        src_dir_fd=dir_fd,
        dst_dir_fd=dir_fd,
    )


def _fleet_note_path(vault_root: Path, note_name: str) -> Path:
    """Return the path of a fleet turn note, migrating the legacy folder safely.

    The configured vault root is trusted input. If the root is completely
    absent, return root / 70-Agent-Fleet / name without creating anything,
    matching the pre-migration shape. Otherwise the root is resolved once.
    If only the legacy folder exists it is renamed atomically on a
    same-directory O_NOFOLLOW fd, using renameat2(RENAME_NOREPLACE) on
    Linux. If both folders exist the call refuses and leaves both untouched.
    A dangling-symlink root, or a symlink at either fleet entry inside the
    vault, is refused. A read-only or failed rename leaves the legacy folder
    unchanged.
    """

    vault_root = Path(vault_root)
    note_path = vault_root / FLEET_FOLDER / note_name
    if not os.path.lexists(vault_root):
        return note_path
    try:
        resolved_root = vault_root.resolve(strict=True)
    except OSError as exc:
        raise ProtocolError(
            "VAULT_FOLDER_UNSAFE",
            "vault root is not an owned directory",
        ) from exc
    fd = _open_owned_directory(resolved_root)
    try:
        current_st = _lstat_at(fd, FLEET_FOLDER)
        legacy_st = _lstat_at(fd, LEGACY_FLEET_FOLDER)
        if current_st is not None and stat.S_ISLNK(current_st.st_mode):
            raise ProtocolError("VAULT_FOLDER_UNSAFE", "fleet note folder is a symlink")
        if legacy_st is not None and stat.S_ISLNK(legacy_st.st_mode):
            raise ProtocolError("VAULT_FOLDER_UNSAFE", "fleet note folder is a symlink")
        if current_st is not None and not stat.S_ISDIR(current_st.st_mode):
            raise ProtocolError("VAULT_FOLDER_UNSAFE", "fleet note folder is not a directory")
        if legacy_st is not None and not stat.S_ISDIR(legacy_st.st_mode):
            raise ProtocolError("VAULT_FOLDER_UNSAFE", "fleet note folder is not a directory")
        current_dir = current_st is not None
        legacy_dir = legacy_st is not None
        if current_dir and legacy_dir:
            raise ProtocolError(
                "VAULT_FOLDER_CONFLICT",
                "both legacy and current fleet folders exist; leaving both untouched",
            )
        if legacy_dir and current_st is None:
            if not os.access(".", os.W_OK, dir_fd=fd, follow_symlinks=False):
                raise ProtocolError(
                    "VAULT_FOLDER_UNSAFE",
                    "legacy fleet folder cannot be migrated on a read-only path",
                )
            try:
                _rename_legacy_fleet(fd)
            except OSError as exc:
                raise ProtocolError(
                    "VAULT_FOLDER_UNSAFE",
                    "legacy fleet folder could not be migrated atomically",
                ) from exc
            current_st = _lstat_at(fd, FLEET_FOLDER)
            if (
                current_st is None
                or stat.S_ISLNK(current_st.st_mode)
                or not stat.S_ISDIR(current_st.st_mode)
            ):
                raise ProtocolError("VAULT_FOLDER_UNSAFE", "fleet note folder is a symlink")
    finally:
        os.close(fd)
    return note_path


def promote_turn(run_dir: Path) -> dict[str, Any]:
    # Compatibility import for callers of the M001 module path. M003 requires
    # explicit proposal and review commands before this boundary can succeed.
    from .m003 import promote_turn as promote_m003

    return promote_m003(run_dir)

    # Retained below only as historical implementation context; it is
    # unreachable from the public API.
    _process_namespace()
    marker = _load_marker(run_dir)
    envelope = read_json(
        run_dir / "mailbox" / "inbox" / marker["recipient"]["surface"] / f"{marker['message_id']}.json"
    )
    acknowledgment = read_json(run_dir / "receipts" / "acknowledgment.json")
    delivery = read_json(run_dir / "receipts" / "delivery.json")
    state = read_json(run_dir / "state" / "task-state.json")
    validate_document(envelope, "work-envelope")
    validate_document(acknowledgment, "acknowledgment")
    verify_document(envelope, _trusted_key(run_dir, "issuer", marker["issuer_key_id"]))
    verify_document(
        acknowledgment, _trusted_key(run_dir, "consumer", marker["consumer_key_id"])
    )
    if acknowledgment["outcome"] != "APPLIED" or not acknowledgment["state"]["changed"]:
        raise ProtocolError("PROMOTION_INELIGIBLE", "only applied state changes are promotable")
    if acknowledgment["message_id"] != marker["message_id"]:
        raise ProtocolError("ACKNOWLEDGMENT_MISMATCH", "acknowledgment references another message")
    if acknowledgment["state"]["after_sha256"] != document_digest(state):
        raise ProtocolError("STATE_RECEIPT_MISMATCH", "acknowledgment does not match persisted state")
    if (
        delivery.get("message_id") != marker["message_id"]
        or delivery.get("envelope_sha256") != document_digest(envelope)
        or delivery.get("machine") != marker["recipient"]["machine"]
        or delivery.get("recipient_surface") != marker["recipient"]["surface"]
    ):
        raise ProtocolError("DELIVERY_RECEIPT_MISMATCH", "delivery receipt does not match the turn")

    turn_stem = _safe_note_name(f"Hive turn {marker['message_id']}")
    relations = [
        ("project", envelope["identity"]["project"]),
        ("surface", marker["recipient"]["surface"]),
        ("machine", marker["recipient"]["machine"]),
        ("seat", envelope["identity"]["seat"]),
    ]
    relation_lines = "\n".join(
        f"  - type: {relation}\n    target: \"[[{_safe_note_name(entity)}]]\""
        for relation, entity in relations
    )
    note = (
        "---\n"
        "type: hive-turn-receipt\n"
        "privacy: non-private\n"
        f"message_id: {marker['message_id']}\n"
        "relations:\n"
        f"{relation_lines}\n"
        "---\n\n"
        f"# {turn_stem}\n\n"
        f"- Outcome: `{acknowledgment['outcome']}`\n"
        f"- Reason: `{acknowledgment['reason_code']}`\n"
        f"- State key: `{acknowledgment['state']['key']}`\n"
        f"- Before: `{acknowledgment['state']['before']}`\n"
        f"- After: `{acknowledgment['state']['after']}`\n"
        f"- Consumer: `[[{marker['recipient']['surface']}]]` on `[[{marker['recipient']['machine']}]]`\n"
    )
    candidate = {
        "schema_version": "hive.vault-candidate.v1",
        "message_id": marker["message_id"],
        "privacy": "non-private",
        "note_name": f"{turn_stem}.md",
        "note": note,
        "relations": [{"type": relation, "target": entity} for relation, entity in relations],
        "source_acknowledgment_sha256": document_digest(acknowledgment),
    }
    staging_root = run_dir / "vault-staging"
    candidate_path = staging_root / "_unreviewed" / f"{marker['message_id']}.json"
    atomic_write_json(candidate_path, candidate)

    vault_root = run_dir / "vault"
    note_path = _fleet_note_path(vault_root, candidate["note_name"])
    atomic_write_bytes(note_path, note.encode("utf-8"))
    entity_paths: list[str] = []
    for relation, entity in relations:
        entity_name = _safe_note_name(entity)
        entity_path = vault_root / "entities" / f"{entity_name}.md"
        existing = entity_path.read_text(encoding="utf-8") if entity_path.exists() else ""
        atomic_write_bytes(
            entity_path,
            _backlink_note(entity_name, f"{relation}_of", turn_stem, existing).encode("utf-8"),
        )
        entity_paths.append(str(entity_path.relative_to(vault_root)))

    promoted_path = staging_root / "_promoted" / candidate_path.name
    promoted_path.parent.mkdir(parents=True, exist_ok=True)
    os.replace(candidate_path, promoted_path)
    promotion = {
        "schema_version": "hive.vault-promotion.v1",
        "message_id": marker["message_id"],
        "promoted_at": utc_now(),
        "candidate_sha256": document_digest(candidate),
        "note_path": str(note_path.relative_to(vault_root)),
        "note_sha256": _sha256_file(note_path),
        "typed_backlinks": entity_paths,
        "unreviewed_remaining": len(list((staging_root / "_unreviewed").glob("*.json"))),
    }
    atomic_write_json(run_dir / "receipts" / "promotion.json", promotion)

    receipt = {
        "schema_version": "hive.turn-receipt.v1",
        "receipt_id": str(uuid4()),
        "message_id": marker["message_id"],
        "recorded_at": utc_now(),
        "retrieved_at": None,
        "environment": envelope["authority"]["environment"],
        "privacy": "non-private",
        "artifacts": {
            "envelope_sha256": document_digest(envelope),
            "delivery_sha256": document_digest(delivery),
            "acknowledgment_sha256": document_digest(acknowledgment),
            "state_sha256": document_digest(state),
            "vault_note_sha256": promotion["note_sha256"],
            "promotion_sha256": document_digest(promotion),
        },
        "proof": {
            "exists": "VERIFIED",
            "current": "VERIFIED",
            "wired": "VERIFIED",
            "running": "VERIFIED",
            "delivered": "VERIFIED",
            "consumed": "VERIFIED",
            "changed_behavior": "VERIFIED",
            "persists_next_turn": "PENDING",
        },
    }
    signed = sign_document(
        receipt, load_private_key(run_dir / "keys" / "consumer.private.pem")
    )
    validate_document(signed, "turn-receipt")
    atomic_write_json(run_dir / "receipts" / "turn-receipt.json", signed)
    return {
        "outcome": "PROMOTED",
        "message_id": marker["message_id"],
        "note_path": str(note_path),
        "typed_backlinks": entity_paths,
        "unreviewed_remaining": promotion["unreviewed_remaining"],
        "receipt_sha256": document_digest(signed),
    }


def retrieve_next_turn(run_dir: Path) -> dict[str, Any]:
    # Compatibility import for callers of the M001 module path.
    from .m003 import retrieve_next_turn as retrieve_m003

    return retrieve_m003(run_dir)

    # Retained below only as historical implementation context; it is
    # unreachable from the public API.
    process_namespace = _process_namespace()
    marker = _load_marker(run_dir)
    receipt_path = run_dir / "receipts" / "turn-receipt.json"
    receipt = read_json(receipt_path)
    validate_document(receipt, "turn-receipt")
    verify_document(receipt, _trusted_key(run_dir, "consumer", marker["consumer_key_id"]))
    state = read_json(run_dir / "state" / "task-state.json")
    if state.get("last_message_id") != marker["message_id"]:
        raise ProtocolError("NEXT_TURN_STATE_MISSING", "state does not reference the consumed message")
    if state.get("values", {}).get("organizational-turn.status") != "acknowledged":
        raise ProtocolError("NEXT_TURN_STATE_MISSING", "expected state change is not retrievable")
    if document_digest(state) != receipt["artifacts"]["state_sha256"]:
        raise ProtocolError("NEXT_TURN_STATE_DRIFT", "persisted state hash changed")

    note_stem = _safe_note_name(f"Hive turn {marker['message_id']}")
    note_path = _fleet_note_path(run_dir / "vault", f"{note_stem}.md")
    if _sha256_file(note_path) != receipt["artifacts"]["vault_note_sha256"]:
        raise ProtocolError("NEXT_TURN_NOTE_DRIFT", "vault note hash changed")
    entities = ["HIVE-LAB", "HIVE-SURFACE", "hive-lab-host", "UNASSIGNED"]
    for entity in entities:
        entity_path = run_dir / "vault" / "entities" / f"{entity}.md"
        if f"[[{note_stem}]]" not in entity_path.read_text(encoding="utf-8"):
            raise ProtocolError("BACKLINK_MISSING", f"missing backlink from {entity}")

    receipt["retrieved_at"] = utc_now()
    receipt["proof"]["persists_next_turn"] = "VERIFIED"
    signed = sign_document(
        receipt, load_private_key(run_dir / "keys" / "consumer.private.pem")
    )
    validate_document(signed, "turn-receipt")
    atomic_write_json(receipt_path, signed)

    lab_root = Path(marker["lab_root"])
    evidence_root = lab_root / "evidence"
    evidence_root.mkdir(parents=True, exist_ok=True)
    evidence_path = evidence_root / f"{marker['run_id']}.turn-receipt.json"
    atomic_write_json(evidence_path, signed)
    consumer_public_source = run_dir / "keys" / "consumer.public.pem"
    load_public_key(consumer_public_source)
    consumer_public_path = evidence_root / f"{marker['run_id']}.consumer.public.pem"
    atomic_write_bytes(consumer_public_path, consumer_public_source.read_bytes())
    retrieval = {
        "schema_version": "hive.next-turn-retrieval.v1",
        "run_id": marker["run_id"],
        "message_id": marker["message_id"],
        "retrieved_at": signed["retrieved_at"],
        "process_id": os.getpid(),
        "process_namespace": process_namespace,
        "receipt_sha256": document_digest(signed),
        "state_sha256": document_digest(state),
        "vault_note_sha256": _sha256_file(note_path),
        "consumer_public_key_sha256": _sha256_file(consumer_public_path),
        "backlinks_verified": len(entities),
    }
    atomic_write_json(evidence_root / f"{marker['run_id']}.retrieval.json", retrieval)
    return {"outcome": "RETRIEVED_NEXT_TURN", **retrieval}


def rollback_turn(run_dir: Path, lab_root: Path) -> dict[str, Any]:
    _process_namespace()
    marker = _load_marker(run_dir)
    resolved_lab = lab_root.resolve()
    if resolved_lab != Path(marker["lab_root"]).resolve():
        raise ProtocolError("ROLLBACK_BOUNDARY", "LAB root does not match the run marker")
    expected_parent = resolved_lab / "runs"
    if run_dir.resolve().parent != expected_parent.resolve():
        raise ProtocolError("ROLLBACK_BOUNDARY", "run is outside the LAB runs directory")
    if run_dir.is_symlink():
        raise ProtocolError("ROLLBACK_BOUNDARY", "refusing to remove a symlinked run")

    evidence_root = resolved_lab / "evidence"
    receipt_path = evidence_root / f"{marker['run_id']}.turn-receipt.json"
    retrieval_path = evidence_root / f"{marker['run_id']}.retrieval.json"
    consumer_public_path = evidence_root / f"{marker['run_id']}.consumer.public.pem"
    if not receipt_path.is_file() or not retrieval_path.is_file() or not consumer_public_path.is_file():
        raise ProtocolError(
            "ROLLBACK_EVIDENCE_MISSING",
            "persistent receipt, retrieval, or verifier evidence is absent",
        )
    receipt = read_json(receipt_path)
    verifier = load_public_key(consumer_public_path)
    verify_document(receipt, {marker["consumer_key_id"]: verifier})
    rollback_record = {
        "schema_version": "hive.rollback.v1",
        "run_id": marker["run_id"],
        "message_id": marker["message_id"],
        "rolled_back_at": utc_now(),
        "target": str(run_dir.resolve()),
        "receipt_sha256": _sha256_file(receipt_path),
        "retrieval_sha256": _sha256_file(retrieval_path),
        "consumer_public_key_sha256": _sha256_file(consumer_public_path),
        "operational_residue": "PENDING_CHECK",
    }
    rollback_path = evidence_root / f"{marker['run_id']}.rollback.json"
    atomic_write_json(rollback_path, rollback_record)
    shutil.rmtree(run_dir)
    residue = [str(path) for path in expected_parent.glob(f"*{marker['run_id']}*")]
    if run_dir.exists() or residue:
        raise ProtocolError("ROLLBACK_RESIDUE", f"operational residue remains: {residue}")
    rollback_record["operational_residue"] = "NONE"
    atomic_write_json(rollback_path, rollback_record)
    return {"outcome": "ROLLED_BACK", **rollback_record}
