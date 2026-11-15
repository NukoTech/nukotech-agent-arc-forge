"""Atomic filesystem storage and replay ledgers."""

from __future__ import annotations

import fcntl
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
from uuid import uuid4

from .core import ProtocolError, canonical_bytes


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def require_owned_directory(path: Path) -> None:
    """Create path if needed and require a real, owner-only directory."""

    if path.is_symlink():
        raise ProtocolError(
            "OWNED_DIRECTORY_UNSAFE",
            "directory must not be a symlink",
        )
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or path.resolve() != path or path.stat().st_uid != os.geteuid():
        raise ProtocolError(
            "OWNED_DIRECTORY_UNSAFE",
            "directory is not owned and canonical",
        )
    os.chmod(path, 0o700)


def atomic_write_bytes(path: Path, payload: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.{uuid4().hex}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()


def atomic_write_json(path: Path, document: Mapping[str, Any], mode: int = 0o644) -> None:
    atomic_write_bytes(path, canonical_bytes(document) + b"\n", mode=mode)


def read_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ProtocolError("MISSING_DOCUMENT", f"expected regular file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProtocolError("INVALID_DOCUMENT", f"cannot read JSON document: {path}") from exc
    if not isinstance(value, dict):
        raise ProtocolError("INVALID_DOCUMENT", f"JSON root must be an object: {path}")
    return value


def require_no_symlink_components(
    root: Path,
    target: Path,
    *,
    code: str,
    detail: str,
) -> None:
    """Reject any existing symlink between one trusted root and target."""

    root = root.expanduser().absolute()
    target = target.expanduser().absolute()
    try:
        relative = target.relative_to(root)
    except ValueError as exc:
        raise ProtocolError(code, detail) from exc
    current = root
    if current.is_symlink():
        raise ProtocolError(code, detail)
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ProtocolError(code, detail)


def ensure_owned_directory(
    root: Path,
    target: Path,
    *,
    code: str,
    detail: str,
    mode: int = 0o700,
) -> Path:
    """Create one contained directory tree and reject links or foreign ownership."""

    root = root.expanduser().absolute()
    target = target.expanduser().absolute()
    require_no_symlink_components(root, target, code=code, detail=detail)
    try:
        target.mkdir(parents=True, exist_ok=True, mode=mode)
    except OSError as exc:
        raise ProtocolError(code, detail) from exc
    require_no_symlink_components(root, target, code=code, detail=detail)
    try:
        metadata = target.stat()
    except OSError as exc:
        raise ProtocolError(code, detail) from exc
    if (
        target.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
    ):
        raise ProtocolError(code, detail)
    os.chmod(target, mode)
    return target


class _ExclusiveLock:
    """Context manager that does not mutate frozen exceptions on exit."""

    def __init__(self, lock_path: Path) -> None:
        self.lock_path = lock_path
        self.handle = None

    def __enter__(self):
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.lock_path, flags, 0o600)
        except OSError as exc:
            raise ProtocolError(
                "LOCK_BOUNDARY", "lock path is not a safe regular file"
            ) from exc
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
            os.close(descriptor)
            raise ProtocolError(
                "LOCK_BOUNDARY", "lock path is not an owned regular file"
            )
        os.fchmod(descriptor, 0o600)
        self.handle = os.fdopen(descriptor, "a+", encoding="utf-8")
        fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        if self.handle is not None:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            self.handle.close()
        return False


def exclusive_lock(lock_path: Path) -> _ExclusiveLock:
    """Hold an inter-process exclusive lock for a filesystem transaction."""

    return _ExclusiveLock(lock_path)


class ReplayLedger:
    """Claim message IDs and nonces under an inter-process file lock."""

    def __init__(self, ledger_path: Path, *, mode: int = 0o644) -> None:
        self.ledger_path = ledger_path
        self.lock_path = ledger_path.with_suffix(ledger_path.suffix + ".lock")
        self.mode = mode

    def begin(self, message_id: str, nonce: str) -> str:
        """Begin a replay-protected transaction, resuming only its pending claim."""

        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with exclusive_lock(self.lock_path):
            ledger = (
                read_json(self.ledger_path)
                if self.ledger_path.exists()
                else {"schema_version": "hive.replay-ledger.v1", "messages": {}, "nonces": {}}
            )
            messages = ledger.get("messages")
            nonces = ledger.get("nonces")
            if not isinstance(messages, dict) or not isinstance(nonces, dict):
                raise ProtocolError("REPLAY_LEDGER_INVALID", "replay ledger is malformed")
            existing = messages.get(message_id)
            if existing is not None:
                if (
                    isinstance(existing, dict)
                    and existing.get("nonce") == nonce
                    and existing.get("state") == "PENDING"
                ):
                    return "RESUME"
                raise ProtocolError("REPLAY_MESSAGE_ID", "message ID was already consumed", 3)
            if nonce in nonces:
                raise ProtocolError("REPLAY_NONCE", "nonce was already consumed", 3)
            claimed_at = utc_now()
            messages[message_id] = {
                "nonce": nonce,
                "state": "PENDING",
                "claimed_at": claimed_at,
                "completed_at": None,
            }
            nonces[nonce] = {"message_id": message_id, "claimed_at": claimed_at}
            atomic_write_json(self.ledger_path, ledger, mode=self.mode)
            return "NEW"

    def complete(self, message_id: str, nonce: str) -> None:
        """Mark a pending claim complete after its durable effects exist."""

        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with exclusive_lock(self.lock_path):
            ledger = read_json(self.ledger_path)
            existing = ledger.get("messages", {}).get(message_id)
            if (
                not isinstance(existing, dict)
                or existing.get("nonce") != nonce
                or existing.get("state") != "PENDING"
            ):
                raise ProtocolError("REPLAY_LEDGER_INVALID", "pending replay claim is absent")
            existing["state"] = "COMPLETE"
            existing["completed_at"] = utc_now()
            atomic_write_json(self.ledger_path, ledger, mode=self.mode)

    def claim(self, message_id: str, nonce: str) -> None:
        """Claim immediately for operations that do not support crash resumption."""

        result = self.begin(message_id, nonce)
        if result == "RESUME":
            raise ProtocolError("REPLAY_MESSAGE_ID", "message ID has a pending claim", 3)
        self.complete(message_id, nonce)
