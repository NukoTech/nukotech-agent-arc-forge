"""Attended signed plans, immutable declarative installs and owned lifecycle."""

from __future__ import annotations

import copy
import ctypes
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from importlib.resources import files
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
if os.name != "nt" and not sys.platform.startswith("win"):
    import fcntl  # POSIX only; Windows is refused until v1.1
from typing import Any, Mapping
from uuid import uuid4

from jsonschema import Draft202012Validator, FormatChecker

from hive_protocol.adapters.models import AdapterApproval, validate_adapter_document
from hive_protocol.adapters.security import reject_credential_values
from hive_protocol.core import (ProtocolError, canonical_bytes, document_digest,
    public_key_id, sign_document, verify_document)
from hive_protocol.storage import (atomic_write_bytes, atomic_write_json,
    ensure_owned_directory, exclusive_lock, require_no_symlink_components)

from .artifacts import (ArcPackage, MAX_FILE_BYTES, digest, inspect_arc_package, json_object, read_bounded,
    refuse_windows, safe_path)

_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
MAX_CONTEXT_BYTES = MAX_FILE_BYTES
_CONTEXT_FIELDS = {"schema_version", "loadout_id", "version_digest", "target",
    "admission_key_id", "execution_mode", "grants_authority", "adapter_references",
    "components", "context_sha256"}


def _error(code: str, message: str) -> None:
    raise ProtocolError(f"LOADOUT_{code}", message)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _date(value: str) -> datetime:
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if date.tzinfo is None:
            raise ValueError("timezone required")
        return date
    except (ValueError, TypeError, AttributeError) as exc:
        raise ProtocolError("LOADOUT_EXPIRY_INVALID", "loadout timestamp is invalid") from exc


def _identity(metadata) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


class _OwnedDirectory:
    """Anchor every path component; never traverse a replaced directory name."""

    def __init__(self, vault: Path, path: Path, *, create: bool = False):
        self.vault, self.path, self.create = vault, path, create
        self.opened, self.chain = [], []

    def __enter__(self):
        if not self.path.is_relative_to(self.vault):
            _error("ROOT_BOUNDARY", "recovery directory leaves the Hive")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            parent = os.open(self.path.anchor, flags)
            self.opened.append(parent)
            current = Path(self.path.anchor)
            for name in self.path.parts[1:]:
                current /= name
                owned = current == self.vault or current.is_relative_to(self.vault)
                try:
                    child = os.open(name, flags, dir_fd=parent)
                except FileNotFoundError:
                    if not self.create or not owned:
                        raise
                    try:
                        os.mkdir(name, mode=0o700, dir_fd=parent)
                    except FileExistsError:
                        pass
                    child = os.open(name, flags, dir_fd=parent)
                self.opened.append(child)
                metadata = os.fstat(child)
                if owned and (metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022):
                    _error("ROOT_BOUNDARY", "recovery directory is unowned or writable by others")
                self.chain.append((parent, name, child))
                parent = child
            self.fd = parent
            self.verify()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def verify(self):
        for parent, name, child in self.chain:
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISDIR(named.st_mode) or _identity(named) != _identity(os.fstat(child)):
                _error("ROOT_BOUNDARY", "recovery directory was replaced; preserve all copies")

    def __exit__(self, *_):
        for descriptor in reversed(self.opened):
            os.close(descriptor)
        self.opened.clear()
        return False


def _rename_preserving_destination(source_fd: int, source: str, target_fd: int, target: str):
    """Native atomic no-clobber rename; ordinary rename can replace an empty dir."""
    native = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        function, flag = getattr(native, "renameatx_np", None), 4  # RENAME_EXCL, sys/stdio.h
    elif sys.platform.startswith("linux"):
        function, flag = getattr(native, "renameat2", None), 1  # RENAME_NOREPLACE
    else:
        function = None
    if function is None:
        _error("RECOVERY_UNSUPPORTED", "this host lacks verified atomic no-clobber recovery moves")
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    if function(source_fd, os.fsencode(source), target_fd, os.fsencode(target), flag):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _verify_directory_content(descriptor: int, version: Mapping[str, Any], *, allow_missing: bool):
    """Read the captured inode, not a pathname which another writer can replace."""
    expected = version["files"]
    directories = {str(parent) for name in expected for parent in PurePosixPath(safe_path(name)).parents if str(parent) != "."}
    actual = set()

    def visit(parent, prefix=""):
        for name in os.listdir(parent):
            relative = prefix + name
            metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                if relative not in directories:
                    _error("OWNED_CONTENT_CHANGED", "recovery preserves an unowned directory")
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    if _identity(os.fstat(child)) != _identity(metadata):
                        _error("OWNED_CONTENT_CHANGED", "recovery directory changed during verification")
                    visit(child, relative + "/")
                finally:
                    os.close(child)
            else:
                if (relative not in expected or not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_nlink != 1 or metadata.st_size > MAX_FILE_BYTES):
                    _error("OWNED_CONTENT_CHANGED", "recovery preserves changed or unowned content")
                child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                try:
                    opened = os.fstat(child)
                    if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                            or _identity(opened) != _identity(metadata)):
                        _error("OWNED_CONTENT_CHANGED", "recovery file changed during verification")
                    with os.fdopen(os.dup(child), "rb") as handle:
                        payload = handle.read(MAX_FILE_BYTES + 1)
                    after = os.fstat(child)
                    if (len(payload) > MAX_FILE_BYTES or digest(payload) != expected[relative]
                            or (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) !=
                            (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                        _error("OWNED_CONTENT_CHANGED", "recovery preserves concurrently changed content")
                    actual.add(relative)
                finally:
                    os.close(child)
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if _identity(named) != _identity(metadata):
                _error("OWNED_CONTENT_CHANGED", "recovery entry changed during verification")

    visit(descriptor)
    if not allow_missing and actual != set(expected):
        _error("OWNED_CONTENT_CHANGED", "recovery file set changed")


class _ReadOnlyLock:
    def __init__(self, path: Path):
        self.path, self.descriptor = path, None

    def __enter__(self):
        refuse_windows()
        try:
            descriptor = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError as exc:
            raise ProtocolError("LOADOUT_ROOT_BOUNDARY", "existing loadout lock is unavailable") from exc
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
            os.close(descriptor)
            _error("ROOT_BOUNDARY", "existing loadout lock is not an owned regular file")
        fcntl.flock(descriptor, fcntl.LOCK_SH)
        self.descriptor = descriptor
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.descriptor is not None:
            fcntl.flock(self.descriptor, fcntl.LOCK_UN)
            os.close(self.descriptor)
        return False


class LoadoutManager:
    """The keys belong to the existing local attended operator, never to Arc."""

    def __init__(self, vault: Path, *, target: Mapping[str, str], registry: Any,
                 request_key: Any, approver_key: Any, state_key: Any,
                 approver_identity: Mapping[str, str], read_only: bool = False):
        refuse_windows()
        raw = vault.expanduser().absolute()
        if any(path.is_symlink() for path in (raw, *raw.parents)) or not raw.is_dir():
            _error("ROOT_BOUNDARY", "loadouts require an existing canonical Hive root")
        self.vault = raw.resolve()
        self.root = self.vault / ".hive" / "loadouts"
        self.target = copy.deepcopy(dict(target))
        self.registry = registry
        self.read_only = read_only
        self.request_key, self.approver_key, self.state_key = request_key, approver_key, state_key
        self.approver_identity = copy.deepcopy(dict(approver_identity))
        self._request_keys = {public_key_id(request_key.public_key()): request_key.public_key()}
        self._approver_keys = {public_key_id(approver_key.public_key()): approver_key.public_key()}
        self._state_keys = {public_key_id(state_key.public_key()): state_key.public_key()}
        self._schema = json.loads(files("hive_protocol.schemas").joinpath("loadout-plan.v1.schema.json").read_text())
        validator = Draft202012Validator(self._schema["$defs"]["target"])
        if list(validator.iter_errors(self.target)):
            _error("TARGET_INVALID", "loadout target is incomplete")
        if any(self.approver_identity.get(key) != self.target[key] for key in
               ("persona_id", "surface_id", "machine_id", "project_id")):
            _error("TARGET_INVALID", "attended operator identity does not match loadout target")
        for directory in (self.root, self.root / "objects", self.root / "journals"):
            if read_only:
                self._path(directory)
                if not directory.is_dir() or directory.stat().st_uid != os.geteuid():
                    _error("ROOT_BOUNDARY", "existing loadout storage is unavailable or unowned")
            else:
                self._directory(directory)

    def _directory(self, path: Path) -> Path:
        return ensure_owned_directory(self.vault, path, code="LOADOUT_ROOT_BOUNDARY",
                                      detail="loadout storage must be owned and free of symlinks")

    def _path(self, path: Path) -> Path:
        require_no_symlink_components(self.vault, path, code="LOADOUT_ROOT_BOUNDARY",
                                      detail="loadout path must remain inside its owned namespace")
        return path

    def _read_state(self) -> dict[str, Any]:
        path = self._path(self.root / "state.json")
        if not path.exists():
            return sign_document({"schema_version": "hive.loadout-state.v1", "target": copy.deepcopy(self.target),
                "revision": 0, "records": {}, "completed": {}}, self.state_key)
        state = json_object(read_bounded(path))
        verify_document(state, self._state_keys)
        if (set(state) != {"schema_version", "target", "revision", "records", "completed", "signature"} or
                state["schema_version"] != "hive.loadout-state.v1" or state["target"] != self.target or
                not isinstance(state["revision"], int) or not isinstance(state["records"], dict) or
                not isinstance(state["completed"], dict)):
            _error("STATE_INVALID", "loadout state binding is invalid")
        return state

    def _write_state(self, state: dict[str, Any]) -> None:
        state["revision"] += 1
        signed = sign_document(state, self.state_key)
        reject_credential_values(signed, location="loadout state", verified_by=self._state_keys)
        if len(canonical_bytes(signed)) > 8 * 1024 * 1024:
            _error("STATE_LIMIT", "loadout state reached its bounded capacity")
        atomic_write_json(self._path(self.root / "state.json"), signed, mode=0o600)

    def _references(self, references: Any) -> list[dict[str, Any]]:
        if not isinstance(references, list) or len(references) > 64:
            _error("ADAPTER_PIN_INVALID", "adapter references must be a bounded array")
        result = []
        seen = set()
        for reference in references:
            if not isinstance(reference, dict) or set(reference) != {"adapter_id", "version", "manifest_digest", "capability_ids"}:
                _error("ADAPTER_PIN_INVALID", "adapter reference shape is invalid")
            if reference["adapter_id"] in seen:
                _error("ADAPTER_PIN_INVALID", "adapter references must be unique")
            seen.add(reference["adapter_id"])
            # Registry instances may outlive a revocation made by another attended
            # request; consult durable revocation state before accepting the pin.
            if reference["adapter_id"] in self.registry._load_revocations():
                _error("ADAPTER_REVOKED", "referenced adapter was revoked")
            entry = self.registry.require(reference["adapter_id"], reference["version"])
            capabilities = reference["capability_ids"]
            if (entry.manifest_digest != reference["manifest_digest"] or
                    not isinstance(capabilities, list) or not capabilities or
                    any(not isinstance(x, str) for x in capabilities) or
                    len(set(capabilities)) != len(capabilities) or
                    set(capabilities) - set(entry.manifest.capability_ids)):
                _error("ADAPTER_PIN_INVALID", "adapter hash or capability reference differs from its registered manifest")
            result.append(copy.deepcopy(reference))
        return sorted(result, key=lambda value: value["adapter_id"])

    def _manifest(self, loadout_id: str, arc: ArcPackage, references: Any) -> dict[str, Any]:
        result = {**copy.deepcopy(arc.manifest), "loadout_id": loadout_id,
                  "target": copy.deepcopy(self.target), "adapter_references": self._references(references)}
        reject_credential_values(result, location="loadout manifest")
        return result

    def plan(self, operation: str, loadout_id: str, *, authorization_ref: str,
             source: Mapping[str, Path] | None = None, adapter_references: list | None = None,
             version_digest: str | None = None, reason: str = "attended operator request",
             ttl_seconds: int = 900) -> dict[str, Any]:
        if self.read_only:
            _error("READ_ONLY", "this loadout view cannot prepare changes")
        if not isinstance(loadout_id, str) or not _ID.fullmatch(loadout_id):
            _error("IDENTITY_INVALID", "loadout ID is invalid")
        if operation not in {"admit", "revoke", "rollback", "uninstall"}:
            _error("OPERATION_INVALID", "loadout operation is unsupported")
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or not 1 <= ttl_seconds <= 3600:
            _error("EXPIRY_INVALID", "plan lifetime must be between 1 and 3600 seconds")
        with exclusive_lock(self._path(self.root / ".lifecycle.lock")):
            state = self._read_state()
            record = state["records"].get(loadout_id)
            if operation == "admit":
                if source is None:
                    _error("SOURCE_REQUIRED", "admission requires the exact Arc package and original inputs")
                arc = inspect_arc_package(**source)
                manifest = self._manifest(loadout_id, arc, adapter_references or [])
                pin = document_digest(manifest)
                if record and pin in record["revoked"]:
                    _error("REVOKED", "this exact loadout version has been revoked")
                payload = {"manifest": manifest, "version_digest": pin}
            else:
                if not record or not record["versions"]:
                    _error("NOT_INSTALLED", "loadout has no installed versions")
                target = version_digest
                if operation == "rollback":
                    candidates = [pin for pin in record["history"] if pin != record["active"]
                                  and pin not in record["revoked"] and pin in record["versions"]]
                    target = target or (candidates[-1] if candidates else None)
                    if target not in candidates:
                        _error("ROLLBACK_INVALID", "no matching previously admitted unrevoked version is available")
                    self._verify_object(target, record["versions"][target])
                    self._references(record["versions"][target]["manifest"]["adapter_references"])
                if operation == "revoke" and not record["active"]:
                    _error("NOT_ACTIVE", "loadout has no active version to revoke")
                payload = {"from_digest": record["active"], "to_digest": target if operation == "rollback" else None,
                           "owned_digests": sorted(record["versions"]), "reason": reason}
            now = _now()
            plan = sign_document({"schema_version": "hive.loadout-plan.v1", "plan_id": str(uuid4()),
                "operation": operation, "loadout_id": loadout_id, "target": copy.deepcopy(self.target),
                "issued_at": now.isoformat(), "expires_at": (now + timedelta(seconds=ttl_seconds)).isoformat(),
                "state_digest": document_digest(state), "authorization_ref": authorization_ref,
                "payload": payload}, self.request_key)
            self._verify_plan(plan)
            return plan

    def _verify_plan(self, plan: Mapping[str, Any], *, current: bool = True) -> None:
        if len(canonical_bytes(plan)) > 2 * 1024 * 1024:
            _error("PLAN_INVALID", "loadout plan exceeds its byte limit")
        if list(Draft202012Validator(self._schema, format_checker=FormatChecker()).iter_errors(plan)):
            _error("PLAN_INVALID", "loadout plan schema is invalid")
        verify_document(plan, self._request_keys)
        reject_credential_values(plan, location="loadout plan", verified_by=self._request_keys)
        if plan["target"] != self.target:
            _error("TARGET_MISMATCH", "loadout targets a different identity, project or native platform")
        issued, expiry = _date(plan["issued_at"]), _date(plan["expires_at"])
        if expiry <= issued or (expiry - issued).total_seconds() > 3600:
            _error("EXPIRY_INVALID", "loadout plan lifetime is invalid")
        if current and not issued <= _now() < expiry:
            _error("EXPIRED", "loadout plan is not currently valid")

    def approve(self, plan: Mapping[str, Any]) -> dict[str, Any]:
        if self.read_only:
            _error("READ_ONLY", "this loadout view cannot approve changes")
        self._verify_plan(plan)
        if plan["state_digest"] != document_digest(self._read_state()):
            _error("STATE_CHANGED", "loadout state changed; prepare a new plan")
        approval = AdapterApproval(str(uuid4()), document_digest(plan), self.approver_identity,
                                   "APPROVED", plan["expires_at"], uuid4().hex).as_dict()
        signed = sign_document(approval, self.approver_key)
        validate_adapter_document("adapter-approval.v1.schema.json", signed)
        return signed

    def _verify_approval(self, plan: Mapping[str, Any], approval: Mapping[str, Any], *, current: bool) -> None:
        validate_adapter_document("adapter-approval.v1.schema.json", approval)
        verify_document(approval, self._approver_keys)
        if (approval["decision"] != "APPROVED" or approval["plan_digest"] != document_digest(plan) or
                approval["approver"] != self.approver_identity or
                _date(approval["expires_at"]) > _date(plan["expires_at"])):
            _error("APPROVAL_INVALID", "approval does not bind this exact attended loadout plan")
        if current and _now() >= _date(approval["expires_at"]):
            _error("APPROVAL_EXPIRED", "loadout approval has expired")

    def _verify_object(self, pin: str, version: Mapping[str, Any], *, allow_missing: bool = False) -> None:
        root = self._path(self.root / "objects" / pin)
        expected = version["files"]
        expected_directories = {str(parent) for name in expected
            for parent in PurePosixPath(name).parents if str(parent) != "."}
        actual = set()
        if root.exists():
            for path in root.rglob("*"):
                self._path(path)
                if path.is_file():
                    relative = path.relative_to(root).as_posix()
                    actual.add(relative)
                    if relative not in expected or digest(read_bounded(path)) != expected[relative]:
                        _error("OWNED_CONTENT_CHANGED", "installed loadout files changed; preserve them for review")
                elif not path.is_dir():
                    _error("OWNED_CONTENT_CHANGED", "installed loadout contains a non-regular entry")
                elif path.relative_to(root).as_posix() not in expected_directories:
                    _error("OWNED_CONTENT_CHANGED", "installed loadout contains an unowned directory")
        if actual - set(expected) or (not allow_missing and actual != set(expected)):
            _error("OWNED_CONTENT_CHANGED", "installed loadout file set changed")

    def _install(self, pin: str, manifest: dict, arc: ArcPackage) -> dict[str, Any]:
        content = {**arc.files, "hive-loadout-manifest.json": canonical_bytes(manifest) + b"\n"}
        version = {"manifest": manifest, "files": {name: digest(payload) for name, payload in content.items()}}
        root = self._path(self.root / "objects" / pin)
        if root.exists():
            self._verify_object(pin, version, allow_missing=True)
        self._directory(root)
        for name, payload in sorted(content.items()):
            path = self._path(root / safe_path(name))
            self._directory(path.parent)
            if not path.exists():
                atomic_write_bytes(path, payload, mode=0o600)
        self._verify_object(pin, version)
        return version

    def _prepare_removals(self, plan, record, *, allow_missing):
        origin = document_digest(plan)
        entries = {}
        with _OwnedDirectory(self.vault, self.root / "objects") as objects:
            for pin, version in sorted(record["versions"].items()):
                if not re.fullmatch(r"[a-f0-9]{64}", pin):
                    _error("RECOVERY_INVALID", "recovery version pin is invalid")
                try:
                    with _OwnedDirectory(self.vault, self.root / "objects" / pin) as source:
                        _verify_directory_content(source.fd, version, allow_missing=allow_missing)
                        source.verify()
                        metadata = os.fstat(source.fd)
                        identity = list(_identity(metadata))
                except FileNotFoundError:
                    if not allow_missing:
                        _error("OWNED_CONTENT_CHANGED", "owned object disappeared before removal preparation")
                    identity = None  # Only an authenticated legacy partial removal permits this.
                entries[pin] = {"identity": identity, "allow_missing": allow_missing}
            objects.verify()
        return {"mode": "RETAIN_RECOVERY_V1", "origin_plan_digest": origin, "entries": entries}

    def _verify_removals(self, removals, pins):
        if (not isinstance(removals, dict) or set(removals) != {"mode", "origin_plan_digest", "entries"}
                or removals["mode"] != "RETAIN_RECOVERY_V1"
                or not isinstance(removals["origin_plan_digest"], str)
                or re.fullmatch(r"[a-f0-9]{64}", removals["origin_plan_digest"]) is None
                or not isinstance(removals["entries"], dict) or set(removals["entries"]) != set(pins)):
            _error("RECOVERY_INVALID", "signed removal destinations do not match the owned set")
        for pin, entry in removals["entries"].items():
            if (re.fullmatch(r"[a-f0-9]{64}", pin) is None or not isinstance(entry, dict)
                    or set(entry) != {"identity", "allow_missing"} or not isinstance(entry["allow_missing"], bool)):
                _error("RECOVERY_INVALID", "signed removal identity is invalid")
            identity = entry["identity"]
            if identity is None and entry["allow_missing"]:
                continue
            if (not isinstance(identity, list) or len(identity) != 2
                    or any(type(item) is not int or item < 0 for item in identity)):
                _error("RECOVERY_INVALID", "signed removal inode binding is invalid")

    def _verify_removal_origin(self, journal):
        """A renewed approval may name only its authenticated predecessor's copy."""
        seen = set()
        for _ in range(64):
            current = journal["plan"]
            current_digest = document_digest(current)
            if journal["removals"]["origin_plan_digest"] == current_digest:
                return
            previous_digest = journal.get("recovery_from")
            if (not isinstance(previous_digest, str) or re.fullmatch(r"[a-f0-9]{64}", previous_digest) is None
                    or previous_digest in seen):
                _error("RECOVERY_INVALID", "recovery origin lacks an exact signed predecessor")
            seen.add(previous_digest)
            previous = json_object(read_bounded(self._path(self.root / "journals" / f"{previous_digest}.json")))
            verify_document(previous, self._state_keys)
            old = previous.get("plan", {})
            self._verify_plan(old, current=False)
            self._verify_approval(old, previous.get("approval", {}), current=False)
            if (previous.get("schema_version") != "hive.loadout-journal.v1" or previous.get("phase") != "PREPARED"
                    or document_digest(old) != previous_digest or old["operation"] != "uninstall"
                    or old["loadout_id"] != current["loadout_id"] or old["state_digest"] != current["state_digest"]
                    or previous.get("removals") != journal["removals"]
                    or any(old["payload"].get(key) != current["payload"].get(key)
                           for key in ("from_digest", "to_digest", "owned_digests"))):
                _error("RECOVERY_INVALID", "recovery copy differs from its exact approved predecessor")
            journal = previous
        _error("RECOVERY_INVALID", "recovery predecessor chain exceeds its bound")

    def _remove(self, pin: str, version: Mapping[str, Any], *, removals, plan, approval) -> dict[str, Any]:
        """Remove from active storage by retaining, never unlinking, captured bytes.

        A hash followed by unlink cannot protect a concurrent replacement or an
        already-open writer. Recovery copies deliberately remain mutable evidence;
        no purge operation is implied or scheduled.
        """
        entry = removals["entries"][pin]
        relative = f'.hive/loadouts/recovery/{removals["origin_plan_digest"]}/{pin}'
        destination = self.vault / relative
        expected = tuple(entry["identity"]) if entry["identity"] is not None else None
        with _OwnedDirectory(self.vault, self.root / "objects") as objects, \
                _OwnedDirectory(self.vault, destination.parent, create=True) as recovery:
            def named(parent):
                try:
                    return os.stat(pin, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    return None

            source, retained = named(objects.fd), named(recovery.fd)
            if expected is None:
                if source is not None or retained is not None:
                    _error("RECOVERY_COLLISION", "previously absent object is occupied; preserve it")
                return {"version_digest": pin, "path": None, "disposition": "LEGACY_ALREADY_ABSENT"}
            if retained is None:
                if source is None or not stat.S_ISDIR(source.st_mode) or _identity(source) != expected:
                    _error("OWNED_CONTENT_CHANGED", "owned root changed before retention; preserve it")
                with _OwnedDirectory(self.vault, self.root / "objects" / pin) as opened:
                    if _identity(os.fstat(opened.fd)) != expected:
                        _error("OWNED_CONTENT_CHANGED", "owned root changed before retention")
                    _verify_directory_content(opened.fd, version, allow_missing=entry["allow_missing"])
                    opened.verify()
                    objects.verify()
                    recovery.verify()
                    # The bounded reads above may outlast a short approval.
                    self._verify_plan(plan)
                    self._verify_approval(plan, approval, current=True)
                    try:
                        _rename_preserving_destination(objects.fd, pin, recovery.fd, pin)
                    except OSError as exc:
                        raise ProtocolError("LOADOUT_RECOVERY_COLLISION", "recovery move refused; all existing paths are preserved") from exc
                    os.fsync(objects.fd)
                    os.fsync(recovery.fd)
                retained = named(recovery.fd)
            if retained is None or not stat.S_ISDIR(retained.st_mode) or _identity(retained) != expected:
                _error("OWNED_CONTENT_CHANGED", f"changed root preserved for review at {relative}")
            if named(objects.fd) is not None:
                _error("RECOVERY_COLLISION", f"original path is occupied; recovery preserved at {relative}")
            with _OwnedDirectory(self.vault, destination) as captured:
                if _identity(os.fstat(captured.fd)) != expected:
                    _error("OWNED_CONTENT_CHANGED", "captured root changed during recovery verification")
                _verify_directory_content(captured.fd, version, allow_missing=entry["allow_missing"])
                captured.verify()
            objects.verify()
            recovery.verify()
        return {"version_digest": pin, "path": relative, "disposition": "RETAINED_NOT_PURGED"}

    def _prior_removal_proof(self, plan: Mapping[str, Any]) -> str | None:
        """A fresh approval may continue only an exact previously preverified set."""
        for path in sorted((self.root / "journals").glob("*.json")):
            try:
                journal = json_object(read_bounded(self._path(path)))
                verify_document(journal, self._state_keys)
                previous = journal.get("plan", {})
                approval = journal.get("approval", {})
                self._verify_plan(previous, current=False)
                self._verify_approval(previous, approval, current=False)
            except ProtocolError:
                continue
            if (journal.get("schema_version") == "hive.loadout-journal.v1" and
                    journal.get("phase") == "PREPARED" and previous["operation"] == "uninstall" and
                    previous["loadout_id"] == plan["loadout_id"] and
                    previous["state_digest"] == plan["state_digest"] and
                    all(previous["payload"].get(key) == plan["payload"].get(key)
                        for key in ("from_digest", "to_digest", "owned_digests"))):
                return document_digest(previous)
        return None

    def apply(self, plan: Mapping[str, Any], approval: Mapping[str, Any], *,
              source: Mapping[str, Path] | None = None) -> dict[str, Any]:
        # Completed replay only observes an authentic committed result. All new
        # effects repeat current authorization and exact-state checks under lock.
        if self.read_only:
            _error("READ_ONLY", "this loadout view cannot apply changes")
        self._verify_plan(plan, current=False)
        self._verify_approval(plan, approval, current=False)
        plan_digest = document_digest(plan)
        with exclusive_lock(self._path(self.root / ".lifecycle.lock")):
            state = self._read_state()
            if plan_digest in state["completed"]:
                return copy.deepcopy(state["completed"][plan_digest])
            self._verify_plan(plan)
            self._verify_approval(plan, approval, current=True)
            if plan["state_digest"] != document_digest(state):
                _error("STATE_CHANGED", "loadout state changed; prepare a new plan")
            loadout_id, operation, payload = plan["loadout_id"], plan["operation"], plan["payload"]
            record = copy.deepcopy(state["records"].get(loadout_id) or
                {"active": None, "versions": {}, "history": [], "revoked": []})
            journal_path = self._path(self.root / "journals" / f"{plan_digest}.json")
            resume = journal_path.exists()
            if resume:
                journal = json_object(read_bounded(journal_path))
                verify_document(journal, self._state_keys)
                if (journal.get("schema_version") != "hive.loadout-journal.v1" or
                        journal.get("phase") != "PREPARED" or
                        journal.get("plan") != plan or journal.get("approval") != approval):
                    _error("RECOVERY_INVALID", "recovery journal does not match this exact operation")
            arc = None
            prior_removal = self._prior_removal_proof(plan) if operation == "uninstall" and not resume else None
            if operation == "admit":
                if source is None:
                    _error("SOURCE_REQUIRED", "admission requires exact source artifacts")
                arc = inspect_arc_package(**source)
                manifest = self._manifest(loadout_id, arc, payload.get("manifest", {}).get("adapter_references"))
                pin = document_digest(manifest)
                if payload != {"manifest": manifest, "version_digest": pin} or pin in record["revoked"]:
                    _error("ARTIFACT_CHANGED", "loadout artifacts changed or this version was revoked")
            else:
                if payload.get("from_digest") != record["active"] or payload.get("owned_digests") != sorted(record["versions"]):
                    _error("STATE_CHANGED", "loadout lifecycle pins differ from installed state")
                if operation != "uninstall":
                    for pin, version in record["versions"].items():
                        self._verify_object(pin, version)
                if operation == "rollback":
                    pin = payload.get("to_digest")
                    if pin not in record["versions"] or pin in record["revoked"] or pin == record["active"]:
                        _error("ROLLBACK_INVALID", "rollback target is unavailable or revoked")
                    self._references(record["versions"][pin]["manifest"]["adapter_references"])
            self._verify_plan(plan)
            self._verify_approval(plan, approval, current=True)
            if not resume:
                journal = {"schema_version": "hive.loadout-journal.v1", "plan": plan,
                    "approval": approval, "phase": "PREPARED", "recovery_from": prior_removal}
            if operation == "uninstall" and "removals" not in journal:
                previous = None
                if prior_removal:
                    previous = json_object(read_bounded(self._path(self.root / "journals" / f"{prior_removal}.json")))
                    verify_document(previous, self._state_keys)
                journal["removals"] = (copy.deepcopy(previous["removals"]) if previous and "removals" in previous
                    else self._prepare_removals(plan, record, allow_missing=resume or prior_removal is not None))
                resume = False  # Persist the signed inode/destination set before the first move.
            if operation == "uninstall":
                self._verify_removals(journal["removals"], record["versions"])
                self._verify_removal_origin(journal)
            if not resume:
                journal = sign_document(journal, self.state_key)
                atomic_write_json(journal_path, journal, mode=0o600)
            if operation == "admit":
                record["versions"][pin] = self._install(pin, manifest, arc)
                # Staged declarative bytes do not authorize a new active pin once
                # the attended approval expires during filesystem work.
                self._verify_plan(plan)
                self._verify_approval(plan, approval, current=True)
                self._references(manifest["adapter_references"])
                record["active"] = pin
                if pin in record["history"]:
                    record["history"].remove(pin)
                record["history"].append(pin)
            elif operation == "revoke":
                if not record["active"]:
                    _error("NOT_ACTIVE", "loadout has no active version")
                record["revoked"] = sorted(set(record["revoked"]) | {record["active"]})
                record["active"] = None
            elif operation == "rollback":
                record["active"] = payload["to_digest"]
            else:
                retained_recovery = []
                for pin, version in record["versions"].items():
                    retained_recovery.append(self._remove(pin, version, removals=journal["removals"], plan=plan, approval=approval))
                record.update(active=None, versions={}, history=[])
                record["retained_recovery"] = record.get("retained_recovery", []) + retained_recovery
            state["records"][loadout_id] = record
            receipt = sign_document({"schema_version": "hive.loadout-receipt.v1", "operation": operation,
                "loadout_id": loadout_id, "plan_digest": plan_digest, "approval_digest": document_digest(approval),
                "target": copy.deepcopy(self.target), "active_version_digest": record["active"], "outcome": "APPLIED",
                "authorization_ref": plan["authorization_ref"], "completed_at": _now().isoformat(),
                "grants_authority": False,
                **({"retained_recovery": retained_recovery, "content_purged": False} if operation == "uninstall" else {})}, self.state_key)
            state["completed"][plan_digest] = receipt
            self._write_state(state)
            return receipt

    def status(self) -> list[dict[str, Any]]:
        lock = self._path(self.root / ".lifecycle.lock")
        guard = _ReadOnlyLock(lock) if lock.exists() or (self.root / "state.json").exists() else nullcontext()
        with guard:
            state = self._read_state()
            result = []
            for loadout_id, record in sorted(state["records"].items()):
                active = record["active"]
                status = "ACTIVE" if active else "REVOKED" if record["revoked"] and record["versions"] else "UNINSTALLED"
                reason = None
                manifest = record["versions"].get(active, {}).get("manifest")
                if active:
                    try:
                        self._verify_object(active, record["versions"][active])
                        self._references(manifest["adapter_references"])
                    except ProtocolError as exc:
                        status, reason = "BLOCKED", exc.code
                result.append({"loadout_id": loadout_id, "status": status, "reason": reason,
                    "active_version_digest": active, "installed_versions": list(record["history"]),
                    "revoked_versions": list(record["revoked"]), "target": copy.deepcopy(self.target),
                    "manifest": copy.deepcopy(manifest), "retained_recovery": copy.deepcopy(record.get("retained_recovery", []))})
            return result

    def read_active(self, loadout_id: str) -> dict[str, str]:
        """Read admitted declarative context; callers still enforce their own grants."""
        with _ReadOnlyLock(self._path(self.root / ".lifecycle.lock")):
            record = self._read_state()["records"].get(loadout_id)
            if not record or not record["active"] or record["active"] in record["revoked"]:
                _error("NOT_ACTIVE", "loadout has no currently admitted version")
            pin = record["active"]
            version = record["versions"][pin]
            self._verify_object(pin, version)
            self._references(version["manifest"]["adapter_references"])
            return {component["path"]: read_bounded(self.root / "objects" / pin / component["path"]).decode("utf-8")
                    for component in version["manifest"]["components"]}

    def _context_snapshot_locked(self, loadout_id: str) -> dict[str, Any]:
        record = self._read_state()["records"].get(loadout_id)
        if not record or not record["active"] or record["active"] in record["revoked"]:
            _error("NOT_ACTIVE", "loadout has no currently admitted version")
        pin = record["active"]
        version = record["versions"][pin]
        self._verify_object(pin, version)
        self._references(version["manifest"]["adapter_references"])
        components = {}
        for component in version["manifest"]["components"]:
            path = component["path"]
            content = read_bounded(self._path(self.root / "objects" / pin / path))
            content_hash = digest(content)
            if content_hash != version["files"][path]:
                _error("CONTEXT_CHANGED", "component changed between integrity check and context read")
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ProtocolError("LOADOUT_CONTEXT_CHANGED", "component is no longer UTF-8") from exc
            components[path] = {"sha256": content_hash, "text": text}
        payload = {"schema_version": "hive.loadout-context.v1", "loadout_id": loadout_id,
            "version_digest": pin, "target": copy.deepcopy(self.target),
            "admission_key_id": public_key_id(self.state_key.public_key()),
            "execution_mode": "DECLARATIVE_ONLY", "grants_authority": False,
            "adapter_references": copy.deepcopy(version["manifest"]["adapter_references"]),
            "components": components}
        result = {**payload, "context_sha256": digest(canonical_bytes(payload))}
        if len(canonical_bytes(result)) > MAX_CONTEXT_BYTES:
            _error("CONTEXT_LIMIT", "context handoff exceeds the 8 MiB aggregate limit")
        return result

    def context_snapshot(self, loadout_id: str) -> dict[str, Any]:
        """Read a bounded exact context handoff; no execution or invocation grant."""
        if not isinstance(loadout_id, str) or not _ID.fullmatch(loadout_id):
            _error("CONTEXT_INVALID", "context requires one valid loadout ID")
        with _ReadOnlyLock(self._path(self.root / ".lifecycle.lock")):
            return self._context_snapshot_locked(loadout_id)

    def verify_context(self, snapshot: Mapping[str, Any]) -> dict[str, Any]:
        """Revalidate the envelope against this vault's current signed admission."""
        if (not isinstance(snapshot, dict) or set(snapshot) != _CONTEXT_FIELDS or
                not isinstance(snapshot.get("loadout_id"), str) or
                not _ID.fullmatch(snapshot["loadout_id"])):
            _error("CONTEXT_INVALID", "context must be one closed handoff envelope")
        try:
            supplied = canonical_bytes(snapshot)
        except (TypeError, ValueError, RecursionError) as exc:
            raise ProtocolError("LOADOUT_CONTEXT_INVALID", "context is not bounded JSON") from exc
        if len(supplied) > MAX_CONTEXT_BYTES:
            _error("CONTEXT_LIMIT", "context handoff exceeds the 8 MiB aggregate limit")
        with _ReadOnlyLock(self._path(self.root / ".lifecycle.lock")):
            current = self._context_snapshot_locked(snapshot["loadout_id"])
            if supplied != canonical_bytes(current):
                _error("CONTEXT_CHANGED", "context differs from this vault's current admitted target, version or bytes")
            return {"outcome": "LOADOUT_CONTEXT_VERIFIED", "loadout_id": current["loadout_id"],
                "version_digest": current["version_digest"], "target": current["target"],
                "admission_key_id": current["admission_key_id"], "context_sha256": current["context_sha256"],
                "verified_at": _now().isoformat(), "execution_mode": "DECLARATIVE_ONLY",
                "grants_authority": False}
