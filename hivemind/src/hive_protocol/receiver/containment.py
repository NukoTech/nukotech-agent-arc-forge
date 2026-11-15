"""Descriptor-anchored validation and root-level storage for receiver state.

All relative components are validated before lookup. Directory traversal uses
``dir_fd`` plus ``O_NOFOLLOW`` and verifies the complete chain before commit,
while committed objects live directly under the governed root. No renameable
nested directory participates in the atomic replace.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from uuid import uuid4

from ..core import ProtocolError, canonical_bytes


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
_FILE_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def validate_identifier(value: object, field: str = "identifier") -> str:
    if not isinstance(value, str) or not value:
        raise ProtocolError("IDENTIFIER_INVALID", f"{field} must be a nonempty string")
    if (
        value in {".", ".."}
        or ".." in value
        or "%" in value
        or "/" in value
        or "\\" in value
        or Path(value).is_absolute()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or not _IDENTIFIER.fullmatch(value)
    ):
        raise ProtocolError("IDENTIFIER_INVALID", f"{field} is not a safe path identifier")
    return value


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


class _DirectoryLease:
    def __init__(self, owner: "GovernedRoot", components: Sequence[str], create: bool) -> None:
        self.owner = owner
        self.components = [
            validate_identifier(component, "path component") for component in components
        ]
        self.create = create
        self.descriptors: list[int] = []
        self.chain: list[tuple[int, str, os.stat_result]] = []

    def __enter__(self) -> tuple[int, list[tuple[int, str, os.stat_result]]]:
        self.owner._verify_root()
        descriptor = os.dup(self.owner._root_fd)
        self.descriptors.append(descriptor)
        try:
            for component in self.components:
                try:
                    child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
                except FileNotFoundError:
                    if not self.create:
                        raise
                    try:
                        os.mkdir(component, mode=0o700, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                    child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
                child_stat = os.fstat(child)
                named = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
                if not stat.S_ISDIR(named.st_mode) or not _same_file(child_stat, named):
                    os.close(child)
                    raise ProtocolError("PATH_COMPONENT_SUBSTITUTED", "directory component changed")
                self.chain.append((descriptor, component, child_stat))
                self.descriptors.append(child)
                descriptor = child
            self.owner._verify_chain(self.chain)
            return descriptor, self.chain
        except OSError as exc:
            self.__exit__(type(exc), exc, exc.__traceback__)
            if exc.errno in {getattr(os, "ELOOP", 40), 20}:
                raise ProtocolError("PATH_COMPONENT_SYMLINK", "symlink component is forbidden") from exc
            raise
        except BaseException as exc:
            self.__exit__(type(exc), exc, exc.__traceback__)
            raise

    def __exit__(self, _type, _value, _traceback) -> bool:
        for opened in reversed(self.descriptors):
            try:
                os.close(opened)
            except OSError:
                pass
        self.descriptors.clear()
        return False


class _LockLease:
    def __init__(self, owner: "GovernedRoot", components: Sequence[str]) -> None:
        if len(components) < 1:
            raise ProtocolError("PATH_INVALID", "lock path is empty")
        self.owner = owner
        self.directories = components[:-1]
        self.filename = validate_identifier(components[-1], "lock filename")
        self.directory_lease = owner._directory(self.directories, create=True)
        self.parent: int | None = None
        self.chain: list[tuple[int, str, os.stat_result]] = []
        self.descriptor: int | None = None

    def __enter__(self) -> None:
        self.parent, self.chain = self.directory_lease.__enter__()
        try:
            self.descriptor = os.open(
                self.filename,
                os.O_RDWR | os.O_CREAT | _FILE_NOFOLLOW,
                0o600,
                dir_fd=self.parent,
            )
            lock_stat = os.fstat(self.descriptor)
            named = os.stat(self.filename, dir_fd=self.parent, follow_symlinks=False)
            if (
                not stat.S_ISREG(lock_stat.st_mode)
                or lock_stat.st_nlink != 1
                or not _same_file(lock_stat, named)
            ):
                raise ProtocolError("LOCK_UNSAFE", "lock is not one owned regular file")
            fcntl.flock(self.descriptor, fcntl.LOCK_EX)
            self.owner._verify_chain(self.chain)
            return None
        except BaseException as exc:
            self.__exit__(type(exc), exc, exc.__traceback__)
            raise

    def __exit__(self, exception_type, _exception, _traceback) -> bool:
        verification_error: BaseException | None = None
        if self.descriptor is not None:
            try:
                self.owner._verify_chain(self.chain)
            except BaseException as exc:
                verification_error = exc
            try:
                fcntl.flock(self.descriptor, fcntl.LOCK_UN)
            finally:
                os.close(self.descriptor)
                self.descriptor = None
        self.directory_lease.__exit__(exception_type, _exception, _traceback)
        if exception_type is None and verification_error is not None:
            raise verification_error
        return False


class GovernedRoot:
    """Perform receiver state operations beneath one immutable root descriptor."""

    def __init__(self, root: Path) -> None:
        self.path = Path(os.path.abspath(root))
        self._reject_existing_symlink_components(self.path)
        try:
            os.mkdir(self.path, mode=0o700)
        except FileExistsError:
            pass
        if self.path.is_symlink() or not self.path.is_dir():
            raise ProtocolError("GOVERNED_ROOT_INVALID", "governed root must be a regular directory")
        root_stat = self.path.stat(follow_symlinks=False)
        if root_stat.st_uid != os.getuid() or stat.S_IMODE(root_stat.st_mode) != 0o700:
            raise ProtocolError("GOVERNED_ROOT_MODE", "governed root must be owner-only mode 0700")
        self._root_fd = os.open(self.path, _DIRECTORY_FLAGS)
        self._root_stat = os.fstat(self._root_fd)
        if not _same_file(root_stat, self._root_stat):
            os.close(self._root_fd)
            raise ProtocolError("GOVERNED_ROOT_RACE", "governed root changed while opening")

    @staticmethod
    def _reject_existing_symlink_components(path: Path) -> None:
        current = Path(path.anchor)
        for component in path.parts[1:]:
            current /= component
            try:
                mode = current.lstat().st_mode
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(mode):
                raise ProtocolError("GOVERNED_ROOT_SYMLINK", "governed root contains a symlink")

    def _verify_root(self) -> None:
        try:
            named = self.path.stat(follow_symlinks=False)
        except FileNotFoundError as exc:
            raise ProtocolError("GOVERNED_ROOT_SUBSTITUTED", "governed root disappeared") from exc
        if not stat.S_ISDIR(named.st_mode) or not _same_file(named, self._root_stat):
            raise ProtocolError("GOVERNED_ROOT_SUBSTITUTED", "governed root identity changed")

    def _directory(
        self, components: Sequence[str], *, create: bool
    ) -> _DirectoryLease:
        return _DirectoryLease(self, components, create)

    def _verify_chain(self, chain: Sequence[tuple[int, str, os.stat_result]]) -> None:
        self._verify_root()
        for parent, component, expected in chain:
            try:
                named = os.stat(component, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError as exc:
                raise ProtocolError("PATH_COMPONENT_SUBSTITUTED", "directory component disappeared") from exc
            if not stat.S_ISDIR(named.st_mode) or not _same_file(named, expected):
                raise ProtocolError("PATH_COMPONENT_SUBSTITUTED", "directory component changed")

    @staticmethod
    def _object_name(components: Sequence[str]) -> str:
        logical_path = [
            validate_identifier(component, "path component") for component in components
        ]
        digest = hashlib.sha256(canonical_bytes({"logical_path": logical_path})).hexdigest()
        return f"object-{digest}.json"

    @staticmethod
    def _stored_object(
        components: Sequence[str], document: Mapping[str, Any]
    ) -> dict[str, Any]:
        return {
            "schema_version": "hive.governed-object.v1",
            "logical_path": list(components),
            "document": dict(document),
        }

    @staticmethod
    def _unpack_object(
        stored: object, components: Sequence[str]
    ) -> dict[str, Any]:
        if (
            not isinstance(stored, dict)
            or stored.get("schema_version") != "hive.governed-object.v1"
            or stored.get("logical_path") != list(components)
            or not isinstance(stored.get("document"), dict)
        ):
            raise ProtocolError("INVALID_DOCUMENT", "governed object binding is invalid")
        return dict(stored["document"])

    def _read_root_object(self, object_name: str) -> dict[str, Any]:
        descriptor = os.open(object_name, os.O_RDONLY | _FILE_NOFOLLOW, dir_fd=self._root_fd)
        try:
            file_stat = os.fstat(descriptor)
            named = os.stat(object_name, dir_fd=self._root_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(file_stat.st_mode)
                or file_stat.st_nlink != 1
                or not _same_file(file_stat, named)
            ):
                raise ProtocolError("SOURCE_UNSAFE", "source is not one owned regular file")
            with os.fdopen(descriptor, "r", encoding="utf-8", closefd=False) as handle:
                value = json.load(handle)
            self._verify_root()
        except json.JSONDecodeError as exc:
            raise ProtocolError("INVALID_DOCUMENT", "governed JSON document is malformed") from exc
        finally:
            os.close(descriptor)
        if not isinstance(value, dict):
            raise ProtocolError("INVALID_DOCUMENT", "governed JSON root must be an object")
        return value

    def _read_legacy_json(self, components: Sequence[str]) -> dict[str, Any]:
        filename = components[-1]
        with self._directory(components[:-1], create=False) as (parent, chain):
            descriptor = os.open(filename, os.O_RDONLY | _FILE_NOFOLLOW, dir_fd=parent)
            try:
                file_stat = os.fstat(descriptor)
                named = os.stat(filename, dir_fd=parent, follow_symlinks=False)
                if (
                    not stat.S_ISREG(file_stat.st_mode)
                    or file_stat.st_nlink != 1
                    or not _same_file(file_stat, named)
                ):
                    raise ProtocolError(
                        "SOURCE_UNSAFE", "legacy source is not one owned regular file"
                    )
                with os.fdopen(descriptor, "r", encoding="utf-8", closefd=False) as handle:
                    value = json.load(handle)
                self._verify_chain(chain)
            except json.JSONDecodeError as exc:
                raise ProtocolError(
                    "INVALID_DOCUMENT", "legacy governed JSON document is malformed"
                ) from exc
            finally:
                os.close(descriptor)
        if not isinstance(value, dict):
            raise ProtocolError("INVALID_DOCUMENT", "legacy governed JSON root must be an object")
        return value

    def write_json(
        self,
        components: Sequence[str],
        document: Mapping[str, Any],
        *,
        before_commit: Callable[[], None] | None = None,
    ) -> None:
        if len(components) < 1:
            raise ProtocolError("PATH_INVALID", "destination path is empty")
        normalized = [
            validate_identifier(component, "path component") for component in components
        ]
        directories = normalized[:-1]
        filename = normalized[-1]
        object_name = self._object_name(normalized)
        with self._directory(directories, create=True) as (parent, chain):
            temporary = validate_identifier(f"tmp-{uuid4().hex}.json", "temporary filename")
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | _FILE_NOFOLLOW,
                0o600,
                dir_fd=self._root_fd,
            )
            backup: str | None = None
            committed = False
            try:
                payload = canonical_bytes(self._stored_object(normalized, document)) + b"\n"
                with os.fdopen(descriptor, "wb", closefd=False) as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                if before_commit is not None:
                    before_commit()
                self._verify_chain(chain)
                try:
                    destination = os.stat(filename, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    destination = None
                if destination is not None and (
                    not stat.S_ISREG(destination.st_mode) or destination.st_nlink != 1
                ):
                    raise ProtocolError("DESTINATION_UNSAFE", "destination is not one owned regular file")
                try:
                    existing = os.stat(
                        object_name, dir_fd=self._root_fd, follow_symlinks=False
                    )
                except FileNotFoundError:
                    existing = None
                if existing is not None:
                    if not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1:
                        raise ProtocolError(
                            "DESTINATION_UNSAFE", "stored destination is not one regular file"
                        )
                    backup = validate_identifier(
                        f"backup-{uuid4().hex}.json", "backup filename"
                    )
                    previous = self._read_root_object(object_name)
                    backup_descriptor = os.open(
                        backup,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | _FILE_NOFOLLOW,
                        0o600,
                        dir_fd=self._root_fd,
                    )
                    try:
                        with os.fdopen(
                            backup_descriptor, "wb", closefd=False
                        ) as handle:
                            handle.write(canonical_bytes(previous) + b"\n")
                            handle.flush()
                            os.fsync(handle.fileno())
                    finally:
                        os.close(backup_descriptor)
                try:
                    os.replace(
                        temporary,
                        object_name,
                        src_dir_fd=self._root_fd,
                        dst_dir_fd=self._root_fd,
                    )
                    committed = True
                    os.fsync(self._root_fd)
                    self._verify_root()
                    self._verify_chain(chain)
                except BaseException as exc:
                    if committed:
                        if backup is None:
                            os.unlink(object_name, dir_fd=self._root_fd)
                        else:
                            os.rename(
                                backup,
                                object_name,
                                src_dir_fd=self._root_fd,
                                dst_dir_fd=self._root_fd,
                            )
                            backup = None
                        os.fsync(self._root_fd)
                    if isinstance(exc, OSError):
                        raise ProtocolError(
                            "ATOMIC_COMMIT_BOUNDARY",
                            "root-qualified atomic commit could not be completed safely",
                        ) from exc
                    raise
            finally:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                try:
                    os.unlink(temporary, dir_fd=self._root_fd)
                except FileNotFoundError:
                    pass
                if backup is not None:
                    try:
                        os.unlink(backup, dir_fd=self._root_fd)
                    except FileNotFoundError:
                        pass

    def read_json(self, components: Sequence[str], *, optional: bool = False) -> dict[str, Any] | None:
        if len(components) < 1:
            raise ProtocolError("PATH_INVALID", "source path is empty")
        normalized = [
            validate_identifier(component, "path component") for component in components
        ]
        object_name = self._object_name(normalized)
        try:
            with self._directory(normalized[:-1], create=False) as (_parent, chain):
                value = self._read_root_object(object_name)
                self._verify_chain(chain)
        except FileNotFoundError:
            try:
                return self._read_legacy_json(normalized)
            except FileNotFoundError:
                if optional:
                    return None
                raise ProtocolError(
                    "MISSING_DOCUMENT", "expected governed JSON document"
                ) from None
        return self._unpack_object(value, normalized)

    def list_json(self, components: Sequence[str]) -> list[str]:
        normalized = [
            validate_identifier(component, "path component") for component in components
        ]
        try:
            with self._directory(normalized, create=False) as (_directory, chain):
                names: list[str] = []
                for object_name in os.listdir(self._root_fd):
                    if not object_name.startswith("object-") or not object_name.endswith(".json"):
                        continue
                    try:
                        stored = self._read_root_object(object_name)
                    except (FileNotFoundError, ProtocolError):
                        continue
                    logical_path = stored.get("logical_path")
                    if (
                        isinstance(logical_path, list)
                        and logical_path[:-1] == normalized
                        and isinstance(logical_path[-1] if logical_path else None, str)
                        and self._object_name(logical_path) == object_name
                    ):
                        try:
                            self._unpack_object(stored, logical_path)
                        except ProtocolError:
                            continue
                        names.append(logical_path[-1])
                for name in os.listdir(_directory):
                    try:
                        validate_identifier(name, "directory entry")
                    except ProtocolError:
                        continue
                    if not name.endswith(".json"):
                        continue
                    entry = os.stat(name, dir_fd=_directory, follow_symlinks=False)
                    if stat.S_ISREG(entry.st_mode) and entry.st_nlink == 1:
                        names.append(name)
                self._verify_chain(chain)
                return sorted(set(names))
        except FileNotFoundError:
            return []

    def unlink(self, components: Sequence[str]) -> None:
        if len(components) < 1:
            raise ProtocolError("PATH_INVALID", "unlink path is empty")
        normalized = [
            validate_identifier(component, "path component") for component in components
        ]
        object_name = self._object_name(normalized)
        filename = normalized[-1]
        with self._directory(normalized[:-1], create=False) as (parent, chain):
            try:
                entry = os.stat(object_name, dir_fd=self._root_fd, follow_symlinks=False)
            except FileNotFoundError:
                entry = None
            try:
                legacy = os.stat(filename, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                legacy = None
            for candidate in (entry, legacy):
                if candidate is not None and (
                    not stat.S_ISREG(candidate.st_mode) or candidate.st_nlink != 1
                ):
                    raise ProtocolError(
                        "DESTINATION_UNSAFE", "unlink target is not one regular file"
                    )
            if entry is None and legacy is None:
                raise FileNotFoundError(filename)
            self._verify_chain(chain)
            if entry is not None:
                os.unlink(object_name, dir_fd=self._root_fd)
                os.fsync(self._root_fd)
            if legacy is not None:
                os.unlink(filename, dir_fd=parent)
                os.fsync(parent)
            self._verify_chain(chain)

    def lock(self, components: Sequence[str]) -> _LockLease:
        return _LockLease(self, components)
