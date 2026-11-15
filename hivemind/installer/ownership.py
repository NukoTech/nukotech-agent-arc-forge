#!/usr/bin/env python3
"""Validate and remove only files owned by one NukoTech Hive Local installation."""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


PRODUCT = "nukotech-hive-local"
VERSION = "0.1.0"
MARKER_NAME = ".nukotech-hive-local-owner.json"
MANIFEST_NAME = ".nukotech-hive-local-manifest.json"
ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")


class OwnershipError(RuntimeError):
    pass


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_prefix(raw: str) -> Path:
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        raise OwnershipError("install prefix must be absolute")
    if ".." in candidate.parts:
        raise OwnershipError("install prefix may not contain traversal")
    normalized = Path(os.path.normpath(str(candidate)))
    current = Path(normalized.anchor)
    for part in normalized.parts[1:]:
        current /= part
        if current.is_symlink():
            raise OwnershipError(f"install prefix contains a symlink component: {current}")
    canonical = normalized.resolve(strict=False)
    home = Path.home().resolve(strict=False)
    if canonical == Path(canonical.anchor):
        raise OwnershipError("refusing filesystem root as install prefix")
    if canonical == home:
        raise OwnershipError("refusing HOME as install prefix")
    return canonical


def safe_relative(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or ".." in path.parts or path.as_posix() != value:
        raise OwnershipError(f"unsafe manifest path: {value}")
    return path


def beneath(prefix: Path, relative: str) -> Path:
    safe = safe_relative(relative)
    path = prefix.joinpath(*safe.parts)
    parent = path.parent.resolve(strict=False)
    if parent != prefix and prefix not in parent.parents:
        raise OwnershipError(f"manifest path escapes prefix: {relative}")
    return path


def atomic_json(path: Path, document: dict[str, Any]) -> None:
    payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists() and not temporary.is_symlink():
            temporary.unlink()


def control_paths(prefix: Path) -> tuple[Path, Path]:
    return prefix / MARKER_NAME, prefix / MANIFEST_NAME


def load_json_file(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    if not path.is_file() or path.is_symlink():
        raise OwnershipError(f"{label} is missing or not a regular file")
    payload = path.read_bytes()
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OwnershipError(f"{label} is not valid JSON") from exc
    if not isinstance(document, dict):
        raise OwnershipError(f"{label} must be a JSON object")
    return document, payload


def installed_entry(prefix: Path, path: Path) -> dict[str, Any]:
    relative = path.relative_to(prefix).as_posix()
    if path.is_symlink():
        return {"path": relative, "kind": "symlink", "target": os.readlink(path)}
    if path.is_file():
        return {
            "path": relative,
            "kind": "file",
            "sha256": sha256_file(path),
            "size_bytes": path.stat().st_size,
        }
    raise OwnershipError(f"unsupported installed entry: {path}")


def finalize(prefix: Path, installation_id: str, bin_created: bool) -> dict[str, Any]:
    if not ID_PATTERN.fullmatch(installation_id):
        raise OwnershipError("installation ID is invalid")
    marker_path, manifest_path = control_paths(prefix)
    if marker_path.exists() or marker_path.is_symlink() or manifest_path.exists() or manifest_path.is_symlink():
        raise OwnershipError("ownership control files already exist")
    owned_root = prefix / f".nukotech-hive-local-owned-{installation_id}"
    command_path = prefix / "bin" / "hive-local"
    expected_target = str(owned_root / "venv" / "bin" / "hive-local")
    if not owned_root.is_dir() or owned_root.is_symlink():
        raise OwnershipError("unique ownership root is missing or unsafe")
    if not command_path.is_symlink() or os.readlink(command_path) != expected_target:
        raise OwnershipError("installed command link does not match the ownership root")
    entries = [installed_entry(prefix, path) for path in sorted(owned_root.rglob("*")) if not path.is_dir() or path.is_symlink()]
    entries.append(installed_entry(prefix, command_path))
    directories = [
        path.relative_to(prefix).as_posix()
        for path in sorted(
            (path for path in owned_root.rglob("*") if path.is_dir() and not path.is_symlink()),
            key=lambda value: (len(value.parts), value.as_posix()),
        )
    ]
    directories.append(owned_root.relative_to(prefix).as_posix())
    if bin_created:
        directories.append("bin")
    manifest = {
        "schema_version": "nukotech.hive-local.install-manifest.v1",
        "product": PRODUCT,
        "version": VERSION,
        "installation_id": installation_id,
        "prefix": str(prefix),
        "owned_root": owned_root.relative_to(prefix).as_posix(),
        "control_files": [MARKER_NAME, MANIFEST_NAME],
        "entries": sorted(entries, key=lambda item: item["path"]),
        "directories": sorted(set(directories), key=lambda value: (len(PurePosixPath(value).parts), value)),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    atomic_json(manifest_path, manifest)
    try:
        marker = {
            "schema_version": "nukotech.hive-local.owner.v1",
            "product": PRODUCT,
            "version": VERSION,
            "installation_id": installation_id,
            "prefix": str(prefix),
            "manifest": MANIFEST_NAME,
            "manifest_sha256": sha256_file(manifest_path),
        }
        atomic_json(marker_path, marker)
    except Exception:
        if manifest_path.is_file() and not manifest_path.is_symlink():
            manifest_path.unlink()
        raise
    return marker


def verify_entry(prefix: Path, entry: dict[str, Any]) -> Path:
    if not isinstance(entry, dict) or set(entry) not in (
        {"path", "kind", "sha256", "size_bytes"},
        {"path", "kind", "target"},
    ):
        raise OwnershipError("manifest entry shape is invalid")
    path = beneath(prefix, str(entry.get("path", "")))
    if entry["kind"] == "file":
        if path.is_symlink() or not path.is_file():
            raise OwnershipError(f"manifest-owned file is missing or unsafe: {entry['path']}")
        if path.stat().st_size != entry["size_bytes"] or sha256_file(path) != entry["sha256"]:
            raise OwnershipError(f"manifest-owned file was altered: {entry['path']}")
    elif entry["kind"] == "symlink":
        if not path.is_symlink() or os.readlink(path) != entry["target"]:
            raise OwnershipError(f"manifest-owned symlink was altered: {entry['path']}")
    else:
        raise OwnershipError("manifest entry kind is invalid")
    return path


def validate(prefix: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    marker_path, manifest_path = control_paths(prefix)
    marker, _ = load_json_file(marker_path, "ownership marker")
    manifest, manifest_payload = load_json_file(manifest_path, "installed-file manifest")
    expected_marker_keys = {
        "schema_version", "product", "version", "installation_id", "prefix", "manifest", "manifest_sha256"
    }
    expected_manifest_keys = {
        "schema_version", "product", "version", "installation_id", "prefix", "owned_root",
        "control_files", "entries", "directories", "created_at"
    }
    if set(marker) != expected_marker_keys or set(manifest) != expected_manifest_keys:
        raise OwnershipError("ownership control shape is invalid")
    installation_id = str(marker.get("installation_id", ""))
    if not ID_PATTERN.fullmatch(installation_id):
        raise OwnershipError("ownership marker installation ID is invalid")
    if marker != {
        "schema_version": "nukotech.hive-local.owner.v1",
        "product": PRODUCT,
        "version": VERSION,
        "installation_id": installation_id,
        "prefix": str(prefix),
        "manifest": MANIFEST_NAME,
        "manifest_sha256": sha256_bytes(manifest_payload),
    }:
        raise OwnershipError("ownership marker was altered or mismatched")
    if manifest["schema_version"] != "nukotech.hive-local.install-manifest.v1":
        raise OwnershipError("installed-file manifest schema is invalid")
    if manifest["product"] != PRODUCT or manifest["version"] != VERSION:
        raise OwnershipError("installed-file manifest product is mismatched")
    if manifest["installation_id"] != installation_id or manifest["prefix"] != str(prefix):
        raise OwnershipError("marker and manifest ownership are mismatched")
    expected_root = f".nukotech-hive-local-owned-{installation_id}"
    if manifest["owned_root"] != expected_root:
        raise OwnershipError("installed-file manifest ownership root is mismatched")
    if manifest["control_files"] != [MARKER_NAME, MANIFEST_NAME]:
        raise OwnershipError("installed-file manifest control inventory is mismatched")
    entries = manifest["entries"]
    directories = manifest["directories"]
    if not isinstance(entries, list) or not entries or not isinstance(directories, list):
        raise OwnershipError("installed-file manifest inventory is invalid")
    entry_paths = [str(entry.get("path", "")) for entry in entries if isinstance(entry, dict)]
    if len(entry_paths) != len(entries) or len(entry_paths) != len(set(entry_paths)):
        raise OwnershipError("installed-file manifest contains duplicate or invalid paths")
    allowed_command = "bin/hive-local"
    for entry in entries:
        relative = safe_relative(str(entry["path"]))
        if relative.parts[0] != expected_root and relative.as_posix() != allowed_command:
            raise OwnershipError(f"manifest entry is outside owned locations: {relative}")
        verify_entry(prefix, entry)
    seen_directories: set[str] = set()
    for value in directories:
        if not isinstance(value, str) or value in seen_directories:
            raise OwnershipError("installed-file manifest directory inventory is invalid")
        seen_directories.add(value)
        relative = safe_relative(value)
        if relative.parts[0] != expected_root and relative.as_posix() != "bin":
            raise OwnershipError(f"manifest directory is outside owned locations: {relative}")
        path = beneath(prefix, value)
        if path.exists() and (path.is_symlink() or not path.is_dir()):
            raise OwnershipError(f"manifest directory was altered: {value}")
    return marker, manifest


def uninstall(prefix: Path) -> dict[str, Any]:
    marker, manifest = validate(prefix)
    entries = sorted(manifest["entries"], key=lambda item: (len(PurePosixPath(item["path"]).parts), item["path"]), reverse=True)
    for entry in entries:
        path = verify_entry(prefix, entry)
        path.unlink()
    directories = sorted(
        manifest["directories"],
        key=lambda value: (len(PurePosixPath(value).parts), value),
        reverse=True,
    )
    for relative in directories:
        path = beneath(prefix, relative)
        if not path.exists():
            continue
        if path.is_symlink() or not path.is_dir():
            raise OwnershipError(f"refusing altered manifest directory: {relative}")
        try:
            path.rmdir()
        except OSError as exc:
            if exc.errno not in {errno.ENOTEMPTY, errno.EEXIST}:
                raise
    marker_path, manifest_path = control_paths(prefix)
    manifest_path.unlink()
    marker_path.unlink()
    return {
        "outcome": "UNINSTALLED",
        "installation_id": marker["installation_id"],
        "removed_entries": len(entries),
        "prefix_removed": False,
    }


def cleanup_partial(prefix: Path, installation_id: str, bin_created: bool) -> None:
    if not ID_PATTERN.fullmatch(installation_id):
        raise OwnershipError("partial-cleanup installation ID is invalid")
    owned_root = prefix / f".nukotech-hive-local-owned-{installation_id}"
    command = prefix / "bin" / "hive-local"
    expected_target = str(owned_root / "venv" / "bin" / "hive-local")
    if command.is_symlink() and os.readlink(command) == expected_target:
        command.unlink()
    if owned_root.is_symlink():
        raise OwnershipError("partial ownership root became a symlink")
    if owned_root.is_dir():
        for current, directories, files in os.walk(owned_root, topdown=False, followlinks=False):
            current_path = Path(current)
            for name in files:
                (current_path / name).unlink()
            for name in directories:
                path = current_path / name
                if path.is_symlink():
                    path.unlink()
                else:
                    path.rmdir()
        owned_root.rmdir()
    if bin_created:
        bin_path = prefix / "bin"
        if bin_path.is_dir() and not bin_path.is_symlink():
            try:
                bin_path.rmdir()
            except OSError as exc:
                if exc.errno not in {errno.ENOTEMPTY, errno.EEXIST}:
                    raise


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    canonical = commands.add_parser("canonicalize")
    canonical.add_argument("prefix")
    check = commands.add_parser("check")
    check.add_argument("prefix")
    new_id = commands.add_parser("new-id")
    new_id.add_argument("prefix")
    finish = commands.add_parser("finalize")
    finish.add_argument("prefix")
    finish.add_argument("installation_id")
    finish.add_argument("--bin-created", action="store_true")
    remove = commands.add_parser("uninstall")
    remove.add_argument("prefix")
    partial = commands.add_parser("cleanup-partial")
    partial.add_argument("prefix")
    partial.add_argument("installation_id")
    partial.add_argument("--bin-created", action="store_true")
    args = parser.parse_args()
    try:
        prefix = canonical_prefix(args.prefix)
        if args.command == "canonicalize":
            print(prefix)
        elif args.command == "check":
            marker, manifest = control_paths(prefix)
            if not marker.exists() and not marker.is_symlink() and not manifest.exists() and not manifest.is_symlink():
                print(json.dumps({"outcome": "ABSENT", "prefix": str(prefix)}))
                return 3
            owner, installed = validate(prefix)
            print(json.dumps({"outcome": "VALID", "installation_id": owner["installation_id"], "entries": len(installed["entries"])}))
        elif args.command == "new-id":
            while True:
                value = uuid.uuid4().hex
                if not (prefix / f".nukotech-hive-local-owned-{value}").exists():
                    print(value)
                    break
        elif args.command == "finalize":
            print(json.dumps(finalize(prefix, args.installation_id, args.bin_created), sort_keys=True))
        elif args.command == "uninstall":
            print(json.dumps(uninstall(prefix), sort_keys=True))
        elif args.command == "cleanup-partial":
            cleanup_partial(prefix, args.installation_id, args.bin_created)
        return 0
    except (OSError, OwnershipError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
