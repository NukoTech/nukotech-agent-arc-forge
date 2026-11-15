"""Manifest-bounded uninstall preserving user-authored project material."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from ..core import ProtocolError


_MARKER = ".hive-root-manifest.json"
_GENERATED = ("tasks", "receipts", "queue", "replay", "project_state", "operator")


def safe_uninstall(root: Path) -> dict[str, object]:
    if root.is_symlink() or not root.is_dir():
        raise ProtocolError("UNINSTALL_ROOT_INVALID", "uninstall root must be a real directory")
    root = root.resolve()
    marker = root / _MARKER
    if not marker.is_file() or marker.is_symlink():
        raise ProtocolError("UNINSTALL_MARKER_REQUIRED", "single-root manifest is required")
    try:
        document = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProtocolError("UNINSTALL_MANIFEST_INVALID", "manifest cannot be read") from exc
    if document.get("schema_version") != "hive.cycle2.root-manifest.v1":
        raise ProtocolError("UNINSTALL_MANIFEST_INVALID", "unexpected manifest schema")
    removed: list[str] = []
    for name in _GENERATED:
        target = root / name
        if target.exists() or target.is_symlink():
            if target.is_symlink() or root not in target.resolve().parents:
                raise ProtocolError("UNINSTALL_PATH_BOUNDARY", f"generated path is unsafe: {name}")
            shutil.rmtree(target)
            removed.append(name)
    marker.unlink()
    return {"status": "UNINSTALLED", "removed": removed, "preserved": ["project_material", *[p.name for p in root.iterdir()]]}
