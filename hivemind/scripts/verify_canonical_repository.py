#!/usr/bin/env python3
"""Verify the canonical HiveMind plan binding and legacy-root boundary."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "nukotech.hivemind.repository-boundary.v1"
MANIFEST_NAME = "CANONICAL_HIVEMIND.json"


def _safe_path(repository: Path, relative: object) -> Path | None:
    if not isinstance(relative, str):
        return None
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        return None
    lexical = repository / candidate
    resolved = lexical.resolve(strict=False)
    try:
        resolved.relative_to(repository)
    except ValueError:
        return None
    return lexical


def verify(repository: Path) -> dict[str, Any]:
    errors: list[str] = []
    plan_digest: str | None = None
    legacy_checked = 0
    repository = repository.resolve(strict=True)
    manifest_path = repository / MANIFEST_NAME

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        manifest = {}
        errors.append("MANIFEST_INVALID")

    if manifest.get("schema_version") != SCHEMA_VERSION:
        errors.append("MANIFEST_SCHEMA_INVALID")

    canonical_plan = manifest.get("canonical_plan")
    if not isinstance(canonical_plan, dict):
        errors.append("CANONICAL_PLAN_BINDING_INVALID")
    else:
        plan_path = _safe_path(repository, canonical_plan.get("path"))
        expected_digest = canonical_plan.get("sha256")
        if plan_path is None or not isinstance(expected_digest, str):
            errors.append("CANONICAL_PLAN_BINDING_INVALID")
        elif plan_path.is_symlink():
            errors.append("CANONICAL_PLAN_SYMLINK_REFUSED")
        elif not plan_path.is_file():
            errors.append("CANONICAL_PLAN_MISSING")
        else:
            plan_digest = hashlib.sha256(plan_path.read_bytes()).hexdigest()
            if plan_digest != expected_digest:
                errors.append("PLAN_HASH_MISMATCH")

    active_roots = manifest.get("active_roots")
    if not isinstance(active_roots, list) or not active_roots:
        errors.append("ACTIVE_ROOTS_INVALID")
        active_roots = []
    for relative in active_roots:
        root = _safe_path(repository, relative)
        if root is None or not root.is_dir() or root.is_symlink():
            errors.append("ACTIVE_ROOT_INVALID")

    legacy_roots = manifest.get("legacy_roots")
    if not isinstance(legacy_roots, list):
        errors.append("LEGACY_ROOTS_INVALID")
        legacy_roots = []
    legacy_checked = len(legacy_roots)
    for entry in legacy_roots:
        if not isinstance(entry, dict):
            errors.append("LEGACY_ROOT_INVALID")
            continue
        root = _safe_path(repository, entry.get("path"))
        notice = _safe_path(repository, entry.get("notice"))
        if root is None or notice is None or not root.is_dir() or root.is_symlink():
            errors.append("LEGACY_ROOT_INVALID")
            continue
        try:
            notice.relative_to(root)
        except ValueError:
            errors.append("LEGACY_NOTICE_OUTSIDE_ROOT")
            continue
        if not notice.is_file() or notice.is_symlink():
            errors.append("LEGACY_NOTICE_MISSING")

    return {
        "schema_version": SCHEMA_VERSION,
        "outcome": "VERIFIED" if not errors else "REFUSED",
        "canonical_plan_sha256": plan_digest,
        "active_roots_checked": len(active_roots),
        "legacy_roots_checked": legacy_checked,
        "errors": sorted(set(errors)),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = verify(args.repository)
    except (OSError, RuntimeError):
        report = {
            "schema_version": SCHEMA_VERSION,
            "outcome": "REFUSED",
            "canonical_plan_sha256": None,
            "active_roots_checked": 0,
            "legacy_roots_checked": 0,
            "errors": ["REPOSITORY_INVALID"],
        }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["outcome"] == "VERIFIED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
