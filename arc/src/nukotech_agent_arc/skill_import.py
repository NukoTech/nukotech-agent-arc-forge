"""Turn a SKILL.md folder into an exact-hash Agent Arc registry component."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

COMPONENT_TYPES = frozenset(
    {"governance_or_harness", "skill", "loop", "graph_or_memory_binding", "runtime_binding", "protocol"}
)
_FRONTMATTER = re.compile(r"\A---\r?\n(.*?)\r?\n---\r?\n", re.DOTALL)
_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")


class SkillImportError(ValueError):
    """Raised when a skill folder cannot be imported deterministically."""


def read_frontmatter(skill_md: Path) -> dict[str, Any]:
    text = skill_md.read_text(encoding="utf-8")
    match = _FRONTMATTER.match(text)
    if not match:
        raise SkillImportError(f"{skill_md}: missing YAML frontmatter")
    data = yaml.safe_load(match.group(1))
    if not isinstance(data, dict):
        raise SkillImportError(f"{skill_md}: frontmatter must be a mapping")
    return data


def import_skill(
    skill_dir: Path,
    *,
    component_type: str = "skill",
    registry_root: Path | None = None,
    capabilities: tuple[str, ...] = (),
    license_id: str = "MIT",
    owner: str = "first-party",
    source: str = "first-party",
) -> dict[str, Any]:
    """Return a registry component mapping for ``skill_dir/SKILL.md``.

    The component path is written relative to ``registry_root`` (POSIX form)
    so the registry stays portable. Only SKILL.md bytes are pinned.
    """

    if component_type not in COMPONENT_TYPES:
        raise SkillImportError(f"unsupported component type {component_type!r}")
    skill_md = Path(skill_dir) / "SKILL.md"
    if not skill_md.is_file():
        raise SkillImportError(f"{skill_dir}: SKILL.md not found")
    meta = read_frontmatter(skill_md)
    name = str(meta.get("name", "")).strip()
    if not _SAFE_ID.match(name):
        raise SkillImportError(f"{skill_md}: frontmatter name {name!r} is not a safe id")
    metadata = meta.get("metadata") if isinstance(meta.get("metadata"), dict) else {}
    version = str(metadata.get("version") or meta.get("version") or "0.0.0")
    root = Path(registry_root) if registry_root else Path(skill_dir).parent
    try:
        relative = skill_md.resolve().relative_to(root.resolve())
    except ValueError as error:
        raise SkillImportError(f"{skill_md} is outside registry root {root}") from error
    return {
        "schema": "nukotech.agent_arc.component.v1",
        "id": name,
        "version": version,
        "type": component_type,
        "sha256": hashlib.sha256(skill_md.read_bytes()).hexdigest(),
        "path": str(PurePosixPath(*relative.parts)),
        "license": license_id,
        "provenance": {"source": source, "owner": owner},
        "dependencies": [],
        "conflicts": [],
        "capabilities": sorted(set(capabilities)),
        "side_effects": [],
        "stop_conditions": ["operator_stop", "authorization_boundary"],
        "rollback": ["remove_candidate_package"],
    }
