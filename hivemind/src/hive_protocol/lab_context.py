"""Local lab identity context: assign a persona without changing the bundled sample."""

from __future__ import annotations

import json
import os
import re
from importlib.resources import files
from pathlib import Path
from typing import Any, Mapping

from .core import ProtocolError, require_assigned_persona, validate_identity_context
from .storage import atomic_write_json, read_json, require_owned_directory


PERSONA_ASSIGN_COMMAND = "hive-local persona assign <name>"
LAB_CONTEXT_ENV = "HIVE_LAB_CONTEXT"
_PERSONA_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}$")


def bundled_sample_identity() -> dict[str, Any]:
    return json.loads(
        files("hive_protocol")
        .joinpath("reference", "sample-lab-context.json")
        .read_text(encoding="utf-8")
    )


def default_lab_context_path() -> Path:
    configured = os.environ.get("XDG_CONFIG_HOME", "").strip()
    base = Path(configured) if configured else Path.home() / ".config"
    return base / "nukotech-hive-local" / "lab-context.json"


def resolve_lab_context_path(explicit: Path | None = None) -> Path:
    if explicit is not None:
        return Path(explicit)
    override = os.environ.get(LAB_CONTEXT_ENV, "").strip()
    if override:
        return Path(override)
    return default_lab_context_path()


def _fallback_identity() -> dict[str, Any]:
    # Imported lazily to avoid a cycle with turn.py and to honor test patches
    # of EXPECTED_IDENTITY when no local context file is present.
    from .turn import EXPECTED_IDENTITY

    return json.loads(json.dumps(EXPECTED_IDENTITY))


def load_lab_identity(*, context_path: Path | None = None) -> dict[str, Any]:
    """Load the local lab identity, or the bundled unassigned sample if none exists."""

    if context_path is not None:
        path = Path(context_path)
    else:
        override = os.environ.get(LAB_CONTEXT_ENV, "").strip()
        path = Path(override) if override else default_lab_context_path()
        if not override and not path.exists():
            return _fallback_identity()
        if override and not os.path.lexists(path):
            return _fallback_identity()
    if not os.path.lexists(path):
        return _fallback_identity()
    if path.is_symlink():
        raise ProtocolError(
            "VAULT_FOLDER_UNSAFE",
            "lab context file may not be a symlink",
        )
    document = read_json(path)
    validate_identity_context(document)
    return document


def validate_persona_name(name: str) -> str:
    if not isinstance(name, str) or not name.strip():
        raise ProtocolError("PERSONA_NAME_INVALID", "persona name must be a non-empty string")
    candidate = name.strip()
    normalized = candidate.upper()
    if normalized == "UNASSIGNED" or (
        normalized.startswith("PERSONA:") and normalized.split(":", 1)[1] == "UNASSIGNED"
    ):
        raise ProtocolError("PERSONA_NAME_INVALID", "persona name cannot be UNASSIGNED")
    if not _PERSONA_NAME.fullmatch(candidate):
        raise ProtocolError(
            "PERSONA_NAME_INVALID",
            "persona name must start with a letter and use only letters, digits, dots, underscores, or hyphens",
        )
    return candidate


def assign_persona(
    name: str,
    *,
    context_path: Path | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Write a local lab context with an assigned persona. Never mutates the bundle."""

    assigned = validate_persona_name(name)
    path = resolve_lab_context_path(context_path).expanduser()
    parent = path.parent
    if parent.exists():
        parent = parent.resolve()
        path = parent / path.name
    require_owned_directory(parent)
    if path.is_symlink():
        raise ProtocolError("VAULT_FOLDER_UNSAFE", "lab context file may not be a symlink")
    if os.path.lexists(path):
        current = read_json(path)
        validate_identity_context(current)
        try:
            require_assigned_persona(current)
        except ProtocolError as exc:
            if exc.code != "PERSONA_UNASSIGNED":
                raise
            identity = json.loads(json.dumps(current))
        else:
            if not force:
                raise ProtocolError(
                    "PERSONA_ALREADY_ASSIGNED",
                    "local persona is already assigned; pass --force to replace it",
                )
            identity = json.loads(json.dumps(current))
    else:
        identity = bundled_sample_identity()
    continuity = f"persona:{assigned}"
    identity["persona"]["id"] = assigned
    identity["persona"]["continuity_id"] = continuity
    identity["surface"]["persona_continuity_id"] = continuity
    identity["agent_worker"]["acts_for_persona"] = assigned
    validate_identity_context(identity)
    require_assigned_persona(identity)
    atomic_write_json(path, identity, mode=0o600)
    return {
        "outcome": "ASSIGNED",
        "command": PERSONA_ASSIGN_COMMAND,
        "context_path": str(path),
        "persona": {
            "id": assigned,
            "continuity_id": continuity,
            "governance_role": identity["persona"]["governance_role"],
        },
    }
