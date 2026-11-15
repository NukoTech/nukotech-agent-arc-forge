"""Checked-in release repository identity, bound at the launch cut; fails closed if unbound."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from contextlib import contextmanager
from importlib.resources import files
from typing import Any

from hive_protocol.core import ProtocolError


UNBOUND_PLACEHOLDER = re.compile(r"<[A-Z][A-Z0-9_]+>")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
RELEASE_IDENTITY_RESOURCE = "release-identity.json"

_UNSET = object()
_override: object = _UNSET


def _validate_repository(value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or UNBOUND_PLACEHOLDER.search(value):
        raise ProtocolError(
            "RELEASE_IDENTITY_UNBOUND",
            "release repository is missing, empty, or still a launch placeholder",
        )
    repository = value.strip()
    if REPOSITORY_PATTERN.fullmatch(repository) is None:
        raise ProtocolError(
            "RELEASE_IDENTITY_UNBOUND",
            "release repository is not a bound owner/name",
        )
    return repository


def _load_checked_in_repository() -> Any:
    path = files("hive_protocol").joinpath(RELEASE_IDENTITY_RESOURCE)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(
            "RELEASE_IDENTITY_UNBOUND",
            "release identity source is missing or invalid",
        ) from exc
    if not isinstance(payload, dict):
        raise ProtocolError(
            "RELEASE_IDENTITY_UNBOUND",
            "release identity source is missing or invalid",
        )
    return payload.get("repository")


def require_release_repository() -> str:
    """Return the bound owner/name, or fail closed if it is not yet bound."""

    if _override is _UNSET:
        return _validate_repository(_load_checked_in_repository())
    return _validate_repository(_override)


def require_matching_repository(actual: Any) -> str:
    """Fail closed unless *actual* equals the bound release repository."""

    expected = require_release_repository()
    if not isinstance(actual, str) or actual != expected:
        raise ProtocolError(
            "RELEASE_IDENTITY_MISMATCH",
            "repository does not match the bound release identity",
        )
    return expected


@contextmanager
def bound_release_repository(repository: str | None) -> Iterator[str | None]:
    """Temporarily bind or unbind the release repository (tests only)."""

    global _override
    previous = _override
    _override = repository
    try:
        yield repository
    finally:
        _override = previous
