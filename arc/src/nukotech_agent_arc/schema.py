"""Schema validation boundary."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator
from referencing import Registry, Resource


@dataclass(frozen=True, order=True)
class ValidationIssue:
    path: str
    code: str
    message: str


_SCHEMA_ROOT = Path(__file__).resolve().parent / "schemas"


def _pointer(parts: list[Any]) -> str:
    if not parts:
        return "/"
    escaped = [str(part).replace("~", "~0").replace("/", "~1") for part in parts]
    return "/" + "/".join(escaped)


def validate_document(document: Mapping[str, Any], schema_name: str) -> tuple[ValidationIssue, ...]:
    """Return every schema violation in deterministic order."""

    schema_path = _SCHEMA_ROOT / f"{schema_name}.schema.json"
    if not schema_path.is_file():
        raise ValueError(f"unknown schema: {schema_name}")
    schemas = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(_SCHEMA_ROOT.glob("*.schema.json"))]
    registry = Registry()
    for candidate in schemas:
        identifier = candidate.get("$id")
        if identifier:
            registry = registry.with_resource(identifier, Resource.from_contents(candidate))
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, registry=registry)
    issues = [
        ValidationIssue(
            path=_pointer(list(error.absolute_path)),
            code=error.validator,
            message=error.message,
        )
        for error in validator.iter_errors(document)
    ]
    return tuple(sorted(issues))
