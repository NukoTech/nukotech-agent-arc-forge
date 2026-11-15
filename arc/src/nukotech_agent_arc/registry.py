"""Exact registry resolution."""

from __future__ import annotations

import hashlib
from collections import Counter
from pathlib import Path

from .digests import digests_equal
from .models import Recipe, Registry, ResolutionResult, ResolvedComponent
from .schema import ValidationIssue


def _issue(code: str, path: str, message: str) -> ValidationIssue:
    return ValidationIssue(path=path, code=code, message=message)


def resolve_components(recipe: Recipe, registry: Registry, component_root: Path) -> ResolutionResult:
    """Resolve every recipe reference by exact identity and verified disk bytes."""

    root = Path(component_root).resolve()
    issues: list[ValidationIssue] = []
    resolved: list[ResolvedComponent] = []
    identities = [(item.id, item.version, item.type) for item in registry.components]
    duplicate_identities = {identity for identity, count in Counter(identities).items() if count > 1}

    for index, reference in enumerate(recipe.components):
        pointer = f"/components/{index}"
        same_version = [
            item for item in registry.components if item.id == reference.id and item.version == reference.version
        ]
        exact = [item for item in same_version if item.type == reference.type]
        identity = (reference.id, reference.version, reference.type)

        if identity in duplicate_identities:
            issues.append(
                _issue(
                    "duplicate_registry_identity",
                    pointer,
                    f"registry contains duplicate identity {reference.id}@{reference.version}:{reference.type}",
                )
            )
            continue
        if same_version and not exact:
            issues.append(
                _issue(
                    "component_type_mismatch",
                    pointer,
                    f"{reference.id}@{reference.version} is not registered as {reference.type}",
                )
            )
            continue
        if not exact:
            issues.append(
                _issue(
                    "component_not_found",
                    pointer,
                    f"no exact registry entry for {reference.id}@{reference.version}:{reference.type}",
                )
            )
            continue

        entry = exact[0]
        if not digests_equal(entry.sha256, reference.sha256):
            issues.append(
                _issue(
                    "component_declared_hash_mismatch",
                    pointer,
                    f"recipe and registry hashes differ for {reference.id}@{reference.version}",
                )
            )
            continue

        artifact = (root / entry.path).resolve()
        if not artifact.is_relative_to(root):
            issues.append(_issue("component_path_outside_root", pointer, f"component path escapes root: {entry.path}"))
            continue
        if not artifact.is_file():
            issues.append(_issue("component_artifact_missing", pointer, f"component file is missing: {entry.path}"))
            continue

        actual_sha256 = hashlib.sha256(artifact.read_bytes()).hexdigest()
        if not digests_equal(actual_sha256, entry.sha256):
            issues.append(
                _issue(
                    "component_hash_mismatch",
                    pointer,
                    f"disk hash does not match declared hash for {reference.id}@{reference.version}",
                )
            )
            continue

        resolved.append(
            ResolvedComponent(
                id=entry.id,
                version=entry.version,
                type=entry.type,
                declared_sha256=entry.sha256,
                actual_sha256=actual_sha256,
                path=artifact,
                license=entry.license,
                provenance=entry.provenance,
                dependencies=entry.dependencies,
                conflicts=entry.conflicts,
                capabilities=entry.capabilities,
                side_effects=entry.side_effects,
                stop_conditions=entry.stop_conditions,
                rollback=entry.rollback,
            )
        )

    return ResolutionResult(
        components=tuple(sorted(resolved, key=lambda item: (item.type, item.id, item.version))),
        issues=tuple(sorted(issues)),
    )
