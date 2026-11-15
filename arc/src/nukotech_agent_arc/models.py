"""Normalized immutable Agent Arc models."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .schema import ValidationIssue


def _strings(value: Any) -> tuple[str, ...]:
    return tuple(str(item) for item in (value or ()))


@dataclass(frozen=True)
class ComponentRef:
    id: str
    version: str
    type: str
    sha256: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ComponentRef":
        return cls(
            id=str(value.get("id", "")),
            version=str(value.get("version", "")),
            type=str(value.get("type", "")),
            sha256=str(value.get("sha256", "")),
        )


@dataclass(frozen=True)
class Recipe:
    id: str
    version: str
    purpose: str
    authority_profile: str
    components: tuple[ComponentRef, ...]
    requested_capabilities: tuple[str, ...]
    side_effects: tuple[str, ...]
    stop_conditions: tuple[str, ...]
    acceptance_tests: tuple[str, ...]
    receipt_policy: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "Recipe":
        return cls(
            id=str(value.get("id", "")),
            version=str(value.get("version", "")),
            purpose=str(value.get("purpose", "")),
            authority_profile=str(value.get("authority_profile", "")),
            components=tuple(ComponentRef.from_mapping(item) for item in value.get("components", ())),
            requested_capabilities=_strings(value.get("requested_capabilities")),
            side_effects=_strings(value.get("side_effects")),
            stop_conditions=_strings(value.get("stop_conditions")),
            acceptance_tests=_strings(value.get("acceptance_tests")),
            receipt_policy=str(value.get("receipt_policy", "")),
        )


@dataclass(frozen=True)
class RegistryEntry:
    id: str
    version: str
    type: str
    sha256: str
    path: str
    license: str
    provenance: Mapping[str, str]
    dependencies: tuple[str, ...]
    conflicts: tuple[str, ...]
    capabilities: tuple[str, ...]
    side_effects: tuple[str, ...]
    stop_conditions: tuple[str, ...]
    rollback: tuple[str, ...]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RegistryEntry":
        provenance = value.get("provenance") or {}
        return cls(
            id=str(value.get("id", "")),
            version=str(value.get("version", "")),
            type=str(value.get("type", "")),
            sha256=str(value.get("sha256", "")),
            path=str(value.get("path", "")),
            license=str(value.get("license", "")),
            provenance={str(key): str(item) for key, item in provenance.items()},
            dependencies=_strings(value.get("dependencies")),
            conflicts=_strings(value.get("conflicts")),
            capabilities=_strings(value.get("capabilities")),
            side_effects=_strings(value.get("side_effects")),
            stop_conditions=_strings(value.get("stop_conditions")),
            rollback=_strings(value.get("rollback")),
        )


@dataclass(frozen=True)
class Registry:
    registry_version: str
    product_id: str
    product_status: str
    components: tuple[RegistryEntry, ...]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "Registry":
        product = value.get("product") or {}
        return cls(
            registry_version=str(value.get("registry_version", "")),
            product_id=str(product.get("id", "")),
            product_status=str(product.get("status", "")),
            components=tuple(RegistryEntry.from_mapping(item) for item in value.get("components", ())),
        )


@dataclass(frozen=True)
class ResolvedComponent:
    id: str
    version: str
    type: str
    declared_sha256: str
    actual_sha256: str
    path: Path
    license: str
    provenance: Mapping[str, str]
    dependencies: tuple[str, ...]
    conflicts: tuple[str, ...]
    capabilities: tuple[str, ...]
    side_effects: tuple[str, ...]
    stop_conditions: tuple[str, ...]
    rollback: tuple[str, ...]


@dataclass(frozen=True)
class ResolutionResult:
    components: tuple[ResolvedComponent, ...]
    issues: tuple[ValidationIssue, ...]
