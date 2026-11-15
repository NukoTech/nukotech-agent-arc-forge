from __future__ import annotations

import hashlib
import importlib
from pathlib import Path


def _modules():
    models = importlib.import_module("nukotech_agent_arc.models")
    registry = importlib.import_module("nukotech_agent_arc.registry")
    assert hasattr(models, "Recipe"), "Recipe model is not implemented"
    assert hasattr(models, "Registry"), "Registry model is not implemented"
    assert hasattr(registry, "resolve_components"), "resolver is not implemented"
    return models, registry


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _component_record(*, path: str, sha256: str, component_type: str = "skill") -> dict:
    return {
        "schema": "nukotech.agent_arc.component.v1",
        "id": "safe-skill",
        "version": "1.0.0",
        "type": component_type,
        "sha256": sha256,
        "path": path,
        "license": "MIT",
        "provenance": {"source": "first-party", "owner": "example"},
        "dependencies": [],
        "conflicts": [],
        "capabilities": ["draft_content"],
        "side_effects": [],
        "stop_conditions": ["operator_stop"],
        "rollback": ["remove_candidate"],
    }


def _recipe_ref(*, version: str = "1.0.0", component_type: str = "skill", sha256: str) -> dict:
    return {
        "id": "safe-skill",
        "version": version,
        "type": component_type,
        "sha256": sha256,
    }


def _recipe(models, ref: dict):
    return models.Recipe.from_mapping(
        {
            "schema": "nukotech.agent_arc.recipe.v1",
            "id": "marketing-operator",
            "version": "1.0.0",
            "purpose": "Create drafts only",
            "authority_profile": "draft-only",
            "components": [ref],
            "requested_capabilities": ["draft_content"],
            "side_effects": [],
            "stop_conditions": ["operator_stop"],
            "acceptance_tests": ["draft_created"],
            "receipt_policy": "canonical-json",
        }
    )


def _registry(models, components: list[dict]):
    return models.Registry.from_mapping(
        {
            "schema": "nukotech.agent_arc.registry.v1",
            "registry_version": "0.3.0-alpha.1",
            "product": {"id": "nukotech-agent-arc", "status": "LOCAL_COMPOSER_ALPHA"},
            "components": components,
        }
    )


def test_exact_identity_and_disk_hash_resolve(tmp_path: Path) -> None:
    models, resolver = _modules()
    payload = b"safe skill\n"
    artifact = tmp_path / "components" / "safe-skill.txt"
    artifact.parent.mkdir()
    artifact.write_bytes(payload)
    digest = _sha(payload)

    result = resolver.resolve_components(
        _recipe(models, _recipe_ref(sha256=digest)),
        _registry(models, [_component_record(path="components/safe-skill.txt", sha256=digest)]),
        tmp_path,
    )

    assert result.issues == ()
    assert [(item.id, item.version, item.type, item.actual_sha256) for item in result.components] == [
        ("safe-skill", "1.0.0", "skill", digest)
    ]


def test_version_mismatch_is_not_fuzzily_resolved(tmp_path: Path) -> None:
    models, resolver = _modules()
    digest = _sha(b"safe skill\n")

    result = resolver.resolve_components(
        _recipe(models, _recipe_ref(version="2.0.0", sha256=digest)),
        _registry(models, [_component_record(path="safe.txt", sha256=digest)]),
        tmp_path,
    )

    assert [issue.code for issue in result.issues] == ["component_not_found"]
    assert result.components == ()


def test_duplicate_registry_identity_is_rejected(tmp_path: Path) -> None:
    models, resolver = _modules()
    digest = _sha(b"safe skill\n")
    record = _component_record(path="safe.txt", sha256=digest)

    result = resolver.resolve_components(
        _recipe(models, _recipe_ref(sha256=digest)),
        _registry(models, [record, dict(record)]),
        tmp_path,
    )

    assert [issue.code for issue in result.issues] == ["duplicate_registry_identity"]
    assert result.components == ()


def test_missing_component_artifact_is_rejected(tmp_path: Path) -> None:
    models, resolver = _modules()
    digest = _sha(b"safe skill\n")

    result = resolver.resolve_components(
        _recipe(models, _recipe_ref(sha256=digest)),
        _registry(models, [_component_record(path="missing.txt", sha256=digest)]),
        tmp_path,
    )

    assert [issue.code for issue in result.issues] == ["component_artifact_missing"]


def test_component_type_mismatch_is_rejected(tmp_path: Path) -> None:
    models, resolver = _modules()
    digest = _sha(b"safe skill\n")

    result = resolver.resolve_components(
        _recipe(models, _recipe_ref(component_type="loop", sha256=digest)),
        _registry(models, [_component_record(path="safe.txt", sha256=digest, component_type="skill")]),
        tmp_path,
    )

    assert [issue.code for issue in result.issues] == ["component_type_mismatch"]


def test_declared_hash_is_verified_against_disk_bytes(tmp_path: Path) -> None:
    models, resolver = _modules()
    declared = _sha(b"declared\n")
    artifact = tmp_path / "safe.txt"
    artifact.write_bytes(b"different\n")

    result = resolver.resolve_components(
        _recipe(models, _recipe_ref(sha256=declared)),
        _registry(models, [_component_record(path="safe.txt", sha256=declared)]),
        tmp_path,
    )

    assert [issue.code for issue in result.issues] == ["component_hash_mismatch"]
    assert result.components == ()

