from __future__ import annotations

import importlib
from pathlib import Path

import pytest


def _yamlio():
    module = importlib.import_module("nukotech_agent_arc.yamlio")
    assert hasattr(module, "load_yaml_strict"), "load_yaml_strict is not implemented"
    return module


def _schema():
    module = importlib.import_module("nukotech_agent_arc.schema")
    assert hasattr(module, "validate_document"), "validate_document is not implemented"
    return module


def test_valid_yaml_loads_as_mapping(tmp_path: Path) -> None:
    source = tmp_path / "valid.yaml"
    source.write_text("id: example\nversion: 1.0.0\n", encoding="utf-8")

    assert _yamlio().load_yaml_strict(source) == {"id": "example", "version": "1.0.0"}


def test_duplicate_yaml_key_is_rejected_with_location(tmp_path: Path) -> None:
    source = tmp_path / "duplicate.yaml"
    source.write_text("id: first\nid: second\n", encoding="utf-8")

    module = _yamlio()
    with pytest.raises(module.DuplicateKeyError) as caught:
        module.load_yaml_strict(source)

    assert caught.value.key == "id"
    assert caught.value.line == 2
    assert caught.value.path == source


def test_recipe_missing_required_field_returns_stable_issue() -> None:
    recipe = {
        "schema": "nukotech.agent_arc.recipe.v1",
        "id": "sample",
        "version": "1.0.0",
    }

    issues = _schema().validate_document(recipe, "recipe")

    assert [(issue.code, issue.path) for issue in issues] == [
        ("required", "/"),
        ("required", "/"),
        ("required", "/"),
        ("required", "/"),
        ("required", "/"),
        ("required", "/"),
        ("required", "/"),
        ("required", "/"),
    ]
    assert [issue.message for issue in issues] == sorted(issue.message for issue in issues)


def test_unknown_component_type_is_rejected() -> None:
    component = {
        "schema": "nukotech.agent_arc.component.v1",
        "id": "sample",
        "version": "1.0.0",
        "type": "mystery",
        "sha256": "a" * 64,
        "path": "components/sample.yaml",
        "license": "MIT",
        "provenance": {"source": "first-party", "owner": "example"},
        "dependencies": [],
        "conflicts": [],
        "capabilities": [],
        "side_effects": [],
        "stop_conditions": ["operator_stop"],
        "rollback": ["remove_candidate"],
    }

    issues = _schema().validate_document(component, "component")

    assert [(issue.code, issue.path) for issue in issues] == [("enum", "/type")]


def test_validation_issues_are_sorted_by_path_code_and_message() -> None:
    component = {"schema": "wrong", "type": "mystery"}

    issues = _schema().validate_document(component, "component")
    ordering = [(issue.path, issue.code, issue.message) for issue in issues]

    assert ordering == sorted(ordering)
