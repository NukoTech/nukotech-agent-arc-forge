from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


def _schema() -> dict:
    return json.loads(
        files("hive_protocol.schemas")
        .joinpath("application-adapter-manifest.v1.schema.json")
        .read_text(encoding="utf-8")
    )


def test_shipped_and_fixture_manifests_conform_to_v1() -> None:
    root = Path(__file__).parents[1]
    validator = Draft202012Validator(_schema(), format_checker=FormatChecker())
    for relative in (
        "tests/fixtures/adapters/sample-heartbeat.manifest.json",
        "src/hive_protocol/adapters/capture/local-capture.manifest.json",
        "src/hive_protocol/adapters/research/bounded-research.manifest.json",
    ):
        document = json.loads((root / relative).read_text(encoding="utf-8"))
        assert list(validator.iter_errors(document)) == []


def test_manifest_schema_requires_export_revocation_and_resource_limits() -> None:
    required = set(_schema()["required"])
    assert {"export", "revocation_check", "resource_limits"} <= required


def test_native_m2_manifests_do_not_claim_windows_with_posix_runtime_guards() -> None:
    root = Path(__file__).parents[1]
    for relative in (
        "src/hive_protocol/adapters/capture/local-capture.manifest.json",
        "src/hive_protocol/adapters/research/bounded-research.manifest.json",
    ):
        document = json.loads((root / relative).read_text(encoding="utf-8"))
        assert all(platform["os"] != "windows" for platform in document["platforms"])
