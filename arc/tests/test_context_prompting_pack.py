from __future__ import annotations

import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = PROJECT_ROOT / "examples" / "context-and-prompting-pack"


def _run(*arguments: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(PROJECT_ROOT / "src")
    return subprocess.run(
        [sys.executable, "-m", "nukotech_agent_arc.cli", *arguments],
        cwd=PROJECT_ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )


def test_context_prompting_pack_composes_as_a_side_effect_free_architecture(tmp_path: Path) -> None:
    validate = _run(
        "validate",
        "--recipe",
        str(EXAMPLE / "recipe.yaml"),
        "--registry",
        str(EXAMPLE / "registry.yaml"),
    )
    assert validate.returncode == 0, validate.stdout + validate.stderr
    assert validate.stdout.strip() == "VALID"

    output = tmp_path / "output"
    compose = _run(
        "compose",
        "--recipe",
        str(EXAMPLE / "recipe.yaml"),
        "--registry",
        str(EXAMPLE / "registry.yaml"),
        "--authorization",
        str(EXAMPLE / "authorization.yaml"),
        "--component-root",
        str(EXAMPLE),
        "--output",
        str(output),
    )
    package = output / "context-and-prompting-pack-0.1.0.zip"
    manifest = output / "context-and-prompting-pack-0.1.0.MANIFEST.sha256"

    assert compose.returncode == 0, compose.stdout + compose.stderr
    architecture = json.loads((output / "architecture-manifest.json").read_text(encoding="utf-8"))
    assert architecture["recipe"] == {"id": "context-and-prompting-pack", "version": "0.1.0"}
    assert architecture["side_effects"] == []
    assert architecture["requested_capabilities"] == [
        "bootstrap_organization_context",
        "govern_context",
        "select_prompt_strategy",
        "stage_context_candidate",
    ]
    assert [(item["id"], item["type"]) for item in architecture["components"]] == [
        ("context-governance", "governance_or_harness"),
        ("context-manifest", "graph_or_memory_binding"),
        ("organization-context-bootstrap", "loop"),
        ("prompt-strategy-selector", "skill"),
    ]
    assert all(item["side_effects"] == [] for item in architecture["components"])

    verify = _run("verify-package", "--package", str(package), "--manifest", str(manifest))
    assert verify.returncode == 0, verify.stdout + verify.stderr
    assert verify.stdout.strip() == "VERIFIED"
    with zipfile.ZipFile(package) as archive:
        assert archive.namelist() == [
            "architecture-manifest.json",
            "components/context-governance.md",
            "components/context-manifest.md",
            "components/organization-context-bootstrap.md",
            "components/prompt-strategy-selector/SKILL.md",
            "composition-receipt.json",
        ]


def test_bulk_context_and_automatic_memory_promotion_are_refused(tmp_path: Path) -> None:
    output = tmp_path / "output"
    compose = _run(
        "compose",
        "--recipe",
        str(EXAMPLE / "prohibited-recipe.yaml"),
        "--registry",
        str(EXAMPLE / "registry.yaml"),
        "--authorization",
        str(EXAMPLE / "authorization.yaml"),
        "--component-root",
        str(EXAMPLE),
        "--output",
        str(output),
    )

    assert compose.returncode == 2, compose.stdout + compose.stderr
    refusal = json.loads((output / "refusal-receipt.json").read_text(encoding="utf-8"))
    assert refusal["status"] == "REFUSED"
    assert [(item["code"], item["message"]) for item in refusal["issues"]] == [
        ("prohibited_effect", "authorization explicitly prohibits: automatic_memory_promotion"),
        ("prohibited_effect", "authorization explicitly prohibits: bulk_context_import"),
        ("capability_not_authorized", "capability is outside authorization: automatic_memory_promotion"),
        ("capability_not_authorized", "capability is outside authorization: bulk_context_import"),
    ]
    assert list(output.glob("*.zip")) == []
