from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = PROJECT_ROOT / "examples" / "marketing-operator"


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


def test_validate_and_compose_marketing_operator_example(tmp_path: Path) -> None:
    validate = _run(
        "validate",
        "--recipe",
        str(EXAMPLE / "recipe.yaml"),
        "--registry",
        str(EXAMPLE / "registry.yaml"),
    )
    assert validate.returncode == 0
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

    assert compose.returncode == 0
    assert compose.stdout.strip().splitlines() == [
        "STATUS COMPOSED",
        f"RECEIPT {output / 'composition-receipt.json'}",
        f"PACKAGE {output / 'marketing-operator-1.0.0.zip'}",
    ]
    assert (output / "architecture-manifest.json").is_file()
    assert (output / "composition-receipt.json").is_file()
    assert (output / "marketing-operator-1.0.0.zip").is_file()
    assert (output / "marketing-operator-1.0.0.MANIFEST.sha256").is_file()

    verify = _run(
        "verify-package",
        "--package",
        str(output / "marketing-operator-1.0.0.zip"),
        "--manifest",
        str(output / "marketing-operator-1.0.0.MANIFEST.sha256"),
    )
    assert verify.returncode == 0
    assert verify.stdout.strip() == "VERIFIED"


def test_prohibited_publish_request_refuses_without_package(tmp_path: Path) -> None:
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

    assert compose.returncode == 2
    assert compose.stdout.strip().splitlines() == [
        "STATUS REFUSED",
        f"RECEIPT {output / 'refusal-receipt.json'}",
    ]
    assert (output / "refusal-receipt.json").is_file()
    assert list(output.glob("*.zip")) == []


def test_verify_package_uses_distinct_failure_exit_code(tmp_path: Path) -> None:
    package = tmp_path / "broken.zip"
    manifest = tmp_path / "broken.MANIFEST.sha256"
    package.write_bytes(b"not a zip")
    manifest.write_text("0" * 64 + "  item.txt\n", encoding="utf-8")

    verify = _run("verify-package", "--package", str(package), "--manifest", str(manifest))

    assert verify.returncode == 3
    assert verify.stdout.strip() == "NOT VERIFIED"
