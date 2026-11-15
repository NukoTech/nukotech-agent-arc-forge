from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _run(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    return subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )


def test_wheel_installs_composes_and_uninstalls_in_isolated_environment(tmp_path: Path) -> None:
    source = tmp_path / "source"
    shutil.copytree(
        PROJECT_ROOT,
        source,
        ignore=shutil.ignore_patterns(".git", ".venv", ".pytest_cache", "__pycache__", "*.pyc"),
    )
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    build = _run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            ".",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(wheels),
        ],
        cwd=source,
    )
    assert build.returncode == 0, build.stderr
    wheel = next(wheels.glob("nukotech_agent_arc-*.whl"))

    environment = tmp_path / "environment"
    create = _run([sys.executable, "-m", "venv", str(environment)], cwd=tmp_path)
    assert create.returncode == 0, create.stderr
    python = environment / "bin" / "python"
    agent_arc = environment / "bin" / "agent-arc"
    site_packages_result = _run(
        [str(python), "-c", "import site; print(site.getsitepackages()[0])"],
        cwd=tmp_path,
    )
    assert site_packages_result.returncode == 0
    dependency_path = Path(sys.prefix) / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
    site_packages = Path(site_packages_result.stdout.strip())
    (site_packages / "agent_arc_test_dependencies.pth").write_text(str(dependency_path) + "\n", encoding="utf-8")

    install = _run([str(python), "-m", "pip", "install", "--no-deps", str(wheel)], cwd=tmp_path)
    assert install.returncode == 0, install.stderr
    help_result = _run([str(agent_arc), "--help"], cwd=tmp_path)
    assert help_result.returncode == 0
    assert "Deterministic agent architecture composer" in help_result.stdout

    example = source / "examples" / "marketing-operator"
    output = tmp_path / "output"
    compose = _run(
        [
            str(agent_arc),
            "compose",
            "--recipe",
            str(example / "recipe.yaml"),
            "--registry",
            str(example / "registry.yaml"),
            "--authorization",
            str(example / "authorization.yaml"),
            "--component-root",
            str(example),
            "--output",
            str(output),
        ],
        cwd=tmp_path,
    )
    assert compose.returncode == 0, compose.stderr
    assert (output / "marketing-operator-1.0.0.zip").is_file()

    uninstall = _run([str(python), "-m", "pip", "uninstall", "-y", "nukotech-agent-arc"], cwd=tmp_path)
    assert uninstall.returncode == 0, uninstall.stderr
    import_after_uninstall = _run([str(python), "-c", "import nukotech_agent_arc"], cwd=tmp_path)
    assert import_after_uninstall.returncode != 0
