from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

from hive_protocol.product.workspace import HiveWorkspace


FIXTURE = Path(__file__).parents[1] / "scripts/m4-installed-shell-e2e.py"


def _load_fixture():
    spec = importlib.util.spec_from_file_location("m4_installed_shell_e2e", FIXTURE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_fixture_is_standard_library_http_and_packaged_as_verification_only() -> None:
    source = FIXTURE.read_text(encoding="utf-8")
    for required in (
        "urllib.request",
        "http.cookiejar",
        "subprocess.Popen",
        '"/api/v1/session"',
        '"X-Hive-CSRF"',
        '"X-Hive-Idempotency-Key"',
        '"If-Match"',
        "second_process",
    ):
        assert required in source
    for forbidden in (
        "requests",
        "selenium",
        "playwright",
        "from hive_protocol",
        "import hive_protocol",
        "?token=",
        "--daemon",
        "--background",
        "--unattended",
    ):
        assert forbidden not in source

    repository = Path(__file__).parents[1]
    build = (repository / "scripts/build-alpha.sh").read_text(encoding="utf-8")
    verify = (repository / "scripts/verify_alpha_artifact.py").read_text(
        encoding="utf-8"
    )
    fresh = (repository / "scripts/fresh-install-e2e.sh").read_text(
        encoding="utf-8"
    )
    assert "m4-installed-shell-e2e.py" in build
    assert "m4-installed-shell-e2e.py" in verify
    assert "m4-installed-shell-e2e.py" in fresh


def test_foreground_http_fixture_reconstructs_without_browser_persistence(
    tmp_path: Path,
) -> None:
    vault = tmp_path / "hive"
    HiveWorkspace.create(vault)
    module = _load_fixture()
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
    result = module.run_fixture(
        [sys.executable, "-m", "hive_protocol.product.cli"],
        vault,
        tmp_path / "fixture",
        environment=environment,
    )
    assert result["outcome"] == "VERIFIED"
    assert result["second_process"] is True
    assert result["browser_persistence"] is False
    assert result["execution_performed"] is False
    assert result["service_installed"] is False
    assert result["session_rotated"] is True
    assert result["workflow_conflict"] is True
    assert result["workflow_failure"] is True
    assert result["workflow_retry"] is True
    assert result["workflow_stale_release"] is True
    assert result["workflow_completion"] is True
    assert result["workflow_replay_read_only"] is True
    json.dumps(result, sort_keys=True)
