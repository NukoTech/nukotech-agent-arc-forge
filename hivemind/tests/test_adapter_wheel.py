from __future__ import annotations

import os
import subprocess
import sys
import zipfile
from pathlib import Path


def test_sanitized_wheel_contains_frozen_adapter_sdk(tmp_path: Path) -> None:
    repository = Path(__file__).parents[1]
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    built = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-build-isolation",
            "--no-deps",
            "--disable-pip-version-check",
            "--wheel-dir",
            str(wheelhouse),
            str(repository),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert built.returncode == 0, built.stderr
    wheels = list(wheelhouse.glob("nukotech_hive_local-0.1.0-*.whl"))
    assert len(wheels) == 1
    sanitized = subprocess.run(
        [
            sys.executable,
            str(repository / "scripts/sanitize_product_wheel.py"),
            str(wheels[0]),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert sanitized.returncode == 0, sanitized.stderr
    with zipfile.ZipFile(wheels[0]) as archive:
        names = set(archive.namelist())

    imported = subprocess.run(
        [sys.executable, "-c", "from hive_protocol.product.cli import main; assert callable(main)"],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(wheels[0])},
        check=False,
        capture_output=True,
        text=True,
    )
    assert imported.returncode == 0, imported.stderr

    five_sdk_schemas = {
        "hive_protocol/schemas/application-adapter-manifest.v1.schema.json",
        "hive_protocol/schemas/adapter-request.v1.schema.json",
        "hive_protocol/schemas/adapter-plan.v1.schema.json",
        "hive_protocol/schemas/adapter-approval.v1.schema.json",
        "hive_protocol/schemas/adapter-result.v1.schema.json",
    }
    assert five_sdk_schemas <= names
    assert "hive_protocol/schemas/adapter-ownership-manifest.v1.schema.json" in names
    assert {
        "hive_protocol/schemas/capture-envelope.v1.schema.json",
        "hive_protocol/schemas/source-record.v1.schema.json",
        "hive_protocol/schemas/research-workspace.v1.schema.json",
        "hive_protocol/schemas/research-source-set.v1.schema.json",
        "hive_protocol/schemas/research-artifact.v1.schema.json",
        "hive_protocol/capture/models.py",
        "hive_protocol/capture/admission.py",
        "hive_protocol/capture/normalizers.py",
        "hive_protocol/capture/security.py",
        "hive_protocol/capture/store.py",
        "hive_protocol/research/models.py",
        "hive_protocol/research/artifacts.py",
        "hive_protocol/research/portable.py",
        "hive_protocol/research/query.py",
        "hive_protocol/research/workspace.py",
        "hive_protocol/product/agent_adapter.py",
        "hive_protocol/product/cli.py",
    } <= names
    assert {
        "hive_protocol/cognition/__init__.py",
        "hive_protocol/cognition/authority.py",
        "hive_protocol/cognition/deletion.py",
        "hive_protocol/cognition/extraction.py",
        "hive_protocol/cognition/models.py",
        "hive_protocol/cognition/promotion.py",
        "hive_protocol/cognition/retention.py",
        "hive_protocol/cognition/retrieval.py",
        "hive_protocol/cognition/scoring.py",
        "hive_protocol/cognition/store.py",
        "hive_protocol/knowledge/__init__.py",
        "hive_protocol/knowledge/editor.py",
        "hive_protocol/knowledge/graph.py",
        "hive_protocol/knowledge/models.py",
        "hive_protocol/schemas/cognition-event.v1.schema.json",
        "hive_protocol/schemas/memory-candidate.v1.schema.json",
        "hive_protocol/schemas/memory-review-decision.v1.schema.json",
        "hive_protocol/schemas/knowledge-node.v1.schema.json",
        "hive_protocol/schemas/knowledge-edge.v1.schema.json",
        "hive_protocol/schemas/memory-deletion-plan.v1.schema.json",
    } <= names
    assert {
        "hive_protocol/product/workflow_adapter.py",
        "hive_protocol/workflows/__init__.py",
        "hive_protocol/workflows/approvals.py",
        "hive_protocol/workflows/conflicts.py",
        "hive_protocol/workflows/definitions.py",
        "hive_protocol/workflows/events.py",
        "hive_protocol/workflows/matching.py",
        "hive_protocol/workflows/models.py",
        "hive_protocol/workflows/replay.py",
        "hive_protocol/workflows/scheduler.py",
        "hive_protocol/workflows/sessions.py",
        "hive_protocol/schemas/agent-session.v1.schema.json",
        "hive_protocol/schemas/workflow-approval.v1.schema.json",
        "hive_protocol/schemas/workflow-definition.v1.schema.json",
        "hive_protocol/schemas/workflow-event.v1.schema.json",
        "hive_protocol/schemas/workflow-run.v1.schema.json",
        "hive_protocol/schemas/operator-request.v1.schema.json",
        "hive_protocol/schemas/operator-response.v1.schema.json",
        "hive_protocol/product/shell_contracts.py",
        "hive_protocol/product/shell_security.py",
        "hive_protocol/product/shell_service.py",
        "hive_protocol/product/api.py",
        "hive_protocol/product/shell_views.py",
        "hive_protocol/product/static/app.css",
        "hive_protocol/product/static/app.js",
        "hive_protocol/product/static/knowledge.js",
        "hive_protocol/product/static/workflows.js",
    } <= names
    assert {
        "hive_protocol/adapters/authority.py",
        "hive_protocol/adapters/base.py",
        "hive_protocol/adapters/execution.py",
        "hive_protocol/adapters/lifecycle.py",
        "hive_protocol/adapters/lifecycle_state.py",
        "hive_protocol/adapters/manifest.py",
        "hive_protocol/adapters/models.py",
        "hive_protocol/adapters/policy.py",
        "hive_protocol/adapters/registry.py",
        "hive_protocol/adapters/runtime.py",
        "hive_protocol/adapters/security.py",
        "hive_protocol/adapters/capture/local.py",
        "hive_protocol/adapters/research/bounded.py",
    } <= names
    assert {
        "hive_protocol/adapters/capture/local-capture.manifest.json",
        "hive_protocol/adapters/research/bounded-research.manifest.json",
    } <= names
    assert not any("contracts/drafts" in name for name in names)
    assert not any("fixtures/" in name or name.startswith("tests/") for name in names)


def test_fresh_install_proves_installed_adapter_list() -> None:
    repository = Path(__file__).parents[1]
    script = (repository / "scripts/fresh-install-e2e.sh").read_text(encoding="utf-8")
    assert '"$install_prefix/bin/hive-local" adapter-list' in script
    for command in (
        "capture-plan",
        "capture-admit",
        "research-workspace-create",
        "research-source-add",
        "research-search",
        "research-ask",
        "research-artifact",
        "research-export",
        "research-reopen",
        "memory-propose-event",
        "memory-candidates",
        "memory-review",
        "memory-promote",
        "memory-correct",
        "memory-revoke",
        "memory-retention-scan",
        "memory-deletion-plan",
        "memory-deletion-approve",
        "memory-deletion-apply",
        "knowledge-note-preview",
        "knowledge-note-approve",
        "knowledge-note-apply",
        "knowledge-graph",
        "workflow-definition-preview",
        "workflow-definition-publish",
        "workflow-definition-list",
        "workflow-run-launch",
        "workflow-run-status",
        "workflow-replay",
    ):
        assert (
            f'"$install_prefix/bin/hive-local" {command}' in script
            or f"promote_m32_event {command}" in script
        )


def test_alpha_build_inventory_requires_m4_runtime() -> None:
    repository = Path(__file__).parents[1]
    script = (repository / "scripts/build-alpha.sh").read_text(encoding="utf-8")
    for runtime_path in (
        "hive_protocol/product/workflow_adapter.py",
        "hive_protocol/workflows/approvals.py",
        "hive_protocol/workflows/definitions.py",
        "hive_protocol/workflows/events.py",
        "hive_protocol/workflows/replay.py",
        "hive_protocol/workflows/scheduler.py",
        "hive_protocol/workflows/sessions.py",
        "hive_protocol/schemas/workflow-definition.v1.schema.json",
        "hive_protocol/schemas/workflow-run.v1.schema.json",
        "hive_protocol/schemas/workflow-event.v1.schema.json",
        "hive_protocol/schemas/workflow-approval.v1.schema.json",
        "hive_protocol/schemas/agent-session.v1.schema.json",
        "hive_protocol/operator/__init__.py",
        "hive_protocol/operator/lifecycle.py",
        "hive_protocol/operator/projection.py",
        "hive_protocol/receipts/__init__.py",
        "hive_protocol/receipts/core.py",
        "hive_protocol/tasks/__init__.py",
        "hive_protocol/tasks/engine.py",
        "hive_protocol/product/shell_views.py",
        "hive_protocol/product/static/app.css",
        "hive_protocol/product/static/app.js",
        "hive_protocol/product/static/knowledge.js",
        "hive_protocol/product/static/workflows.js",
    ):
        assert f'"{runtime_path}"' in script


def test_wheel_sanitizer_requires_m4_shell_assets() -> None:
    repository = Path(__file__).parents[1]
    script = (repository / "scripts/sanitize_product_wheel.py").read_text(
        encoding="utf-8"
    )
    assert "REQUIRED_M4_RUNTIME" in script
    for runtime_path in (
        "hive_protocol/operator/__init__.py",
        "hive_protocol/operator/lifecycle.py",
        "hive_protocol/operator/projection.py",
        "hive_protocol/receipts/__init__.py",
        "hive_protocol/receipts/core.py",
        "hive_protocol/tasks/__init__.py",
        "hive_protocol/tasks/engine.py",
        "hive_protocol/product/shell_views.py",
        "hive_protocol/product/static/app.css",
        "hive_protocol/product/static/app.js",
        "hive_protocol/product/static/knowledge.js",
        "hive_protocol/product/static/workflows.js",
    ):
        assert f'"{runtime_path}"' in script
