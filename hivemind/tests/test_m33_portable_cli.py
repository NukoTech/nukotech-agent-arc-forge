from __future__ import annotations

import json
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from hive_protocol.product.cli import _parser, main
from hive_protocol.product.workflow_adapter import WorkflowProductService
from hive_protocol.product.workspace import HiveWorkspace
from hive_protocol.operator.lifecycle import safe_uninstall

from test_workflow_product import SHA_A, SHA_B, _definition


NOW = datetime(2026, 9, 1, 13, 0, tzinfo=timezone.utc)


def test_cli_exposes_one_shot_attended_workflow_commands() -> None:
    help_text = _parser().format_help()
    for command in (
        "workflow-definition-preview",
        "workflow-definition-publish",
        "workflow-definition-list",
        "workflow-definition-diff",
        "workflow-run-launch",
        "workflow-run-status",
        "workflow-readiness",
        "workflow-conflicts",
        "workflow-approval-preview",
        "workflow-approval-approve",
        "workflow-claim",
        "workflow-deliver",
        "workflow-session-start",
        "workflow-session-heartbeat",
        "workflow-session-progress",
        "workflow-session-fail",
        "workflow-session-complete",
        "workflow-stale-preview",
        "workflow-stale-apply",
        "workflow-retry",
        "workflow-compensation-preview",
        "workflow-compensation-authorize",
        "workflow-rollback-preview",
        "workflow-rollback-apply",
        "workflow-run-cancel",
        "workflow-replay",
    ):
        assert command in help_text


def test_workflow_history_exports_without_private_or_runtime_state_and_reopens_after_rotation(tmp_path: Path) -> None:
    vault = tmp_path / "hive"
    workspace = HiveWorkspace.create(vault)
    service = WorkflowProductService(vault)
    published = service.publish_definition(
        _definition(service.machine_id),
        idempotency_key="portable-publish",
        now=NOW,
    )
    launched = service.launch_run(
        "workflow:product",
        1,
        run_id=str(uuid4()),
        source_commit=SHA_A,
        input_manifest_sha256=SHA_B,
        event_id=str(uuid4()),
        idempotency_key="portable-launch",
        now=NOW,
    )
    old_operator = service.operator_key_id
    bundle = tmp_path / "workflow-portable.tar.gz"
    workspace.export(bundle)
    with tarfile.open(bundle, "r:gz") as archive:
        names = {member.name for member in archive.getmembers()}
    assert any(name.startswith("hive-export/workflows/definitions/") for name in names)
    assert any(name.startswith("hive-export/workflows/runs/") for name in names)
    assert any(name.startswith("hive-export/.hive/receipts/workflows/") for name in names)
    assert "hive-export/.hive/workflow-keys/public-keys.json" in names
    assert not any("/.hive/keys/" in f"/{name}/" for name in names)
    assert not any("/.hive/runtime/" in f"/{name}/" for name in names)
    assert not any("/replay/" in f"/{name}/" for name in names)
    assert not any(name.endswith(".lock") for name in names)

    reopened = HiveWorkspace.reopen_export(bundle, tmp_path / "reopened")
    rotated = WorkflowProductService(reopened.root)
    assert rotated.operator_key_id != old_operator
    replay = rotated.run_status(launched["run"]["run_id"])
    assert replay["workflow_sha256"] == published["preview"]["workflow_sha256"]
    assert replay["execution_performed"] is False


def test_cli_definition_preview_publish_list_and_secret_refusal_are_json(tmp_path: Path, capsys) -> None:
    vault = tmp_path / "hive"
    assert main(["init", "--vault", str(vault)]) == 0
    capsys.readouterr()
    service = WorkflowProductService(vault)
    definition_path = tmp_path / "definition.json"
    definition_path.write_text(
        json.dumps(_definition(service.machine_id)), encoding="utf-8"
    )
    assert main(
        [
            "workflow-definition-preview",
            "--vault",
            str(vault),
            "--definition",
            str(definition_path),
        ]
    ) == 0
    preview = json.loads(capsys.readouterr().out)
    assert preview["mutation"] == "PUBLISH_IMMUTABLE_VERSION"
    assert main(
        [
            "workflow-definition-publish",
            "--vault",
            str(vault),
            "--definition",
            str(definition_path),
            "--idempotency-key",
            "cli-publish-product",
        ]
    ) == 0
    capsys.readouterr()
    assert main(
        [
            "workflow-definition-list",
            "--vault",
            str(vault),
            "--workflow-id",
            "workflow:product",
        ]
    ) == 0
    listed = json.loads(capsys.readouterr().out)
    assert listed["versions"] == [1]

    secret = "TOP-SECRET-WORKFLOW-VALUE"
    bad = tmp_path / "bad.json"
    bad.write_text(
        json.dumps({**_definition(service.machine_id), "api_token": secret}),
        encoding="utf-8",
    )
    assert main(
        [
            "workflow-definition-preview",
            "--vault",
            str(vault),
            "--definition",
            str(bad),
        ]
    ) != 0
    refused = capsys.readouterr().out
    assert secret not in refused
    assert json.loads(refused)["outcome"] == "REFUSED"


def test_manifest_only_uninstall_preserves_all_m33_portable_authority(tmp_path: Path) -> None:
    root = tmp_path / "installed"
    root.mkdir()
    (root / ".hive-root-manifest.json").write_text(
        json.dumps({"schema_version": "hive.cycle2.root-manifest.v1"}),
        encoding="utf-8",
    )
    for generated in ("tasks", "receipts", "queue", "replay", "project_state", "operator"):
        path = root / generated
        path.mkdir()
        (path / "generated.json").write_text("{}", encoding="utf-8")
    protected = (
        "workflows",
        "sources",
        "staging",
        "prime",
        "knowledge",
        "research",
    )
    for name in protected:
        path = root / name
        path.mkdir()
        (path / "portable.json").write_text(name, encoding="utf-8")
    before = {
        name: (root / name / "portable.json").read_bytes() for name in protected
    }
    result = safe_uninstall(root)
    assert result["status"] == "UNINSTALLED"
    assert before == {
        name: (root / name / "portable.json").read_bytes() for name in protected
    }


def test_snapshot_rollback_restores_m33_portable_workflow_roots_exactly(tmp_path: Path) -> None:
    vault = tmp_path / "hive"
    workspace = HiveWorkspace.create(vault)
    service = WorkflowProductService(vault)
    first = service.publish_definition(
        _definition(service.machine_id),
        idempotency_key="snapshot-workflow-v1",
        now=NOW,
    )
    service.launch_run(
        "workflow:product",
        1,
        run_id=str(uuid4()),
        source_commit=SHA_A,
        input_manifest_sha256=SHA_B,
        event_id=str(uuid4()),
        idempotency_key="snapshot-workflow-run",
        now=NOW,
    )
    source = tmp_path / "portable-source.md"
    source.write_text("portable source", encoding="utf-8")
    workspace.import_content(source)
    for relative in (
        "staging/staged.json",
        "prime/knowledge.md",
        "research/result.md",
    ):
        path = vault / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(relative, encoding="utf-8")
    checkpoint = workspace.snapshot("M3.3 portable checkpoint")["commit"]

    roots = (
        "workflows",
        "sources",
        "staging",
        "prime",
        "research",
        ".hive/provenance",
        ".hive/receipts/workflows",
        ".hive/workflow-keys",
    )

    def manifest() -> dict[str, bytes]:
        return {
            path.relative_to(vault).as_posix(): path.read_bytes()
            for root in roots
            for path in sorted((vault / root).rglob("*"))
            if path.is_file()
        }

    before = manifest()
    second = _definition(service.machine_id)
    second["version"] = 2
    second["parent_digest"] = first["preview"]["workflow_sha256"]
    second["title"] = "Product workflow v2"
    service.publish_definition(
        second,
        idempotency_key="snapshot-workflow-v2",
        now=NOW,
    )
    for root in roots:
        path = vault / root / "later.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("later", encoding="utf-8")
    workspace.snapshot("M3.3 later portable state")
    workspace.rollback(checkpoint)
    assert manifest() == before
