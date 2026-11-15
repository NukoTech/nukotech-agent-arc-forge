from __future__ import annotations

import json
import shlex
import socket
import subprocess
from pathlib import Path

import pytest

from hive_protocol.product.cli import _parser, main
from hive_protocol.product.workspace import HiveWorkspace


def test_cli_exposes_attended_adapter_commands() -> None:
    parser = _parser()
    help_text = parser.format_help()
    for command in (
        "adapter-list",
        "adapter-health",
        "adapter-plan",
        "adapter-invoke",
        "adapter-lifecycle-plan",
        "adapter-approve",
        "adapter-export",
        "adapter-rollback",
        "adapter-uninstall",
        "capture-plan",
        "capture-admit",
        "research-workspace-create",
        "research-source-add",
        "research-source-remove",
        "research-search",
        "research-ask",
        "research-artifact",
        "research-export",
        "research-reopen",
        "memory-propose-event",
        "memory-correct",
        "memory-revoke",
        "memory-candidates",
        "memory-review",
        "memory-promote",
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


def test_app_launcher_is_foreground_loopback_only_and_has_no_background_flags(
    tmp_path: Path, capsys
) -> None:
    parser = _parser()
    parsed = parser.parse_args(
        [
            "app",
            "--vault",
            str(tmp_path / "hive"),
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "--open",
        ]
    )
    assert parsed.command == "app"
    assert parsed.host == "127.0.0.1"
    assert parsed.port == 0
    assert parsed.open is True
    for forbidden in ("--background", "--daemon", "--service", "--unattended"):
        with pytest.raises(SystemExit):
            parser.parse_args(["app", "--vault", str(tmp_path / "hive"), forbidden])

    HiveWorkspace.create(tmp_path / "hive")
    assert (
        main(
            [
                "app",
                "--vault",
                str(tmp_path / "hive"),
                "--host",
                "0.0.0.0",
                "--port",
                "0",
            ]
        )
        != 0
    )
    refused = json.loads(capsys.readouterr().out)
    assert refused["reason_code"] == "WEB_BIND_DENIED"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen(1)
        port = occupied.getsockname()[1]
        assert main(
            [
                "app",
                "--vault",
                str(tmp_path / "hive"),
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ]
        ) != 0
    occupied_result = json.loads(capsys.readouterr().out)
    assert occupied_result["outcome"] == "REFUSED"
    assert occupied_result["reason_code"] == "RUNTIME_ERROR"


def test_readme_attended_commands_parse_and_match_real_flags() -> None:
    readme = (
        Path(__file__).parents[1] / "packaging/product-readme.md"
    ).read_text(encoding="utf-8")
    commands: list[str] = []
    current = ""
    for line in readme.splitlines():
        stripped = line.strip()
        if stripped.startswith("hive-local "):
            current = stripped.removesuffix("\\").rstrip()
            if not stripped.endswith("\\"):
                commands.append(current)
                current = ""
        elif current:
            continuation = stripped.removesuffix("\\").rstrip()
            current = f"{current} {continuation}"
            if not stripped.endswith("\\"):
                commands.append(current)
                current = ""

    expected = {
        "app",
        "adapter-list",
        "adapter-health",
        "adapter-plan",
        "adapter-invoke",
        "adapter-lifecycle-plan",
        "adapter-approve",
        "adapter-export",
        "adapter-rollback",
        "adapter-uninstall",
        "capture-plan",
        "capture-admit",
        "research-workspace-create",
        "research-source-add",
        "research-source-remove",
        "research-search",
        "research-ask",
        "research-artifact",
        "research-export",
        "research-reopen",
        "memory-propose-event",
        "memory-correct",
        "memory-revoke",
        "memory-candidates",
        "memory-review",
        "memory-promote",
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
    }
    vectors = [shlex.split(command)[1:] for command in commands]
    assert {vector[0] for vector in vectors} == expected
    parser = _parser()
    for vector in vectors:
        parser.parse_args(vector)


def test_installed_cli_plans_approves_and_executes_lifecycle(
    tmp_path: Path, capsys
) -> None:
    vault = tmp_path / "hive"
    assert main(["init", "--vault", str(vault)]) == 0
    capsys.readouterr()
    request_path = tmp_path / "request.json"
    invoke_plan_path = tmp_path / "invoke-plan.json"
    assert main(
        [
            "adapter-plan",
            "--vault",
            str(vault),
            "--adapter",
            "nukotech.hive.local-capture",
            "--capability",
            "capture.text",
            "--input",
            "attended lifecycle evidence",
            "--request-output",
            str(request_path),
            "--output",
            str(invoke_plan_path),
        ]
    ) == 0
    capsys.readouterr()
    result_path = tmp_path / "capture-result.json"
    assert main(
        [
            "adapter-invoke",
            "--vault",
            str(vault),
            "--request",
            str(request_path),
            "--plan",
            str(invoke_plan_path),
            "--output",
            str(result_path),
        ]
    ) == 0
    capsys.readouterr()
    assert HiveWorkspace.open(vault).status()["documents"] == 1

    lifecycle_plan_path = tmp_path / "rollback-plan.json"
    assert main(
        [
            "adapter-lifecycle-plan",
            "--vault",
            str(vault),
            "--adapter",
            "nukotech.hive.local-capture",
            "--operation",
            "rollback",
            "--input",
            str(result_path),
            "--output",
            str(lifecycle_plan_path),
        ]
    ) == 0
    lifecycle_plan = json.loads(capsys.readouterr().out)
    assert lifecycle_plan["capability_id"] == "lifecycle.rollback"

    approval_path = tmp_path / "rollback-approval.json"
    assert main(
        [
            "adapter-approve",
            "--vault",
            str(vault),
            "--plan",
            str(lifecycle_plan_path),
            "--output",
            str(approval_path),
        ]
    ) == 0
    approval = json.loads(capsys.readouterr().out)
    assert approval["decision"] == "APPROVED"

    assert main(
        [
            "adapter-rollback",
            "--vault",
            str(vault),
            "--result",
            str(result_path),
            "--plan",
            str(lifecycle_plan_path),
            "--approval",
            str(approval_path),
        ]
    ) == 0
    rolled_back = json.loads(capsys.readouterr().out)
    assert rolled_back["outcome"] == "APPLIED"
    assert HiveWorkspace.open(vault).status()["documents"] == 0

    assert main(
        [
            "adapter-rollback",
            "--vault",
            str(vault),
            "--result",
            str(result_path),
            "--plan",
            str(lifecycle_plan_path),
            "--approval",
            str(approval_path),
        ]
    ) == 3
    assert json.loads(capsys.readouterr().out)["reason_code"] == "REPLAY_MESSAGE_ID"


def test_adapter_plan_command_does_not_capture(tmp_path: Path, capsys) -> None:
    source = tmp_path / "source.txt"
    source.write_text("plan only", encoding="utf-8")
    code = main(
        [
            "adapter-plan",
            "--vault",
            str(tmp_path / "hive"),
            "--adapter",
            "nukotech.hive.local-capture",
            "--capability",
            "capture.file",
            "--input",
            str(source),
        ]
    )
    assert code == 0
    assert not (tmp_path / "hive" / "sources").exists()
    assert json.loads(capsys.readouterr().out)["schema_version"] == (
        "hive.adapter-plan.v1"
    )


def test_adapter_plan_and_invoke_use_exact_envelope_files(
    tmp_path: Path, capsys
) -> None:
    vault = tmp_path / "hive"
    assert main(["init", "--vault", str(vault)]) == 0
    capsys.readouterr()
    source = tmp_path / "evidence.md"
    payload = b"# Evidence\n\nfile envelope evidence\n"
    source.write_bytes(payload)
    request_path = tmp_path / "request.json"
    plan_path = tmp_path / "plan.json"
    assert (
        main(
            [
                "adapter-plan",
                "--vault",
                str(vault),
                "--adapter",
                "nukotech.hive.local-capture",
                "--capability",
                "capture.file",
                "--input",
                str(source),
                "--request-output",
                str(request_path),
                "--output",
                str(plan_path),
            ]
        )
        == 0
    )
    planned = json.loads(capsys.readouterr().out)
    assert planned["schema_version"] == "hive.adapter-plan.v1"
    assert planned["payload"]["sha256"]
    assert HiveWorkspace.open(vault).status()["documents"] == 0

    result_path = tmp_path / "result.json"
    assert (
        main(
            [
                "adapter-invoke",
                "--vault",
                str(vault),
                "--request",
                str(request_path),
                "--plan",
                str(plan_path),
                "--output",
                str(result_path),
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["outcome"] == "APPLIED"
    imported = vault / result["evidence_refs"][0]["imported_relative_path"]
    assert imported.read_bytes() == payload
    assert json.loads(result_path.read_text(encoding="utf-8")) == result


def test_adapter_list_and_product_status_omit_credential_references(
    tmp_path: Path, capsys
) -> None:
    vault = tmp_path / "hive"
    assert main(["init", "--vault", str(vault)]) == 0
    capsys.readouterr()
    assert main(["adapter-list", "--vault", str(vault)]) == 0
    output = capsys.readouterr().out
    document = json.loads(output)
    assert [item["adapter_id"] for item in document["adapters"]] == [
        "nukotech.hive.bounded-research",
        "nukotech.hive.local-capture",
    ]
    assert {item["credential_state"] for item in document["adapters"]} == {
        "NOT_REQUIRED"
    }
    assert "credential_references" not in output
    status = HiveWorkspace.open(vault).status()
    assert len(status["agent_operations"]["adapters"]) == 2


def test_adapter_status_does_not_add_untracked_runtime_or_key_state(
    tmp_path: Path, capsys
) -> None:
    vault = tmp_path / "hive"
    workspace = HiveWorkspace.create(vault)
    workspace.snapshot("before adapter status")

    def pending() -> list[str]:
        completed = subprocess.run(
            ["git", "-C", str(vault), "status", "--short", "--untracked-files=all"],
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout.splitlines()

    before = pending()
    assert main(["adapter-list", "--vault", str(vault)]) == 0
    capsys.readouterr()
    assert pending() == before


def test_attended_m31_capture_research_and_portable_cli_flow(
    tmp_path: Path, capsys
) -> None:
    vault = tmp_path / "hive"
    assert main(["init", "--vault", str(vault)]) == 0
    capsys.readouterr()
    source = tmp_path / "launch.md"
    source.write_text("The launch color is amber.\n", encoding="utf-8")
    request = tmp_path / "capture-request.json"
    plan = tmp_path / "capture-plan.json"
    assert main(
        [
            "capture-plan",
            "--vault",
            str(vault),
            "--channel",
            "markdown",
            "--source",
            str(source),
            "--title",
            "Launch evidence",
            "--request-output",
            str(request),
            "--plan-output",
            str(plan),
        ]
    ) == 0
    planned = json.loads(capsys.readouterr().out)
    assert planned["outcome"] == "PLANNED"
    assert not list((vault / "sources").glob("source-*"))

    capture_result = tmp_path / "capture-result.json"
    assert main(
        [
            "capture-admit",
            "--vault",
            str(vault),
            "--request",
            str(request),
            "--plan",
            str(plan),
            "--output",
            str(capture_result),
        ]
    ) == 0
    admitted = json.loads(capsys.readouterr().out)
    source_id = admitted["evidence_refs"][0]["source_id"]

    assert main(
        [
            "research-workspace-create",
            "--vault",
            str(vault),
            "--workspace-id",
            "research:alpha",
            "--name",
            "Alpha Research",
        ]
    ) == 0
    capsys.readouterr()
    assert main(
        [
            "research-source-add",
            "--vault",
            str(vault),
            "--workspace-id",
            "research:alpha",
            "--source-id",
            source_id,
            "--expected-digest",
            "NONE",
        ]
    ) == 0
    version = json.loads(capsys.readouterr().out)
    source_set_digest = version["source_set_digest"]

    search_result = tmp_path / "search-result.json"
    assert main(
        [
            "research-search",
            "--vault",
            str(vault),
            "--workspace-id",
            "research:alpha",
            "--source-set-digest",
            source_set_digest,
            "--query",
            "launch color",
            "--output",
            str(search_result),
        ]
    ) == 0
    searched = json.loads(capsys.readouterr().out)
    assert searched["research_status"] == "SEARCH_COMPLETE"

    ask_result = tmp_path / "ask-result.json"
    assert main(
        [
            "research-ask",
            "--vault",
            str(vault),
            "--workspace-id",
            "research:alpha",
            "--source-set-digest",
            source_set_digest,
            "--question",
            "launch color",
            "--output",
            str(ask_result),
        ]
    ) == 0
    asked = json.loads(capsys.readouterr().out)
    assert asked["research_status"] == "RETRIEVAL_ONLY"
    assert "No local model" in asked["message"]
    assert "download" not in asked["message"].lower()

    artifact_result = tmp_path / "artifact-result.json"
    assert main(
        [
            "research-artifact",
            "--vault",
            str(vault),
            "--workspace-id",
            "research:alpha",
            "--source-set-digest",
            source_set_digest,
            "--artifact-type",
            "SOURCE_SUMMARY",
            "--title",
            "Launch evidence",
            "--research-result",
            str(ask_result),
            "--output",
            str(artifact_result),
        ]
    ) == 0
    artifact = json.loads(capsys.readouterr().out)
    assert artifact["research_status"] == "RETRIEVAL_ONLY"

    bundle = tmp_path / "research.tar.gz"
    export_plan = tmp_path / "research-export-plan.json"
    assert main(
        [
            "research-export",
            "--vault",
            str(vault),
            "--workspace-id",
            "research:alpha",
            "--source-set-digest",
            source_set_digest,
            "--bundle",
            str(bundle),
            "--plan-output",
            str(export_plan),
        ]
    ) == 0
    assert json.loads(capsys.readouterr().out)["outcome"] == "APPLIED"
    assert export_plan.is_file() and bundle.is_file()

    reopened = tmp_path / "reopened"
    assert main(
        [
            "research-reopen",
            "--bundle",
            str(bundle),
            "--target",
            str(reopened),
        ]
    ) == 0
    assert json.loads(capsys.readouterr().out)["source_set_digest"] == (
        source_set_digest
    )


def test_m31_cli_refuses_secret_echo_stale_write_and_replay(
    tmp_path: Path, capsys
) -> None:
    vault = tmp_path / "hive"
    assert main(["init", "--vault", str(vault)]) == 0
    capsys.readouterr()
    secret = "AKIA" + "A" * 16
    source = tmp_path / "secret.md"
    source.write_text(f"credential {secret}\n", encoding="utf-8")
    request = tmp_path / "secret-request.json"
    plan = tmp_path / "secret-plan.json"
    assert main(
        [
            "capture-plan",
            "--vault",
            str(vault),
            "--channel",
            "markdown",
            "--source",
            str(source),
            "--request-output",
            str(request),
            "--plan-output",
            str(plan),
        ]
    ) != 0
    refusal = capsys.readouterr().out
    assert secret not in refusal
    assert not request.exists() and not plan.exists()

    safe = tmp_path / "safe.md"
    safe.write_text("safe evidence\n", encoding="utf-8")
    assert main(
        [
            "capture-plan",
            "--vault",
            str(vault),
            "--channel",
            "markdown",
            "--source",
            str(safe),
            "--request-output",
            str(request),
            "--plan-output",
            str(plan),
        ]
    ) == 0
    capsys.readouterr()
    assert main(
        [
            "capture-admit",
            "--vault",
            str(vault),
            "--request",
            str(request),
            "--plan",
            str(plan),
        ]
    ) == 0
    capsys.readouterr()
    assert main(
        [
            "capture-admit",
            "--vault",
            str(vault),
            "--request",
            str(request),
            "--plan",
            str(plan),
        ]
    ) == 3
    assert json.loads(capsys.readouterr().out)["reason_code"] == "REPLAY_MESSAGE_ID"

    assert main(
        [
            "research-workspace-create",
            "--vault",
            str(vault),
            "--workspace-id",
            "research:alpha",
            "--name",
            "Alpha",
        ]
    ) == 0
    capsys.readouterr()
    source_id = next(
        json.loads(path.read_text())["source_id"]
        for path in (vault / ".hive" / "provenance").glob("source-*.json")
    )
    assert main(
        [
            "research-source-add",
            "--vault",
            str(vault),
            "--workspace-id",
            "research:alpha",
            "--source-id",
            source_id,
            "--expected-digest",
            "NONE",
        ]
    ) == 0
    capsys.readouterr()
    assert main(
        [
            "research-source-add",
            "--vault",
            str(vault),
            "--workspace-id",
            "research:alpha",
            "--source-id",
            source_id,
            "--expected-digest",
            "NONE",
        ]
    ) != 0
    assert json.loads(capsys.readouterr().out)["reason_code"] == (
        "RESEARCH_SOURCE_SET_STALE"
    )
