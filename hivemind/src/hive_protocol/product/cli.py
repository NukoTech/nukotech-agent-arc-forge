"""One cohesive command-line entrypoint for NukoTech Hive Local Alpha."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import webbrowser
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Sequence
from uuid import uuid4

from hive_protocol.adapters.models import AdapterRequest
from hive_protocol.core import ProtocolError, sign_document
from hive_protocol.storage import atomic_write_json, read_json

from .demo import run_demo
from .scope import TENANT_ID
from .server import make_server
from .workspace import ALPHA_VERSION, HiveWorkspace


def _emit(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")), flush=True)


def _write_launch_handoff(descriptor: int, launch_url: str) -> None:
    if isinstance(descriptor, bool) or descriptor < 3:
        raise ProtocolError(
            "WEB_LAUNCH_HANDOFF_INVALID",
            "browser launch handoff requires an inherited pipe descriptor",
        )
    try:
        metadata = os.fstat(descriptor)
    except OSError as exc:
        raise ProtocolError(
            "WEB_LAUNCH_HANDOFF_INVALID",
            "browser launch handoff descriptor is unavailable",
        ) from exc
    if not stat.S_ISFIFO(metadata.st_mode):
        raise ProtocolError(
            "WEB_LAUNCH_HANDOFF_INVALID",
            "browser launch handoff descriptor is not a pipe",
        )
    payload = f"{launch_url}\n".encode("utf-8")
    try:
        while payload:
            written = os.write(descriptor, payload)
            if written < 1:
                raise OSError("browser launch handoff write made no progress")
            payload = payload[written:]
    except OSError as exc:
        raise ProtocolError(
            "WEB_LAUNCH_HANDOFF_INVALID",
            "browser launch handoff could not be delivered",
        ) from exc
    finally:
        os.close(descriptor)


def _add_workflow_commands(commands: Any) -> None:
    def add(name: str, help_text: str) -> argparse.ArgumentParser:
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--vault", type=Path, required=True)
        return command

    preview = add(
        "workflow-definition-preview", "validate one signed immutable workflow preview"
    )
    preview.add_argument("--definition", type=Path, required=True)
    publish = add(
        "workflow-definition-publish", "publish one immutable workflow version"
    )
    publish.add_argument("--definition", type=Path, required=True)
    publish.add_argument("--idempotency-key", required=True)
    listed = add("workflow-definition-list", "list immutable workflow versions")
    listed.add_argument("--workflow-id", required=True)
    diff = add("workflow-definition-diff", "diff two immutable workflow versions")
    diff.add_argument("--workflow-id", required=True)
    diff.add_argument("--from-version", type=int, required=True)
    diff.add_argument("--to-version", type=int, required=True)

    for name, help_text in (
        ("workflow-run-launch", "launch one attended workflow run"),
        ("workflow-readiness", "compute one read-only step readiness projection"),
        ("workflow-conflicts", "show read-only step conflict warnings"),
        ("workflow-approval-preview", "create one exact protected-action preview"),
        ("workflow-approval-approve", "approve one exact attended preview"),
        ("workflow-claim", "record one deterministic signed step claim"),
        ("workflow-deliver", "deliver one claim-bound signed task envelope"),
        ("workflow-session-start", "start one signed attended agent session"),
        ("workflow-session-heartbeat", "record one signed session heartbeat"),
        ("workflow-session-progress", "record bounded signed session progress"),
        ("workflow-session-fail", "record an immutable failed attempt"),
        ("workflow-session-complete", "record an immutable completed attempt"),
        ("workflow-stale-preview", "preview stale-session abandonment without mutation"),
        ("workflow-stale-apply", "apply one exactly approved stale claim release"),
        ("workflow-retry", "create one attended immutable retry attempt"),
        ("workflow-compensation-preview", "preview one declared compensation"),
        ("workflow-compensation-authorize", "authorize one declared compensation"),
        ("workflow-rollback-preview", "preview one exact Git checkpoint rollback"),
        ("workflow-rollback-apply", "apply one exactly approved Git rollback"),
        ("workflow-run-cancel", "record one attended run cancellation"),
    ):
        command = add(name, help_text)
        command.add_argument(
            "--request", type=Path, required=True, help="closed JSON request object"
        )

    for name, help_text in (
        ("workflow-run-status", "show replayed workflow run status"),
        ("workflow-replay", "replay signed workflow history without mutation"),
    ):
        command = add(name, help_text)
        command.add_argument("--run-id", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hive-local",
        description=f"NukoTech Hive Local Alpha v{ALPHA_VERSION}: portable local memory and governed agents",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {ALPHA_VERSION}")
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="create or open a local-only Hive")
    init.add_argument("--vault", type=Path, required=True)

    persona = commands.add_parser(
        "persona", help="manage the local lab persona assignment"
    )
    persona_commands = persona.add_subparsers(dest="persona_command", required=True)
    assign = persona_commands.add_parser(
        "assign",
        help="assign a persona in the local lab context without changing the bundled sample",
    )
    assign.add_argument("name", help="persona name to assign")
    assign.add_argument(
        "--force",
        action="store_true",
        help="replace an already-assigned local persona",
    )
    assign.add_argument(
        "--context",
        type=Path,
        help="local context file (default: $HIVE_LAB_CONTEXT or ~/.config/nukotech-hive-local/lab-context.json)",
    )

    for name, help_text in (
        ("status", "show health, privacy, provider, vault, Git, agents, tasks, and receipts"),
        ("graph", "show typed graph relationships and backlinks"),
        ("agents", "list registered personas and agents"),
        ("tasks", "list governed tasks and receipts"),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--vault", type=Path, required=True)

    imported = commands.add_parser("import", help="copy Markdown/text without mutating source bytes")
    imported.add_argument("--vault", type=Path, required=True)
    imported.add_argument("--source", type=Path, required=True)

    configure = commands.add_parser("configure", help="select auto, Ollama, or retrieval-only mode")
    configure.add_argument("--vault", type=Path, required=True)
    configure.add_argument("--provider", choices=("auto", "ollama", "retrieval-only"), required=True)
    configure.add_argument("--model")

    search = commands.add_parser("search", help="guaranteed exact-text local retrieval")
    search.add_argument("--vault", type=Path, required=True)
    search.add_argument("--query", required=True)

    ask = commands.add_parser("ask", help="grounded local answer or labeled retrieval-only result")
    ask.add_argument("--vault", type=Path, required=True)
    ask.add_argument("--question", required=True)

    for name, help_text in (
        ("agent-authorize", "authorize one attended, expiring agent capability grant"),
        ("agent-register", "register one governed local agent from an authorized grant"),
    ):
        agent = commands.add_parser(name, help=help_text)
        agent.add_argument("--vault", type=Path, required=True)
        agent.add_argument("--persona", required=True)
        agent.add_argument("--agent-id", required=True)
        agent.add_argument("--capability", action="append", required=True)

    task = commands.add_parser("task-submit", help="submit one capability-checked local task")
    task.add_argument("--vault", type=Path, required=True)
    task.add_argument("--agent-id", required=True)
    task.add_argument("--recipient", required=True)
    task.add_argument("--capability", required=True)
    task.add_argument("--kind", required=True)
    task.add_argument("--payload", default="{}", help="JSON object")

    snapshot = commands.add_parser("snapshot", help="create a Git-backed local checkpoint")
    snapshot.add_argument("--vault", type=Path, required=True)
    snapshot.add_argument("--message", default="hive snapshot")

    rollback = commands.add_parser("rollback", help="restore portable Hive files to an ancestor checkpoint")
    rollback.add_argument("--vault", type=Path, required=True)
    rollback.add_argument("--commit", required=True)
    rollback.add_argument(
        "--allow-unsigned",
        action="store_true",
        help="allow rollback to a legacy Git ancestor that has no signed snapshot checkpoint",
    )

    export = commands.add_parser("export", help="create a portable Markdown/assets bundle")
    export.add_argument("--vault", type=Path, required=True)
    export.add_argument("--output", type=Path, required=True)

    reopen = commands.add_parser("reopen", help="verify and reopen a portable export")
    reopen.add_argument("--bundle", type=Path, required=True)
    reopen.add_argument("--target", type=Path, required=True)
    reopen.add_argument(
        "--require-signature",
        action="store_true",
        help="fail closed unless the export carries a trusted Ed25519 signature",
    )
    reopen.add_argument(
        "--trusted-key",
        type=Path,
        action="append",
        default=[],
        help="PEM public key trusted to sign portable exports (repeatable)",
    )

    inspect = commands.add_parser("inspect", help="inspect a portable export and its signature")
    inspect.add_argument("--bundle", type=Path, required=True)
    inspect.add_argument(
        "--require-signature",
        action="store_true",
        help="fail closed unless the export carries a trusted Ed25519 signature",
    )
    inspect.add_argument(
        "--trusted-key",
        type=Path,
        action="append",
        default=[],
        help="PEM public key trusted to sign portable exports (repeatable)",
    )

    serve = commands.add_parser("serve", help="run the loopback-only local product surface")
    serve.add_argument("--vault", type=Path, required=True)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8787)

    app = commands.add_parser(
        "app", help="run the attended foreground operator application"
    )
    app.add_argument("--vault", type=Path, required=True)
    app.add_argument("--host", default="127.0.0.1")
    app.add_argument("--port", type=int, default=8787)
    app.add_argument(
        "--open",
        action="store_true",
        help="open the private one-time browser launch handoff",
    )
    app.add_argument("--launch-handoff-fd", type=int, help=argparse.SUPPRESS)

    demo = commands.add_parser("demo", help="prove the complete disposable-vault vertical slice")
    demo.add_argument("--work-root", type=Path, required=True)

    adapter_list = commands.add_parser(
        "adapter-list", help="list attended application adapters without secret material"
    )
    adapter_list.add_argument("--vault", type=Path, required=True)

    adapter_health = commands.add_parser(
        "adapter-health", help="show bounded health for attended application adapters"
    )
    adapter_health.add_argument("--vault", type=Path, required=True)
    adapter_health.add_argument("--adapter")

    adapter_plan = commands.add_parser(
        "adapter-plan", help="validate a signed request and write a signed dry plan"
    )
    adapter_plan.add_argument("--vault", type=Path, required=True)
    adapter_plan.add_argument("--request", type=Path)
    adapter_plan.add_argument("--adapter")
    adapter_plan.add_argument("--capability")
    adapter_plan.add_argument("--input")
    adapter_plan.add_argument("--title", default="Attended Capture")
    adapter_plan.add_argument("--limit", type=int, default=5)
    adapter_plan.add_argument("--request-output", type=Path)
    adapter_plan.add_argument("--output", type=Path)

    adapter_invoke = commands.add_parser(
        "adapter-invoke", help="invoke exact signed request and plan envelope files"
    )
    adapter_invoke.add_argument("--vault", type=Path, required=True)
    adapter_invoke.add_argument("--request", type=Path, required=True)
    adapter_invoke.add_argument("--plan", type=Path, required=True)
    adapter_invoke.add_argument("--approval", type=Path)
    adapter_invoke.add_argument("--output", type=Path)

    lifecycle_plan = commands.add_parser(
        "adapter-lifecycle-plan",
        help="create a signed dry plan for export, rollback, or uninstall",
    )
    lifecycle_plan.add_argument("--vault", type=Path, required=True)
    lifecycle_plan.add_argument("--adapter", required=True)
    lifecycle_plan.add_argument(
        "--operation", choices=("export", "rollback", "uninstall"), required=True
    )
    lifecycle_plan.add_argument("--input", type=Path, required=True)
    lifecycle_plan.add_argument("--output", type=Path)

    adapter_approve = commands.add_parser(
        "adapter-approve",
        help="attended approval of one exact stored lifecycle plan",
    )
    adapter_approve.add_argument("--vault", type=Path, required=True)
    adapter_approve.add_argument("--plan", type=Path, required=True)
    adapter_approve.add_argument("--output", type=Path)

    adapter_export = commands.add_parser(
        "adapter-export", help="run a signed, scope-bound adapter export"
    )
    adapter_export.add_argument("--vault", type=Path, required=True)
    adapter_export.add_argument("--adapter", required=True)
    adapter_export.add_argument("--scope", type=Path, required=True)
    adapter_export.add_argument("--plan", type=Path, required=True)
    adapter_export.add_argument("--output", type=Path)

    adapter_rollback = commands.add_parser(
        "adapter-rollback", help="run an approval-bound adapter rollback"
    )
    adapter_rollback.add_argument("--vault", type=Path, required=True)
    adapter_rollback.add_argument("--result", type=Path, required=True)
    adapter_rollback.add_argument("--plan", type=Path, required=True)
    adapter_rollback.add_argument("--approval", type=Path, required=True)
    adapter_rollback.add_argument("--output", type=Path)

    adapter_uninstall = commands.add_parser(
        "adapter-uninstall", help="remove only manifest-owned adapter paths"
    )
    adapter_uninstall.add_argument("--vault", type=Path, required=True)
    adapter_uninstall.add_argument("--adapter", required=True)
    adapter_uninstall.add_argument(
        "--ownership-manifest", type=Path, required=True
    )
    adapter_uninstall.add_argument("--plan", type=Path, required=True)
    adapter_uninstall.add_argument("--approval", type=Path, required=True)
    adapter_uninstall.add_argument("--output", type=Path)

    capture_plan = commands.add_parser(
        "capture-plan",
        help="create explicit signed request and dry plan files for one local handoff",
    )
    capture_plan.add_argument("--vault", type=Path, required=True)
    capture_plan.add_argument(
        "--channel",
        choices=(
            "markdown",
            "clipboard",
            "file",
            "webpage-snapshot",
            "browser-handoff",
            "pdf",
            "image",
            "audio",
            "video",
            "meeting-recording",
            "transcript",
            "folder-handoff",
        ),
        required=True,
    )
    capture_plan.add_argument("--source", type=Path, required=True)
    capture_plan.add_argument("--title", default="Attended Capture")
    capture_plan.add_argument("--media-type")
    capture_plan.add_argument("--request-output", type=Path, required=True)
    capture_plan.add_argument("--plan-output", type=Path, required=True)

    capture_admit = commands.add_parser(
        "capture-admit", help="apply one exact signed capture request and plan"
    )
    capture_admit.add_argument("--vault", type=Path, required=True)
    capture_admit.add_argument("--request", type=Path, required=True)
    capture_admit.add_argument("--plan", type=Path, required=True)
    capture_admit.add_argument("--output", type=Path)

    loadout_plan = commands.add_parser("loadout-plan", help="prepare one signed targeted declarative loadout change")
    loadout_plan.add_argument("--vault", type=Path, required=True)
    loadout_plan.add_argument("--operation", choices=("admit", "revoke", "rollback", "uninstall"), required=True)
    loadout_plan.add_argument("--loadout-id", required=True)
    loadout_plan.add_argument("--authorization-ref", required=True)
    loadout_plan.add_argument("--source", type=Path, help="JSON mapping the five exact Arc artifact paths")
    loadout_plan.add_argument("--adapter-references", type=Path, help="JSON array of exact registered adapter pins")
    loadout_plan.add_argument("--version-digest")
    loadout_plan.add_argument("--reason", default="attended operator request")
    loadout_plan.add_argument("--output", type=Path, required=True)
    loadout_approve = commands.add_parser("loadout-approve", help="approve one exact signed loadout plan")
    loadout_approve.add_argument("--vault", type=Path, required=True)
    loadout_approve.add_argument("--plan", type=Path, required=True)
    loadout_approve.add_argument("--output", type=Path, required=True)
    loadout_apply = commands.add_parser("loadout-apply", help="apply one exact approved loadout change")
    loadout_apply.add_argument("--vault", type=Path, required=True)
    loadout_apply.add_argument("--plan", type=Path, required=True)
    loadout_apply.add_argument("--approval", type=Path, required=True)
    loadout_apply.add_argument("--source", type=Path, help="same five exact Arc artifact paths for admission")
    loadout_apply.add_argument("--output", type=Path)
    loadout_status = commands.add_parser("loadout-status", help="show admitted loadouts and integrity status")
    loadout_status.add_argument("--vault", type=Path, required=True)
    loadout_read = commands.add_parser("loadout-read", help="read the exact active declarative loadout components")
    loadout_read.add_argument("--vault", type=Path, required=True)
    loadout_read.add_argument("--loadout-id", required=True)
    loadout_context = commands.add_parser("loadout-context", help="read a pinned declarative context handoff")
    loadout_context.add_argument("--vault", type=Path, required=True)
    loadout_context.add_argument("--loadout-id", required=True)
    loadout_context.add_argument("--output", type=Path)
    loadout_verify = commands.add_parser("loadout-context-verify", help="revalidate exact context against current admission")
    loadout_verify.add_argument("--vault", type=Path, required=True)
    loadout_verify.add_argument("--context", type=Path, required=True)
    loadout_verify.add_argument("--output", type=Path)

    research_create = commands.add_parser(
        "research-workspace-create",
        help="create one immutable attended bounded-research workspace",
    )
    research_create.add_argument("--vault", type=Path, required=True)
    research_create.add_argument("--workspace-id", required=True)
    research_create.add_argument("--name", required=True)
    research_create.add_argument(
        "--privacy-class", default="PROJECT_PRIVATE", choices=("PROJECT_PRIVATE",)
    )

    for command_name, help_text in (
        ("research-source-add", "append one captured source to an exact source-set head"),
        ("research-source-remove", "remove one source from an exact source-set head"),
    ):
        source_command = commands.add_parser(command_name, help=help_text)
        source_command.add_argument("--vault", type=Path, required=True)
        source_command.add_argument("--workspace-id", required=True)
        source_command.add_argument("--source-id", required=True)
        source_command.add_argument("--expected-digest", required=True)
        source_command.add_argument("--max-results", type=int, default=10)
        source_command.add_argument("--max-quote-bytes", type=int, default=2048)
        source_command.add_argument("--semantic", action="store_true")

    research_search = commands.add_parser(
        "research-search", help="search one exact immutable source set"
    )
    research_search.add_argument("--vault", type=Path, required=True)
    research_search.add_argument("--workspace-id", required=True)
    research_search.add_argument("--source-set-digest", required=True)
    research_search.add_argument("--query", required=True)
    research_search.add_argument("--limit", type=int, default=5)
    research_search.add_argument("--request-output", type=Path)
    research_search.add_argument("--plan-output", type=Path)
    research_search.add_argument("--output", type=Path)

    research_ask = commands.add_parser(
        "research-ask", help="ask one exact immutable source set"
    )
    research_ask.add_argument("--vault", type=Path, required=True)
    research_ask.add_argument("--workspace-id", required=True)
    research_ask.add_argument("--source-set-digest", required=True)
    research_ask.add_argument("--question", required=True)
    research_ask.add_argument("--limit", type=int, default=5)
    research_ask.add_argument("--request-output", type=Path)
    research_ask.add_argument("--plan-output", type=Path)
    research_ask.add_argument("--output", type=Path)

    research_artifact = commands.add_parser(
        "research-artifact", help="persist one verified cited artifact"
    )
    research_artifact.add_argument("--vault", type=Path, required=True)
    research_artifact.add_argument("--workspace-id", required=True)
    research_artifact.add_argument("--source-set-digest", required=True)
    research_artifact.add_argument(
        "--artifact-type",
        choices=(
            "CITED_ANSWER",
            "SOURCE_SUMMARY",
            "COMPARISON",
            "TIMELINE",
            "BRIEF",
            "QUESTIONS",
            "OUTLINE",
            "STUDY_GUIDE",
            "ACTION_ITEMS",
        ),
        required=True,
    )
    research_artifact.add_argument("--title", required=True)
    research_artifact.add_argument("--research-result", type=Path, required=True)
    research_artifact.add_argument("--request-output", type=Path)
    research_artifact.add_argument("--plan-output", type=Path)
    research_artifact.add_argument("--output", type=Path)

    research_export = commands.add_parser(
        "research-export", help="export one exact source-set-bound portable bundle"
    )
    research_export.add_argument("--vault", type=Path, required=True)
    research_export.add_argument("--workspace-id", required=True)
    research_export.add_argument("--source-set-digest", required=True)
    research_export.add_argument("--bundle", type=Path, required=True)
    research_export.add_argument("--plan-output", type=Path, required=True)
    research_export.add_argument("--output", type=Path)

    research_reopen = commands.add_parser(
        "research-reopen", help="verify and reopen one bounded research bundle"
    )
    research_reopen.add_argument("--bundle", type=Path, required=True)
    research_reopen.add_argument("--target", type=Path, required=True)

    for command_name, help_text in (
        ("memory-propose-event", "extract and stage candidates from one typed local event"),
        ("memory-correct", "stage an explicitly typed correction event"),
        ("memory-revoke", "stage an explicitly typed revocation event"),
    ):
        memory_propose = commands.add_parser(command_name, help=help_text)
        memory_propose.add_argument("--vault", type=Path, required=True)
        memory_propose.add_argument("--event", type=Path, required=True)

    memory_candidates = commands.add_parser(
        "memory-candidates", help="list immutable candidates and attended decisions"
    )
    memory_candidates.add_argument("--vault", type=Path, required=True)

    memory_review = commands.add_parser(
        "memory-review", help="record one exact attended candidate decision"
    )
    memory_review.add_argument("--vault", type=Path, required=True)
    memory_review.add_argument("--candidate-id", required=True)
    memory_review.add_argument(
        "--outcome",
        choices=("APPROVED", "REJECTED", "CHANGES_REQUESTED"),
        required=True,
    )
    memory_review.add_argument("--actor-id", required=True)
    memory_review.add_argument("--authorization-ref", required=True)
    memory_review.add_argument("--correction", action="append", default=[])

    memory_promote = commands.add_parser(
        "memory-promote", help="promote one exactly approved candidate into PRIME"
    )
    memory_promote.add_argument("--vault", type=Path, required=True)
    memory_promote.add_argument("--candidate-id", required=True)

    retention_scan = commands.add_parser(
        "memory-retention-scan", help="create review work for expired retention only"
    )
    retention_scan.add_argument("--vault", type=Path, required=True)
    retention_scan.add_argument("--project-id")

    deletion_plan = commands.add_parser(
        "memory-deletion-plan", help="preview exact owned files for one PRIME deletion"
    )
    deletion_plan.add_argument("--vault", type=Path, required=True)
    deletion_plan.add_argument("--node-id", required=True)

    deletion_approve = commands.add_parser(
        "memory-deletion-approve", help="approve one exact deletion plan with typed confirmation"
    )
    deletion_approve.add_argument("--vault", type=Path, required=True)
    deletion_approve.add_argument("--plan-id", required=True)
    deletion_approve.add_argument("--actor-id", required=True)
    deletion_approve.add_argument("--authorization-ref", required=True)
    deletion_approve.add_argument("--confirmation", required=True)
    deletion_approve.add_argument("--output", type=Path, required=True)

    deletion_apply = commands.add_parser(
        "memory-deletion-apply", help="apply one separately approved deletion plan"
    )
    deletion_apply.add_argument("--vault", type=Path, required=True)
    deletion_apply.add_argument("--plan-id", required=True)
    deletion_apply.add_argument("--approval", type=Path, required=True)

    note_preview = commands.add_parser(
        "knowledge-note-preview", help="preview one exact Markdown create or update"
    )
    note_preview.add_argument("--vault", type=Path, required=True)
    note_preview.add_argument("--project-id", required=True)
    note_preview.add_argument("--relative-path", required=True)
    note_preview.add_argument("--content", type=Path, required=True)
    note_preview.add_argument("--expected-sha256")

    note_approve = commands.add_parser(
        "knowledge-note-approve", help="approve one exact Markdown replacement preview"
    )
    note_approve.add_argument("--vault", type=Path, required=True)
    note_approve.add_argument("--preview-id", required=True)
    note_approve.add_argument("--actor-id", required=True)
    note_approve.add_argument("--authorization-ref", required=True)
    note_approve.add_argument("--output", type=Path, required=True)

    note_apply = commands.add_parser(
        "knowledge-note-apply", help="apply one exact previewed Markdown edit"
    )
    note_apply.add_argument("--vault", type=Path, required=True)
    note_apply.add_argument("--preview-id", required=True)
    note_apply.add_argument("--content", type=Path, required=True)
    note_apply.add_argument("--idempotency-key", required=True)
    note_apply.add_argument("--approval", type=Path)

    knowledge_graph = commands.add_parser(
        "knowledge-graph", help="rebuild and filter the portable trusted knowledge graph"
    )
    knowledge_graph.add_argument("--vault", type=Path, required=True)
    knowledge_graph.add_argument("--project-id")
    knowledge_graph.add_argument("--relation")
    knowledge_graph.add_argument("--tag")
    knowledge_graph.add_argument("--trust-state")
    knowledge_graph.add_argument("--lifecycle-state")
    knowledge_graph.add_argument("--node-id")
    knowledge_graph.add_argument("--direction", choices=("inbound", "outbound"))
    _add_workflow_commands(commands)
    return parser


def _agents(workspace: HiveWorkspace) -> list[dict[str, Any]]:
    try:
        from .agent_adapter import list_agents
    except ImportError as exc:
        raise ProtocolError("AGENT_ADAPTER_UNAVAILABLE", "agent operations adapter is absent") from exc
    return list_agents(workspace.root)


def _tasks(workspace: HiveWorkspace) -> list[dict[str, Any]]:
    try:
        from .agent_adapter import list_tasks
    except ImportError as exc:
        raise ProtocolError("AGENT_ADAPTER_UNAVAILABLE", "agent operations adapter is absent") from exc
    return list_tasks(workspace.root)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_optional(path: Path | None, document: dict[str, Any]) -> None:
    if path is None:
        return
    if path.is_symlink():
        raise ProtocolError("CLI_OUTPUT_BOUNDARY", "adapter output may not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(path, document)


def _write_loadout_context_output(vault: Path, path: Path | None, document: dict[str, Any]) -> None:
    if path is None:
        return
    path = path.expanduser().absolute()
    if (any(part.is_symlink() for part in (path, *path.parents)) or
            path.resolve().is_relative_to(vault.expanduser().resolve())):
        raise ProtocolError("CLI_OUTPUT_BOUNDARY", "context output must be outside the Hive with no symlink components")
    _write_optional(path, document)


def _attended_request(args: argparse.Namespace, services: Any) -> dict[str, Any]:
    from hive_protocol.core import public_key_id

    if not args.adapter or not args.capability or args.input is None:
        raise ProtocolError(
            "ADAPTER_REQUEST_REQUIRED",
            "provide --request or attended --adapter, --capability, and --input",
        )
    manifest = services.manifests.get(args.adapter)
    if manifest is None:
        raise ProtocolError("ADAPTER_NOT_REGISTERED", "adapter is not registered")
    capability = args.capability
    if capability == "capture.file":
        source = Path(args.input).expanduser().absolute()
        payload = {"kind": "file", "path": str(source)}
        evidence = [_sha256_file(source)] if source.is_file() and not source.is_symlink() else ["0" * 64]
    elif capability == "capture.text":
        payload = {"kind": "text", "text": args.input, "title": args.title}
        evidence = [hashlib.sha256(args.input.encode("utf-8")).hexdigest()]
    elif capability == "research.search":
        payload = {
            "operation": "search",
            "tenant_id": TENANT_ID,
            "workspace_id": "local-hive",
            "query": args.input,
            "limit": args.limit,
        }
        evidence = [hashlib.sha256(args.input.encode("utf-8")).hexdigest()]
    elif capability == "research.ask":
        payload = {
            "operation": "ask",
            "tenant_id": TENANT_ID,
            "workspace_id": "local-hive",
            "question": args.input,
            "limit": args.limit,
        }
        evidence = [hashlib.sha256(args.input.encode("utf-8")).hexdigest()]
    else:
        raise ProtocolError(
            "ADAPTER_CAPABILITY_DENIED", "unsupported attended adapter capability"
        )
    if capability not in manifest["capability_ids"]:
        raise ProtocolError(
            "ADAPTER_CAPABILITY_DENIED", "capability is not declared by the adapter"
        )
    grant = services.authority.resolve(
        public_key_id(services.request_key.public_key()), args.adapter
    )
    now = datetime.now(timezone.utc)
    request = AdapterRequest(
        request_id=str(uuid4()),
        adapter_id=args.adapter,
        adapter_version=manifest["version"],
        sender=dict(grant.identity),
        project_id=grant.project_id,
        capability_id=capability,
        data_classification="PROJECT_PRIVATE",
        authorization_ref=grant.authorization_ref,
        evidence_sha256=evidence,
        payload=payload,
        nonce=uuid4().hex,
        expires_at=(now + timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
    )
    return sign_document(request.as_dict(), services.request_key)


def _signed_attended_request(
    services: Any,
    *,
    adapter_id: str,
    capability_id: str,
    payload: dict[str, Any],
    evidence: list[str],
) -> dict[str, Any]:
    from hive_protocol.core import public_key_id

    manifest = services.manifests.get(adapter_id)
    if manifest is None or capability_id not in manifest["capability_ids"]:
        raise ProtocolError(
            "ADAPTER_CAPABILITY_DENIED", "capability is not declared by the adapter"
        )
    grant = services.authority.resolve(
        public_key_id(services.request_key.public_key()), adapter_id
    )
    now = datetime.now(timezone.utc)
    request = AdapterRequest(
        request_id=str(uuid4()),
        adapter_id=adapter_id,
        adapter_version=manifest["version"],
        sender=dict(grant.identity),
        project_id=grant.project_id,
        capability_id=capability_id,
        data_classification="PROJECT_PRIVATE",
        authorization_ref=grant.authorization_ref,
        evidence_sha256=evidence,
        payload=payload,
        nonce=uuid4().hex,
        expires_at=(now + timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
    )
    return sign_document(request.as_dict(), services.request_key)


def _exact_external_file(path: Path, vault: Path) -> Path:
    raw = path.expanduser().absolute()
    for candidate in [raw, *raw.parents]:
        if candidate.is_symlink():
            raise ProtocolError(
                "CAPTURE_SOURCE_BOUNDARY", "capture source path contains a symlink"
            )
    resolved = raw.resolve(strict=True)
    vault = vault.expanduser().resolve(strict=False)
    if (
        resolved != raw
        or not resolved.is_file()
        or resolved.stat().st_uid != os.geteuid()
        or resolved == vault
        or vault in resolved.parents
    ):
        raise ProtocolError(
            "CAPTURE_SOURCE_BOUNDARY",
            "capture source must be one owned file outside the Hive",
        )
    return resolved


def _capture_request(args: argparse.Namespace, services: Any) -> dict[str, Any]:
    channel = args.channel
    source = _exact_external_file(args.source, args.vault)
    inline = {
        "markdown": ("capture.markdown", "markdown"),
        "clipboard": ("capture.clipboard", "clipboard"),
    }
    path_channels = {
        "file": ("capture.file", "file", "FILE"),
        "webpage-snapshot": (
            "capture.webpage-snapshot",
            "webpage_snapshot",
            "WEBPAGE_SNAPSHOT",
        ),
        "browser-handoff": (
            "capture.browser-handoff",
            "browser_handoff",
            "BROWSER_HANDOFF",
        ),
        "pdf": ("capture.pdf", "pdf", "PDF"),
        "image": ("capture.image", "image", "IMAGE"),
        "audio": ("capture.audio", "audio", "AUDIO"),
        "video": ("capture.video", "video", "VIDEO"),
        "meeting-recording": (
            "capture.meeting-recording",
            "meeting_recording",
            "MEETING_RECORDING",
        ),
        "transcript": ("capture.transcript", "transcript", "TRANSCRIPT"),
    }
    if channel in inline:
        try:
            text = source.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ProtocolError(
                "CAPTURE_SOURCE_ENCODING", "inline capture source must be UTF-8"
            ) from exc
        capability, kind = inline[channel]
        payload = {"kind": kind, "text": text, "title": args.title}
        evidence = [hashlib.sha256(text.encode("utf-8")).hexdigest()]
    elif channel == "folder-handoff":
        document = read_json(source)
        items = document.get("items")
        if set(document) != {"items"} or not isinstance(items, list):
            raise ProtocolError(
                "CAPTURE_PAYLOAD_INVALID",
                "folder handoff source must contain exactly one items array",
            )
        normalized_items: list[dict[str, str]] = []
        evidence = []
        for item in items:
            if not isinstance(item, dict) or set(item) != {
                "path",
                "channel",
                "media_type",
            }:
                raise ProtocolError(
                    "CAPTURE_PAYLOAD_INVALID", "folder handoff item is invalid"
                )
            item_path = _exact_external_file(Path(item["path"]), args.vault)
            normalized_items.append(
                {
                    "path": str(item_path),
                    "channel": item["channel"],
                    "media_type": item["media_type"],
                }
            )
            evidence.append(_sha256_file(item_path))
        capability = "capture.folder-handoff"
        payload = {"kind": "folder_handoff", "items": normalized_items}
    elif channel in path_channels:
        if not isinstance(args.media_type, str) or not args.media_type:
            raise ProtocolError(
                "CAPTURE_MEDIA_TYPE_REQUIRED",
                "typed capture requires an explicit --media-type",
            )
        capability, kind, typed_channel = path_channels[channel]
        payload = {
            "kind": kind,
            "path": str(source),
            "media_type": args.media_type,
        }
        if channel == "file":
            payload["channel"] = typed_channel
        evidence = [_sha256_file(source)]
    else:  # pragma: no cover - argparse closes the channel set
        raise ProtocolError("CAPTURE_PAYLOAD_INVALID", "capture channel is invalid")
    return _signed_attended_request(
        services,
        adapter_id="nukotech.hive.local-capture",
        capability_id=capability,
        payload=payload,
        evidence=evidence,
    )


def _persist_request_and_plan(
    services: Any,
    request: dict[str, Any],
    plan: dict[str, Any],
    *,
    request_output: Path | None,
    plan_output: Path | None,
) -> None:
    requests_root = services.runtime.root / "requests"
    services.runtime.require_owned_directory(requests_root)
    atomic_write_json(requests_root / f"{request['request_id']}.json", request)
    _write_optional(request_output, request)
    _write_optional(plan_output, plan)


def _research_message(status: str) -> str:
    return {
        "RETRIEVAL_ONLY": (
            "No local model provider was used; returning verified local evidence only."
        ),
        "NO_EVIDENCE": "No evidence in the selected source set matched this request.",
        "MODEL_OUTPUT_REJECTED": (
            "Model output was rejected because it did not remain exactly grounded."
        ),
        "DEGRADED": "The optional local provider was unavailable; no claim was invented.",
        "ANSWERED": "The answer and every factual claim passed exact citation checks.",
        "SEARCH_COMPLETE": "Search completed within the exact selected source set.",
    }.get(status, "The attended research operation completed with a bounded status.")


def _run_research_invocation(
    args: argparse.Namespace,
    *,
    capability: str,
    payload: dict[str, Any],
    evidence: list[str],
) -> tuple[dict[str, Any], int]:
    from .agent_adapter import (
        adapter_invocation_context,
        product_adapter_services,
    )

    services = product_adapter_services(
        args.vault, research_workspace_id=args.workspace_id
    )
    request = _signed_attended_request(
        services,
        adapter_id="nukotech.hive.bounded-research",
        capability_id=capability,
        payload=payload,
        evidence=evidence,
    )
    context = adapter_invocation_context(services, request)
    plan = services.runtime.plan(request, context)
    _persist_request_and_plan(
        services,
        request,
        plan,
        request_output=args.request_output,
        plan_output=args.plan_output,
    )
    result = services.runtime.invoke(request, plan, context, None)
    _write_optional(args.output, result)
    status = str(result.get("detail", {}).get("status", result["outcome"]))
    return {
        "outcome": result["outcome"],
        "research_status": status,
        "message": _research_message(status),
        "result": result,
    }, 0 if result["outcome"] not in {"FAILED", "REFUSED"} else 2


def _expected_digest(value: str) -> str | None:
    return None if value.upper() == "NONE" else value


def _run_m31(args: argparse.Namespace) -> tuple[Any, int]:
    from .agent_adapter import (
        ADAPTER_PROJECT_ID,
        TENANT_ID,
        adapter_invocation_context,
        product_adapter_services,
    )
    from hive_protocol.core import document_digest, public_key_id
    from hive_protocol.research.portable import ResearchPortableService
    from hive_protocol.research.workspace import BoundedResearchWorkspaceStore

    if args.command == "research-reopen":
        reopened = ResearchPortableService.reopen(args.bundle, args.target)
        return {
            "outcome": "REOPENED",
            "workspace_id": reopened.workspace_id,
            "source_set_digest": reopened.source_set_digest,
            "artifact_ids": list(reopened.artifact_ids),
            "bundle_sha256": reopened.bundle_sha256,
        }, 0
    workspace = HiveWorkspace.open(args.vault)
    store = BoundedResearchWorkspaceStore(workspace)
    if args.command == "capture-plan":
        services = product_adapter_services(args.vault)
        request = _capture_request(args, services)
        context = adapter_invocation_context(services, request)
        plan = services.runtime.plan(request, context)
        _persist_request_and_plan(
            services,
            request,
            plan,
            request_output=args.request_output,
            plan_output=args.plan_output,
        )
        return {
            "outcome": "PLANNED",
            "request_id": request["request_id"],
            "plan_id": plan["plan_id"],
            "capability_id": request["capability_id"],
            "requires_approval": plan["requires_approval"],
            "request_output": str(args.request_output),
            "plan_output": str(args.plan_output),
        }, 0
    if args.command == "capture-admit":
        services = product_adapter_services(args.vault)
        request = read_json(args.request)
        plan = read_json(args.plan)
        context = adapter_invocation_context(services, request)
        result = services.runtime.invoke(request, plan, context, None)
        _write_optional(args.output, result)
        return result, 0 if result["outcome"] not in {"FAILED", "REFUSED"} else 2
    if args.command == "research-workspace-create":
        model = store.create_workspace(
            workspace_id=args.workspace_id,
            tenant_id=TENANT_ID,
            project_id=ADAPTER_PROJECT_ID,
            name=args.name,
            privacy_class=args.privacy_class,
        )
        return {"outcome": "WORKSPACE_READY", "workspace": model.as_dict()}, 0
    if args.command in {"research-source-add", "research-source-remove"}:
        current = store.current_source_set(args.workspace_id)
        expected_digest = _expected_digest(args.expected_digest)
        current_digest = (
            current["source_set_digest"] if current is not None else None
        )
        if current_digest != expected_digest:
            raise ProtocolError(
                "RESEARCH_SOURCE_SET_STALE",
                "research source-set head changed",
            )
        current_ids = (
            [item["source_id"] for item in current["source_set"].sources]
            if current is not None
            else []
        )
        if args.command == "research-source-add":
            if args.source_id in current_ids:
                raise ProtocolError(
                    "RESEARCH_SOURCE_ALREADY_PRESENT",
                    "source is already present in the current source set",
                )
            source_ids = [*current_ids, args.source_id]
        else:
            if args.source_id not in current_ids:
                raise ProtocolError(
                    "RESEARCH_SOURCE_ABSENT",
                    "source is not present in the current source set",
                )
            source_ids = [item for item in current_ids if item != args.source_id]
            if not source_ids:
                raise ProtocolError(
                    "RESEARCH_SOURCE_SET_EMPTY",
                    "the final source cannot be removed from an active source set",
                )
        policy = (
            current["source_set"].retrieval_policy
            if current is not None
            else {
                "exact_first": True,
                "semantic_allowed": bool(args.semantic),
                "max_results": args.max_results,
                "max_quote_bytes": args.max_quote_bytes,
            }
        )
        updated = store.update_source_set(
            args.workspace_id,
            expected_parent_digest=expected_digest,
            source_ids=source_ids,
            retrieval_policy=policy,
        )
        return {
            "outcome": "SOURCE_SET_UPDATED",
            "source_set_digest": updated["source_set_digest"],
            "parent_digest": updated["source_set"].parent_digest,
            "source_ids": [
                item["source_id"] for item in updated["source_set"].sources
            ],
        }, 0
    if args.command in {"research-search", "research-ask"}:
        text = args.query if args.command == "research-search" else args.question
        payload = {
            "operation": "search" if args.command == "research-search" else "ask",
            "tenant_id": TENANT_ID,
            "workspace_id": args.workspace_id,
            "source_set_digest": args.source_set_digest,
            "query" if args.command == "research-search" else "question": text,
            "limit": args.limit,
        }
        return _run_research_invocation(
            args,
            capability=(
                "research.search"
                if args.command == "research-search"
                else "research.ask"
            ),
            payload=payload,
            evidence=[
                hashlib.sha256(text.encode("utf-8")).hexdigest(),
                args.source_set_digest,
            ],
        )
    if args.command == "research-artifact":
        source_result = read_json(args.research_result)
        research_result = (
            source_result["detail"]
            if source_result.get("schema_version") == "hive.adapter-result.v1"
            else source_result
        )
        payload = {
            "operation": "artifact",
            "tenant_id": TENANT_ID,
            "workspace_id": args.workspace_id,
            "source_set_digest": args.source_set_digest,
            "artifact_type": args.artifact_type,
            "title": args.title,
            "research_result": research_result,
        }
        return _run_research_invocation(
            args,
            capability="research.artifact",
            payload=payload,
            evidence=[document_digest(research_result), args.source_set_digest],
        )
    if args.command == "research-export":
        services = product_adapter_services(
            args.vault, research_workspace_id=args.workspace_id
        )
        grant = services.authority.resolve(
            public_key_id(services.request_key.public_key()),
            "nukotech.hive.bounded-research",
        )
        scope = {
            "root": str(args.bundle.expanduser().absolute().parent),
            "bundle": str(args.bundle.expanduser().absolute()),
            "workspace_id": args.workspace_id,
            "source_set_digest": args.source_set_digest,
        }
        plan = services.lifecycle.plan(
            "nukotech.hive.bounded-research", "export", scope, grant.project_id
        )
        _write_optional(args.plan_output, plan)
        result = services.lifecycle.export(
            "nukotech.hive.bounded-research", scope, plan
        )
        _write_optional(args.output, result)
        return result, 0 if result["outcome"] not in {"FAILED", "REFUSED"} else 2
    raise ProtocolError("COMMAND_INVALID", f"unsupported command: {args.command}")


def _run_adapter(args: argparse.Namespace) -> tuple[Any, int]:
    from .agent_adapter import (
        adapter_invocation_context,
        adapter_status,
        product_adapter_services,
    )
    from hive_protocol.core import public_key_id

    if args.command in {"adapter-list", "adapter-health"}:
        status = adapter_status(args.vault)
        if args.command == "adapter-health" and args.adapter:
            status = [item for item in status if item["adapter_id"] == args.adapter]
            if not status:
                raise ProtocolError("ADAPTER_NOT_REGISTERED", "adapter is not registered")
        return {"adapters": status}, 0
    services = product_adapter_services(args.vault)
    if args.command == "adapter-plan":
        request = read_json(args.request) if args.request else _attended_request(args, services)
        context = adapter_invocation_context(services, request)
        plan = services.runtime.plan(request, context)
        requests_root = services.runtime.root / "requests"
        services.runtime.require_owned_directory(requests_root)
        atomic_write_json(requests_root / f"{request['request_id']}.json", request)
        _write_optional(args.request_output, request)
        _write_optional(args.output, plan)
        return plan, 0
    if args.command == "adapter-invoke":
        request = read_json(args.request)
        plan = read_json(args.plan)
        approval = read_json(args.approval) if args.approval else None
        context = adapter_invocation_context(services, request)
        result = services.runtime.invoke(request, plan, context, approval)
        _write_optional(args.output, result)
        return result, 0 if result["outcome"] not in {"FAILED", "REFUSED"} else 2
    if args.command == "adapter-lifecycle-plan":
        grant = services.authority.resolve(
            public_key_id(services.request_key.public_key()), args.adapter
        )
        plan = services.lifecycle.plan(
            args.adapter,
            args.operation,
            read_json(args.input),
            grant.project_id,
        )
        _write_optional(args.output, plan)
        return plan, 0
    if args.command == "adapter-approve":
        plan = read_json(args.plan)
        adapter_id = plan.get("adapter_id")
        if not isinstance(adapter_id, str):
            raise ProtocolError(
                "ADAPTER_LIFECYCLE_PLAN_MISMATCH",
                "lifecycle plan lacks its adapter identity",
            )
        grant = services.authority.resolve(
            public_key_id(services.request_key.public_key()), adapter_id
        )
        approval = services.lifecycle.approve(
            plan,
            grant.identity,
            services.approver_key,
        )
        _write_optional(args.output, approval)
        return approval, 0
    if args.command == "adapter-export":
        result = services.lifecycle.export(
            args.adapter, read_json(args.scope), read_json(args.plan)
        )
    elif args.command == "adapter-rollback":
        result = services.lifecycle.rollback(
            read_json(args.result), read_json(args.plan), read_json(args.approval)
        )
    elif args.command == "adapter-uninstall":
        result = services.lifecycle.uninstall(
            args.adapter,
            read_json(args.ownership_manifest),
            read_json(args.plan),
            read_json(args.approval),
        )
    else:
        raise ProtocolError("COMMAND_INVALID", f"unsupported command: {args.command}")
    _write_optional(args.output, result)
    return result, 0 if result["outcome"] not in {"FAILED", "REFUSED"} else 2


def _read_cli_text(path: Path) -> str:
    candidate = path.expanduser().absolute()
    if candidate.is_symlink() or not candidate.is_file():
        raise ProtocolError("CLI_INPUT_INVALID", "input must be one regular non-symlink file")
    try:
        return candidate.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ProtocolError("CLI_INPUT_INVALID", "input must be valid UTF-8") from exc


def _read_cli_json(path: Path) -> dict[str, Any]:
    document = json.loads(_read_cli_text(path))
    if not isinstance(document, dict):
        raise ProtocolError("CLI_INPUT_INVALID", "JSON input must be one object")
    return document


def _workflow_time(request: dict[str, Any], name: str) -> datetime:
    value = request.pop(name, None)
    if not isinstance(value, str):
        raise ProtocolError(
            "WORKFLOW_CLI_TIME_REQUIRED", f"workflow request requires {name}"
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError(
            "WORKFLOW_CLI_TIME_INVALID", f"workflow {name} is invalid"
        ) from exc
    if parsed.tzinfo is None:
        raise ProtocolError(
            "WORKFLOW_CLI_TIME_INVALID", f"workflow {name} requires a timezone"
        )
    return parsed


def _workflow_object(request: dict[str, Any], name: str) -> dict[str, Any]:
    value = request.pop(name, None)
    if not isinstance(value, dict):
        raise ProtocolError(
            "WORKFLOW_CLI_INPUT_INVALID", f"workflow request requires object {name}"
        )
    return value


def _workflow_string(request: dict[str, Any], name: str) -> str:
    value = request.pop(name, None)
    if not isinstance(value, str) or not value:
        raise ProtocolError(
            "WORKFLOW_CLI_INPUT_INVALID", f"workflow request requires string {name}"
        )
    return value


def _run_workflow(args: argparse.Namespace) -> tuple[Any, int]:
    from hive_protocol.product.workflow_adapter import WorkflowProductService

    service = WorkflowProductService(args.vault)
    now = datetime.now(timezone.utc)
    if args.command == "workflow-definition-preview":
        return service.definition_preview(_read_cli_json(args.definition), now=now), 0
    if args.command == "workflow-definition-publish":
        return service.publish_definition(
            _read_cli_json(args.definition),
            idempotency_key=args.idempotency_key,
            now=now,
        ), 0
    if args.command == "workflow-definition-list":
        return service.list_definitions(args.workflow_id), 0
    if args.command == "workflow-definition-diff":
        return service.diff_definitions(
            args.workflow_id, args.from_version, args.to_version
        ), 0
    if args.command in {"workflow-run-status", "workflow-replay"}:
        return service.run_status(args.run_id), 0

    request = _read_cli_json(args.request)
    if args.command == "workflow-run-launch":
        return service.launch_run(
            _workflow_string(request, "workflow_id"),
            int(request.pop("version", 0)),
            run_id=_workflow_string(request, "run_id"),
            source_commit=_workflow_string(request, "source_commit"),
            input_manifest_sha256=_workflow_string(
                request, "input_manifest_sha256"
            ),
            event_id=_workflow_string(request, "event_id"),
            idempotency_key=_workflow_string(request, "idempotency_key"),
            now=_workflow_time(request, "now"),
            stale_after_seconds=int(request.pop("stale_after_seconds", 600)),
            max_concurrent_claims=int(request.pop("max_concurrent_claims", 2)),
        ), 0
    if args.command in {"workflow-readiness", "workflow-conflicts"}:
        run_id = _workflow_string(request, "run_id")
        step_id = _workflow_string(request, "step_id")
        request["now"] = _workflow_time(request, "now")
        operation = service.readiness if args.command.endswith("readiness") else service.conflicts
        return operation(run_id, step_id, **request), 0
    if args.command == "workflow-approval-preview":
        return service.step_approval_preview(
            _workflow_string(request, "run_id"),
            _workflow_object(request, "readiness"),
            action=_workflow_string(request, "action"),
            destination=_workflow_string(request, "destination"),
            expires_at=_workflow_time(request, "expires_at"),
            now=_workflow_time(request, "now"),
        ), 0
    if args.command == "workflow-approval-approve":
        return service.approve(
            _workflow_object(request, "preview"),
            authorization_ref=_workflow_string(request, "authorization_ref"),
            approval_id=_workflow_string(request, "approval_id"),
            idempotency_key=_workflow_string(request, "idempotency_key"),
            now=_workflow_time(request, "now"),
        ), 0
    if args.command == "workflow-claim":
        run_id = _workflow_string(request, "run_id")
        readiness = _workflow_object(request, "readiness")
        approvals = request.pop("approvals", [])
        if not isinstance(approvals, list):
            raise ProtocolError(
                "WORKFLOW_CLI_INPUT_INVALID", "workflow approvals must be a list"
            )
        return service.claim(
            run_id,
            readiness,
            agent_id=_workflow_string(request, "agent_id"),
            expires_at=_workflow_time(request, "expires_at"),
            event_id=_workflow_string(request, "event_id"),
            idempotency_key=_workflow_string(request, "idempotency_key"),
            now=_workflow_time(request, "now"),
            approvals=approvals,
        ), 0
    if args.command == "workflow-deliver":
        return service.deliver_claim(
            _workflow_string(request, "run_id"),
            _workflow_string(request, "claim_event_id"),
            task_id=_workflow_string(request, "task_id"),
            nonce=_workflow_string(request, "nonce"),
            issued_at=_workflow_time(request, "issued_at"),
            expires_at=_workflow_time(request, "expires_at"),
            now=_workflow_time(request, "now"),
        ), 0
    if args.command == "workflow-session-start":
        run_id = _workflow_string(request, "run_id")
        request["recorded_at"] = _workflow_time(request, "recorded_at")
        return service.start_session(run_id, **request), 0
    session_events = {
        "workflow-session-heartbeat": ("SESSION_HEARTBEAT", "ACTIVE"),
        "workflow-session-progress": ("STEP_PROGRESS", "ACTIVE"),
        "workflow-session-fail": ("STEP_FAILED", "FAILED"),
        "workflow-session-complete": ("STEP_COMPLETED", "COMPLETED"),
    }
    if args.command in session_events:
        run_id = _workflow_string(request, "run_id")
        session_id = _workflow_string(request, "session_id")
        event_type, state = session_events[args.command]
        request["event_type"] = event_type
        request["state"] = state
        request["recorded_at"] = _workflow_time(request, "recorded_at")
        return service.record_session(run_id, session_id, **request), 0
    if args.command == "workflow-stale-preview":
        return service.stale_preview(
            _workflow_string(request, "run_id"),
            _workflow_string(request, "session_id"),
            now=_workflow_time(request, "now"),
            expires_at=_workflow_time(request, "expires_at"),
        ), 0
    if args.command == "workflow-stale-apply":
        run_id = _workflow_string(request, "run_id")
        session_id = _workflow_string(request, "session_id")
        request["preview"] = _workflow_object(request, "preview")
        request["approval"] = _workflow_object(request, "approval")
        request["now"] = _workflow_time(request, "now")
        return service.release_stale(run_id, session_id, **request), 0
    if args.command == "workflow-retry":
        run_id = _workflow_string(request, "run_id")
        step_id = _workflow_string(request, "step_id")
        request["recorded_at"] = _workflow_time(request, "recorded_at")
        return service.create_retry(run_id, step_id, **request), 0
    if args.command == "workflow-compensation-preview":
        return service.compensation_preview(
            _workflow_string(request, "run_id"),
            _workflow_string(request, "failed_step_id"),
            failed_attempt=int(request.pop("failed_attempt", 0)),
            now=_workflow_time(request, "now"),
            expires_at=_workflow_time(request, "expires_at"),
        ), 0
    if args.command == "workflow-compensation-authorize":
        run_id = _workflow_string(request, "run_id")
        step_id = _workflow_string(request, "failed_step_id")
        request["preview"] = _workflow_object(request, "preview")
        approval = request.pop("approval", None)
        if approval is not None and not isinstance(approval, dict):
            raise ProtocolError(
                "WORKFLOW_CLI_INPUT_INVALID", "compensation approval must be an object"
            )
        request["approval"] = approval
        request["recorded_at"] = _workflow_time(request, "recorded_at")
        return service.authorize_compensation(run_id, step_id, **request), 0
    if args.command == "workflow-rollback-preview":
        return service.rollback_preview(
            _workflow_string(request, "run_id"),
            _workflow_string(request, "step_id"),
            attempt=int(request.pop("attempt", 0)),
            checkpoint=_workflow_string(request, "checkpoint"),
            now=_workflow_time(request, "now"),
            expires_at=_workflow_time(request, "expires_at"),
        ), 0
    if args.command == "workflow-rollback-apply":
        run_id = _workflow_string(request, "run_id")
        request["preview"] = _workflow_object(request, "preview")
        request["approval"] = _workflow_object(request, "approval")
        request["now"] = _workflow_time(request, "now")
        return service.apply_rollback(run_id, **request), 0
    if args.command == "workflow-run-cancel":
        run_id = _workflow_string(request, "run_id")
        request["now"] = _workflow_time(request, "now")
        request.setdefault("attended_confirmation", True)
        return service.cancel_run(run_id, **request), 0
    raise ProtocolError(
        "COMMAND_INVALID", f"unsupported M3.3 workflow command: {args.command}"
    )


def _run_m32(args: argparse.Namespace) -> tuple[Any, int]:
    from hive_protocol.cognition.authority import CognitionAuthority
    from hive_protocol.cognition.deletion import CognitionDeletionService
    from hive_protocol.cognition.extraction import DeterministicCognitionExtractor
    from hive_protocol.cognition.models import CognitionEvent
    from hive_protocol.cognition.promotion import CognitionPromotionService
    from hive_protocol.cognition.retention import CognitionRetentionService
    from hive_protocol.cognition.store import CognitionStore
    from hive_protocol.knowledge.editor import KnowledgeEditor
    from hive_protocol.knowledge.graph import KnowledgeGraph

    workspace = HiveWorkspace.open(args.vault)
    authority = CognitionAuthority(workspace.root)
    now = datetime.now(timezone.utc)
    store = CognitionStore(workspace.root, authority)

    if args.command in {"memory-propose-event", "memory-correct", "memory-revoke"}:
        event = CognitionEvent.from_dict(_read_cli_json(args.event))
        expected_action = {
            "memory-correct": "CORRECT",
            "memory-revoke": "REVOKE",
        }.get(args.command)
        if expected_action is not None and (
            not event.structured_claims
            or any(
                claim["proposed_action"] != expected_action
                for claim in event.structured_claims
            )
        ):
            raise ProtocolError(
                "COGNITION_ACTION_TARGET_INVALID",
                f"{args.command} requires only explicit {expected_action} claims",
            )
        extraction = DeterministicCognitionExtractor().extract(event, now=now)
        staged = [store.stage(event, candidate) for candidate in extraction.candidates]
        return {
            "outcome": extraction.outcome,
            "event_id": extraction.event_id,
            "candidates": staged,
            "provider_state": extraction.provider_state,
            "warnings": list(extraction.warnings),
        }, 0
    if args.command == "memory-candidates":
        return {"candidates": store.list_candidates()}, 0
    if args.command == "memory-review":
        candidate = store.load_candidate(args.candidate_id)
        decision = authority.create_review(
            candidate,
            outcome=args.outcome,
            actor_id=args.actor_id,
            authorization_ref=args.authorization_ref,
            corrections=list(args.correction),
            now=now,
        )
        return store.record_review(decision, now=now), 0
    if args.command == "memory-promote":
        return CognitionPromotionService(
            workspace.root, store, authority
        ).promote(args.candidate_id, now=now), 0
    if args.command == "memory-retention-scan":
        requests = CognitionRetentionService(workspace.root, authority).scan(
            now=now, project_id=args.project_id
        )
        return {"outcome": "SCANNED", "requests": requests}, 0
    if args.command == "memory-deletion-plan":
        plan = CognitionDeletionService(workspace.root, authority).create_plan(
            args.node_id, now=now
        )
        return plan.as_dict(), 0
    if args.command == "memory-deletion-approve":
        approval = CognitionDeletionService(workspace.root, authority).approve(
            args.plan_id,
            actor_id=args.actor_id,
            authorization_ref=args.authorization_ref,
            confirmation=args.confirmation,
            now=now,
        )
        _write_optional(args.output, approval)
        return approval, 0
    if args.command == "memory-deletion-apply":
        return CognitionDeletionService(workspace.root, authority).apply(
            args.plan_id, _read_cli_json(args.approval), now=now
        ), 0

    editor = KnowledgeEditor(workspace.root, authority)
    if args.command == "knowledge-note-preview":
        return editor.preview(
            project_id=args.project_id,
            relative_path=args.relative_path,
            content=_read_cli_text(args.content),
            expected_sha256=args.expected_sha256,
            now=now,
        ), 0
    if args.command == "knowledge-note-approve":
        approval = editor.approve(
            args.preview_id,
            actor_id=args.actor_id,
            authorization_ref=args.authorization_ref,
            now=now,
        )
        _write_optional(args.output, approval)
        return approval, 0
    if args.command == "knowledge-note-apply":
        approval = _read_cli_json(args.approval) if args.approval else None
        return editor.apply(
            args.preview_id,
            content=_read_cli_text(args.content),
            idempotency_key=args.idempotency_key,
            approval=approval,
            now=now,
        ), 0
    if args.command == "knowledge-graph":
        graph = KnowledgeGraph(workspace.root, authority)
        graph.rebuild()
        if (args.node_id is None) != (args.direction is None):
            raise ProtocolError(
                "KNOWLEDGE_GRAPH_DIRECTION_INVALID",
                "--node-id and --direction must be supplied together",
            )
        if args.node_id is not None:
            return graph.neighbors(args.node_id, direction=args.direction), 0
        if any(
            value is not None
            for value in (
                args.project_id,
                args.relation,
                args.tag,
                args.trust_state,
                args.lifecycle_state,
            )
        ):
            return graph.filter(
                project_id=args.project_id,
                relation=args.relation,
                tag=args.tag,
                trust_state=args.trust_state,
                lifecycle_state=args.lifecycle_state,
            ), 0
        return graph.rebuild(), 0
    raise ProtocolError("COMMAND_INVALID", f"unsupported M3.2 command: {args.command}")


def _run(args: argparse.Namespace) -> tuple[Any, int]:
    if args.command in {
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
    }:
        return _run_m31(args)
    if args.command == "persona":
        from hive_protocol.lab_context import assign_persona

        if args.persona_command != "assign":
            raise ProtocolError("COMMAND_INVALID", f"unsupported command: persona {args.persona_command}")
        return assign_persona(args.name, context_path=args.context, force=args.force), 0
    if args.command == "init":
        workspace = HiveWorkspace.create(args.vault)
        return {"outcome": "READY", "status": workspace.status()}, 0
    if args.command == "reopen":
        from hive_protocol.product.integrity import load_trusted_keys_from_pems

        trusted = load_trusted_keys_from_pems(args.trusted_key) if args.trusted_key else None
        workspace = HiveWorkspace.reopen_export(
            args.bundle,
            args.target,
            trusted_keys=trusted,
            require_signature=args.require_signature,
        )
        return {"outcome": "REOPENED", "status": workspace.status()}, 0
    if args.command == "inspect":
        from hive_protocol.product.integrity import load_trusted_keys_from_pems

        trusted = load_trusted_keys_from_pems(args.trusted_key) if args.trusted_key else None
        inspected = HiveWorkspace.inspect_export(
            args.bundle,
            trusted_keys=trusted,
            require_signature=args.require_signature,
        )
        return {"outcome": "INSPECTED", **inspected}, 0
    if args.command == "demo":
        return run_demo(args.work_root)
    if args.command.startswith("loadout-"):
        from hive_protocol.product.loadout_adapter import (
            apply_loadout, approve_loadout, loadout_status, plan_loadout, read_loadout,
            read_loadout_context, verify_loadout_context,
        )
        if args.command == "loadout-status":
            return {"loadouts": loadout_status(args.vault)}, 0
        if args.command == "loadout-read":
            return {"loadout_id": args.loadout_id, "components": read_loadout(args.vault, args.loadout_id)}, 0
        if args.command == "loadout-context":
            result = read_loadout_context(args.vault, args.loadout_id)
            _write_loadout_context_output(args.vault, args.output, result)
            return result, 0
        if args.command == "loadout-context-verify":
            from hive_protocol.loadouts.artifacts import json_object, read_bounded
            from hive_protocol.loadouts.manager import MAX_CONTEXT_BYTES
            result = verify_loadout_context(args.vault, json_object(read_bounded(args.context, MAX_CONTEXT_BYTES)))
            _write_loadout_context_output(args.vault, args.output, result)
            return result, 0
        if args.command == "loadout-plan":
            references = None
            if args.adapter_references:
                from hive_protocol.loadouts.artifacts import read_bounded
                references = json.loads(read_bounded(args.adapter_references, 128 * 1024))
            result = plan_loadout(args.vault, operation=args.operation, loadout_id=args.loadout_id,
                authorization_ref=args.authorization_ref, source=_read_cli_json(args.source) if args.source else None,
                adapter_references=references, version_digest=args.version_digest, reason=args.reason)
        elif args.command == "loadout-approve":
            result = approve_loadout(args.vault, _read_cli_json(args.plan))
        else:
            result = apply_loadout(args.vault, _read_cli_json(args.plan), _read_cli_json(args.approval),
                source=_read_cli_json(args.source) if args.source else None)
        _write_optional(args.output, result)
        return result, 0
    if args.command.startswith("adapter-"):
        return _run_adapter(args)
    if args.command.startswith(("memory-", "knowledge-note-")) or args.command == "knowledge-graph":
        return _run_m32(args)
    if args.command.startswith("workflow-"):
        return _run_workflow(args)

    workspace = HiveWorkspace.open(args.vault)
    if args.command == "status":
        return workspace.status(), 0
    if args.command == "import":
        return {"outcome": "IMPORTED", "documents": [item.as_dict() for item in workspace.import_content(args.source)]}, 0
    if args.command == "configure":
        return workspace.configure_provider(args.provider, args.model), 0
    if args.command == "search":
        return {"outcome": "SEARCHED", "results": workspace.search_exact(args.query)}, 0
    if args.command == "ask":
        return workspace.ask(args.question), 0
    if args.command == "graph":
        return workspace.graph(), 0
    if args.command == "snapshot":
        return workspace.snapshot(args.message), 0
    if args.command == "rollback":
        return workspace.rollback(args.commit, allow_unsigned=args.allow_unsigned), 0
    if args.command == "export":
        return workspace.export(args.output), 0
    if args.command == "agents":
        return {"agents": _agents(workspace)}, 0
    if args.command == "tasks":
        return {"tasks": _tasks(workspace)}, 0
    if args.command == "agent-authorize":
        from .agent_adapter import authorize_agent_capabilities

        return authorize_agent_capabilities(
            workspace.root, args.persona, args.agent_id, args.capability
        ), 0
    if args.command == "agent-register":
        from .agent_adapter import register_agent

        return register_agent(workspace.root, args.persona, args.agent_id, args.capability), 0
    if args.command == "task-submit":
        from .agent_adapter import submit_task

        payload = json.loads(args.payload)
        if not isinstance(payload, dict):
            raise ProtocolError("TASK_PAYLOAD_INVALID", "task payload must be a JSON object")
        task = {"kind": args.kind, **payload}
        return submit_task(
            workspace.root,
            agent_id=args.agent_id,
            recipient=args.recipient,
            capability=args.capability,
            task=task,
        ), 0
    if args.command in {"serve", "app"}:
        server = make_server(workspace, args.host, args.port)
        address, port = server.server_address[:2]
        display_address = f"[{address}]" if ":" in address else address
        url = f"http://{display_address}:{port}/app"
        launch_url = f"http://{display_address}:{port}{server.launch_path}"
        _emit(
            {
                "outcome": "RUNNING",
                "url": url,
                "access_scope": "loopback-session-and-read-only-bearer-process-lifetime",
                "pid": __import__("os").getpid(),
            }
        )
        if args.command == "app":
            handoff_fd = args.launch_handoff_fd
            if args.open and handoff_fd is not None:
                raise ProtocolError(
                    "WEB_LAUNCH_HANDOFF_INVALID",
                    "browser launch handoff must have exactly one recipient",
                )
            if args.open:
                webbrowser.open(launch_url)
            elif handoff_fd is not None:
                _write_launch_handoff(handoff_fd, launch_url)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return {"outcome": "STOPPED"}, 0
    raise ProtocolError("COMMAND_INVALID", f"unsupported command: {args.command}")


def main(argv: Sequence[str] | None = None) -> int:
    try:
        result, status = _run(_parser().parse_args(argv))
    except ProtocolError as exc:
        _emit({"outcome": "REFUSED", "reason_code": exc.code, "detail": exc.detail})
        return exc.exit_status
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
        _emit(
            {
                "outcome": "REFUSED",
                "reason_code": "RUNTIME_ERROR",
                "detail": "command input or local runtime state is invalid",
            }
        )
        return 2
    _emit(result)
    return status


if __name__ == "__main__":
    sys.exit(main())
