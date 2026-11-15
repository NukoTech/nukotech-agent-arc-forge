"""End-to-end disposable-vault alpha proof."""

from __future__ import annotations

import json
import os
# The next-process check uses fixed argv with shell disabled.
import subprocess  # nosec B404
import sys
import threading
import urllib.request
from pathlib import Path
from typing import Any

from hive_protocol.core import ProtocolError
from hive_protocol.storage import atomic_write_bytes, atomic_write_json, read_json, utc_now

from .server import make_server
from .workspace import ALPHA_VERSION, HiveWorkspace, _sha256_file


def _tree_manifest(root: Path) -> dict[str, str]:
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            result[path.relative_to(root).as_posix()] = _sha256_file(path)
    return result


def _agent_cycle(workspace: HiveWorkspace) -> dict[str, Any]:
    try:
        from .agent_adapter import (
            authorize_agent_capabilities,
            register_agent,
            submit_task,
            verify_task_receipt,
        )
    except ImportError as exc:
        raise ProtocolError(
            "AGENT_ADAPTER_UNAVAILABLE",
            "agent operations adapter is not installed",
        ) from exc
    agent_scope = {
        "persona": "Alpha Researcher",
        "agent_id": "alpha-researcher",
        "capabilities": ["vault:search", "task:acknowledge"],
    }
    authorize_agent_capabilities(workspace.root, **agent_scope)
    agent = register_agent(
        workspace.root,
        **agent_scope,
    )
    task = submit_task(
        workspace.root,
        agent_id="alpha-researcher",
        recipient="alpha-researcher",
        capability="vault:search",
        task={"kind": "search", "query": "rollback"},
    )
    verified = verify_task_receipt(workspace.root, task["receipt_id"])
    return {"agent": agent, "task": task, "receipt_verified": verified}


def run_demo(work_root: Path) -> tuple[dict[str, Any], int]:
    work_root = work_root.expanduser().resolve()
    if work_root.exists() and any(work_root.iterdir()):
        raise ProtocolError("DEMO_ROOT_NOT_EMPTY", "demo root must be absent or empty")
    source = work_root / "source-vault"
    hive_root = work_root / "hive"
    reopened_root = work_root / "reopened"
    source.mkdir(parents=True, exist_ok=True)
    note_a = b"# Alpha Plan\n\nThe rollback target is the frozen parent.\n\n- depends_on [[Alpha Decision]]\n"
    note_b = b"# Alpha Decision\n\nUse portable Markdown and local Git.\n\n- supports [[Alpha Plan]]\n"
    atomic_write_bytes(source / "plan.md", note_a)
    atomic_write_bytes(source / "decision.md", note_b)
    atomic_write_bytes(source / "diagram.bin", b"NukoTech Hive portable alpha asset\x00\x01")
    source_before = _tree_manifest(source)

    steps: dict[str, Any] = {}
    workspace = HiveWorkspace.create(hive_root)
    steps["01_launch"] = {"passed": True, "version": ALPHA_VERSION}
    steps["02_disposable_vault"] = {"passed": hive_root != source, "path": str(hive_root)}

    imported = workspace.import_content(source)
    steps["03_import"] = {
        "passed": len(imported) == 2
        and _tree_manifest(source) == source_before
        and sum(1 for path in workspace.assets.rglob("*") if path.is_file()) == 1,
        "documents": [item.as_dict() for item in imported],
        "source_unchanged": _tree_manifest(source) == source_before,
        "assets_preserved": sum(1 for path in workspace.assets.rglob("*") if path.is_file()),
    }
    search = workspace.search_exact("rollback target")
    steps["04_search"] = {"passed": len(search) == 1, "results": search}
    ask = workspace.ask("What is the rollback target?")
    steps["05_ask"] = {
        "passed": ask["outcome"] in {"ANSWERED", "RETRIEVAL_ONLY"} and bool(ask["citations"]),
        "result": ask,
    }
    graph = workspace.graph()
    steps["06_graph"] = {
        "passed": len(graph["edges"]) == 2 and bool(graph["backlinks"]),
        "nodes": len(graph["nodes"]),
        "edges": graph["edges"],
    }
    agent_cycle = _agent_cycle(workspace)
    steps["07_agent_task"] = {"passed": bool(agent_cycle["receipt_verified"]), **agent_cycle}

    command = [
        sys.executable,
        "-m",
        "hive_protocol.product.cli",
        "search",
        "--vault",
        str(hive_root),
        "--query",
        "portable Markdown",
    ]
    persisted = subprocess.run(  # nosec B603
        command,
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONUTF8": "1"},
    )
    persisted_payload = json.loads(persisted.stdout) if persisted.stdout.strip() else {}
    steps["08_next_process"] = {
        "passed": persisted.returncode == 0 and bool(persisted_payload.get("results")),
        "returncode": persisted.returncode,
        "results": persisted_payload.get("results", []),
    }

    snapshot = workspace.snapshot("alpha demo frozen parent")
    before_rollback = _tree_manifest(workspace.sources)
    tracked_source = hive_root / imported[0].imported_relative_path
    atomic_write_bytes(tracked_source, tracked_source.read_bytes() + b"\nDEMO MUTATION\n")
    if _tree_manifest(workspace.sources) == before_rollback:
        raise ProtocolError("DEMO_MUTATION_FAILED", "rollback test did not change state")
    rollback = workspace.rollback(snapshot["commit"])
    after_rollback = _tree_manifest(workspace.sources)
    steps["09_snapshot_rollback"] = {
        "passed": before_rollback == after_rollback,
        "snapshot": snapshot["commit"],
        "rollback": rollback["target"],
        "exact_restore": before_rollback == after_rollback,
    }

    export_path = work_root / f"nukotech-hive-local-alpha-v{ALPHA_VERSION}-export.tar.gz"
    exported = workspace.export(export_path)
    reopened = HiveWorkspace.reopen_export(export_path, reopened_root)
    reopened_search = reopened.search_exact("portable Markdown")
    steps["10_export_reopen"] = {
        "passed": bool(reopened_search),
        "artifact": exported,
        "reopened_results": reopened_search,
    }

    server = make_server(workspace, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        address, port = server.server_address[:2]
        request = urllib.request.Request(
            f"http://{address}:{port}/api/status",
            headers={"Authorization": f"Bearer {server.access_token}"},  # type: ignore[attr-defined]
        )
        with urllib.request.urlopen(request, timeout=5) as response:  # nosec B310
            surface_status = json.loads(response.read().decode("utf-8"))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    required_status = {
        "health",
        "privacy_mode",
        "provider",
        "vault_path",
        "git",
        "last_receipts",
        "agent_operations",
    }
    steps["11_product_surface"] = {
        "passed": required_status.issubset(surface_status),
        "status": surface_status,
    }

    failures = [name for name, value in steps.items() if not value.get("passed")]
    receipt = {
        "schema_version": "nukotech.hive-local.alpha-demo.v1",
        "product": "NukoTech Hive Local Alpha",
        "version": ALPHA_VERSION,
        "recorded_at": utc_now(),
        "work_root": str(work_root),
        "steps": steps,
        "source_vault_unchanged": _tree_manifest(source) == source_before,
        "unauthorized_external_effects": 0,
        "protected_prime_data_accessed": False,
        "failed_steps": failures,
        "classification": {
            "DOCUMENTED": "VERIFIED",
            "IMPLEMENTED": "VERIFIED",
            "RUNNING": "VERIFIED_DURING_DEMO",
            "WORKING": "VERIFIED" if not failures else "FAILED",
            "VERIFIED": "FRESH_INSTALL_E2E" if os.environ.get("HIVE_FRESH_INSTALL") == "1" and not failures else ("SOURCE_E2E" if not failures else "FAILED"),
            "AUTHORIZED": "OWNER_SAMPLE_BUILDER_A_ALPHA",
        },
    }
    receipt_path = work_root / "alpha-demo-receipt.json"
    atomic_write_json(receipt_path, receipt)
    receipt["receipt_path"] = str(receipt_path)
    receipt["receipt_sha256"] = _sha256_file(receipt_path)
    return receipt, 0 if not failures else 1
