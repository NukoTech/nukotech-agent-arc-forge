from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from hive_protocol.core import public_key_id
from hive_protocol.product.agent_adapter import (
    authorize_agent_capabilities,
    product_adapter_services,
    register_agent,
)
from hive_protocol.product.workflow_adapter import WorkflowProductService
from hive_protocol.product.workspace import HiveWorkspace


NOW = datetime(2026, 9, 1, 14, 0, tzinfo=timezone.utc)
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


def _step(
    step_id: str,
    capability: str,
    machine_id: str,
    *,
    dependencies: list[str],
    inputs: list[dict],
    output_name: str,
    approval_required: bool,
    branches: list[str],
    files: list[str],
    max_attempts: int = 2,
) -> dict:
    return {
        "step_id": step_id,
        "kind": "TASK",
        "dependencies": dependencies,
        "inputs": inputs,
        "outputs": [{"name": output_name, "type": "application/json"}],
        "required_capabilities": [capability],
        "required_trust": "ATTENDED",
        "target": {
            "project_id": "HiveMind",
            "machine_id": machine_id,
            "surface_id": None,
        },
        "approval": {
            "required": approval_required,
            "risk_class": "HIGH" if approval_required else "LOW",
        },
        "retry": {"max_attempts": max_attempts, "timeout_seconds": 300},
        "resources": {
            "max_tokens": 2000,
            "max_cost_microunits": 10000,
            "max_memory_mb": 512,
        },
        "ownership": {"branches": branches, "files": files},
        "rollback": {"mode": "GIT_CHECKPOINT", "compensation_step_id": None},
    }


def _definition(research_machine: str, analysis_machine: str) -> dict:
    return {
        "schema_version": "hive.workflow-definition.v1",
        "workflow_id": "workflow:m33-e2e",
        "version": 1,
        "tenant_id": "local-user",
        "project_id": "HiveMind",
        "title": "M3.3 complete attended workflow",
        "description": "Research, analyze, and publish with bounded recovery.",
        "parent_digest": None,
        "steps": [
            _step(
                "research",
                "vault:search",
                research_machine,
                dependencies=[],
                inputs=[],
                output_name="raw",
                approval_required=False,
                branches=["workflows/shared"],
                files=["research/shared"],
            ),
            _step(
                "analyze",
                "workflow:report",
                analysis_machine,
                dependencies=["research"],
                inputs=[
                    {
                        "name": "research_input",
                        "type": "application/json",
                        "source_step_id": "research",
                        "source_output": "raw",
                        "required": True,
                    }
                ],
                output_name="analysis",
                approval_required=True,
                branches=["workflows/shared"],
                files=["research/shared/analysis.json"],
                max_attempts=3,
            ),
            _step(
                "publish",
                "workflow:report",
                analysis_machine,
                dependencies=["analyze"],
                inputs=[
                    {
                        "name": "analysis_input",
                        "type": "application/json",
                        "source_step_id": "analyze",
                        "source_output": "analysis",
                        "required": True,
                    }
                ],
                output_name="final",
                approval_required=False,
                branches=["workflows/publish"],
                files=["research/final.json"],
            ),
        ],
        "metadata": {"tags": ["e2e", "internal-alpha"]},
    }


def _readiness(
    service: WorkflowProductService,
    run_id: str,
    step_id: str,
    *,
    attempt: int,
    machine_id: str,
    now: datetime,
    approvals=(),
) -> dict:
    return service.readiness(
        run_id,
        step_id,
        attempt=attempt,
        current_source_commit=SHA_A,
        current_machine_id=machine_id,
        task_sha256=hashlib.sha256(
            f"{run_id}:{step_id}:{attempt}".encode("utf-8")
        ).hexdigest(),
        existing_task_sha256s=[],
        required_evidence_refs=[],
        available_evidence_refs=[],
        approvals=list(approvals),
        now=now,
    )


def _approve_step(
    service: WorkflowProductService,
    run_id: str,
    readiness: dict,
    *,
    label: str,
    now: datetime,
) -> dict:
    preview = service.step_approval_preview(
        run_id,
        readiness,
        action=f"run attended {label}",
        destination=f"research/{label}.json",
        now=now,
        expires_at=now + timedelta(minutes=10),
    )
    decision = service.approve(
        preview,
        authorization_ref=f"owner-attended-{label}",
        approval_id=str(uuid4()),
        idempotency_key=f"approve-{label}-{uuid4()}",
        now=now,
    )
    return {"preview": preview, "approval": decision["approval"]}


def _claim(
    service: WorkflowProductService,
    run_id: str,
    readiness: dict,
    *,
    agent_id: str,
    now: datetime,
    approvals=(),
) -> dict:
    return service.claim(
        run_id,
        readiness,
        agent_id=agent_id,
        expires_at=now + timedelta(minutes=5),
        event_id=str(uuid4()),
        idempotency_key=f"claim-{agent_id}-{uuid4()}",
        now=now,
        approvals=list(approvals),
    )


def _start(
    service: WorkflowProductService,
    run_id: str,
    claim: dict,
    *,
    session_id: str,
    total_units: int,
    now: datetime,
) -> dict:
    return service.start_session(
        run_id,
        claim_event_id=claim["event"]["event_id"],
        session_id=session_id,
        total_units=total_units,
        current_source_commit=SHA_A,
        current_input_sha256=claim["claim"]["input_sha256"],
        event_id=str(uuid4()),
        idempotency_key=f"start-{session_id}",
        recorded_at=now,
    )


def _record(
    service: WorkflowProductService,
    run_id: str,
    session_id: str,
    claim: dict,
    *,
    event_type: str,
    state: str,
    completed: int,
    total: int,
    output: dict | None,
    now: datetime,
) -> dict:
    return service.record_session(
        run_id,
        session_id,
        event_type=event_type,
        state=state,
        progress={"completed_units": completed, "total_units": total},
        resources={
            "tokens_used": completed * 100,
            "cost_microunits": completed * 200,
            "peak_memory_mb": 64 if completed else 0,
        },
        outputs=[] if output is None else [output],
        current_source_commit=SHA_A,
        current_input_sha256=claim["claim"]["input_sha256"],
        event_id=str(uuid4()),
        idempotency_key=f"record-{event_type}-{uuid4()}",
        recorded_at=now,
    )


def _portable_bytes(workspace: HiveWorkspace) -> dict[str, bytes]:
    roots = (
        workspace.sources,
        workspace.staging,
        workspace.prime,
        workspace.research,
        workspace.workflows,
        workspace.provenance,
        workspace.receipts / "workflows",
        workspace.workflow_keys,
        workspace.meta / "agent-operations",
    )
    return {
        path.relative_to(workspace.root).as_posix(): path.read_bytes()
        for root in roots
        if root.exists()
        for path in sorted(root.rglob("*"))
        if path.is_file()
        and "replay" not in path.relative_to(root).parts
        and not path.name.endswith(".lock")
        and not path.name.startswith(".")
    }


def test_m33_visual_agent_workflow_complete_installed_boundary(tmp_path: Path) -> None:
    vault = tmp_path / "hive"
    workspace = HiveWorkspace.create(vault)
    anchors = {
        "sources/m31-anchor.md": b"M3.1 source anchor\n",
        "research/m31-result.md": b"M3.1 research anchor\n",
        "staging/m32-candidate.json": b'{"milestone":"M3.2"}\n',
        "prime/m32-knowledge.md": b"# M3.2 Knowledge\n",
    }
    for relative, payload in anchors.items():
        path = vault / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)

    service = WorkflowProductService(vault)
    research_machine = service.machine_id
    analysis_machine = "machine:analysis-node"
    authorize_agent_capabilities(
        vault,
        "Director-Research",
        "researcher",
        ["vault:search"],
        machine_id=research_machine,
        surface_id="surface:researcher",
        issued_at=NOW,
    )
    register_agent(
        vault,
        "Director-Research",
        "researcher",
        ["vault:search"],
        machine_id=research_machine,
        surface_id="surface:researcher",
        now=NOW,
    )
    authorize_agent_capabilities(
        vault,
        "Director-Analysis",
        "analyst",
        ["workflow:report"],
        machine_id=analysis_machine,
        surface_id="surface:analyst",
        issued_at=NOW,
    )
    register_agent(
        vault,
        "Director-Analysis",
        "analyst",
        ["workflow:report"],
        machine_id=analysis_machine,
        surface_id="surface:analyst",
        now=NOW,
    )
    service = WorkflowProductService(vault)
    published = service.publish_definition(
        _definition(research_machine, analysis_machine),
        idempotency_key="publish-m33-e2e",
        now=NOW,
    )
    launched = service.launch_run(
        "workflow:m33-e2e",
        1,
        run_id=str(uuid4()),
        source_commit=SHA_A,
        input_manifest_sha256=SHA_B,
        event_id=str(uuid4()),
        idempotency_key="launch-m33-e2e",
        now=NOW,
        stale_after_seconds=30,
    )
    run_id = launched["run"]["run_id"]

    research_ready = _readiness(
        service,
        run_id,
        "research",
        attempt=1,
        machine_id=research_machine,
        now=NOW,
    )
    research_claim = _claim(
        service,
        run_id,
        research_ready,
        agent_id="researcher",
        now=NOW,
    )
    overlapping = _readiness(
        service,
        run_id,
        "analyze",
        attempt=1,
        machine_id=analysis_machine,
        now=NOW,
    )
    overlap_codes = {item["code"] for item in overlapping["blockers"]}
    assert {"ACTIVE_BRANCH_CLAIM", "ACTIVE_FILE_CLAIM"}.issubset(overlap_codes)
    service.record_conflicts(
        run_id,
        overlapping,
        event_id=str(uuid4()),
        idempotency_key="record-overlap-conflict",
        now=NOW,
        attended_confirmation=True,
    )

    research_session = str(uuid4())
    _start(
        service,
        run_id,
        research_claim,
        session_id=research_session,
        total_units=2,
        now=NOW,
    )
    _record(
        service,
        run_id,
        research_session,
        research_claim,
        event_type="STEP_PROGRESS",
        state="ACTIVE",
        completed=1,
        total=2,
        output=None,
        now=NOW + timedelta(seconds=5),
    )
    raw_output = {
        "name": "raw",
        "type": "application/json",
        "sha256": SHA_B,
        "evidence_refs": ["evidence:raw"],
    }
    _record(
        service,
        run_id,
        research_session,
        research_claim,
        event_type="STEP_COMPLETED",
        state="COMPLETED",
        completed=2,
        total=2,
        output=raw_output,
        now=NOW + timedelta(seconds=10),
    )

    analyze_blocked = _readiness(
        service,
        run_id,
        "analyze",
        attempt=1,
        machine_id=analysis_machine,
        now=NOW + timedelta(seconds=11),
    )
    first_pair = _approve_step(
        service,
        run_id,
        analyze_blocked,
        label="analyze-first",
        now=NOW + timedelta(seconds=12),
    )
    mutated_preview = copy.deepcopy(first_pair["preview"])
    mutated_preview["input_sha256"] = SHA_D
    invalidated = _readiness(
        service,
        run_id,
        "analyze",
        attempt=1,
        machine_id=analysis_machine,
        now=NOW + timedelta(seconds=13),
        approvals=[
            {"preview": mutated_preview, "approval": first_pair["approval"]}
        ],
    )
    assert "APPROVAL_REQUIRED" in {
        item["code"] for item in invalidated["blockers"]
    }
    exact_pair = _approve_step(
        service,
        run_id,
        invalidated,
        label="analyze-exact",
        now=NOW + timedelta(seconds=14),
    )
    analyze_ready = _readiness(
        service,
        run_id,
        "analyze",
        attempt=1,
        machine_id=analysis_machine,
        now=NOW + timedelta(seconds=15),
        approvals=[exact_pair],
    )
    analyze_claim = _claim(
        service,
        run_id,
        analyze_ready,
        agent_id="analyst",
        now=NOW + timedelta(seconds=15),
        approvals=[exact_pair],
    )
    failed_session = str(uuid4())
    _start(
        service,
        run_id,
        analyze_claim,
        session_id=failed_session,
        total_units=2,
        now=NOW + timedelta(seconds=15),
    )
    _record(
        service,
        run_id,
        failed_session,
        analyze_claim,
        event_type="STEP_FAILED",
        state="FAILED",
        completed=1,
        total=2,
        output=None,
        now=NOW + timedelta(seconds=20),
    )
    publish_blocked = _readiness(
        service,
        run_id,
        "publish",
        attempt=1,
        machine_id=analysis_machine,
        now=NOW + timedelta(seconds=21),
    )
    assert "DEPENDENCY_NOT_SUCCEEDED" in {
        item["code"] for item in publish_blocked["blockers"]
    }

    service.create_retry(
        run_id,
        "analyze",
        failed_attempt=1,
        event_id=str(uuid4()),
        idempotency_key="create-analyze-attempt-2",
        recorded_at=NOW + timedelta(seconds=22),
    )
    retry_two_blocked = _readiness(
        service,
        run_id,
        "analyze",
        attempt=2,
        machine_id=analysis_machine,
        now=NOW + timedelta(seconds=23),
    )
    retry_two_pair = _approve_step(
        service,
        run_id,
        retry_two_blocked,
        label="analyze-retry-2",
        now=NOW + timedelta(seconds=24),
    )
    retry_two_ready = _readiness(
        service,
        run_id,
        "analyze",
        attempt=2,
        machine_id=analysis_machine,
        now=NOW + timedelta(seconds=25),
        approvals=[retry_two_pair],
    )
    retry_two_claim = _claim(
        service,
        run_id,
        retry_two_ready,
        agent_id="analyst",
        now=NOW + timedelta(seconds=25),
        approvals=[retry_two_pair],
    )
    stale_session = str(uuid4())
    _start(
        service,
        run_id,
        retry_two_claim,
        session_id=stale_session,
        total_units=2,
        now=NOW + timedelta(seconds=25),
    )
    stale_preview = service.stale_preview(
        run_id,
        stale_session,
        now=NOW + timedelta(seconds=56),
        expires_at=NOW + timedelta(minutes=5),
    )
    stale_decision = service.approve(
        stale_preview,
        authorization_ref="owner-attended-stale-e2e",
        approval_id=str(uuid4()),
        idempotency_key="approve-stale-e2e",
        now=NOW + timedelta(seconds=57),
    )
    service.release_stale(
        run_id,
        stale_session,
        preview=stale_preview,
        approval=stale_decision["approval"],
        now=NOW + timedelta(seconds=58),
        abandonment_event_id=str(uuid4()),
        release_event_id=str(uuid4()),
        idempotency_key="release-stale-e2e",
    )
    assert service.session_status(run_id, stale_session)["effective_state"] == "ABANDONED"

    service.create_retry(
        run_id,
        "analyze",
        failed_attempt=2,
        event_id=str(uuid4()),
        idempotency_key="create-analyze-attempt-3",
        recorded_at=NOW + timedelta(seconds=59),
    )
    retry_three_blocked = _readiness(
        service,
        run_id,
        "analyze",
        attempt=3,
        machine_id=analysis_machine,
        now=NOW + timedelta(seconds=60),
    )
    retry_three_pair = _approve_step(
        service,
        run_id,
        retry_three_blocked,
        label="analyze-retry-3",
        now=NOW + timedelta(seconds=61),
    )
    retry_three_ready = _readiness(
        service,
        run_id,
        "analyze",
        attempt=3,
        machine_id=analysis_machine,
        now=NOW + timedelta(seconds=62),
        approvals=[retry_three_pair],
    )
    retry_three_claim = _claim(
        service,
        run_id,
        retry_three_ready,
        agent_id="analyst",
        now=NOW + timedelta(seconds=62),
        approvals=[retry_three_pair],
    )
    successful_session = str(uuid4())
    _start(
        service,
        run_id,
        retry_three_claim,
        session_id=successful_session,
        total_units=1,
        now=NOW + timedelta(seconds=62),
    )
    analysis_output = {
        "name": "analysis",
        "type": "application/json",
        "sha256": SHA_C,
        "evidence_refs": ["evidence:analysis"],
    }
    _record(
        service,
        run_id,
        successful_session,
        retry_three_claim,
        event_type="STEP_COMPLETED",
        state="COMPLETED",
        completed=1,
        total=1,
        output=analysis_output,
        now=NOW + timedelta(seconds=63),
    )

    publish_ready = _readiness(
        service,
        run_id,
        "publish",
        attempt=1,
        machine_id=analysis_machine,
        now=NOW + timedelta(seconds=64),
    )
    publish_claim = _claim(
        service,
        run_id,
        publish_ready,
        agent_id="analyst",
        now=NOW + timedelta(seconds=64),
    )
    publish_session = str(uuid4())
    _start(
        service,
        run_id,
        publish_claim,
        session_id=publish_session,
        total_units=1,
        now=NOW + timedelta(seconds=64),
    )
    final_output = {
        "name": "final",
        "type": "application/json",
        "sha256": SHA_D,
        "evidence_refs": ["evidence:final"],
    }
    _record(
        service,
        run_id,
        publish_session,
        publish_claim,
        event_type="STEP_COMPLETED",
        state="COMPLETED",
        completed=1,
        total=1,
        output=final_output,
        now=NOW + timedelta(seconds=65),
    )
    service.complete_run(
        run_id,
        event_id=str(uuid4()),
        idempotency_key="complete-m33-e2e",
        now=NOW + timedelta(seconds=66),
        attended_confirmation=True,
    )

    before_replay = _portable_bytes(workspace)
    repository = Path(__file__).parents[1]
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(repository / "src")
    replayed_process = subprocess.run(
        [
            sys.executable,
            "-m",
            "hive_protocol.product.cli",
            "workflow-replay",
            "--vault",
            str(vault),
            "--run-id",
            run_id,
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert replayed_process.returncode == 0, replayed_process.stderr
    replay = json.loads(replayed_process.stdout)
    assert replay["state"] == "COMPLETED"
    assert replay["conflicts"]
    assert replay["approvals"]
    assert replay["execution_performed"] is False
    assert replay["mutation_performed"] is False
    assert _portable_bytes(workspace) == before_replay

    unrelated = vault / "unrelated.sentinel"
    unrelated.write_bytes(b"preserve unrelated")
    checkpoint = workspace.snapshot("M3.3 E2E rollback checkpoint")["commit"]
    milestone_before = {relative: (vault / relative).read_bytes() for relative in anchors}
    source = vault / "sources" / "m31-anchor.md"
    source.write_bytes(b"disposable mutation\n")
    workspace.snapshot("M3.3 disposable mutation")
    rollback_preview = service.rollback_preview(
        run_id,
        "publish",
        attempt=1,
        checkpoint=checkpoint,
        now=NOW + timedelta(minutes=2),
        expires_at=NOW + timedelta(minutes=10),
    )
    rollback_decision = service.approve(
        rollback_preview,
        authorization_ref="owner-attended-e2e-rollback",
        approval_id=str(uuid4()),
        idempotency_key="approve-e2e-rollback",
        now=NOW + timedelta(minutes=3),
    )
    service.apply_rollback(
        run_id,
        rollback_preview,
        approval=rollback_decision["approval"],
        start_event_id=str(uuid4()),
        complete_event_id=str(uuid4()),
        idempotency_key="apply-e2e-rollback",
        now=NOW + timedelta(minutes=3),
    )
    assert unrelated.read_bytes() == b"preserve unrelated"
    assert milestone_before == {
        relative: (vault / relative).read_bytes() for relative in anchors
    }

    bundle = tmp_path / "m33-export.tar.gz"
    workspace.export(bundle)
    reopened = HiveWorkspace.reopen_export(bundle, tmp_path / "reopened")
    rotated = WorkflowProductService(reopened.root)
    assert rotated.operator_key_id != service.operator_key_id
    assert rotated.list_definitions("workflow:m33-e2e")["versions"] == [1]
    reopened_replay = rotated.run_status(run_id)
    assert reopened_replay["state"] == "COMPLETED"
    assert reopened_replay["conflicts"] == replay["conflicts"]
    assert reopened_replay["approvals"] == replay["approvals"]
    assert rotated.session_status(run_id, failed_session)["effective_state"] == "FAILED"
    assert rotated.session_status(run_id, stale_session)["effective_state"] == "ABANDONED"
    assert rotated.session_status(run_id, successful_session)["effective_state"] == "COMPLETED"
    assert not (reopened.root / ".hive" / "derived" / "workflows").exists()
    assert not (reopened.root / ".hive" / "runtime" / "workflows" / "workflow-events.json").exists()
    assert published["preview"]["workflow_sha256"] == reopened_replay["workflow_sha256"]

    services = product_adapter_services(vault)
    owned_root = tmp_path / "adapter-owned"
    owned_root.mkdir()
    owned = owned_root / "owned.txt"
    owned.write_bytes(b"adapter-owned")
    sentinel = owned_root / "sentinel.txt"
    sentinel.write_bytes(b"unrelated")
    ownership = {
        "schema_version": "hive.adapter-ownership-manifest.v1",
        "installation_id": "m33-e2e-install",
        "adapter_id": "nukotech.hive.local-capture",
        "adapter_version": services.manifests["nukotech.hive.local-capture"]["version"],
        "root": str(owned_root.resolve()),
        "created_at": NOW.isoformat().replace("+00:00", "Z"),
        "paths": [
            {
                "path": owned.name,
                "kind": "file",
                "sha256": hashlib.sha256(owned.read_bytes()).hexdigest(),
            }
        ],
    }
    grant = services.authority.resolve(
        public_key_id(services.request_key.public_key()),
        "nukotech.hive.local-capture",
    )
    plan = services.lifecycle.plan(
        "nukotech.hive.local-capture", "uninstall", ownership, grant.project_id
    )
    approval = services.lifecycle.approve(
        plan, grant.identity, services.approver_key
    )
    before_uninstall = _portable_bytes(workspace)
    uninstall = services.lifecycle.uninstall(
        "nukotech.hive.local-capture", ownership, plan, approval
    )
    assert uninstall["outcome"] == "APPLIED"
    assert not owned.exists()
    assert sentinel.read_bytes() == b"unrelated"
    assert _portable_bytes(workspace) == before_uninstall
