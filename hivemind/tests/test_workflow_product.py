from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from hive_protocol.core import ProtocolError
from hive_protocol.product.agent_adapter import authorize_agent_capabilities, register_agent
from hive_protocol.product.workflow_adapter import WorkflowProductService
from hive_protocol.product.workspace import HiveWorkspace


NOW = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
SHA_A = "a" * 64
SHA_B = "b" * 64


def _definition(machine_id: str, *, approval: bool = False) -> dict:
    return {
        "schema_version": "hive.workflow-definition.v1",
        "workflow_id": "workflow:product",
        "version": 1,
        "tenant_id": "local-user",
        "project_id": "HiveMind",
        "title": "Product workflow",
        "description": "Exercise the attended workflow control room.",
        "parent_digest": None,
        "steps": [
            {
                "step_id": "research",
                "kind": "TASK",
                "dependencies": [],
                "inputs": [],
                "outputs": [{"name": "result", "type": "application/json"}],
                "required_capabilities": ["vault:search"],
                "required_trust": "ATTENDED",
                "target": {
                    "project_id": "HiveMind",
                    "machine_id": machine_id,
                    "surface_id": None,
                },
                "approval": {
                    "required": approval,
                    "risk_class": "HIGH" if approval else "LOW",
                },
                "retry": {"max_attempts": 2, "timeout_seconds": 300},
                "resources": {
                    "max_tokens": 1000,
                    "max_cost_microunits": 5000,
                    "max_memory_mb": 256,
                },
                "ownership": {
                    "branches": ["workflows/product"],
                    "files": ["research/product.json"],
                },
                "rollback": {
                    "mode": "GIT_CHECKPOINT",
                    "compensation_step_id": None,
                },
            }
        ],
        "metadata": {"tags": ["internal-alpha"]},
    }


def _fixture(tmp_path: Path, *, approval: bool = False):
    vault = tmp_path / "hive"
    workspace = HiveWorkspace.create(vault)
    service = WorkflowProductService(vault)
    authorize_agent_capabilities(
        vault,
        "Director",
        "researcher",
        ["vault:search"],
        machine_id=service.machine_id,
        surface_id="surface:researcher",
        issued_at=NOW,
    )
    register_agent(
        vault,
        "Director",
        "researcher",
        ["vault:search"],
        machine_id=service.machine_id,
        surface_id="surface:researcher",
        now=NOW,
    )
    service = WorkflowProductService(vault)
    published = service.publish_definition(
        _definition(service.machine_id, approval=approval),
        idempotency_key="publish-product-workflow",
        now=NOW,
    )
    launched = service.launch_run(
        "workflow:product",
        1,
        run_id=str(uuid4()),
        source_commit=SHA_A,
        input_manifest_sha256=SHA_B,
        event_id=str(uuid4()),
        idempotency_key="launch-product-workflow",
        now=NOW,
    )
    return workspace, service, published, launched


def _readiness(service: WorkflowProductService, run_id: str, *, approvals=()):
    return service.readiness(
        run_id,
        "research",
        attempt=1,
        current_source_commit=SHA_A,
        current_machine_id=service.machine_id,
        task_sha256="c" * 64,
        existing_task_sha256s=[],
        required_evidence_refs=[],
        available_evidence_refs=[],
        approvals=list(approvals),
        now=NOW,
    )


def test_control_room_publishes_launches_claims_delivers_and_records_session(tmp_path: Path) -> None:
    _, service, published, launched = _fixture(tmp_path)
    assert published["preview"]["execution_authorized"] is False
    assert service.list_definitions("workflow:product")["versions"] == [1]
    assert service.diff_definitions("workflow:product", 1, 1)["changes"] == []
    run_id = launched["run"]["run_id"]
    ready = _readiness(service, run_id)
    claim = service.claim(
        run_id,
        ready,
        agent_id="researcher",
        expires_at=NOW + timedelta(minutes=5),
        event_id=str(uuid4()),
        idempotency_key="claim-product-research",
        now=NOW,
    )
    delivered = service.deliver_claim(
        run_id,
        claim["event"]["event_id"],
        task_id=str(uuid4()),
        nonce="product-delivery-nonce",
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        now=NOW,
    )
    assert delivered["outcome"] == "DELIVERED"
    assert delivered["execution_started"] is False

    session_id = str(uuid4())
    started = service.start_session(
        run_id,
        claim_event_id=claim["event"]["event_id"],
        session_id=session_id,
        total_units=1,
        current_source_commit=SHA_A,
        current_input_sha256=claim["claim"]["input_sha256"],
        event_id=str(uuid4()),
        idempotency_key="start-product-session",
        recorded_at=NOW,
    )
    assert started["execution_started"] is False
    completed = service.record_session(
        run_id,
        session_id,
        event_type="STEP_COMPLETED",
        state="COMPLETED",
        progress={"completed_units": 1, "total_units": 1},
        resources={
            "tokens_used": 25,
            "cost_microunits": 50,
            "peak_memory_mb": 32,
        },
        outputs=[
            {
                "name": "result",
                "type": "application/json",
                "sha256": SHA_B,
                "evidence_refs": ["evidence:product"],
            }
        ],
        current_source_commit=SHA_A,
        current_input_sha256=claim["claim"]["input_sha256"],
        event_id=str(uuid4()),
        idempotency_key="complete-product-session",
        recorded_at=NOW + timedelta(minutes=1),
    )
    assert completed["session"]["state"] == "COMPLETED"
    status = service.run_status(run_id)
    assert status["steps"]["research"]["attempts"]["1"]["state"] == "COMPLETED"
    assert status["resource_use"] == {
        "tokens_used": 25,
        "cost_microunits": 50,
        "peak_memory_mb": 32,
    }
    assert status["execution_performed"] is False


def test_conflict_record_rejects_a_forged_readiness_view(tmp_path: Path) -> None:
    _, service, _, launched = _fixture(tmp_path)
    run_id = launched["run"]["run_id"]
    readiness = service.readiness(
        run_id,
        "research",
        attempt=1,
        current_source_commit=SHA_B,
        current_machine_id=service.machine_id,
        task_sha256="c" * 64,
        existing_task_sha256s=[],
        required_evidence_refs=[],
        available_evidence_refs=[],
        approvals=[],
        now=NOW,
    )
    forged = dict(readiness)
    forged["blockers"] = [dict(item) for item in readiness["blockers"]]
    forged["blockers"][0]["conflict_id"] = "conflict:" + "f" * 64
    forged_body = dict(forged)
    forged_body.pop("readiness_sha256")
    from hive_protocol.core import document_digest

    forged["readiness_sha256"] = document_digest(forged_body)
    with pytest.raises(ProtocolError, match="WORKFLOW_CONFLICT_VIEW_INVALID"):
        service.record_conflicts(
            run_id,
            forged,
            event_id=str(uuid4()),
            idempotency_key="record-forged-conflict",
            now=NOW,
            attended_confirmation=True,
        )


def test_run_completion_rejects_an_unclaimed_step_event(tmp_path: Path) -> None:
    _, service, _, launched = _fixture(tmp_path)
    run_id = launched["run"]["run_id"]
    with pytest.raises(ProtocolError, match="WORKFLOW_EVENT_AUTHORITY_INVALID"):
        service._journal().append(
            run_id,
            event_type="STEP_COMPLETED",
            actor=service.operator_identity,
            payload={
                "outputs": [
                    {
                        "name": "result",
                        "type": "application/json",
                        "sha256": SHA_B,
                        "evidence_refs": [],
                    }
                ]
            },
            private_key=service.operator_key,
            event_id=str(uuid4()),
            idempotency_key="inject-unclaimed-step-completion",
            recorded_at=NOW,
            step_id="research",
            attempt=1,
        )


def test_protected_step_and_portable_rollback_require_separate_exact_approvals(tmp_path: Path) -> None:
    workspace, service, _, launched = _fixture(tmp_path, approval=True)
    run_id = launched["run"]["run_id"]
    blocked = _readiness(service, run_id)
    assert "APPROVAL_REQUIRED" in {item["code"] for item in blocked["blockers"]}
    preview = service.step_approval_preview(
        run_id,
        blocked,
        action="run attended product research",
        destination="research/product.json",
        expires_at=NOW + timedelta(minutes=10),
        now=NOW,
    )
    decision = service.approve(
        preview,
        authorization_ref="owner-attended-product-step",
        approval_id=str(uuid4()),
        idempotency_key="approve-product-step",
        now=NOW,
    )
    approved = _readiness(
        service,
        run_id,
        approvals=[{"preview": preview, "approval": decision["approval"]}],
    )
    assert approved["ready"] is True

    (workspace.sources / "portable.md").write_text("checkpoint\n", encoding="utf-8")
    checkpoint = workspace.snapshot("workflow rollback checkpoint")["commit"]
    (workspace.sources / "portable.md").write_text("mutated\n", encoding="utf-8")
    workspace.snapshot("workflow rollback mutation")
    rollback_preview = service.rollback_preview(
        run_id,
        "research",
        attempt=1,
        checkpoint=checkpoint,
        now=NOW + timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=10),
    )
    with pytest.raises(ProtocolError, match="approval"):
        service.apply_rollback(
            run_id,
            rollback_preview,
            approval={},
            start_event_id=str(uuid4()),
            complete_event_id=str(uuid4()),
            idempotency_key="rollback-without-approval",
            now=NOW + timedelta(minutes=2),
        )
    rollback_approval = service.approve(
        rollback_preview,
        authorization_ref="owner-attended-product-rollback",
        approval_id=str(uuid4()),
        idempotency_key="approve-product-rollback",
        now=NOW + timedelta(minutes=2),
    )
    applied = service.apply_rollback(
        run_id,
        rollback_preview,
        approval=rollback_approval["approval"],
        start_event_id=str(uuid4()),
        complete_event_id=str(uuid4()),
        idempotency_key="apply-product-rollback",
        now=NOW + timedelta(minutes=2),
    )
    assert applied["outcome"] == "ROLLBACK_COMPLETED"
    assert (workspace.sources / "portable.md").read_text(encoding="utf-8") == "checkpoint\n"


def test_run_cancellation_is_attended_idempotent_and_never_executes(tmp_path: Path) -> None:
    _, service, _, launched = _fixture(tmp_path)
    run_id = launched["run"]["run_id"]
    arguments = {
        "run_id": run_id,
        "event_id": str(uuid4()),
        "idempotency_key": "cancel-product-run",
        "now": NOW + timedelta(minutes=1),
        "attended_confirmation": True,
    }
    first = service.cancel_run(**arguments)
    second = service.cancel_run(**arguments)
    assert first["changed"] is True
    assert second["changed"] is False
    assert service.run_status(run_id)["state"] == "CANCELLED"
    assert first["execution_started"] is False
    with pytest.raises(ProtocolError, match="WORKFLOW_RUN_TERMINAL"):
        service.cancel_run(
            run_id,
            event_id=str(uuid4()),
            idempotency_key="second-distinct-cancel",
            now=NOW + timedelta(minutes=2),
            attended_confirmation=True,
        )
    blocked = _readiness(service, run_id)
    assert "RUN_TERMINAL" in {item["code"] for item in blocked["blockers"]}
