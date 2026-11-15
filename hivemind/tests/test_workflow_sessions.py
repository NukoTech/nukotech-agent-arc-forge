from __future__ import annotations

from datetime import timedelta
from pathlib import Path
import shutil
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.agents import AgentOperations
from hive_protocol.core import ProtocolError, public_key_id, sign_document
from hive_protocol.workflows.approvals import (
    WorkflowApprovalAuthority,
)
from hive_protocol.workflows.events import WorkflowRunJournal
from hive_protocol.workflows.scheduler import WorkflowScheduler
from hive_protocol.workflows.sessions import WorkflowSessionManager

from test_workflow_events import NOW, SHA_A, SHA_B, _run
from test_workflow_scheduler import (
    _agent_identity,
    _agent_record,
    _evaluate,
    _two_step_definition,
)


def _fixture(tmp_path: Path, *, compensation: bool = False):
    operator = Ed25519PrivateKey.generate()
    researcher = Ed25519PrivateKey.generate()
    analyst = Ed25519PrivateKey.generate()
    approver = Ed25519PrivateKey.generate()
    definition = _two_step_definition(operator, approval_required=compensation)
    if compensation:
        definition.pop("signature")
        definition["steps"][0]["rollback"] = {
            "mode": "COMPENSATION",
            "compensation_step_id": "analyze",
        }
        definition["steps"][1]["kind"] = "COMPENSATION"
        definition["steps"][1]["dependencies"] = []
        definition["steps"][1]["inputs"] = []
        definition = sign_document(definition, operator)
    run = _run(operator, definition)
    ops = AgentOperations(tmp_path / "hive" / ".hive" / "agent-operations")
    ops.register(_agent_record(researcher, "researcher", ["vault:search"]))
    ops.register(_agent_record(analyst, "analyst", ["workflow:report"]))
    trusted = {
        public_key_id(key.public_key()): key.public_key()
        for key in (operator, researcher, analyst, approver)
    }
    journal = WorkflowRunJournal(tmp_path / "hive", trusted)
    journal.start(
        definition,
        run,
        private_key=operator,
        event_id=str(uuid4()),
        idempotency_key="start-session-fixture",
    )
    authority = WorkflowApprovalAuthority(
        tmp_path / "hive",
        {public_key_id(approver.public_key()): approver.public_key()},
    )
    scheduler = WorkflowScheduler(
        tmp_path / "hive",
        definition,
        run,
        journal=journal,
        registry=ops.registry_snapshot(),
        approval_authority=authority,
    )
    manager = WorkflowSessionManager(
        tmp_path / "hive",
        definition,
        run,
        journal=journal,
        approval_authority=authority,
    )
    return {
        "operator": operator,
        "researcher": researcher,
        "analyst": analyst,
        "approver": approver,
        "definition": definition,
        "run": run,
        "journal": journal,
        "scheduler": scheduler,
        "manager": manager,
    }


def _claim_research(fixture, *, attempt: int = 1, now=NOW):
    ready = _evaluate(fixture["scheduler"], "research", attempt=attempt, now=now)
    return fixture["scheduler"].claim(
        ready,
        agent_id="researcher",
        actor=_agent_identity(fixture["researcher"], "researcher"),
        private_key=fixture["researcher"],
        expires_at=now + timedelta(minutes=5),
        event_id=str(uuid4()),
        idempotency_key=f"claim-research-{attempt}",
        now=now,
    )


def _start_session(fixture, claim, *, session_id: str, now=NOW):
    arguments = {
        "claim_event_id": claim["event"]["event_id"],
        "session_id": session_id,
        "agent": _agent_identity(fixture["researcher"], "researcher"),
        "private_key": fixture["researcher"],
        "total_units": 3,
        "current_source_commit": SHA_A,
        "current_input_sha256": claim["claim"]["input_sha256"],
        "event_id": str(uuid4()),
        "idempotency_key": f"start-session-{session_id}",
        "recorded_at": now,
    }
    result = fixture["manager"].start(**arguments)
    result["test_replay_arguments"] = arguments
    return result


def _record(fixture, session_id: str, event_type: str, *, state="ACTIVE", completed=0, tokens=0, cost=0, memory=0, outputs=(), now=NOW, current_source_commit=SHA_A, current_input_sha256=None):
    status = fixture["manager"].status(session_id)
    return fixture["manager"].record(
        session_id,
        event_type=event_type,
        agent=_agent_identity(fixture["researcher"], "researcher"),
        private_key=fixture["researcher"],
        state=state,
        progress={"completed_units": completed, "total_units": 3},
        resources={
            "tokens_used": tokens,
            "cost_microunits": cost,
            "peak_memory_mb": memory,
        },
        outputs=list(outputs),
        current_source_commit=current_source_commit,
        current_input_sha256=(
            status["claim"]["input_sha256"]
            if current_input_sha256 is None
            else current_input_sha256
        ),
        event_id=str(uuid4()),
        idempotency_key=f"record-{event_type.lower()}-{uuid4()}",
        recorded_at=now,
    )


def test_signed_session_history_is_monotonic_bounded_terminal_and_replay_safe(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    claim = _claim_research(fixture)
    session_id = str(uuid4())
    started = _start_session(fixture, claim, session_id=session_id)
    replayed = fixture["manager"].start(**started["test_replay_arguments"])
    assert replayed["changed"] is False
    with pytest.raises(ProtocolError, match="fork"):
        _start_session(fixture, claim, session_id=str(uuid4()))

    snapshot = fixture["manager"]._session_paths(session_id)[0]
    duplicate = snapshot.with_name(f"{snapshot.stem}-duplicate.json")
    shutil.copyfile(snapshot, duplicate)
    with pytest.raises(ProtocolError, match="snapshot and workflow event do not bind"):
        fixture["manager"].history(session_id)
    duplicate.unlink()

    with pytest.raises(ProtocolError, match="stale"):
        _record(
            fixture,
            session_id,
            "SESSION_HEARTBEAT",
            current_source_commit=SHA_B,
            now=NOW + timedelta(seconds=1),
        )
    _record(
        fixture,
        session_id,
        "SESSION_HEARTBEAT",
        now=NOW + timedelta(seconds=1),
    )
    _record(fixture, session_id, "STEP_ACKNOWLEDGED", now=NOW + timedelta(seconds=2))
    _record(
        fixture,
        session_id,
        "STEP_PROGRESS",
        completed=1,
        tokens=100,
        cost=200,
        memory=64,
        now=NOW + timedelta(seconds=3),
    )
    with pytest.raises(ProtocolError, match="regress"):
        _record(
            fixture,
            session_id,
            "STEP_PROGRESS",
            completed=0,
            tokens=99,
            cost=200,
            memory=64,
            now=NOW + timedelta(seconds=4),
        )
    with pytest.raises(ProtocolError, match="resource"):
        _record(
            fixture,
            session_id,
            "STEP_PROGRESS",
            completed=2,
            tokens=1001,
            cost=200,
            memory=64,
            now=NOW + timedelta(seconds=4),
        )
    with pytest.raises(ProtocolError, match="signer"):
        fixture["manager"].record(
            session_id,
            event_type="SESSION_HEARTBEAT",
            agent=_agent_identity(fixture["analyst"], "researcher"),
            private_key=fixture["analyst"],
            state="ACTIVE",
            progress={"completed_units": 1, "total_units": 3},
            resources={"tokens_used": 100, "cost_microunits": 200, "peak_memory_mb": 64},
            outputs=[],
            current_source_commit=SHA_A,
            current_input_sha256=claim["claim"]["input_sha256"],
            event_id=str(uuid4()),
            idempotency_key="wrong-session-signer",
            recorded_at=NOW + timedelta(seconds=4),
        )

    output = {"name": "result", "type": "application/json", "sha256": SHA_B, "evidence_refs": ["evidence:result"]}
    _record(
        fixture,
        session_id,
        "STEP_OUTPUT",
        completed=2,
        tokens=200,
        cost=400,
        memory=96,
        outputs=[output],
        now=NOW + timedelta(seconds=5),
    )
    completed = _record(
        fixture,
        session_id,
        "STEP_COMPLETED",
        state="COMPLETED",
        completed=3,
        tokens=250,
        cost=500,
        memory=96,
        outputs=[output],
        now=NOW + timedelta(seconds=6),
    )
    assert completed["session"]["state"] == "COMPLETED"
    assert fixture["manager"].status(session_id)["effective_state"] == "COMPLETED"
    with pytest.raises(ProtocolError, match="terminal"):
        _record(
            fixture,
            session_id,
            "SESSION_HEARTBEAT",
            state="ACTIVE",
            completed=3,
            tokens=250,
            cost=500,
            memory=96,
            outputs=[output],
            now=NOW + timedelta(seconds=7),
        )


def test_stale_release_is_read_only_then_exactly_approval_bound_and_crash_safe(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    claim = _claim_research(fixture)
    session_id = str(uuid4())
    _start_session(fixture, claim, session_id=session_id)
    before = sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*"))
    preview = fixture["manager"].stale_preview(
        session_id,
        now=NOW + timedelta(minutes=11),
        expires_at=NOW + timedelta(minutes=20),
    )
    after = sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*"))
    assert before == after
    assert preview["approval_kind"] == "STALE_RELEASE"
    with pytest.raises(ProtocolError):
        fixture["manager"].release_stale(
            session_id,
            preview=preview,
            approval={},
            actor=fixture["run"]["launched_by"],
            private_key=fixture["operator"],
            now=NOW + timedelta(minutes=12),
            abandonment_event_id=str(uuid4()),
            release_event_id=str(uuid4()),
            idempotency_key="release-without-approval",
        )

    approver_identity = {
        "actor_id": "approver",
        "persona_id": "persona:owner",
        "surface_id": "surface:human",
        "machine_id": "machine:hive-lab-host",
        "project_id": "HiveMind",
        "app_actor": "app:approval",
        "key_id": public_key_id(fixture["approver"].public_key()),
    }
    decision = fixture["manager"].approval_authority.decide(
        preview,
        decision="APPROVED",
        approver=approver_identity,
        authorization_ref="owner-attended-stale-release",
        private_key=fixture["approver"],
        approval_id=str(uuid4()),
        idempotency_key="approve-stale-release",
        decided_at=NOW + timedelta(minutes=12),
        disallowed_agent_key_ids={public_key_id(fixture["researcher"].public_key())},
    )
    arguments = {
        "session_id": session_id,
        "preview": preview,
        "approval": decision["approval"],
        "actor": fixture["run"]["launched_by"],
        "private_key": fixture["operator"],
        "now": NOW + timedelta(minutes=12),
        "abandonment_event_id": str(uuid4()),
        "release_event_id": str(uuid4()),
        "idempotency_key": "apply-stale-release",
    }
    with pytest.raises(SystemExit, match="recovery crash"):
        fixture["manager"].release_stale(
            **arguments,
            after_abandonment_event=lambda: (_ for _ in ()).throw(SystemExit("recovery crash")),
        )
    recovered = fixture["manager"].release_stale(**arguments)
    assert recovered["outcome"] == "CLAIM_RELEASED"
    assert fixture["manager"].status(session_id)["effective_state"] == "ABANDONED"
    event_types = [event.event_type for event in fixture["journal"].events(fixture["run"]["run_id"])]
    assert event_types.count("SESSION_ABANDONED") == 1
    assert event_types.count("CLAIM_RELEASED") == 1
    with pytest.raises(ProtocolError, match="already"):
        fixture["manager"].release_stale(
            **{
                **arguments,
                "release_event_id": str(uuid4()),
                "idempotency_key": "second-distinct-release",
            }
        )


def test_failure_blocks_dependents_and_attended_retry_creates_new_attempt(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    claim = _claim_research(fixture)
    first_session_id = str(uuid4())
    _start_session(fixture, claim, session_id=first_session_id)
    _record(
        fixture,
        first_session_id,
        "STEP_FAILED",
        state="FAILED",
        completed=1,
        tokens=100,
        cost=200,
        memory=64,
        now=NOW + timedelta(minutes=1),
    )
    blocked = _evaluate(fixture["scheduler"], "analyze", now=NOW + timedelta(minutes=1))
    assert "DEPENDENCY_NOT_SUCCEEDED" in {item["code"] for item in blocked["blockers"]}
    unauthorized = _evaluate(
        fixture["scheduler"], "research", attempt=2, now=NOW + timedelta(minutes=1)
    )
    assert "RETRY_NOT_AUTHORIZED" in {item["code"] for item in unauthorized["blockers"]}

    retry = fixture["manager"].create_retry(
        "research",
        failed_attempt=1,
        actor=fixture["run"]["launched_by"],
        private_key=fixture["operator"],
        event_id=str(uuid4()),
        idempotency_key="retry-research-2",
        recorded_at=NOW + timedelta(minutes=1),
        attended_confirmation=True,
    )
    assert retry["new_attempt"] == 2
    with pytest.raises(ProtocolError, match="already"):
        fixture["manager"].create_retry(
            "research",
            failed_attempt=1,
            actor=fixture["run"]["launched_by"],
            private_key=fixture["operator"],
            event_id=str(uuid4()),
            idempotency_key="second-retry-research-2",
            recorded_at=NOW + timedelta(minutes=1),
            attended_confirmation=True,
        )
    ready = _evaluate(
        fixture["scheduler"], "research", attempt=2, now=NOW + timedelta(minutes=1)
    )
    assert ready["ready"] is True
    second_claim = _claim_research(fixture, attempt=2, now=NOW + timedelta(minutes=1))
    second_session_id = str(uuid4())
    _start_session(
        fixture,
        second_claim,
        session_id=second_session_id,
        now=NOW + timedelta(minutes=1),
    )
    _record(
        fixture,
        second_session_id,
        "STEP_FAILED",
        state="FAILED",
        completed=1,
        tokens=100,
        cost=200,
        memory=64,
        now=NOW + timedelta(minutes=2),
    )
    with pytest.raises(ProtocolError, match="exhausted"):
        fixture["manager"].create_retry(
            "research",
            failed_attempt=2,
            actor=fixture["run"]["launched_by"],
            private_key=fixture["operator"],
            event_id=str(uuid4()),
            idempotency_key="retry-research-3",
            recorded_at=NOW + timedelta(minutes=2),
            attended_confirmation=True,
        )
    assert fixture["manager"].status(first_session_id)["effective_state"] == "FAILED"
    assert fixture["manager"].status(second_session_id)["effective_state"] == "FAILED"


def test_only_declared_separately_approved_compensation_becomes_ready(tmp_path: Path) -> None:
    ordinary = _fixture(tmp_path / "ordinary")
    ordinary_claim = _claim_research(ordinary)
    ordinary_session = str(uuid4())
    _start_session(ordinary, ordinary_claim, session_id=ordinary_session)
    _record(
        ordinary,
        ordinary_session,
        "STEP_FAILED",
        state="FAILED",
        completed=1,
        now=NOW + timedelta(minutes=1),
    )
    with pytest.raises(ProtocolError, match="not declared"):
        ordinary["manager"].compensation_preview(
            "research",
            failed_attempt=1,
            now=NOW + timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=10),
        )

    fixture = _fixture(tmp_path / "declared", compensation=True)
    claim = _claim_research(fixture)
    session_id = str(uuid4())
    _start_session(fixture, claim, session_id=session_id)
    _record(
        fixture,
        session_id,
        "STEP_FAILED",
        state="FAILED",
        completed=1,
        now=NOW + timedelta(minutes=1),
    )
    preview = fixture["manager"].compensation_preview(
        "research",
        failed_attempt=1,
        now=NOW + timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=10),
    )
    blocked = _evaluate(
        fixture["scheduler"], "analyze", now=NOW + timedelta(minutes=1)
    )
    assert "COMPENSATION_NOT_AUTHORIZED" in {
        item["code"] for item in blocked["blockers"]
    }
    with pytest.raises(ProtocolError, match="approval"):
        fixture["manager"].authorize_compensation(
            "research",
            failed_attempt=1,
            preview=preview,
            approval=None,
            actor=fixture["run"]["launched_by"],
            private_key=fixture["operator"],
            event_id=str(uuid4()),
            idempotency_key="unapproved-compensation",
            recorded_at=NOW + timedelta(minutes=2),
            attended_confirmation=True,
        )
    approver_identity = {
        "actor_id": "approver",
        "persona_id": "persona:owner",
        "surface_id": "surface:human",
        "machine_id": "machine:hive-lab-host",
        "project_id": "HiveMind",
        "app_actor": "app:approval",
        "key_id": public_key_id(fixture["approver"].public_key()),
    }
    decision = fixture["manager"].approval_authority.decide(
        preview,
        decision="APPROVED",
        approver=approver_identity,
        authorization_ref="owner-attended-compensation",
        private_key=fixture["approver"],
        approval_id=str(uuid4()),
        idempotency_key="approve-compensation",
        decided_at=NOW + timedelta(minutes=2),
        disallowed_agent_key_ids={public_key_id(fixture["researcher"].public_key())},
    )
    authorized = fixture["manager"].authorize_compensation(
        "research",
        failed_attempt=1,
        preview=preview,
        approval=decision["approval"],
        actor=fixture["run"]["launched_by"],
        private_key=fixture["operator"],
        event_id=str(uuid4()),
        idempotency_key="approved-compensation",
        recorded_at=NOW + timedelta(minutes=2),
        attended_confirmation=True,
    )
    assert authorized["step_id"] == "analyze"
    ready = _evaluate(
        fixture["scheduler"],
        "analyze",
        approvals=[{"preview": preview, "approval": decision["approval"]}],
        now=NOW + timedelta(minutes=2),
    )
    assert ready["ready"] is True
