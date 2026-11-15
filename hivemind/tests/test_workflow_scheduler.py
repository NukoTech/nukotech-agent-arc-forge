from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.agents import AgentOperations, public_pem
from hive_protocol.core import (
    ProtocolError,
    document_digest,
    public_key_id,
    sign_document,
)
from hive_protocol.workflows.approvals import (
    WorkflowApprovalAuthority,
    build_approval_preview,
)
from hive_protocol.workflows.events import WorkflowRunJournal
from hive_protocol.workflows.scheduler import WorkflowScheduler

from test_workflow_events import NOW, SHA_A, SHA_B, _definition, _identity, _run


def _agent_identity(key: Ed25519PrivateKey, agent_id: str) -> dict[str, str]:
    return {
        "actor_id": agent_id,
        "persona_id": f"persona:{agent_id}",
        "surface_id": f"surface:{agent_id}",
        "machine_id": "machine:hive-lab-host",
        "project_id": "HiveMind",
        "app_actor": f"app:{agent_id}",
        "key_id": public_key_id(key.public_key()),
    }


def _agent_record(
    key: Ed25519PrivateKey, agent_id: str, capabilities: list[str]
) -> dict[str, object]:
    identity = _agent_identity(key, agent_id)
    return {
        "agent_id": agent_id,
        "tenant_id": "local-user",
        "workspace_id": "local-hive",
        "persona_id": identity["persona_id"],
        "surface_id": identity["surface_id"],
        "machine_id": identity["machine_id"],
        "project_ids": ["HiveMind"],
        "app_actor": identity["app_actor"],
        "capabilities": capabilities,
        "trust_level": "ATTENDED",
        "recipient_aliases": [],
        "key_id": identity["key_id"],
        "public_key_pem": public_pem(key),
        "active": True,
    }


def _two_step_definition(
    operator: Ed25519PrivateKey, *, approval_required: bool = False
) -> dict[str, object]:
    document = copy.deepcopy(_definition(operator))
    document.pop("signature")
    collect = document["steps"][0]
    analyze = copy.deepcopy(collect)
    analyze.update(
        step_id="analyze",
        dependencies=["research"],
        inputs=[
            {
                "name": "upstream",
                "type": "application/json",
                "source_step_id": "research",
                "source_output": "result",
                "required": True,
            }
        ],
        required_capabilities=["workflow:report"],
    )
    analyze["ownership"] = {
        "branches": ["workflows/analyze"],
        "files": ["research/analyze.md"],
    }
    analyze["approval"] = {
        "required": approval_required,
        "risk_class": "HIGH" if approval_required else "LOW",
    }
    document["steps"] = [collect, analyze]
    return sign_document(document, operator)


def _fixture(
    tmp_path: Path,
    *,
    approval_required: bool = False,
    max_concurrent_claims: int = 2,
) -> tuple[
    WorkflowScheduler,
    WorkflowRunJournal,
    dict[str, object],
    Ed25519PrivateKey,
    Ed25519PrivateKey,
    Ed25519PrivateKey,
    WorkflowApprovalAuthority,
]:
    operator = Ed25519PrivateKey.generate()
    researcher = Ed25519PrivateKey.generate()
    analyst = Ed25519PrivateKey.generate()
    approver = Ed25519PrivateKey.generate()
    definition = _two_step_definition(operator, approval_required=approval_required)
    run = _run(operator, definition)
    if max_concurrent_claims != 2:
        run.pop("signature")
        run["policy"]["max_concurrent_claims"] = max_concurrent_claims
        run = sign_document(run, operator)
    ops = AgentOperations(tmp_path / "hive" / ".hive" / "agent-operations")
    ops.register(_agent_record(researcher, "researcher", ["vault:search"]))
    ops.register(_agent_record(analyst, "analyst", ["workflow:report"]))
    trusted = {
        public_key_id(operator.public_key()): operator.public_key(),
        public_key_id(researcher.public_key()): researcher.public_key(),
        public_key_id(analyst.public_key()): analyst.public_key(),
        public_key_id(approver.public_key()): approver.public_key(),
    }
    journal = WorkflowRunJournal(tmp_path / "hive", trusted)
    journal.start(
        definition,
        run,
        private_key=operator,
        event_id="22222222-2222-4222-8222-222222222222",
        idempotency_key="start-scheduler",
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
    return scheduler, journal, run, researcher, analyst, approver, authority


def _evaluate(
    scheduler: WorkflowScheduler,
    step_id: str,
    *,
    attempt: int = 1,
    approvals=(),
    current_source_commit: str = SHA_A,
    now: datetime = NOW,
) -> dict[str, object]:
    return scheduler.evaluate(
        step_id,
        attempt=attempt,
        current_source_commit=current_source_commit,
        current_machine_id="machine:hive-lab-host",
        task_sha256="c" * 64,
        existing_task_sha256s=[],
        required_evidence_refs=[],
        available_evidence_refs=[],
        approvals=list(approvals),
        now=now,
    )


def test_readiness_matches_claims_and_unlocks_typed_dependency(tmp_path: Path) -> None:
    scheduler, journal, run, researcher, _, _, _ = _fixture(tmp_path)
    ready = _evaluate(scheduler, "research")
    assert ready["ready"] is True
    assert ready["eligible_agents"] == ["researcher"]

    claim = scheduler.claim(
        ready,
        agent_id="researcher",
        actor=_agent_identity(researcher, "researcher"),
        private_key=researcher,
        expires_at=NOW + timedelta(minutes=5),
        event_id="33333333-3333-4333-8333-333333333333",
        idempotency_key="claim-research",
        now=NOW,
    )
    assert claim["claim"]["source_commit"] == SHA_A
    assert claim["claim"]["owned_files"] == ["research/report.md"]

    journal.append(
        run["run_id"],
        event_type="STEP_COMPLETED",
        actor=_agent_identity(researcher, "researcher"),
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
        private_key=researcher,
        event_id="44444444-4444-4444-8444-444444444444",
        idempotency_key="complete-research",
        recorded_at=NOW,
        step_id="research",
        attempt=1,
    )
    analyze = _evaluate(scheduler, "analyze")
    assert analyze["ready"] is True
    assert analyze["eligible_agents"] == ["analyst"]
    assert analyze["inputs"][0]["sha256"] == SHA_B


def test_missing_dependency_input_source_and_agent_are_visible_blockers(tmp_path: Path) -> None:
    scheduler, _, _, _, _, _, _ = _fixture(tmp_path)
    blocked = _evaluate(scheduler, "analyze", current_source_commit=SHA_B)
    codes = {blocker["code"] for blocker in blocked["blockers"]}
    assert {"DEPENDENCY_NOT_SUCCEEDED", "INPUT_MISSING", "STALE_SOURCE_COMMIT"}.issubset(codes)
    assert blocked["ready"] is False


def test_unclaimed_completion_cannot_unlock_a_dependency(tmp_path: Path) -> None:
    scheduler, journal, run, _, analyst, _, _ = _fixture(tmp_path)
    with pytest.raises(ProtocolError, match="WORKFLOW_EVENT_AUTHORITY_INVALID"):
        journal.append(
            run["run_id"],
            event_type="STEP_COMPLETED",
            actor=_agent_identity(analyst, "analyst"),
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
            private_key=analyst,
            event_id=str(uuid4()),
            idempotency_key="forged-unclaimed-completion",
            recorded_at=NOW,
            step_id="research",
            attempt=1,
        )
    assert _evaluate(scheduler, "analyze")["ready"] is False


def test_protected_step_requires_exact_current_approval(tmp_path: Path) -> None:
    scheduler, journal, run, researcher, analyst, approver, authority = _fixture(
        tmp_path, approval_required=True
    )
    ready = _evaluate(scheduler, "research")
    scheduler.claim(
        ready,
        agent_id="researcher",
        actor=_agent_identity(researcher, "researcher"),
        private_key=researcher,
        expires_at=NOW + timedelta(minutes=5),
        event_id=str(uuid4()),
        idempotency_key="claim-approved-fixture",
        now=NOW,
    )
    journal.append(
        run["run_id"],
        event_type="STEP_COMPLETED",
        actor=_agent_identity(researcher, "researcher"),
        payload={"outputs": [{"name": "result", "type": "application/json", "sha256": SHA_B, "evidence_refs": []}]},
        private_key=researcher,
        event_id=str(uuid4()),
        idempotency_key="complete-approved-fixture",
        recorded_at=NOW,
        step_id="research",
        attempt=1,
    )
    missing = _evaluate(scheduler, "analyze")
    assert "APPROVAL_REQUIRED" in {item["code"] for item in missing["blockers"]}
    preview = build_approval_preview(
        approval_kind="STEP_APPROVAL",
        run_id=run["run_id"],
        workflow_sha256=run["workflow_sha256"],
        step_id="analyze",
        attempt=1,
        tenant_id="local-user",
        project_id="HiveMind",
        action="run attended analyze step",
        destination="research/analyze.md",
        data_classes=["PROJECT_PRIVATE"],
        side_effects=["workflow-step-result"],
        evidence_refs=[],
        rollback={"mode": "GIT_CHECKPOINT", "checkpoint": SHA_A},
        risk_class="HIGH",
        input_sha256=missing["input_sha256"],
        conflict_ids=[],
        existing_capabilities=["workflow:report"],
        requested_capabilities=["workflow:report"],
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )
    approver_identity = {
        "actor_id": "approver",
        "persona_id": "persona:owner",
        "surface_id": "surface:human",
        "machine_id": "machine:hive-lab-host",
        "project_id": "HiveMind",
        "app_actor": "app:approval",
        "key_id": public_key_id(approver.public_key()),
    }
    decision = authority.decide(
        preview,
        decision="APPROVED",
        approver=approver_identity,
        authorization_ref="owner-attended-alpha",
        private_key=approver,
        approval_id=str(uuid4()),
        idempotency_key="approve-analyze",
        decided_at=NOW,
    )
    approved = _evaluate(
        scheduler,
        "analyze",
        approvals=[{"approval": decision["approval"], "preview": preview}],
    )
    assert approved["ready"] is True
    with pytest.raises(ProtocolError, match="stale"):
        scheduler.claim(
            approved,
            agent_id="analyst",
            actor=_agent_identity(analyst, "analyst"),
            private_key=analyst,
            expires_at=NOW + timedelta(minutes=12),
            event_id=str(uuid4()),
            idempotency_key="expired-approval-claim",
            now=NOW + timedelta(minutes=11),
            approvals=[{"approval": decision["approval"], "preview": preview}],
        )


def test_conflict_exception_is_exact_and_cannot_approve_protected_step(
    tmp_path: Path,
) -> None:
    scheduler, journal, run, researcher, _, approver, authority = _fixture(
        tmp_path, approval_required=True
    )
    scheduler.claim(
        _evaluate(scheduler, "research"),
        agent_id="researcher",
        actor=_agent_identity(researcher, "researcher"),
        private_key=researcher,
        expires_at=NOW + timedelta(minutes=5),
        event_id=str(uuid4()),
        idempotency_key="claim-conflict-exception-fixture",
        now=NOW,
    )
    journal.append(
        run["run_id"],
        event_type="STEP_COMPLETED",
        actor=_agent_identity(researcher, "researcher"),
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
        private_key=researcher,
        event_id=str(uuid4()),
        idempotency_key="complete-conflict-exception-fixture",
        recorded_at=NOW,
        step_id="research",
        attempt=1,
    )
    arguments = {
        "attempt": 1,
        "current_source_commit": SHA_B,
        "current_machine_id": "machine:hive-lab-host",
        "task_sha256": "c" * 64,
        "existing_task_sha256s": [],
        "required_evidence_refs": ["evidence:required"],
        "available_evidence_refs": [],
        "now": NOW,
    }
    blocked = scheduler.evaluate("analyze", approvals=[], **arguments)
    conflicts = {
        item["code"]: item
        for item in blocked["blockers"]
        if item.get("conflict_id") is not None
    }
    assert {"MISSING_EVIDENCE", "STALE_SOURCE_COMMIT"}.issubset(conflicts)

    preview = build_approval_preview(
        approval_kind="CONFLICT_EXCEPTION",
        run_id=run["run_id"],
        workflow_sha256=run["workflow_sha256"],
        step_id="analyze",
        attempt=1,
        tenant_id="local-user",
        project_id="HiveMind",
        action="except one exact stale source conflict",
        destination="research/analyze.md",
        data_classes=["PROJECT_PRIVATE"],
        side_effects=["conflict-exception"],
        evidence_refs=[],
        rollback={"mode": "NONE"},
        risk_class="HIGH",
        input_sha256=blocked["input_sha256"],
        conflict_ids=[conflicts["STALE_SOURCE_COMMIT"]["conflict_id"]],
        existing_capabilities=["workflow:report"],
        requested_capabilities=["workflow:report"],
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )
    decision = authority.decide(
        preview,
        decision="APPROVED",
        approver={
            "actor_id": "approver",
            "persona_id": "persona:owner",
            "surface_id": "surface:human",
            "machine_id": "machine:hive-lab-host",
            "project_id": "HiveMind",
            "app_actor": "app:approval",
            "key_id": public_key_id(approver.public_key()),
        },
        authorization_ref="owner-attended-alpha",
        private_key=approver,
        approval_id=str(uuid4()),
        idempotency_key="except-exact-stale-source",
        decided_at=NOW,
    )
    evaluated = scheduler.evaluate(
        "analyze",
        approvals=[{"approval": decision["approval"], "preview": preview}],
        **arguments,
    )
    codes = {item["code"] for item in evaluated["blockers"]}
    assert "STALE_SOURCE_COMMIT" not in codes
    assert {"MISSING_EVIDENCE", "APPROVAL_REQUIRED"}.issubset(codes)
    assert evaluated["approved_conflict_ids"] == [
        conflicts["STALE_SOURCE_COMMIT"]["conflict_id"]
    ]
    assert evaluated["ready"] is False


def test_matching_selects_one_deterministic_or_explicit_assignee(tmp_path: Path) -> None:
    scheduler, _, _, _, _, _, _ = _fixture(tmp_path)
    alternate = Ed25519PrivateKey.generate()
    scheduler.registry["agents"]["researcher-z"] = _agent_record(
        alternate, "researcher-z", ["vault:search"]
    )
    automatic = _evaluate(scheduler, "research")
    assert automatic["eligible_agents"] == ["researcher", "researcher-z"]
    assert automatic["assigned_agent_id"] == "researcher"

    explicit = scheduler.evaluate(
        "research",
        attempt=1,
        current_source_commit=SHA_A,
        current_machine_id="machine:hive-lab-host",
        task_sha256="c" * 64,
        existing_task_sha256s=[],
        required_evidence_refs=[],
        available_evidence_refs=[],
        approvals=[],
        now=NOW,
        explicit_agent_id="researcher-z",
    )
    assert explicit["eligible_agents"] == ["researcher-z"]
    assert explicit["assigned_agent_id"] == "researcher-z"


def test_stale_readiness_wrong_key_and_double_claim_refuse(tmp_path: Path) -> None:
    scheduler, _, _, researcher, analyst, _, _ = _fixture(tmp_path)
    ready = _evaluate(scheduler, "research")
    with pytest.raises(ProtocolError):
        scheduler.claim(
            ready,
            agent_id="researcher",
            actor=_agent_identity(analyst, "researcher"),
            private_key=analyst,
            expires_at=NOW + timedelta(minutes=5),
            event_id=str(uuid4()),
            idempotency_key="wrong-key",
            now=NOW,
        )
    forged = copy.deepcopy(ready)
    forged["input_sha256"] = "f" * 64
    forged_body = dict(forged)
    forged_body.pop("readiness_sha256")
    forged["readiness_sha256"] = document_digest(forged_body)
    with pytest.raises(ProtocolError, match="stale"):
        scheduler.claim(
            forged,
            agent_id="researcher",
            actor=_agent_identity(researcher, "researcher"),
            private_key=researcher,
            expires_at=NOW + timedelta(minutes=5),
            event_id=str(uuid4()),
            idempotency_key="fabricated-readiness",
            now=NOW,
        )
    with pytest.raises(ProtocolError):
        scheduler.claim(
            ready,
            agent_id="researcher",
            actor=_agent_identity(researcher, "researcher"),
            private_key=researcher,
            expires_at=NOW,
            event_id=str(uuid4()),
            idempotency_key="expired-claim",
            now=NOW,
        )
    scheduler.claim(
        ready,
        agent_id="researcher",
        actor=_agent_identity(researcher, "researcher"),
        private_key=researcher,
        expires_at=NOW + timedelta(minutes=5),
        event_id="55555555-5555-4555-8555-555555555555",
        idempotency_key="first-claim",
        now=NOW,
    )
    with pytest.raises(ProtocolError, match="stale"):
        scheduler.claim(
            ready,
            agent_id="researcher",
            actor=_agent_identity(researcher, "researcher"),
            private_key=researcher,
            expires_at=NOW + timedelta(minutes=5),
            event_id="66666666-6666-4666-8666-666666666666",
            idempotency_key="double-claim",
            now=NOW,
        )


def test_claim_crash_is_adopted_without_duplicate(tmp_path: Path) -> None:
    scheduler, journal, run, researcher, _, _, _ = _fixture(tmp_path)
    ready = _evaluate(scheduler, "research")
    arguments = {
        "agent_id": "researcher",
        "actor": _agent_identity(researcher, "researcher"),
        "private_key": researcher,
        "expires_at": NOW + timedelta(minutes=5),
        "event_id": "77777777-7777-4777-8777-777777777777",
        "idempotency_key": "claim-crash",
        "now": NOW,
    }
    with pytest.raises(SystemExit, match="claim crash"):
        scheduler.claim(
            ready,
            **arguments,
            after_event_write=lambda: (_ for _ in ()).throw(SystemExit("claim crash")),
        )
    recovered = scheduler.claim(ready, **arguments)
    assert recovered["changed"] is True
    assert len([event for event in journal.events(run["run_id"]) if event.event_type == "STEP_CLAIMED"]) == 1


def test_expired_claim_does_not_consume_active_concurrency_limit(tmp_path: Path) -> None:
    scheduler, _, _, researcher, _, _, _ = _fixture(
        tmp_path, max_concurrent_claims=1
    )
    ready = _evaluate(scheduler, "research")
    scheduler.claim(
        ready,
        agent_id="researcher",
        actor=_agent_identity(researcher, "researcher"),
        private_key=researcher,
        expires_at=NOW + timedelta(minutes=5),
        event_id=str(uuid4()),
        idempotency_key="expiring-claim",
        now=NOW,
    )
    after_expiry = _evaluate(
        scheduler, "research", now=NOW + timedelta(minutes=6)
    )
    assert after_expiry["ready"] is True
    assert "CLAIM_LIMIT_REACHED" not in {
        item["code"] for item in after_expiry["blockers"]
    }
