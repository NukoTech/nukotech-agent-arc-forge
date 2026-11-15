from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.core import ProtocolError, document_digest, public_key_id, sign_document
from hive_protocol.workflows.models import (
    AgentSession,
    WorkflowApproval,
    WorkflowDefinition,
    WorkflowEvent,
    WorkflowRun,
    workflow_document_digest,
)


NOW = datetime(2026, 9, 1, 7, 0, tzinfo=timezone.utc)
SHA_A = "a" * 64
SHA_B = "b" * 64


def _actor(key: Ed25519PrivateKey, actor_id: str = "agent:operator") -> dict[str, str]:
    return {
        "actor_id": actor_id,
        "persona_id": "persona:Director",
        "surface_id": "surface:LeadA",
        "machine_id": "machine:hive-lab-host",
        "project_id": "HiveMind",
        "app_actor": "app:hive-local-attended",
        "key_id": public_key_id(key.public_key()),
    }


def _step(step_id: str = "research") -> dict[str, object]:
    return {
        "step_id": step_id,
        "kind": "TASK",
        "dependencies": [],
        "inputs": [],
        "outputs": [{"name": "brief", "type": "application/json"}],
        "required_capabilities": ["vault:search"],
        "required_trust": "ATTENDED",
        "target": {
            "project_id": "HiveMind",
            "machine_id": "machine:hive-lab-host",
            "surface_id": None,
        },
        "approval": {"required": False, "risk_class": "LOW"},
        "retry": {"max_attempts": 2, "timeout_seconds": 300},
        "resources": {
            "max_tokens": 1000,
            "max_cost_microunits": 5000,
            "max_memory_mb": 256,
        },
        "ownership": {
            "branches": ["workflows/alpha"],
            "files": ["research/alpha.md"],
        },
        "rollback": {"mode": "GIT_CHECKPOINT", "compensation_step_id": None},
    }


def _definition(key: Ed25519PrivateKey) -> dict[str, object]:
    return sign_document(
        {
            "schema_version": "hive.workflow-definition.v1",
            "workflow_id": "workflow:alpha",
            "version": 1,
            "tenant_id": "local-user",
            "project_id": "HiveMind",
            "title": "Attended research workflow",
            "description": "Produce one bounded research brief.",
            "parent_digest": None,
            "steps": [_step()],
            "metadata": {"tags": ["internal-alpha"]},
            "publisher": _actor(key),
            "created_at": NOW.isoformat().replace("+00:00", "Z"),
        },
        key,
    )


def _run(key: Ed25519PrivateKey, definition: dict[str, object]) -> dict[str, object]:
    return sign_document(
        {
            "schema_version": "hive.workflow-run.v1",
            "run_id": str(uuid4()),
            "workflow_id": definition["workflow_id"],
            "workflow_version": definition["version"],
            "workflow_sha256": workflow_document_digest(definition),
            "tenant_id": "local-user",
            "project_id": "HiveMind",
            "source_commit": SHA_A,
            "input_manifest_sha256": SHA_B,
            "policy": {
                "mode": "ATTENDED",
                "stale_after_seconds": 600,
                "allow_claim_release": True,
                "max_concurrent_claims": 2,
            },
            "launched_by": _actor(key),
            "started_at": NOW.isoformat().replace("+00:00", "Z"),
        },
        key,
    )


def _event(key: Ed25519PrivateKey, run: dict[str, object]) -> dict[str, object]:
    payload = {"definition_verified": True}
    return sign_document(
        {
            "schema_version": "hive.workflow-event.v1",
            "event_id": str(uuid4()),
            "run_id": run["run_id"],
            "workflow_sha256": run["workflow_sha256"],
            "tenant_id": "local-user",
            "project_id": "HiveMind",
            "sequence": 1,
            "event_type": "RUN_STARTED",
            "step_id": None,
            "attempt": None,
            "actor": _actor(key),
            "payload": payload,
            "payload_sha256": document_digest(payload),
            "previous_event_sha256": None,
            "recorded_at": NOW.isoformat().replace("+00:00", "Z"),
        },
        key,
    )


def _approval(key: Ed25519PrivateKey, run: dict[str, object]) -> dict[str, object]:
    return sign_document(
        {
            "schema_version": "hive.workflow-approval.v1",
            "approval_id": str(uuid4()),
            "approval_kind": "STEP_APPROVAL",
            "run_id": run["run_id"],
            "workflow_sha256": run["workflow_sha256"],
            "step_id": "research",
            "attempt": 1,
            "tenant_id": "local-user",
            "project_id": "HiveMind",
            "preview_sha256": SHA_A,
            "input_sha256": SHA_B,
            "decision": "APPROVED",
            "risk_class": "HIGH",
            "approver": _actor(key, "agent:approver"),
            "authorization_ref": "owner-attended-alpha",
            "decided_at": NOW.isoformat().replace("+00:00", "Z"),
            "expires_at": (NOW + timedelta(minutes=10)).isoformat().replace(
                "+00:00", "Z"
            ),
        },
        key,
    )


def _session(key: Ed25519PrivateKey, run: dict[str, object]) -> dict[str, object]:
    return sign_document(
        {
            "schema_version": "hive.agent-session.v1",
            "session_id": str(uuid4()),
            "run_id": run["run_id"],
            "workflow_sha256": run["workflow_sha256"],
            "step_id": "research",
            "attempt": 1,
            "claim_event_id": str(uuid4()),
            "tenant_id": "local-user",
            "project_id": "HiveMind",
            "agent": _actor(key, "agent:researcher"),
            "state": "ACTIVE",
            "heartbeat_at": NOW.isoformat().replace("+00:00", "Z"),
            "progress": {"completed_units": 1, "total_units": 3},
            "resources": {
                "tokens_used": 100,
                "cost_microunits": 500,
                "peak_memory_mb": 64,
            },
            "outputs": [],
            "recorded_at": NOW.isoformat().replace("+00:00", "Z"),
        },
        key,
    )


def test_all_workflow_documents_round_trip_immutably_and_digest_stably() -> None:
    publisher = Ed25519PrivateKey.generate()
    approver = Ed25519PrivateKey.generate()
    agent = Ed25519PrivateKey.generate()
    definition = _definition(publisher)
    run = _run(publisher, definition)
    fixtures = [
        (WorkflowDefinition, definition),
        (WorkflowRun, run),
        (WorkflowEvent, _event(publisher, run)),
        (WorkflowApproval, _approval(approver, run)),
        (AgentSession, _session(agent, run)),
    ]

    for model, document in fixtures:
        parsed = model.from_dict(document)
        assert parsed.as_dict() == document
        assert parsed.digest == workflow_document_digest(document)
        returned = parsed.as_dict()
        returned["project_id"] = "changed"
        assert parsed.project_id == "HiveMind"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(schema_version="hive.workflow-definition.v2"),
        lambda value: value.update(project_id="../escape"),
        lambda value: value.update(unexpected_authority="grant:all"),
        lambda value: value["steps"].append(copy.deepcopy(value["steps"][0])),
        lambda value: value["steps"][0]["resources"].update(max_cost_microunits=float("nan")),
        lambda value: value["publisher"].update(surface_id="persona:Director"),
        lambda value: value["publisher"].update(key_id="ed25519:" + "0" * 24),
    ],
)
def test_workflow_definition_rejects_noncanonical_or_authority_broadening(mutation) -> None:
    document = _definition(Ed25519PrivateKey.generate())
    mutation(document)
    with pytest.raises(ProtocolError):
        WorkflowDefinition.from_dict(document)


def test_run_is_attended_and_binds_exact_definition() -> None:
    key = Ed25519PrivateKey.generate()
    definition = _definition(key)
    run = _run(key, definition)
    assert WorkflowRun.from_dict(run).workflow_sha256 == workflow_document_digest(definition)

    run["policy"]["mode"] = "UNATTENDED"
    with pytest.raises(ProtocolError):
        WorkflowRun.from_dict(run)


def test_event_rejects_payload_tampering_and_bad_attempt_shape() -> None:
    key = Ed25519PrivateKey.generate()
    run = _run(key, _definition(key))
    event = _event(key, run)
    event["payload"]["definition_verified"] = False
    with pytest.raises(ProtocolError, match="payload"):
        WorkflowEvent.from_dict(event)

    step_event = _event(key, run)
    step_event.update(event_type="STEP_CLAIMED", step_id="research", attempt=None)
    step_event = sign_document(step_event, key)
    with pytest.raises(ProtocolError):
        WorkflowEvent.from_dict(step_event)


def test_approval_requires_future_expiry_and_matching_signer() -> None:
    operator = Ed25519PrivateKey.generate()
    approver = Ed25519PrivateKey.generate()
    run = _run(operator, _definition(operator))
    approval = _approval(approver, run)
    approval["expires_at"] = approval["decided_at"]
    approval = sign_document(approval, approver)
    with pytest.raises(ProtocolError):
        WorkflowApproval.from_dict(approval)

    approval = _approval(approver, run)
    approval["approver"]["key_id"] = public_key_id(operator.public_key())
    approval = sign_document(approval, approver)
    with pytest.raises(ProtocolError):
        WorkflowApproval.from_dict(approval)


def test_session_rejects_impossible_progress_and_nonfinite_resources() -> None:
    operator = Ed25519PrivateKey.generate()
    agent = Ed25519PrivateKey.generate()
    run = _run(operator, _definition(operator))
    session = _session(agent, run)
    session["progress"] = {"completed_units": 4, "total_units": 3}
    session = sign_document(session, agent)
    with pytest.raises(ProtocolError):
        AgentSession.from_dict(session)

    session = _session(agent, run)
    session["resources"]["cost_microunits"] = float("inf")
    with pytest.raises(ProtocolError):
        AgentSession.from_dict(session)
