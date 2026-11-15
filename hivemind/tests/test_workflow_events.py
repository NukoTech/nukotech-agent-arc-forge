from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.core import ProtocolError, public_key_id, sign_document
from hive_protocol.workflows.events import WorkflowRunJournal
from hive_protocol.workflows.models import workflow_document_digest


NOW = datetime(2026, 9, 1, 8, 0, tzinfo=timezone.utc)
SHA_A = "a" * 64
SHA_B = "b" * 64


def _identity(key: Ed25519PrivateKey, actor_id: str = "agent:operator") -> dict[str, str]:
    return {
        "actor_id": actor_id,
        "persona_id": "persona:Director",
        "surface_id": "surface:LeadA",
        "machine_id": "machine:hive-lab-host",
        "project_id": "HiveMind",
        "app_actor": "app:hive-local-attended",
        "key_id": public_key_id(key.public_key()),
    }


def _definition(key: Ed25519PrivateKey) -> dict[str, object]:
    return sign_document(
        {
            "schema_version": "hive.workflow-definition.v1",
            "workflow_id": "workflow:journal",
            "version": 1,
            "tenant_id": "local-user",
            "project_id": "HiveMind",
            "title": "Journal fixture",
            "description": "One attended step.",
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
                        "branches": ["workflows/research"],
                        "files": ["research/report.md"],
                    },
                    "rollback": {
                        "mode": "GIT_CHECKPOINT",
                        "compensation_step_id": None,
                    },
                }
            ],
            "metadata": {"tags": ["internal-alpha"]},
            "publisher": _identity(key),
            "created_at": NOW.isoformat().replace("+00:00", "Z"),
        },
        key,
    )


def _run(key: Ed25519PrivateKey, definition: dict[str, object]) -> dict[str, object]:
    return sign_document(
        {
            "schema_version": "hive.workflow-run.v1",
            "run_id": "11111111-1111-4111-8111-111111111111",
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
            "launched_by": _identity(key),
            "started_at": NOW.isoformat().replace("+00:00", "Z"),
        },
        key,
    )


def _journal(tmp_path: Path, key: Ed25519PrivateKey) -> WorkflowRunJournal:
    return WorkflowRunJournal(
        tmp_path / "hive", {public_key_id(key.public_key()): key.public_key()}
    )


def _start(tmp_path: Path, key: Ed25519PrivateKey) -> tuple[WorkflowRunJournal, dict, dict]:
    definition = _definition(key)
    run = _run(key, definition)
    journal = _journal(tmp_path, key)
    journal.start(
        definition,
        run,
        private_key=key,
        event_id="22222222-2222-4222-8222-222222222222",
        idempotency_key="start-journal",
    )
    return journal, definition, run


def test_run_binds_exact_definition_and_appends_contiguous_signed_events(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    journal, definition, run = _start(tmp_path, key)
    assert journal.load_run(run["run_id"]).workflow_sha256 == workflow_document_digest(definition)

    claim = journal.append(
        run["run_id"],
        event_type="STEP_CLAIMED",
        actor=_identity(key),
        payload={"claim_id": "claim:research", "source_commit": SHA_A},
        private_key=key,
        event_id="33333333-3333-4333-8333-333333333333",
        idempotency_key="claim-research",
        recorded_at=NOW,
        step_id="research",
        attempt=1,
    )
    completed = journal.append(
        run["run_id"],
        event_type="STEP_COMPLETED",
        actor=_identity(key),
        payload={"outputs": [{"name": "result", "sha256": SHA_B}]},
        private_key=key,
        event_id="44444444-4444-4444-8444-444444444444",
        idempotency_key="complete-research",
        recorded_at=NOW,
        step_id="research",
        attempt=1,
    )
    assert claim["event"]["sequence"] == 2
    assert completed["event"]["sequence"] == 3
    events = journal.events(run["run_id"])
    assert [event.sequence for event in events] == [1, 2, 3]
    assert events[1].previous_event_sha256 == events[0].digest
    assert events[2].previous_event_sha256 == events[1].digest


def test_start_refuses_wrong_definition_binding_and_historical_rewrite(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    definition = _definition(key)
    run = _run(key, definition)
    wrong = copy.deepcopy(run)
    wrong["workflow_sha256"] = SHA_A
    wrong = sign_document(wrong, key)
    with pytest.raises(ProtocolError):
        _journal(tmp_path, key).start(
            definition,
            wrong,
            private_key=key,
            event_id=str(uuid4()),
            idempotency_key="wrong-binding",
        )

    journal, _, persisted_run = _start(tmp_path, key)
    rewritten = copy.deepcopy(persisted_run)
    rewritten["input_manifest_sha256"] = SHA_A
    rewritten = sign_document(rewritten, key)
    with pytest.raises(ProtocolError):
        journal.start(
            definition,
            rewritten,
            private_key=key,
            event_id=str(uuid4()),
            idempotency_key="rewrite-run",
        )


def test_append_replay_and_crash_after_event_are_exact(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    journal, _, run = _start(tmp_path, key)
    journal.append(
        run["run_id"],
        event_type="STEP_CLAIMED",
        actor=_identity(key),
        payload={"claim_id": "claim:failure-fixture", "source_commit": SHA_A},
        private_key=key,
        event_id="44444444-4444-4444-8444-444444444444",
        idempotency_key="claim-failure-fixture",
        recorded_at=NOW,
        step_id="research",
        attempt=1,
    )
    arguments = {
        "event_type": "STEP_FAILED",
        "actor": _identity(key),
        "payload": {"reason_code": "FIXTURE_FAILURE"},
        "private_key": key,
        "event_id": "55555555-5555-4555-8555-555555555555",
        "idempotency_key": "fail-research",
        "recorded_at": NOW,
        "step_id": "research",
        "attempt": 1,
    }
    with pytest.raises(SystemExit, match="event crash"):
        journal.append(
            run["run_id"],
            **arguments,
            after_event_write=lambda: (_ for _ in ()).throw(SystemExit("event crash")),
        )
    recovered = _journal(tmp_path, key).append(run["run_id"], **arguments)
    assert recovered["changed"] is True
    replay = journal.append(run["run_id"], **arguments)
    assert replay["changed"] is False
    assert len(journal.events(run["run_id"])) == 3


def test_corrupt_event_payload_gap_and_wrong_signer_fail_closed(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    stranger = Ed25519PrivateKey.generate()
    journal, _, run = _start(tmp_path, key)
    with pytest.raises(ProtocolError):
        journal.append(
            run["run_id"],
            event_type="STEP_PROGRESS",
            actor=_identity(stranger, "agent:stranger"),
            payload={"progress": 1},
            private_key=stranger,
            event_id=str(uuid4()),
            idempotency_key="unknown-signer",
            recorded_at=NOW,
            step_id="research",
            attempt=1,
        )

    journal.append(
        run["run_id"],
        event_type="STEP_PROGRESS",
        actor=_identity(key),
        payload={"progress": 1},
        private_key=key,
        event_id="66666666-6666-4666-8666-666666666666",
        idempotency_key="progress",
        recorded_at=NOW,
        step_id="research",
        attempt=1,
    )
    path = journal.event_paths(run["run_id"])[1]
    event = json.loads(path.read_text(encoding="utf-8"))
    event["payload"]["progress"] = 2
    path.write_text(json.dumps(event), encoding="utf-8")
    with pytest.raises(ProtocolError):
        journal.events(run["run_id"])


def test_event_gap_and_run_level_role_mismatch_fail_closed(tmp_path: Path) -> None:
    operator = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    definition = _definition(operator)
    run = _run(operator, definition)
    journal = WorkflowRunJournal(
        tmp_path / "hive",
        {
            public_key_id(operator.public_key()): operator.public_key(),
            public_key_id(other.public_key()): other.public_key(),
        },
    )
    journal.start(
        definition,
        run,
        private_key=operator,
        event_id="88888888-8888-4888-8888-888888888888",
        idempotency_key="start-role",
    )
    with pytest.raises(ProtocolError):
        journal.append(
            run["run_id"],
            event_type="RUN_COMPLETED",
            actor=_identity(other, "agent:other"),
            payload={"result": "forged completion"},
            private_key=other,
            event_id="99999999-9999-4999-8999-999999999999",
            idempotency_key="forged-completion",
            recorded_at=NOW,
            step_id=None,
            attempt=None,
        )

    journal.append(
        run["run_id"],
        event_type="STEP_PROGRESS",
        actor=_identity(operator),
        payload={"progress": 1},
        private_key=operator,
        event_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        idempotency_key="gap-progress",
        recorded_at=NOW,
        step_id="research",
        attempt=1,
    )
    second = journal.event_paths(run["run_id"])[1]
    second.rename(second.with_name(second.name.replace("000000002", "000000003")))
    with pytest.raises(ProtocolError, match="gapped"):
        journal.events(run["run_id"])


def test_trusted_agent_cannot_sign_operator_control_events(tmp_path: Path) -> None:
    operator = Ed25519PrivateKey.generate()
    agent = Ed25519PrivateKey.generate()
    definition = _definition(operator)
    run = _run(operator, definition)
    journal = WorkflowRunJournal(
        tmp_path / "hive",
        {
            public_key_id(operator.public_key()): operator.public_key(),
            public_key_id(agent.public_key()): agent.public_key(),
        },
    )
    journal.start(
        definition,
        run,
        private_key=operator,
        event_id=str(uuid4()),
        idempotency_key="start-control-role",
    )
    with pytest.raises(ProtocolError, match="ROLE_MISMATCH"):
        journal.append(
            run["run_id"],
            event_type="STEP_RETRY_CREATED",
            actor=_identity(agent, "agent:worker"),
            payload={"failed_attempt": 1, "new_attempt": 2},
            private_key=agent,
            event_id=str(uuid4()),
            idempotency_key="forged-retry-control",
            recorded_at=NOW,
            step_id="research",
            attempt=2,
        )


def test_nested_run_symlink_cannot_redirect_event_reads_or_writes(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    journal, _, run = _start(tmp_path, key)
    run_root = (
        tmp_path
        / "hive"
        / ".hive"
        / "receipts"
        / "workflows"
        / run["run_id"]
    )
    outside = tmp_path / "outside-events"
    run_root.rename(outside)
    run_root.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ProtocolError, match="WORKFLOW_JOURNAL_BOUNDARY"):
        journal.events(run["run_id"])
    before = sorted(path.relative_to(outside) for path in outside.rglob("*"))
    with pytest.raises(ProtocolError, match="WORKFLOW_JOURNAL_BOUNDARY"):
        journal.append(
            run["run_id"],
            event_type="STEP_PROGRESS",
            actor=_identity(key),
            payload={"progress": 1},
            private_key=key,
            event_id=str(uuid4()),
            idempotency_key="nested-symlink-event",
            recorded_at=NOW,
            step_id="research",
            attempt=1,
        )
    assert sorted(path.relative_to(outside) for path in outside.rglob("*")) == before


def test_start_crash_after_run_file_is_recovered_without_duplicate_event(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    definition = _definition(key)
    run = _run(key, definition)
    journal = _journal(tmp_path, key)
    arguments = {
        "private_key": key,
        "event_id": "77777777-7777-4777-8777-777777777777",
        "idempotency_key": "start-crash",
    }
    with pytest.raises(SystemExit, match="run crash"):
        journal.start(
            definition,
            run,
            **arguments,
            after_run_write=lambda: (_ for _ in ()).throw(SystemExit("run crash")),
        )
    recovered = _journal(tmp_path, key).start(definition, run, **arguments)
    assert recovered["changed"] is True
    assert len(journal.events(run["run_id"])) == 1
