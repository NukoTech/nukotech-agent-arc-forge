from __future__ import annotations

import hashlib
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.core import public_key_id
from hive_protocol.workflows.replay import WorkflowReplay

from test_workflow_events import NOW, _identity, _start


def _manifest(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_replay_reconstructs_complete_timeline_without_mutation_or_execution(
    tmp_path: Path,
) -> None:
    key = Ed25519PrivateKey.generate()
    journal, _, run = _start(tmp_path, key)
    events = [
        ("CONFLICT_DETECTED", {"conflict_ids": ["conflict:" + "c" * 64]}, None, None),
        ("APPROVAL_RECORDED", {"approval_id": "approval:alpha"}, "research", 1),
        ("STEP_ASSIGNED", {"agent_id": "agent:researcher"}, "research", 1),
        ("STEP_CLAIMED", {"claim_id": "claim:attempt-1"}, "research", 1),
        ("STEP_FAILED", {"reason_code": "FIXTURE_FAILURE"}, "research", 1),
        ("STEP_RETRY_CREATED", {"prior_attempt": 1}, "research", 2),
        ("STEP_CLAIMED", {"claim_id": "claim:attempt-2"}, "research", 2),
        ("STEP_OUTPUT", {"tokens_used": 25, "github_ref": "example-org/example-repo#1001"}, "research", 2),
        ("STEP_COMPLETED", {"outputs": [{"name": "result", "sha256": "d" * 64}]}, "research", 2),
        ("RUN_COMPLETED", {"result": "SUCCESS"}, None, None),
    ]
    for index, (event_type, payload, step_id, attempt) in enumerate(events, start=3):
        journal.append(
            run["run_id"],
            event_type=event_type,
            actor=_identity(key),
            payload=payload,
            private_key=key,
            event_id=f"{index:08d}-0000-4000-8000-000000000000",
            idempotency_key=f"event-{index}",
            recorded_at=NOW,
            step_id=step_id,
            attempt=attempt,
        )
    hive = tmp_path / "hive"
    before = _manifest(hive)
    replay = WorkflowReplay(
        hive, {public_key_id(key.public_key()): key.public_key()}
    ).reconstruct(run["run_id"])
    after = _manifest(hive)

    assert before == after
    assert replay["state"] == "COMPLETED"
    assert replay["workflow_sha256"] == run["workflow_sha256"]
    assert replay["steps"]["research"]["attempts"]["1"]["state"] == "FAILED"
    assert replay["steps"]["research"]["attempts"]["2"]["state"] == "COMPLETED"
    assert replay["conflicts"] == ["conflict:" + "c" * 64]
    assert replay["approvals"] == ["approval:alpha"]
    assert replay["resource_use"]["tokens_used"] == 25
    assert replay["github_refs"] == ["example-org/example-repo#1001"]
    assert replay["execution_performed"] is False
    assert replay["mutation_performed"] is False
