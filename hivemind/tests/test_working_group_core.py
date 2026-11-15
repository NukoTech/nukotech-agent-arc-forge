from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.core import ProtocolError, document_digest, public_key_id
from hive_protocol.operator.lifecycle import safe_uninstall
from hive_protocol.operator.projection import OperatorProjection
from hive_protocol.project_state.store import ProjectStateStore
from hive_protocol.tasks.engine import TaskEngine, TaskError, TaskIdentity


def identity(suffix: str) -> TaskIdentity:
    return TaskIdentity(
        persona_id=f"persona-{suffix}",
        surface_id=f"surface-{suffix}",
        machine_id=f"machine-{suffix}",
        project_id="project-alpha",
        app_actor=f"app-{suffix}",
    )


class WorkingGroupCoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.creator_key = Ed25519PrivateKey.generate()
        self.assignee_key = Ed25519PrivateKey.generate()
        self.creator = identity("creator")
        self.assignee = identity("worker")
        self.engine = TaskEngine(self.root)
        self.future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def task(self) -> dict[str, object]:
        return self.engine.create(
            identity=self.creator,
            assignee=self.assignee,
            operation="index.document",
            payload={"title": "durable fact"},
            capability="project.write",
            source_refs=[{"uri": "git:blob/example", "sha256": "a" * 64}],
            private_key=self.creator_key,
            task_id="task-001",
            expires_at=self.future,
        )

    def test_full_lifecycle_is_signed_durable_and_recoverable(self) -> None:
        task = self.task()
        self.assertEqual(task["state"], "CREATED")
        self.assertEqual(self.engine.recover(), ["task-001"])
        self.engine.transition("task-001", target="ASSIGNED", actor=self.creator, private_key=self.creator_key, expected_version=1, event_id="event-assign", nonce="n" * 16)
        self.engine.transition("task-001", target="ACCEPTED", actor=self.assignee, private_key=self.assignee_key, expected_version=2, event_id="event-accept", nonce="o" * 16)
        self.engine.transition("task-001", target="ACKNOWLEDGED", actor=self.assignee, private_key=self.assignee_key, expected_version=3, event_id="event-ack", nonce="p" * 16)
        self.engine.transition("task-001", target="PROGRESS", actor=self.assignee, private_key=self.assignee_key, expected_version=4, event_id="event-progress", nonce="q" * 16)
        receipt = self.engine.transition("task-001", target="COMPLETED", actor=self.assignee, private_key=self.assignee_key, expected_version=5, result={"changed": True}, artifact_refs=[{"uri": "state.json", "sha256": "b" * 64}], event_id="event-complete", nonce="r" * 16)
        self.assertEqual(receipt["state_after"], "COMPLETED")
        self.assertEqual(self.engine._load("task-001")["version"], 6)
        self.engine.verify_all_receipts()
        self.assertEqual(self.engine.recover(), [])

    def test_rejection_and_cancellation_are_terminal(self) -> None:
        self.task()
        self.engine.transition("task-001", target="ASSIGNED", actor=self.creator, private_key=self.creator_key, expected_version=1, event_id="assign-reject", nonce="v" * 16)
        self.engine.transition("task-001", target="REJECTED", actor=self.assignee, private_key=self.assignee_key, expected_version=2, event_id="reject", nonce="w" * 16)
        with self.assertRaisesRegex(TaskError, "TASK_TRANSITION_INVALID"):
            self.engine.transition("task-001", target="PROGRESS", actor=self.assignee, private_key=self.assignee_key, expected_version=3, event_id="after-reject", nonce="x" * 16)
        second = self.engine.create(identity=self.creator, assignee=self.assignee, operation="cancel.me", payload={}, capability="project.write", source_refs=[], private_key=self.creator_key, task_id="task-002", expires_at=self.future)
        self.engine.transition("task-002", target="CANCELLED", actor=self.creator, private_key=self.creator_key, expected_version=1, event_id="cancel", nonce="y" * 16)
        self.assertEqual(self.engine._load("task-002")["state"], "CANCELLED")

    def test_wrong_recipient_stale_and_replay_are_rejected(self) -> None:
        self.task()
        with self.assertRaisesRegex(TaskError, "TASK_UNAUTHORIZED"):
            self.engine.transition("task-001", target="ASSIGNED", actor=self.assignee, private_key=self.assignee_key, expected_version=1, event_id="bad", nonce="s" * 16)
        self.engine.transition("task-001", target="ASSIGNED", actor=self.creator, private_key=self.creator_key, expected_version=1, event_id="assign", nonce="t" * 16)
        with self.assertRaisesRegex(TaskError, "TASK_STALE"):
            self.engine.transition("task-001", target="ACCEPTED", actor=self.assignee, private_key=self.assignee_key, expected_version=1, event_id="stale", nonce="u" * 16)
        with self.assertRaisesRegex(TaskError, "TASK_REPLAY"):
            self.engine.transition("task-001", target="ACCEPTED", actor=self.assignee, private_key=self.assignee_key, expected_version=2, event_id="assign", nonce="t" * 16)

    def test_project_state_snapshot_rollback_operator_and_safe_uninstall(self) -> None:
        state = ProjectStateStore(self.root / "project_state")
        state.initialize("project-alpha", self.creator)
        before = state.digest("project-alpha")
        updated = state.apply("project-alpha", expected_version=1, task_id="task-001", patch={"status": "complete"})
        snapshot, _ = state.snapshot("project-alpha", "before-rollback")
        state.apply("project-alpha", expected_version=2, task_id="task-002", patch={"status": "other"})
        state.rollback("project-alpha", snapshot)
        self.assertEqual(state.digest("project-alpha"), document_digest(updated))
        projection = OperatorProjection(self.root, machine_status={"machine_id": "hive-lab-host", "online": False}).read()
        self.assertEqual(projection["machine_status"]["machine_id"], "hive-lab-host")

        (self.root / "project_material").mkdir()
        (self.root / "project_material" / "user.md").write_text("user-authored", encoding="utf-8")
        (self.root / ".hive-root-manifest.json").write_text(json.dumps({"schema_version": "hive.cycle2.root-manifest.v1"}), encoding="utf-8")
        result = safe_uninstall(self.root)
        self.assertEqual(result["status"], "UNINSTALLED")
        self.assertEqual((self.root / "project_material" / "user.md").read_text(encoding="utf-8"), "user-authored")

    def test_identity_and_immutable_reference_boundaries(self) -> None:
        with self.assertRaisesRegex(TaskError, "TASK_IDENTITY_COLLAPSE"):
            TaskIdentity(persona_id="same", surface_id="same", machine_id="m", project_id="p", app_actor="a")
        with self.assertRaisesRegex(TaskError, "TASK_REFERENCE_INVALID"):
            self.engine.create(identity=self.creator, assignee=self.assignee, operation="x", payload={}, capability="c", source_refs=[{"uri": "x", "sha256": "bad"}], private_key=self.creator_key)


if __name__ == "__main__":
    unittest.main()
