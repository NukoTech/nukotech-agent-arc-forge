import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.agents import AgentOperations, build_signed_ack, build_signed_task, public_pem
from hive_protocol.core import ProtocolError, document_digest, public_key_id
from hive_protocol.storage import atomic_write_json


def _agent(agent_id, key, capabilities, aliases=None):
    return {
        "agent_id": agent_id, "tenant_id": "tenant-a", "workspace_id": "alpha",
        "persona_id": f"persona:{agent_id}", "surface_id": f"surface:{agent_id}",
        "capabilities": capabilities, "trust_level": "ATTENDED", "recipient_aliases": aliases or [],
        "key_id": public_key_id(key.public_key()), "public_key_pem": public_pem(key), "active": True,
    }


class AgentOperationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.sender_key, self.worker_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        self.ops = AgentOperations(self.root / "ops")
        self.ops.register(_agent("sender", self.sender_key, ["memory.propose"]))
        self.ops.register(_agent("worker", self.worker_key, ["memory.propose"], ["local-worker"]))

    def tearDown(self):
        self.temporary.cleanup()

    def task(self):
        now = datetime.now(timezone.utc)
        return build_signed_task({
            "schema_version": "hive.task-envelope.v1", "task_id": str(uuid4()),
            "tenant_id": "tenant-a", "workspace_id": "alpha", "sender_agent": "sender",
            "recipient_agent": "worker", "required_capabilities": ["memory.propose"],
            "required_trust": "PROPOSE", "operation": "memory.propose",
            "payload": {"proposal": "retain this bounded fact"}, "provenance": ["fixture:alpha"],
            "issued_at": now.isoformat(), "expires_at": (now + timedelta(minutes=10)).isoformat(),
            "nonce": uuid4().hex,
        }, self.sender_key)

    def acknowledgment(self, task):
        return build_signed_ack({
            "schema_version": "hive.task-acknowledgment.v1", "ack_id": str(uuid4()),
            "task_id": task["task_id"], "tenant_id": "tenant-a", "workspace_id": "alpha",
            "recipient_agent": "worker", "outcome": "APPLIED", "changed": True,
            "state_sha256": document_digest({"state": "changed"}),
            "acknowledged_at": datetime.now(timezone.utc).isoformat(), "nonce": uuid4().hex,
        }, self.worker_key)

    def test_signed_delivery_ack_and_fresh_instance_persistence(self):
        envelope = self.task()
        self.assertEqual(self.ops.deliver(envelope)["status"], "DELIVERED")
        ack = self.acknowledgment(envelope)
        self.assertTrue(self.ops.acknowledge(ack)["changed"])
        next_turn = AgentOperations(self.root / "ops").retrieve_next_turn(
            envelope["task_id"], tenant_id="tenant-a", workspace_id="alpha", recipient_agent="worker"
        )
        self.assertEqual(next_turn["status"], "PERSISTED_NEXT_TURN")
        self.assertEqual(next_turn["acknowledgment"]["state_sha256"], ack["state_sha256"])

    def test_recipient_alias_resolves_but_signed_task_requires_canonical_id(self):
        self.assertEqual(
            self.ops.resolve_recipient("tenant-a", "alpha", "local-worker")["agent_id"], "worker"
        )

    def test_next_turn_binds_task_path_and_acknowledgment_scope(self):
        envelope = self.task()
        self.ops.deliver(envelope)
        acknowledgment = self.acknowledgment(envelope)
        self.ops.acknowledge(acknowledgment)
        task_path = self.root / "ops" / "inbox" / "worker" / f"{envelope['task_id']}.json"
        receipt_path = self.root / "ops" / "receipts" / f"{envelope['task_id']}.json"

        atomic_write_json(task_path, self.task())
        with self.assertRaisesRegex(ProtocolError, "NEXT_TURN_SCOPE_INVALID"):
            self.ops.retrieve_next_turn(
                envelope["task_id"],
                tenant_id="tenant-a",
                workspace_id="alpha",
                recipient_agent="worker",
            )

        atomic_write_json(task_path, envelope)
        foreign_ack = build_signed_ack(
            {
                **{
                    key: value
                    for key, value in acknowledgment.items()
                    if key != "signature"
                },
                "tenant_id": "tenant-other",
                "ack_id": str(uuid4()),
                "nonce": uuid4().hex,
            },
            self.worker_key,
        )
        atomic_write_json(receipt_path, foreign_ack)
        with self.assertRaisesRegex(ProtocolError, "NEXT_TURN_SCOPE_INVALID"):
            self.ops.retrieve_next_turn(
                envelope["task_id"],
                tenant_id="tenant-a",
                workspace_id="alpha",
                recipient_agent="worker",
            )


if __name__ == "__main__":
    unittest.main()
