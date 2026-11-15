from __future__ import annotations

import hashlib
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.core import ProtocolError, public_key_id, sign_document, verify_document
from hive_protocol.receiver import (
    ACTIVE_MAILBOX_NAMES,
    LEGACY_ROUTE_NAMES,
    ReceiverMatrix,
    RuntimeAuthorityBinding,
    default_enrollments,
)


class ReceiverMatrixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "receiver"
        self.sender = Ed25519PrivateKey.generate()
        self.receipt = Ed25519PrivateKey.generate()
        sender_id = public_key_id(self.sender.public_key())
        surfaces = ("LeadA", "BuildA", "LeadB", "BuildB", "LeadC", "BuildC", "LeadP", "BuildP")
        actors = {
            "LeadA": "hive-leada-app[bot]",
            "BuildA": "hive-builda-app[bot]",
            "LeadB": "hive-leadb-app[bot]",
            "BuildB": "hive-buildb-app[bot]",
            "LeadC": "hive-leadc-app[bot]",
            "BuildC": "hive-buildc-app[bot]",
            "LeadP": "hive-leadp-app[bot]",
            "BuildP": "hive-buildp-app[bot]",
        }
        self.enrollments = default_enrollments(
            {
                surface: RuntimeAuthorityBinding(
                    runtime_adapter=f"test-adapter-{surface.lower()}",
                    app_actor=actors[surface],
                    verification_key_id=(
                        sender_id
                        if surface == "BuildA"
                        else "ed25519:" + hashlib.sha256(surface.encode()).hexdigest()[:24]
                    ),
                )
                for surface in surfaces
            }
        )
        self.matrix = ReceiverMatrix(
            self.root,
            {sender_id: self.sender.public_key()},
            self.receipt,
            enrollments=self.enrollments,
            max_attempts=2,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def envelope(self, recipient: str = "LeadA", *, message_id: str | None = None, nonce: str | None = None):
        now = datetime.now(timezone.utc)
        return sign_document(
            {
                "schema_version": "hive.receiver-envelope.v1",
                "message_id": message_id or str(uuid4()),
                "nonce": nonce or uuid4().hex,
                "recipient_surface": recipient,
                "created_at": now.isoformat().replace("+00:00", "Z"),
                "expires_at": (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
                "payload_sha256": "a" * 64,
                "source_channel": "03 Reviews and Decisions",
                "delivery": {
                    "wake_mode": "EVENT",
                    "dependency_ids": [],
                    "transport_kind": "FILES_01_04",
                    "transport_actor": "existing-local-filesystem",
                    "authorized": True,
                },
                "authority": {
                    "project_id": "hivemind-sample",
                    "sender_surface": "BuildA",
                    "sender_machine": "hive-lab-host",
                    "claimed_device_director": "LeadA",
                    "claimed_project_lead": "LeadA",
                    "supreme_authority": "Owner",
                    "network_membership_authorizes": False,
                    "future_hierarchy": "DOCUMENTED_INACTIVE",
                    "voting_state": "DOCUMENTED_INACTIVE",
                },
            },
            self.sender,
        )

    def test_active_and_held_enrollment_is_exact(self) -> None:
        active = {
            record.surface_id
            for record in self.matrix.enrollments.values()
            if record.technical_admission == "ACTIVE"
        }
        held = {
            record.surface_id
            for record in self.matrix.enrollments.values()
            if record.technical_admission != "ACTIVE"
        }
        self.assertEqual(active, {"LeadA", "BuildA", "LeadB", "BuildB", "LeadC", "BuildC"})
        self.assertEqual(held, {"LeadP", "BuildP"})
        directors = {
            "LeadA": "LeadA",
            "BuildA": "LeadA",
            "LeadB": "LeadB",
            "BuildB": "LeadB",
            "LeadC": "LeadC",
            "BuildC": "LeadC",
            "LeadP": "LeadP",
            "BuildP": "LeadP",
        }
        for record in self.matrix.enrollments.values():
            self.assertEqual(record.project_id, "hivemind-sample")
            self.assertEqual(record.device_director, directors[record.surface_id])
            self.assertEqual(record.current_project_lead, "LeadA")
            self.assertEqual(record.supreme_authority, "Owner")
            self.assertEqual(record.future_hierarchy, "DOCUMENTED_INACTIVE")
            self.assertEqual(record.voting_state, "DOCUMENTED_INACTIVE")
            self.assertFalse(record.network_membership_authorizes)
            self.assertTrue(record.runtime_adapter)
            self.assertTrue(record.app_actor.endswith("[bot]"))
            self.assertTrue(record.verification_key_id.startswith("ed25519:"))

    def test_active_and_legacy_routes_are_preserved(self) -> None:
        self.assertEqual(len(ACTIVE_MAILBOX_NAMES), 4)
        self.assertIn("03 Reviews and Decisions", ACTIVE_MAILBOX_NAMES)
        self.assertIn("peer_outbox/to_group", LEGACY_ROUTE_NAMES)
        self.assertIn("shared-work-channel", LEGACY_ROUTE_NAMES)

    def test_each_active_receiver_gets_its_own_cursor_and_signed_ack(self) -> None:
        for surface in ("LeadA", "BuildA", "LeadB", "BuildB", "LeadC", "BuildC"):
            envelope = self.envelope(surface)
            receipt = self.matrix.route(envelope, lambda _message, _recipient: None)
            self.assertEqual(receipt["status"], "DELIVERED")
            verify_document(receipt, {public_key_id(self.receipt.public_key()): self.receipt.public_key()})
            cursor = self.matrix.fs.read_json(("state", "cursors", f"{surface}.json"))
            self.assertIsNotNone(cursor)
            self.assertEqual(cursor["last_message_id"], envelope["message_id"])

    def test_unknown_and_android_receivers_fail_closed(self) -> None:
        with self.assertRaisesRegex(ProtocolError, "not enrolled"):
            self.matrix.route(self.envelope("Other"), lambda *_: None)
        with self.assertRaisesRegex(ProtocolError, "held"):
            self.matrix.route(self.envelope("LeadP"), lambda *_: None)
        with self.assertRaisesRegex(ProtocolError, "held"):
            self.matrix.route(self.envelope("BuildP"), lambda *_: None)

    def test_traversal_and_invalid_message_identifiers_fail_before_path_use(self) -> None:
        for message_id in (
            "../escape",
            "/absolute",
            "nested/../../escape",
            "%2e%2e%2fescape",
            "nested\\..\\escape",
            "control\nmessage",
        ):
            with self.subTest(message_id=repr(message_id)):
                envelope = self.envelope(message_id=message_id)
                with self.assertRaisesRegex(ProtocolError, "safe path identifier"):
                    self.matrix.route(envelope, lambda *_: None)
        self.assertFalse((Path(self.temp.name) / "escape").exists())

    def test_cross_device_project_lead_future_and_network_claim_claims_fail(self) -> None:
        cross_device = self.envelope()
        cross_device["authority"].update(
            {
                "sender_surface": "BuildB",
                "sender_machine": "node-b",
                "claimed_device_director": "LeadA",
            }
        )
        cross_device = sign_document(
            {key: value for key, value in cross_device.items() if key != "signature"}, self.sender
        )
        with self.assertRaisesRegex(ProtocolError, "another device director"):
            self.matrix.route(cross_device, lambda *_: None)

        wrong_lead = self.envelope()
        wrong_lead["authority"]["claimed_project_lead"] = "LeadB"
        wrong_lead = sign_document(
            {key: value for key, value in wrong_lead.items() if key != "signature"}, self.sender
        )
        with self.assertRaisesRegex(ProtocolError, "project-lead claim"):
            self.matrix.route(wrong_lead, lambda *_: None)

        future = self.envelope()
        future["authority"]["future_hierarchy"] = "ACTIVE"
        future = sign_document(
            {key: value for key, value in future.items() if key != "signature"}, self.sender
        )
        with self.assertRaisesRegex(ProtocolError, "not active"):
            self.matrix.route(future, lambda *_: None)

        network_claim = self.envelope()
        network_claim["authority"]["network_membership_authorizes"] = True
        network_claim = sign_document(
            {key: value for key, value in network_claim.items() if key != "signature"}, self.sender
        )
        with self.assertRaisesRegex(ProtocolError, "transport evidence"):
            self.matrix.route(network_claim, lambda *_: None)

    def test_unsigned_expired_malformed_and_unauthorized_fail_closed(self) -> None:
        unsigned = dict(self.envelope())
        unsigned.pop("signature")
        with self.assertRaises(ProtocolError):
            self.matrix.route(unsigned, lambda *_: None)
        expired = self.envelope()
        expired["expires_at"] = "2000-01-01T00:00:00Z"
        expired = sign_document({key: value for key, value in expired.items() if key != "signature"}, self.sender)
        with self.assertRaisesRegex(ProtocolError, "expired"):
            self.matrix.route(expired, lambda *_: None)
        malformed = self.envelope()
        malformed["delivery"] = {"wake_mode": "EVENT"}
        malformed = sign_document({key: value for key, value in malformed.items() if key != "signature"}, self.sender)
        with self.assertRaisesRegex(ProtocolError, "malformed"):
            self.matrix.route(malformed, lambda *_: None)
        unauthorized = self.envelope()
        unauthorized["delivery"]["authorized"] = False
        unauthorized = sign_document(
            {key: value for key, value in unauthorized.items() if key != "signature"}, self.sender
        )
        with self.assertRaisesRegex(ProtocolError, "authorization"):
            self.matrix.route(unauthorized, lambda *_: None)
        human_github = self.envelope()
        human_github["source_channel"] = "github:issue"
        human_github["delivery"] = {
            "wake_mode": "EVENT",
            "dependency_ids": [],
            "transport_kind": "GITHUB_APP",
            "transport_actor": "example-human",
            "authorized": True,
        }
        human_github = sign_document(
            {key: value for key, value in human_github.items() if key != "signature"}, self.sender
        )
        with self.assertRaisesRegex(ProtocolError, "App bot"):
            self.matrix.route(human_github, lambda *_: None)
        untrusted_bot = self.envelope()
        untrusted_bot["source_channel"] = "github:issue"
        untrusted_bot["delivery"] = {
            "wake_mode": "EVENT",
            "dependency_ids": [],
            "transport_kind": "GITHUB_APP",
            "transport_actor": "hive-untrusted-node[bot]",
            "authorized": True,
        }
        untrusted_bot = sign_document(
            {key: value for key, value in untrusted_bot.items() if key != "signature"}, self.sender
        )
        with self.assertRaisesRegex(ProtocolError, "not allowlisted"):
            self.matrix.route(untrusted_bot, lambda *_: None)

    def test_tampering_and_replay_are_rejected(self) -> None:
        envelope = self.envelope("LeadC")
        self.matrix.route(envelope, lambda *_: None)
        with self.assertRaisesRegex(ProtocolError, "already consumed"):
            self.matrix.route(envelope, lambda *_: None)
        tampered = dict(self.envelope("BuildC"))
        tampered["payload_sha256"] = "b" * 64
        with self.assertRaises(ProtocolError):
            self.matrix.route(tampered, lambda *_: None)

    def test_trusted_but_wrong_surface_signing_key_is_rejected(self) -> None:
        alternate = Ed25519PrivateKey.generate()
        alternate_id = public_key_id(alternate.public_key())
        self.matrix.trusted_keys[alternate_id] = alternate.public_key()
        envelope = self.envelope()
        envelope = sign_document(
            {key: value for key, value in envelope.items() if key != "signature"}, alternate
        )
        with self.assertRaisesRegex(ProtocolError, "enrolled sender surface"):
            self.matrix.route(envelope, lambda *_: None)

    def test_bounded_retry_quarantines_and_signs_failure(self) -> None:
        envelope = self.envelope("BuildB")
        def fail(*_args):
            raise OSError("synthetic transport failure")
        with self.assertRaisesRegex(ProtocolError, "bounded retry remains"):
            self.matrix.route(envelope, fail)
        receipt = self.matrix.route(envelope, fail)
        self.assertEqual(receipt["status"], "QUARANTINED")
        self.assertEqual(receipt["attempt"], 2)
        verify_document(receipt, {public_key_id(self.receipt.public_key()): self.receipt.public_key()})
        quarantined = self.matrix.fs.read_json(
            ("quarantine", f"{envelope['message_id']}.json")
        )
        self.assertEqual(quarantined, envelope)

    def test_all_state_is_scoped_for_exact_rollback(self) -> None:
        outside = Path(self.temp.name) / "sentinel"
        outside.write_text("unowned", encoding="utf-8")
        self.matrix.route(self.envelope("LeadB"), lambda *_: None)
        import shutil
        shutil.rmtree(self.root)
        self.assertEqual(outside.read_text(encoding="utf-8"), "unowned")
        self.assertFalse(self.root.exists())


if __name__ == "__main__":
    unittest.main()
