from __future__ import annotations

import json
import multiprocessing
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from hive_protocol.core import (
    ProtocolError,
    load_private_key,
    require_assigned_persona,
    sign_document,
    validate_identity_context,
)
from hive_protocol.m003 import promote_turn, propose_turn, retrieve_next_turn, review_turn
from hive_protocol.memory import _safe_narrative, validate_pruning_base
from hive_protocol.storage import atomic_write_bytes, atomic_write_json, read_json
from hive_protocol.turn import (
    _safe_note_name,
    consume_turn,
    prepare_turn,
    rollback_turn,
    route_turn,
)

from lab_identity import assigned_lab_identity


COMMIT = "a" * 40


def _route_worker(run_dir: str, results: object) -> None:
    try:
        routed = route_turn(Path(run_dir))
        results.put((0, routed["outcome"]))
    except ProtocolError as error:
        results.put((error.exit_status, error.code))


class ProtocolSchemaTests(unittest.TestCase):
    def test_schemas_are_meta_valid(self) -> None:
        schema_root = files("hive_protocol.schemas")
        for name in (
            "work-envelope.v1.schema.json",
            "work-envelope.v2.schema.json",
            "acknowledgment.v1.schema.json",
            "turn-receipt.v1.schema.json",
            "repository-roster.v1.schema.json",
            "identity-context.v1.schema.json",
            "memory-proposal.v1.schema.json",
            "promotion-decision.v1.schema.json",
            "promotion-receipt.v1.schema.json",
            "governance-release.v1.schema.json",
            "node-pin.v1.schema.json",
            "distribution-receipt.v1.schema.json",
        ):
            with self.subTest(schema=name):
                schema = json.loads(schema_root.joinpath(name).read_text(encoding="utf-8"))
                Draft202012Validator.check_schema(schema)

    def test_unassigned_sample_context_validates_and_separates_identity_dimensions(self) -> None:
        context_path = Path(__file__).parents[1] / "config" / "sample-lab-context.json"
        context = json.loads(context_path.read_text(encoding="utf-8"))
        schema = json.loads(
            files("hive_protocol.schemas")
            .joinpath("identity-context.v1.schema.json")
            .read_text(encoding="utf-8")
        )
        Draft202012Validator(schema, format_checker=None).validate(context)
        validate_identity_context(context)
        self.assertEqual(context["persona"]["governance_role"], "QUEEN")
        self.assertEqual(context["persona"]["id"], "UNASSIGNED")
        self.assertEqual(context["persona"]["continuity_id"], "UNASSIGNED")
        self.assertEqual(context["surface"]["persona_continuity_id"], "UNASSIGNED")
        self.assertEqual(context["agent_worker"]["acts_for_persona"], "UNASSIGNED")
        self.assertEqual(
            context["persona"]["continuity_id"],
            context["surface"]["persona_continuity_id"],
        )
        self.assertNotEqual(context["persona"]["id"], context["agent_worker"]["id"])
        self.assertNotEqual(context["persona"]["id"], context["model_runtime"]["runtime"])
        self.assertNotEqual(context["persona"]["id"], context["machine_node"]["machine"])
        self.assertEqual(context["governance_seat"]["worker_seat"], "UNASSIGNED")
        self.assertFalse(context["memory_vault_namespace"]["raw_memory_in_github"])

    def test_surface_divergence_does_not_change_persona_continuity(self) -> None:
        context_path = Path(__file__).parents[1] / "config" / "sample-lab-context.json"
        first = json.loads(context_path.read_text(encoding="utf-8"))
        second = json.loads(json.dumps(first))
        second["surface"]["id"] = "Sample-Edge"
        second["surface"]["experience_namespace"] = "surface/sample/edge"
        self.assertNotEqual(first["surface"], second["surface"])
        self.assertEqual(first["persona"], second["persona"])
        self.assertEqual(
            first["persona"]["continuity_id"],
            second["surface"]["persona_continuity_id"],
        )
        validate_identity_context(second)

    def test_surface_cannot_forge_persona_continuity(self) -> None:
        context_path = Path(__file__).parents[1] / "config" / "sample-lab-context.json"
        context = json.loads(context_path.read_text(encoding="utf-8"))
        context["surface"]["persona_continuity_id"] = "persona:forged"
        with self.assertRaisesRegex(ProtocolError, "IDENTITY_CONTINUITY_INVALID"):
            validate_identity_context(context)

    def test_worker_cannot_silently_act_for_another_persona(self) -> None:
        context_path = Path(__file__).parents[1] / "config" / "sample-lab-context.json"
        context = json.loads(context_path.read_text(encoding="utf-8"))
        context["agent_worker"]["acts_for_persona"] = "Other"
        with self.assertRaisesRegex(ProtocolError, "IDENTITY_DELEGATION_INVALID"):
            validate_identity_context(context)

    def test_unassigned_persona_cannot_prepare_or_act(self) -> None:
        context_path = Path(__file__).parents[1] / "config" / "sample-lab-context.json"
        context = json.loads(context_path.read_text(encoding="utf-8"))
        validate_identity_context(context)
        with self.assertRaisesRegex(ProtocolError, "PERSONA_UNASSIGNED"):
            require_assigned_persona(context)
        with patch("hive_protocol.turn.EXPECTED_IDENTITY", context):
            with self.assertRaisesRegex(ProtocolError, "PERSONA_UNASSIGNED"):
                prepare_turn(self.lab_root, COMMIT)
        self.assertFalse(self.lab_root.exists())

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.lab_root = Path(self.temporary.name) / "lab"
        self.namespace_patch = patch.dict(
            os.environ,
            {
                "HIVE_PROCESS_NAMESPACE": "HIVE-LAB-UNIT",
                "HIVE_LAB_CONTEXT": str(Path(self.temporary.name) / "absent-lab-context.json"),
            },
        )
        self.hostname_patch = patch("hive_protocol.turn.socket.gethostname", return_value="hive-lab-host")
        self.namespace_patch.start()
        self.hostname_patch.start()
        self.identity_patch = patch(
            "hive_protocol.turn.EXPECTED_IDENTITY",
            assigned_lab_identity(),
        )
        self.identity_patch.start()
        self.addCleanup(self.namespace_patch.stop)
        self.addCleanup(self.hostname_patch.stop)
        self.addCleanup(self.identity_patch.stop)

    def _prepare(self) -> tuple[dict[str, object], Path]:
        prepared = prepare_turn(self.lab_root, COMMIT)
        return prepared, Path(str(prepared["run_dir"]))

    def _resign_envelope(self, run_dir: Path, mutate: object) -> None:
        marker = read_json(run_dir / ".hive-lab-run.json")
        envelope_path = (
            run_dir
            / "mailbox"
            / "outbox"
            / marker["sender_surface"]
            / f"{marker['message_id']}.json"
        )
        envelope = read_json(envelope_path)
        mutate(envelope)
        signed = sign_document(
            envelope, load_private_key(run_dir / "keys" / "issuer.private.pem")
        )
        atomic_write_json(envelope_path, signed)

    def test_full_turn_persists_then_rolls_back_without_operational_residue(self) -> None:
        prepared, run_dir = self._prepare()
        delivery = route_turn(run_dir)
        acknowledgment, exit_status = consume_turn(run_dir)
        staged = propose_turn(run_dir)
        reviewed = review_turn(run_dir)
        promotion = promote_turn(run_dir)
        retrieval = retrieve_next_turn(run_dir)
        rolled_back = rollback_turn(run_dir, self.lab_root)

        self.assertEqual(delivery["outcome"], "DELIVERED")
        self.assertEqual(acknowledgment["outcome"], "APPLIED")
        self.assertEqual(exit_status, 0)
        self.assertEqual(staged["outcome"], "STAGED_PROPOSALS")
        self.assertEqual(reviewed["outcome"], "APPROVED")
        self.assertEqual(promotion["base_count"], 8)
        self.assertEqual(promotion["unreviewed_remaining"], 0)
        self.assertEqual(retrieval["backlinks_verified"], 2)
        self.assertEqual(retrieval["base_views_verified"], 9)
        self.assertEqual(rolled_back["operational_residue"], "NONE")
        self.assertFalse(run_dir.exists())
        evidence_root = self.lab_root / "evidence"
        evidence = list(evidence_root.glob(f"{prepared['run_id']}.*"))
        self.assertEqual(len(evidence), 4)
        self.assertTrue(
            (evidence_root / f"{prepared['run_id']}.consumer.public.pem").is_file()
        )

    def test_unsigned_tamper_is_refused(self) -> None:
        _, run_dir = self._prepare()
        marker = read_json(run_dir / ".hive-lab-run.json")
        envelope_path = (
            run_dir
            / "mailbox"
            / "outbox"
            / marker["sender_surface"]
            / f"{marker['message_id']}.json"
        )
        envelope = read_json(envelope_path)
        envelope["task"]["value"] = "poisoned"
        atomic_write_json(envelope_path, envelope)
        with self.assertRaisesRegex(ProtocolError, "SIGNATURE_INVALID"):
            route_turn(run_dir)

    def test_forged_identity_is_refused_even_when_signed(self) -> None:
        _, run_dir = self._prepare()

        def mutate(envelope: dict[str, object]) -> None:
            identity = envelope["identity"]
            assert isinstance(identity, dict)
            seat = identity["governance_seat"]
            assert isinstance(seat, dict)
            seat["worker_seat"] = "PRIME"

        self._resign_envelope(run_dir, mutate)
        with self.assertRaisesRegex(ProtocolError, "IDENTITY_DENIED"):
            route_turn(run_dir)

    def test_missing_capability_is_refused_even_when_signed(self) -> None:
        _, run_dir = self._prepare()

        def mutate(envelope: dict[str, object]) -> None:
            authority = envelope["authority"]
            assert isinstance(authority, dict)
            capabilities = authority["capabilities"]
            assert isinstance(capabilities, list)
            capabilities.remove("vault:promote")

        self._resign_envelope(run_dir, mutate)
        with self.assertRaisesRegex(ProtocolError, "CAPABILITY_DENIED"):
            route_turn(run_dir)

    def test_capability_escalation_is_refused_even_when_signed(self) -> None:
        _, run_dir = self._prepare()

        def mutate(envelope: dict[str, object]) -> None:
            authority = envelope["authority"]
            assert isinstance(authority, dict)
            capabilities = authority["capabilities"]
            assert isinstance(capabilities, list)
            capabilities.append("production:activate")

        self._resign_envelope(run_dir, mutate)
        with self.assertRaisesRegex(ProtocolError, "CAPABILITY_ESCALATION"):
            route_turn(run_dir)

    def test_forged_recipient_is_refused_even_when_signed(self) -> None:
        _, run_dir = self._prepare()

        def mutate(envelope: dict[str, object]) -> None:
            recipient = envelope["recipient"]
            assert isinstance(recipient, dict)
            recipient["surface"] = "Sample-Other"

        self._resign_envelope(run_dir, mutate)
        with self.assertRaisesRegex(ProtocolError, "RECIPIENT_DENIED"):
            route_turn(run_dir)

    def test_expired_envelope_is_refused_even_when_signed(self) -> None:
        _, run_dir = self._prepare()

        def mutate(envelope: dict[str, object]) -> None:
            expired = datetime.now(timezone.utc) - timedelta(minutes=1)
            envelope["expires_at"] = expired.isoformat().replace("+00:00", "Z")

        self._resign_envelope(run_dir, mutate)
        with self.assertRaisesRegex(ProtocolError, "EXPIRED"):
            route_turn(run_dir)

    def test_consumer_replay_is_refused_with_distinct_status(self) -> None:
        _, run_dir = self._prepare()
        route_turn(run_dir)
        consume_turn(run_dir)
        with self.assertRaises(ProtocolError) as context:
            consume_turn(run_dir)
        self.assertEqual(context.exception.code, "REPLAY_MESSAGE_ID")
        self.assertEqual(context.exception.exit_status, 3)

    def test_router_recovers_from_crash_after_replay_claim(self) -> None:
        _, run_dir = self._prepare()
        with patch("hive_protocol.turn.atomic_write_bytes", side_effect=OSError("crash")):
            with self.assertRaisesRegex(OSError, "crash"):
                route_turn(run_dir)

        delivery = route_turn(run_dir)
        self.assertEqual(delivery["outcome"], "DELIVERED")
        ledger = read_json(run_dir / "replay" / "router.json")
        marker = read_json(run_dir / ".hive-lab-run.json")
        self.assertEqual(ledger["messages"][marker["message_id"]]["state"], "COMPLETE")

    def test_concurrent_delivery_allows_one_delivery_and_one_replay(self) -> None:
        _, run_dir = self._prepare()
        context = multiprocessing.get_context("fork")
        results = context.Queue()
        processes = [context.Process(target=_route_worker, args=(str(run_dir), results)) for _ in range(2)]
        for process in processes:
            process.start()
        for process in processes:
            process.join(10)
            self.assertEqual(process.exitcode, 0)
        outcomes = sorted([results.get(timeout=2), results.get(timeout=2)])
        self.assertEqual(outcomes, [(0, "DELIVERED"), (3, "REPLAY_MESSAGE_ID")])

    def test_acknowledgment_signature_tampering_blocks_proposal(self) -> None:
        _, run_dir = self._prepare()
        route_turn(run_dir)
        consume_turn(run_dir)
        acknowledgment_path = run_dir / "receipts" / "acknowledgment.json"
        acknowledgment = read_json(acknowledgment_path)
        acknowledgment["reason_code"] = "POISONED"
        atomic_write_json(acknowledgment_path, acknowledgment)
        with self.assertRaisesRegex(ProtocolError, "SIGNATURE_INVALID"):
            propose_turn(run_dir)

    def test_poisoned_delivery_receipt_blocks_proposal(self) -> None:
        _, run_dir = self._prepare()
        route_turn(run_dir)
        consume_turn(run_dir)
        delivery_path = run_dir / "receipts" / "delivery.json"
        delivery = read_json(delivery_path)
        delivery["recipient_surface"] = "forged-surface"
        atomic_write_json(delivery_path, delivery)
        with self.assertRaisesRegex(ProtocolError, "DELIVERY_RECEIPT_MISMATCH"):
            propose_turn(run_dir)

    def test_false_next_turn_persistence_is_refused(self) -> None:
        _, run_dir = self._prepare()
        route_turn(run_dir)
        consume_turn(run_dir)
        propose_turn(run_dir)
        review_turn(run_dir)
        promote_turn(run_dir)
        state_path = run_dir / "state" / "task-state.json"
        state = read_json(state_path)
        state["unreceipted_change"] = True
        atomic_write_json(state_path, state)
        with self.assertRaisesRegex(ProtocolError, "NEXT_TURN_STATE_DRIFT"):
            retrieve_next_turn(run_dir)

    def test_malicious_obsidian_note_names_are_refused(self) -> None:
        for unsafe_name in ("[[poison]]", "../../escape", "entity|alias", "line\nbreak"):
            with self.subTest(name=unsafe_name):
                with self.assertRaisesRegex(ProtocolError, "NOTE_NAME_DENIED"):
                    _safe_note_name(unsafe_name)

    def test_malicious_obsidian_links_are_refused(self) -> None:
        for unsafe in ("[[poison]]", "javascript:alert(1)", "file:///etc/passwd", "<script>"):
            with self.subTest(value=unsafe):
                with self.assertRaisesRegex(ProtocolError, "OBSIDIAN_LINK_DENIED"):
                    _safe_narrative(unsafe)

    def test_pruning_base_requires_two_stages_retention_and_receipt(self) -> None:
        policy = validate_pruning_base()
        self.assertEqual(policy["retention_days"], 30)
        self.assertFalse(policy["automatic_delete"])
        self.assertEqual(len(policy["views"]), 2)

    def test_atomic_write_failure_preserves_target_and_removes_temporary(self) -> None:
        target = Path(self.temporary.name) / "atomic.json"
        target.write_bytes(b"original\n")
        with patch("hive_protocol.storage.os.replace", side_effect=OSError("replace failed")):
            with self.assertRaisesRegex(OSError, "replace failed"):
                atomic_write_bytes(target, b"replacement\n")
        self.assertEqual(target.read_bytes(), b"original\n")
        self.assertEqual(list(target.parent.glob(f".{target.name}.*.tmp")), [])

    def test_unmarked_nonempty_lab_root_is_refused(self) -> None:
        self.lab_root.mkdir()
        (self.lab_root / "unrelated.txt").write_text("preserve me", encoding="utf-8")
        with self.assertRaisesRegex(ProtocolError, "LAB_ROOT_BOUNDARY"):
            prepare_turn(self.lab_root, COMMIT)
        self.assertEqual((self.lab_root / "unrelated.txt").read_text(), "preserve me")

    def test_missing_process_namespace_is_refused_before_creation(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ProtocolError, "PROCESS_NAMESPACE_DENIED"):
                prepare_turn(self.lab_root, COMMIT)
        self.assertFalse(self.lab_root.exists())

    def test_symlinked_lab_root_is_refused(self) -> None:
        real_root = Path(self.temporary.name) / "real-lab"
        real_root.mkdir()
        self.lab_root.symlink_to(real_root, target_is_directory=True)
        with self.assertRaisesRegex(ProtocolError, "LAB_ROOT_BOUNDARY"):
            prepare_turn(self.lab_root, COMMIT)
        self.assertEqual(list(real_root.iterdir()), [])


class UnassignedBundledIdentityCliTests(unittest.TestCase):
    def test_cli_prepare_refuses_unassigned_bundled_persona(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lab_root = Path(temporary) / "lab"
            environment = dict(os.environ)
            environment["HIVE_PROCESS_NAMESPACE"] = "HIVE-LAB-TEST-PREPARE"
            environment["HIVE_LAB_CONTEXT"] = str(Path(temporary) / "absent-lab-context.json")
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "hive_protocol.cli",
                    "prepare",
                    "--lab-root",
                    str(lab_root),
                    "--commit",
                    COMMIT,
                ],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )
            combined = completed.stdout + completed.stderr
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("PERSONA_UNASSIGNED", combined)
            self.assertFalse(lab_root.exists())
