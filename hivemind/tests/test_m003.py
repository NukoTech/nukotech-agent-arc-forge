from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hive_protocol.core import ProtocolError, load_private_key, sign_document
from hive_protocol.distribution import build_governance_release, stage_governance_release
from hive_protocol.m003 import promote_turn, propose_turn, retrieve_next_turn, review_turn
from hive_protocol.storage import atomic_write_bytes, atomic_write_json, read_json
from hive_protocol.turn import _load_marker, consume_turn, prepare_turn, route_turn

from lab_identity import ASSIGNED_PERSONA_ID, assigned_lab_identity


COMMIT = "b" * 40
TREE = "c" * 40


class M003SecurityAndGovernanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.namespace = "HIVE-LAB-M003-SECURITY-TEST"
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.lab_root = Path(self.temporary.name) / "lab"
        self.namespace_patch = patch.dict(
            os.environ,
            {
                "HIVE_PROCESS_NAMESPACE": self.namespace,
                "HIVE_LAB_CONTEXT": str(Path(self.temporary.name) / "absent-lab-context.json"),
            },
        )
        self.hostname_patch = patch(
            "hive_protocol.turn.socket.gethostname", return_value="hive-lab-host"
        )
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

    def _consumed(self) -> tuple[Path, dict[str, object]]:
        prepared = prepare_turn(self.lab_root, COMMIT)
        run_dir = Path(str(prepared["run_dir"]))
        route_turn(run_dir)
        consume_turn(run_dir)
        return run_dir, _load_marker(run_dir)

    def _approved(self) -> tuple[Path, dict[str, object]]:
        run_dir, marker = self._consumed()
        propose_turn(run_dir)
        reviewed = review_turn(run_dir)
        self.assertEqual(reviewed["outcome"], "APPROVED")
        return run_dir, marker

    def test_persona_and_surface_lanes_exist_without_direct_prime_write(self) -> None:
        run_dir, _ = self._consumed()
        staged = propose_turn(run_dir)
        self.assertFalse((run_dir / "vault-prime").exists())
        self.assertEqual(
            {proposal["lane"] for proposal in staged["proposals"]},
            {f"PERSONA:{ASSIGNED_PERSONA_ID}", "SURFACE:Sample-Lab"},
        )

    def test_promoter_requires_separately_keyed_review_decision(self) -> None:
        run_dir, _ = self._consumed()
        propose_turn(run_dir)
        with self.assertRaisesRegex(ProtocolError, "MISSING_DOCUMENT"):
            promote_turn(run_dir)
        self.assertFalse((run_dir / "vault-prime").exists())

    def test_forged_lane_is_refused_even_when_proposer_signs_it(self) -> None:
        run_dir, _ = self._consumed()
        propose_turn(run_dir)
        proposal_path = sorted((run_dir / "vault-staging" / "_proposals").glob("*/*/*.json"))[0]
        proposal = read_json(proposal_path)
        proposal["lane"]["owner_id"] = "Forged-Persona"
        proposal = sign_document(
            proposal,
            load_private_key(run_dir / "keys" / "consumer.private.pem"),
        )
        atomic_write_json(proposal_path, proposal)
        with self.assertRaisesRegex(ProtocolError, "PROPOSAL_LANE_DENIED"):
            review_turn(run_dir)

    def test_symlinked_proposal_is_refused(self) -> None:
        run_dir, _ = self._consumed()
        propose_turn(run_dir)
        source = sorted((run_dir / "vault-staging" / "_proposals").glob("*/*/*.json"))[0]
        malicious = run_dir / "vault-staging" / "_proposals" / "surface" / "Sample-Lab" / "malicious.json"
        malicious.symlink_to(source)
        with self.assertRaisesRegex(ProtocolError, "PROPOSAL_LANE_DENIED"):
            review_turn(run_dir)

    def test_existing_fact_without_precondition_becomes_visible_conflict(self) -> None:
        run_dir, _ = self._consumed()
        propose_turn(run_dir)
        proposal_path = next(
            path
            for path in (run_dir / "vault-staging" / "_proposals").glob("*/*/*.json")
            if read_json(path)["record"]["record_type"] == "DURABLE_FACT"
        )
        proposal = read_json(proposal_path)
        fact_key = proposal["record"]["fact_key"]
        current = run_dir / "vault-prime" / "30-Durable-Facts" / f"{fact_key}.md"
        atomic_write_bytes(current, b"---\nstatus: CURRENT\nvalue: conflicting\n---\n")
        reviewed = review_turn(run_dir)
        self.assertEqual(reviewed["outcome"], "CONFLICT")
        self.assertEqual(reviewed["conflict_count"], 1)
        contradictions = list((run_dir / "vault-staging" / "_contradictions").glob("*.md"))
        self.assertEqual(len(contradictions), 1)
        with self.assertRaisesRegex(ProtocolError, "PROMOTION_CONFLICT"):
            promote_turn(run_dir)
        self.assertFalse((run_dir / "vault-prime" / "00-MOC").exists())

    def test_reviewer_signature_tampering_blocks_promotion(self) -> None:
        run_dir, _ = self._approved()
        decision_path = run_dir / "receipts" / "promotion-decision.json"
        decision = read_json(decision_path)
        decision["reviewer"]["worker_id"] = "forged-reviewer"
        atomic_write_json(decision_path, decision)
        with self.assertRaisesRegex(ProtocolError, "SIGNATURE_INVALID"):
            promote_turn(run_dir)

    def test_release_artifact_tampering_fails_closed(self) -> None:
        run_dir, marker = self._consumed()
        build_governance_release(run_dir, marker, "0.2.0-lab.1", TREE, self.namespace)
        artifact = next((run_dir / "distribution" / "outbox" / "0.2.0-lab.1" / "artifacts").glob("*/*"))
        atomic_write_bytes(artifact, artifact.read_bytes() + b"tamper")
        with self.assertRaisesRegex(ProtocolError, "RELEASE_ARTIFACT_DRIFT"):
            stage_governance_release(run_dir, marker, "0.2.0-lab.1", self.namespace)

    def test_signed_release_cannot_claim_raw_memory(self) -> None:
        run_dir, marker = self._consumed()
        build_governance_release(run_dir, marker, "0.2.0-lab.1", TREE, self.namespace)
        release_path = run_dir / "distribution" / "outbox" / "0.2.0-lab.1" / "release.json"
        release = read_json(release_path)
        release["contains_raw_memory"] = True
        release = sign_document(
            release,
            load_private_key(run_dir / "keys" / "issuer.private.pem"),
        )
        atomic_write_json(release_path, release)
        with self.assertRaisesRegex(ProtocolError, "SCHEMA_INVALID"):
            stage_governance_release(run_dir, marker, "0.2.0-lab.1", self.namespace)

    def test_false_base_persistence_is_refused_next_turn(self) -> None:
        run_dir, _ = self._approved()
        promote_turn(run_dir)
        base = run_dir / "vault-prime" / "90-Bases" / "durable-facts.base"
        atomic_write_bytes(base, base.read_bytes() + b"\n# poisoned\n")
        with self.assertRaisesRegex(ProtocolError, "NEXT_TURN_MEMORY_DRIFT"):
            retrieve_next_turn(run_dir)


if __name__ == "__main__":
    unittest.main()
