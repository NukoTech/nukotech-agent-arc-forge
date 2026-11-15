from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from hive_protocol.observer import observe_repositories
from hive_protocol.storage import atomic_write_bytes, atomic_write_json, read_json


class RepositoryObserverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.helper = self.root / "app-helper"
        atomic_write_bytes(self.helper, b"#!/bin/sh\nexit 1\n", mode=0o700)
        self.namespace_patch = patch.dict(
            os.environ, {"HIVE_PROCESS_NAMESPACE": "HIVE-LAB-OBSERVER-TEST"}
        )
        self.namespace_patch.start()
        self.addCleanup(self.namespace_patch.stop)

    def _roster(self, observed_at: datetime) -> Path:
        roster_path = self.root / "roster.json"
        atomic_write_json(
            roster_path,
            {
                "schema_version": "hive.repository-roster.v1",
                "repositories": [
                    {
                        "id": "historical-lineage",
                        "repository": "Example/legacy",
                        "ref": "refs/heads/main",
                        "role": "immutable-history",
                        "required": True,
                        "transport": "fixed-read-evidence",
                        "expected_commit": "a" * 40,
                        "evidence_observed_at": observed_at.isoformat().replace("+00:00", "Z"),
                        "evidence_max_age_hours": 24,
                    }
                ],
            },
        )
        return roster_path

    def test_current_fixed_evidence_produces_append_only_receipt(self) -> None:
        roster = self._roster(datetime.now(timezone.utc))
        output = self.root / "receipts"
        receipt = observe_repositories(roster, output, self.helper)
        self.assertEqual(receipt["outcome"], "HEALTHY")
        self.assertEqual(receipt["repositories"][0]["status"], "CURRENT_EVIDENCE")
        persisted = read_json(Path(receipt["receipt_path"]))
        self.assertEqual(persisted["mutation_policy"], "OBSERVE_ONLY_NO_GIT_WRITE")

    def test_stale_required_evidence_degrades_observation(self) -> None:
        roster = self._roster(datetime.now(timezone.utc) - timedelta(hours=25))
        receipt = observe_repositories(roster, self.root / "receipts", self.helper)
        self.assertEqual(receipt["outcome"], "DEGRADED")
        self.assertEqual(receipt["unhealthy_required"], ["historical-lineage"])


if __name__ == "__main__":
    unittest.main()
