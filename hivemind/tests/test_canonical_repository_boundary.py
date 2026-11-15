from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).parents[1]
VERIFIER = REPOSITORY_ROOT / "scripts" / "verify_canonical_repository.py"


class CanonicalRepositoryBoundaryTests(unittest.TestCase):
    def run_verifier(self, repository: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(VERIFIER), "--repository", str(repository)],
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_current_repository_has_one_bound_plan_and_no_legacy_roots(self) -> None:
        result = self.run_verifier(REPOSITORY_ROOT)

        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        report = json.loads(result.stdout)
        self.assertEqual(report["outcome"], "VERIFIED")
        self.assertEqual(
            report["canonical_plan_sha256"],
            "d5bd471278d446539a330d9ab8b6458ec8bb9403c6aa36c53e9023d1bc98ebdc",
        )
        self.assertEqual(report["legacy_roots_checked"], 0)

    def test_mutated_plan_fails_with_a_distinct_hash_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repository = Path(temp)
            (repository / "docs" / "plans").mkdir(parents=True)
            (repository / "docs" / "plans" / "plan.md").write_text(
                "mutated plan\n", encoding="utf-8"
            )
            for active_root in ("src", "tests"):
                (repository / active_root).mkdir()
            for legacy_root in ("_governance", "surfaces", "products", "recommendations_from_external"):
                root = repository / legacy_root
                root.mkdir()
                (root / "LEGACY_NOTICE.md").write_text("legacy\n", encoding="utf-8")
            manifest = {
                "schema_version": "nukotech.hivemind.repository-boundary.v1",
                "canonical_plan": {
                    "path": "docs/plans/plan.md",
                    "sha256": "bda3eebff68b37cb4d27b04f9c2fc9f61d190a8c8b3439aa9ac2e45d6744cba3",
                },
                "active_roots": ["src", "tests"],
                "legacy_roots": [
                    {"path": path, "notice": f"{path}/LEGACY_NOTICE.md"}
                    for path in (
                        "_governance",
                        "surfaces",
                        "products",
                        "recommendations_from_external",
                    )
                ],
            }
            (repository / "CANONICAL_HIVEMIND.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )

            result = self.run_verifier(repository)

        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        self.assertEqual(report["outcome"], "REFUSED")
        self.assertIn("PLAN_HASH_MISMATCH", report["errors"])

    def test_symlinked_canonical_plan_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repository = Path(temp)
            plans = repository / "docs" / "plans"
            plans.mkdir(parents=True)
            target = plans / "actual.md"
            target.write_text("canonical plan\n", encoding="utf-8")
            (plans / "plan.md").symlink_to(target)
            for active_root in ("src", "tests"):
                (repository / active_root).mkdir()
            legacy_roots = []
            for path in (
                "_governance",
                "surfaces",
                "products",
                "recommendations_from_external",
            ):
                root = repository / path
                root.mkdir()
                notice = root / "LEGACY_NOTICE.md"
                notice.write_text("legacy\n", encoding="utf-8")
                legacy_roots.append({"path": path, "notice": str(notice.relative_to(repository))})
            manifest = {
                "schema_version": "nukotech.hivemind.repository-boundary.v1",
                "canonical_plan": {
                    "path": "docs/plans/plan.md",
                    "sha256": "bda3eebff68b37cb4d27b04f9c2fc9f61d190a8c8b3439aa9ac2e45d6744cba3",
                },
                "active_roots": ["src", "tests"],
                "legacy_roots": legacy_roots,
            }
            (repository / "CANONICAL_HIVEMIND.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )

            result = self.run_verifier(repository)

        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        self.assertEqual(report["outcome"], "REFUSED")
        self.assertIn("CANONICAL_PLAN_SYMLINK_REFUSED", report["errors"])


if __name__ == "__main__":
    unittest.main()
