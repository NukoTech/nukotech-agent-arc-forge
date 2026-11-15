import unittest
from pathlib import Path


# Nested hivemind/.github was removed; the flagship root workflow is the CI contract.
WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/hivemind-tests.yml"


class CiWorkflowPolicyTests(unittest.TestCase):
    def test_canonical_cycle2_build_is_not_tied_to_one_feature_branch(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("HIVE_CYCLE2_DEVELOPMENT: '1'", workflow)
        self.assertNotIn("startsWith(github.event.pull_request.head.ref", workflow)
        self.assertNotIn(
            "github.event.pull_request.head.ref != "
            "'builda/hivemind-cycle2-m1-working-group-20260828'",
            workflow,
        )

    def test_ci_executes_pytest_style_cycle2_suites(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("build==1.4.0", workflow)
        self.assertIn("pytest==9.0.2", workflow)
        self.assertIn("setuptools==84.0.0", workflow)
        self.assertIn("python -m pytest -q", workflow)
        self.assertIn("924 0", workflow)


if __name__ == "__main__":
    unittest.main()
