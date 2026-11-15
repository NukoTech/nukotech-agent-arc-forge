#!/usr/bin/env python3
"""Exercise the PR-gate verifier's positive path and mandatory rejections."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_case(name: str, command: list[str], expect_success: bool) -> dict[str, object]:
    result = subprocess.run(command, check=False, capture_output=True, text=True)  # nosec B603
    passed = (result.returncode == 0) is expect_success
    lines = result.stdout.strip().splitlines()
    observed: object = lines[-1] if lines else ""
    if lines:
        try:
            observed = json.loads(lines[-1])
        except json.JSONDecodeError:
            pass
    return {
        "case": name,
        "expected": "accept" if expect_success else "reject",
        "exit_code": result.returncode,
        "observed": observed,
        "passed": passed,
    }


def replace_value(command: list[str], option: str, value: str) -> list[str]:
    changed = command.copy()
    changed[changed.index(option) + 1] = value
    return changed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--execution-receipt", type=Path, required=True)
    parser.add_argument("--pr-head-sha", required=True)
    parser.add_argument("--pr-head-tree", required=True)
    parser.add_argument("--pr-base-sha", required=True)
    parser.add_argument("--pr-merge-ref", required=True)
    parser.add_argument("--pr-merge-sha", required=True)
    parser.add_argument("--pr-merge-tree", required=True)
    parser.add_argument("--workflow-identity", required=True)
    parser.add_argument("--cosign-binary", type=Path, required=True)
    parser.add_argument("--cosign-binary-sha256", required=True)
    args = parser.parse_args()

    verifier = Path(__file__).with_name("verify_pr_gate_attestation.py")
    digest = sha256(args.artifact)
    results: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="hive-pr-gate-proof-") as raw:
        root = Path(raw)
        ledger = root / "accepted-ledger.json"
        base = [
            sys.executable,
            str(verifier),
            "--artifact", str(args.artifact),
            "--bundle", str(args.bundle),
            "--policy", str(args.policy),
            "--execution-receipt", str(args.execution_receipt),
            "--expected-sha256", digest,
            "--pr-head-sha", args.pr_head_sha,
            "--pr-head-tree", args.pr_head_tree,
            "--pr-base-sha", args.pr_base_sha,
            "--pr-merge-ref", args.pr_merge_ref,
            "--pr-merge-sha", args.pr_merge_sha,
            "--pr-merge-tree", args.pr_merge_tree,
            "--workflow-identity", args.workflow_identity,
            "--claim-id", "alpha2-pr-gate-candidate",
            "--ledger", str(ledger),
            "--cosign-binary", str(args.cosign_binary),
            "--cosign-binary-sha256", args.cosign_binary_sha256,
        ]
        results.append(run_case("valid_pr_attestation", base, True))

        replay = replace_value(base, "--claim-id", "second-claim-same-attestation")
        results.append(run_case("replayed_attestation", replay, False))

        tampered = root / args.artifact.name
        shutil.copyfile(args.artifact, tampered)
        with tampered.open("ab") as handle:
            handle.write(b"TAMPER")
        tampered_command = replace_value(base, "--artifact", str(tampered))
        tampered_command = replace_value(tampered_command, "--expected-sha256", sha256(tampered))
        tampered_command = replace_value(tampered_command, "--ledger", str(root / "tampered.json"))
        results.append(run_case("tampered_artifact", tampered_command, False))

        wrong_digest = replace_value(base, "--expected-sha256", "0" * 64)
        wrong_digest = replace_value(wrong_digest, "--ledger", str(root / "wrong-digest.json"))
        results.append(run_case("wrong_digest", wrong_digest, False))

        wrong_identity = replace_value(
            base,
            "--workflow-identity",
            "https://github.com/example-org/unrelated-repo/.github/workflows/unrelated-workflow.yml@refs/pull/1/merge",
        )
        wrong_identity = replace_value(wrong_identity, "--ledger", str(root / "wrong-identity.json"))
        results.append(run_case("wrong_identity", wrong_identity, False))

        unsigned = base.copy()
        bundle_index = unsigned.index("--bundle")
        del unsigned[bundle_index : bundle_index + 2]
        unsigned = replace_value(unsigned, "--ledger", str(root / "unsigned.json"))
        results.append(run_case("unsigned_artifact", unsigned, False))

    passed = all(bool(item["passed"]) for item in results)
    print(json.dumps({"outcome": "VERIFIED" if passed else "FAILED", "cases": results}, indent=2, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
