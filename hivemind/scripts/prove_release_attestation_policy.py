#!/usr/bin/env python3
"""Exercise positive and mandatory negative attestation-policy paths."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
# The proof invokes only the repository-owned verifier with the current interpreter.
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_case(name: str, command: list[str], expect_success: bool) -> dict[str, object]:
    # The command starts with sys.executable and the repository-owned verifier path.
    result = subprocess.run(  # nosec B603
        command, check=False, capture_output=True, text=True
    )
    passed = (result.returncode == 0) is expect_success
    output = result.stdout.strip().splitlines()
    parsed: object = output[-1] if output else ""
    if output:
        try:
            parsed = json.loads(output[-1])
        except json.JSONDecodeError:
            pass
    return {
        "case": name,
        "expected": "accept" if expect_success else "reject",
        "exit_code": result.returncode,
        "observed": parsed,
        "passed": passed,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--source-digest", required=True)
    parser.add_argument("--cosign-binary", type=Path, required=True)
    parser.add_argument("--cosign-binary-sha256", required=True)
    args = parser.parse_args()

    verifier = Path(__file__).with_name("verify_release_attestation.py")
    digest = sha256(args.artifact)
    results: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="hive-attestation-proof-") as raw:
        root = Path(raw)
        ledger = root / "accepted-ledger.json"
        base = [
            sys.executable,
            str(verifier),
            "--artifact",
            str(args.artifact),
            "--policy",
            str(args.policy),
            "--expected-sha256",
            digest,
            "--expected-source-digest",
            args.source_digest,
            "--claim-id",
            "alpha-signing-candidate",
            "--ledger",
            str(ledger),
            "--bundle",
            str(args.bundle),
            "--cosign-binary",
            str(args.cosign_binary),
            "--cosign-binary-sha256",
            args.cosign_binary_sha256,
        ]
        results.append(run_case("valid_attestation", base, True))
        replay = base.copy()
        replay[replay.index("alpha-signing-candidate")] = "second-claim-same-attestation"
        results.append(run_case("replayed_attestation", replay, False))

        tampered = root / args.artifact.name
        shutil.copyfile(args.artifact, tampered)
        with tampered.open("ab") as handle:
            handle.write(b"TAMPER")
        tampered_command = base.copy()
        tampered_command[tampered_command.index(str(args.artifact))] = str(tampered)
        tampered_command[tampered_command.index(digest)] = sha256(tampered)
        tampered_command[tampered_command.index(str(ledger))] = str(root / "tampered-ledger.json")
        results.append(run_case("tampered_artifact", tampered_command, False))

        wrong_digest = base.copy()
        wrong_digest[wrong_digest.index(digest)] = "0" * 64
        wrong_digest[wrong_digest.index(str(ledger))] = str(root / "wrong-digest-ledger.json")
        results.append(run_case("wrong_expected_digest", wrong_digest, False))

        unsigned = root / "unsigned-artifact.bin"
        unsigned.write_bytes(b"not-attested\n")
        unsigned_command = base.copy()
        unsigned_command[unsigned_command.index(str(args.artifact))] = str(unsigned)
        unsigned_command[unsigned_command.index(digest)] = sha256(unsigned)
        unsigned_command[unsigned_command.index(str(ledger))] = str(root / "unsigned-ledger.json")
        results.append(run_case("unsigned_artifact", unsigned_command, False))

        wrong_policy = json.loads(args.policy.read_text(encoding="utf-8"))
        wrong_policy["identity"]["repository"] = "example-org/unrelated-repo"
        wrong_policy["identity"]["certificate_identity"] = (
            "https://github.com/example-org/unrelated-repo/.github/workflows/unrelated-workflow.yml@"
            "refs/heads/main"
        )
        wrong_path = root / "wrong-identity-policy.json"
        wrong_path.write_text(json.dumps(wrong_policy, sort_keys=True), encoding="utf-8")
        wrong_identity = base.copy()
        wrong_identity[wrong_identity.index(str(args.policy))] = str(wrong_path)
        wrong_identity[wrong_identity.index(str(ledger))] = str(root / "wrong-identity-ledger.json")
        results.append(run_case("wrong_identity", wrong_identity, False))

    passed = all(bool(item["passed"]) for item in results)
    print(json.dumps({"outcome": "VERIFIED" if passed else "FAILED", "cases": results}, indent=2, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
