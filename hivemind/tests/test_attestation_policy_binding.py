"""Checked-in attestation policies stay unbound until the launch cut fills them."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

import pytest

HIVEMIND = Path(__file__).resolve().parents[1]
POLICIES = (
    HIVEMIND / "policies" / "pr-gate-attestation-policy.json",
    HIVEMIND / "policies" / "release-attestation-policy.json",
)


def _verifier():
    path = HIVEMIND / "scripts" / "verify_release_attestation.py"
    spec = importlib.util.spec_from_file_location("verify_release_attestation", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_checked_in_attestation_policies_fail_closed_while_unbound(tmp_path: Path) -> None:
    verifier = _verifier()
    bound = {
        "certificate_identity": (
            "https://github.com/example-org/example-repo/.github/workflows/"
            "release-provenance.yml@refs/tags/v1.0.0"
        ),
        "oidc_issuer": "https://token.actions.githubusercontent.com",
        "repository": "example-org/example-repo",
        "source_ref": "refs/tags/v1.0.0",
        "workflow_name": "Release provenance",
        "workflow_trigger": "push",
    }
    verifier.require_bound_identity(bound)

    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"placeholder-artifact\n")
    for policy in POLICIES:
        identity = json.loads(policy.read_text(encoding="utf-8"))["identity"]
        with pytest.raises(verifier.VerificationError, match="POLICY_IDENTITY_UNBOUND"):
            verifier.require_bound_identity(identity)
        args = argparse.Namespace(
            artifact=artifact,
            policy=policy,
            expected_sha256="0" * 64,
            expected_source_digest="0" * 40,
            claim_id="unbound-policy",
            ledger=tmp_path / "ledger.json",
            bundle=None,
            cosign_binary=tmp_path / "cosign",
            cosign_binary_sha256="0" * 64,
        )
        with pytest.raises(verifier.VerificationError, match="POLICY_IDENTITY_UNBOUND"):
            verifier.verify(args)
