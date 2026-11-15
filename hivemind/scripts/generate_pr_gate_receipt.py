#!/usr/bin/env python3
"""Generate a deterministic receipt that distinguishes PR head and merge-ref state."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


SHA1 = re.compile(r"^[0-9a-f]{40}$")


def require_sha(value: str, label: str) -> str:
    if not SHA1.fullmatch(value):
        raise SystemExit(f"{label} must be a lowercase 40-character Git object ID")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pr-number", type=int, required=True)
    parser.add_argument("--pr-head-repository", required=True)
    parser.add_argument("--pr-head-sha", required=True)
    parser.add_argument("--pr-head-tree", required=True)
    parser.add_argument("--pr-base-sha", required=True)
    parser.add_argument("--pr-merge-ref", required=True)
    parser.add_argument("--pr-merge-sha", required=True)
    parser.add_argument("--pr-merge-tree", required=True)
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--github-ref", required=True)
    parser.add_argument("--github-sha", required=True)
    parser.add_argument("--workflow-name", required=True)
    parser.add_argument("--workflow-identity", required=True)
    parser.add_argument("--oidc-issuer", required=True)
    parser.add_argument("--signed-subject-identity", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    expected_ref = f"refs/pull/{args.pr_number}/merge"
    identity_prefix = f"https://github.com/{args.repository}/.github/workflows/"
    identity_suffix = f"@{expected_ref}"
    workflow_identity = args.workflow_identity
    if (
        not workflow_identity.startswith(identity_prefix)
        or not workflow_identity.endswith(identity_suffix)
    ):
        raise SystemExit("workflow identity is not exact for this PR merge ref")
    workflow_path = workflow_identity[len(identity_prefix) : len(workflow_identity) - len(identity_suffix)]
    if re.fullmatch(r"[A-Za-z0-9._-]+\.ya?ml", workflow_path) is None:
        raise SystemExit("workflow identity is not exact for this PR merge ref")
    expected_identity = f"{identity_prefix}{workflow_path}{identity_suffix}"
    if args.event_name != "pull_request":
        raise SystemExit("event must be pull_request")
    if args.pr_number <= 0 or args.pr_merge_ref != expected_ref:
        raise SystemExit("PR merge ref does not match PR number")
    if args.github_ref != args.pr_merge_ref or args.github_sha != args.pr_merge_sha:
        raise SystemExit("GITHUB_REF/GITHUB_SHA do not describe the PR merge ref")
    if args.pr_head_repository != args.repository:
        raise SystemExit("PR head repository is not the workflow repository")
    if args.workflow_identity != expected_identity:
        raise SystemExit("workflow identity is not exact for this PR merge ref")
    if args.signed_subject_identity != args.workflow_identity:
        raise SystemExit("signed subject identity differs from workflow identity")
    if args.oidc_issuer != "https://token.actions.githubusercontent.com":
        raise SystemExit("unexpected OIDC issuer")

    receipt = {
        "schema": "nukotech.hive.alpha.pr-gate-execution-receipt.v1",
        "event_name": args.event_name,
        "github": {"ref": args.github_ref, "sha": require_sha(args.github_sha, "github sha")},
        "pull_request": {
            "number": args.pr_number,
            "head": {
                "repository": args.pr_head_repository,
                "sha": require_sha(args.pr_head_sha, "PR head sha"),
                "tree": require_sha(args.pr_head_tree, "PR head tree"),
            },
            "base": {"sha": require_sha(args.pr_base_sha, "PR base sha")},
            "merge_ref": {
                "ref": args.pr_merge_ref,
                "sha": require_sha(args.pr_merge_sha, "PR merge sha"),
                "tree": require_sha(args.pr_merge_tree, "PR merge tree"),
            },
        },
        "workflow": {
            "name": args.workflow_name,
            "identity": args.workflow_identity,
            "oidc_issuer": args.oidc_issuer,
            "signed_subject_identity": args.signed_subject_identity,
        },
        "status": "PR_GATE_ATTESTATION_NOT_A_RELEASE",
    }
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
