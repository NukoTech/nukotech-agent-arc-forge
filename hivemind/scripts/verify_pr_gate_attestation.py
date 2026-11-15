#!/usr/bin/env python3
"""Fail-closed verification for the exact PR head/merge execution identity."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from verify_release_attestation import (
    VerificationError,
    bind_policy_repository,
    load_json_object,
    verify,
    workflow_path_for_ref,
)


def require_equal(actual: object, expected: object, label: str) -> None:
    if actual != expected:
        raise VerificationError(f"PR_GATE_{label}_MISMATCH")


def verify_pr_gate(args: argparse.Namespace) -> dict[str, object]:
    if args.bundle is None:
        raise VerificationError("SIGSTORE_BUNDLE_REQUIRED")
    execution = load_json_object(args.execution_receipt.resolve(), "PR_GATE_EXECUTION_RECEIPT")
    policy = load_json_object(args.policy.resolve(), "POLICY")
    pull_request = execution.get("pull_request")
    workflow = execution.get("workflow")
    github = execution.get("github")
    identity = policy.get("identity")
    if not all(isinstance(value, dict) for value in (pull_request, workflow, github, identity)):
        raise VerificationError("PR_GATE_FIELDS_INVALID")
    head = pull_request.get("head")
    base = pull_request.get("base")
    merge_ref = pull_request.get("merge_ref")
    if not all(isinstance(value, dict) for value in (head, base, merge_ref)):
        raise VerificationError("PR_GATE_GIT_FIELDS_INVALID")

    git_ids = (
        args.pr_head_sha,
        args.pr_head_tree,
        args.pr_base_sha,
        args.pr_merge_sha,
        args.pr_merge_tree,
    )
    if any(re.fullmatch(r"[0-9a-f]{40}", value) is None for value in git_ids):
        raise VerificationError("PR_GATE_GIT_OBJECT_ID_INVALID")
    match = re.fullmatch(r"refs/pull/([1-9][0-9]*)/merge", args.pr_merge_ref)
    if match is None:
        raise VerificationError("PR_GATE_MERGE_REF_INVALID")
    identity = bind_policy_repository(identity)
    policy["identity"] = identity
    repository = identity.get("repository")
    if not isinstance(repository, str):
        raise VerificationError("POLICY_IDENTITY_UNBOUND")
    workflow_path = workflow_path_for_ref(
        str(identity.get("certificate_identity")),
        repository,
        args.pr_merge_ref,
    )
    expected_identity = (
        f"https://github.com/{repository}/.github/workflows/"
        f"{workflow_path}@{args.pr_merge_ref}"
    )

    require_equal(execution.get("schema"), "nukotech.hive.alpha.pr-gate-execution-receipt.v1", "SCHEMA")
    require_equal(execution.get("event_name"), "pull_request", "EVENT")
    require_equal(pull_request.get("number"), int(match.group(1)), "NUMBER")
    require_equal(head.get("repository"), repository, "HEAD_REPOSITORY")
    require_equal(head.get("sha"), args.pr_head_sha, "HEAD_SHA")
    require_equal(head.get("tree"), args.pr_head_tree, "HEAD_TREE")
    require_equal(base.get("sha"), args.pr_base_sha, "BASE_SHA")
    require_equal(merge_ref.get("ref"), args.pr_merge_ref, "MERGE_REF")
    require_equal(merge_ref.get("sha"), args.pr_merge_sha, "MERGE_SHA")
    require_equal(merge_ref.get("tree"), args.pr_merge_tree, "MERGE_TREE")
    require_equal(github.get("ref"), args.pr_merge_ref, "GITHUB_REF")
    require_equal(github.get("sha"), args.pr_merge_sha, "GITHUB_SHA")
    require_equal(workflow.get("identity"), args.workflow_identity, "WORKFLOW_IDENTITY")
    require_equal(workflow.get("name"), identity.get("workflow_name"), "WORKFLOW_NAME")
    require_equal(workflow.get("signed_subject_identity"), args.workflow_identity, "SUBJECT_IDENTITY")
    require_equal(workflow.get("oidc_issuer"), "https://token.actions.githubusercontent.com", "OIDC_ISSUER")
    require_equal(identity.get("certificate_identity"), args.workflow_identity, "POLICY_IDENTITY")
    require_equal(args.workflow_identity, expected_identity, "EXPECTED_IDENTITY")
    require_equal(identity.get("oidc_issuer"), "https://token.actions.githubusercontent.com", "POLICY_ISSUER")
    require_equal(identity.get("source_ref"), args.pr_merge_ref, "POLICY_REF")
    require_equal(identity.get("workflow_trigger"), "pull_request", "POLICY_TRIGGER")
    if args.pr_head_sha == args.pr_merge_sha:
        raise VerificationError("PR_GATE_HEAD_MISLABELED_AS_MERGE_SHA")

    common = argparse.Namespace(
        artifact=args.artifact,
        policy=args.policy,
        expected_sha256=args.expected_sha256,
        expected_source_digest=args.pr_merge_sha,
        claim_id=args.claim_id,
        ledger=args.ledger,
        bundle=args.bundle,
        cosign_binary=args.cosign_binary,
        cosign_binary_sha256=args.cosign_binary_sha256,
    )
    accepted = verify(common)
    return {
        "outcome": "ACCEPTED",
        "mode": "exact-pr-gate",
        "pr_head_sha": args.pr_head_sha,
        "pr_head_tree": args.pr_head_tree,
        "pr_base_sha": args.pr_base_sha,
        "pr_merge_ref": args.pr_merge_ref,
        "pr_merge_sha": args.pr_merge_sha,
        "pr_merge_tree": args.pr_merge_tree,
        "workflow_identity": args.workflow_identity,
        "attestation": accepted,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--execution-receipt", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--pr-head-sha", required=True)
    parser.add_argument("--pr-head-tree", required=True)
    parser.add_argument("--pr-base-sha", required=True)
    parser.add_argument("--pr-merge-ref", required=True)
    parser.add_argument("--pr-merge-sha", required=True)
    parser.add_argument("--pr-merge-tree", required=True)
    parser.add_argument("--workflow-identity", required=True)
    parser.add_argument("--claim-id", required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--cosign-binary", type=Path, required=True)
    parser.add_argument("--cosign-binary-sha256", required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        receipt = verify_pr_gate(args)
    except (KeyError, OSError, VerificationError) as exc:
        print(json.dumps({"outcome": "REJECTED", "reason": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
