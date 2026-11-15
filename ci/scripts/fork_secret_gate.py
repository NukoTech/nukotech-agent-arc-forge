#!/usr/bin/env python3
"""Skip secret-backed CI checks on fork PRs when the secret is absent.

GitHub does not provide repository secrets to pull_request workflows that
run on a fork. Detect that case from event metadata and an empty secret
env value, then exit successfully with a maintainer notice. Missing or
malformed secrets still fail closed on same-repository pull requests,
pushes, and every other event.

This module never prints a secret, its length, or a digest of it.
"""

from __future__ import annotations

import os
from pathlib import Path

FORK_SKIP_NOTICE = (
    "Fork PR: secret-backed check skipped; a maintainer must re-run before merge"
)
GITHUB_NOTICE = f"::notice::{FORK_SKIP_NOTICE}"


def github_event_name(
    event_name: str | None = None,
) -> str:
    if event_name is not None:
        return event_name
    return os.environ.get("EVENT_NAME") or os.environ.get("GITHUB_EVENT_NAME") or ""


def github_repository(repository: str | None = None) -> str:
    if repository is not None:
        return repository
    return os.environ.get("GITHUB_REPOSITORY") or ""


def pull_request_head_repo(head_repo: str | None = None) -> str:
    if head_repo is not None:
        return head_repo
    return os.environ.get("HEAD_REPO") or ""


def secret_is_absent(raw: str | None) -> bool:
    return raw is None or not str(raw).strip()


def is_fork_pull_request(
    event_name: str | None = None,
    head_repo: str | None = None,
    repository: str | None = None,
) -> bool:
    event = github_event_name(event_name)
    head = pull_request_head_repo(head_repo)
    repo = github_repository(repository)
    if event != "pull_request":
        return False
    if not head or not repo:
        return False
    return head != repo


def should_skip_secret_backed_check(
    *,
    secret: str | None,
    event_name: str | None = None,
    head_repo: str | None = None,
    repository: str | None = None,
) -> bool:
    """True only for a fork pull_request whose secret env value is empty."""
    return is_fork_pull_request(event_name, head_repo, repository) and secret_is_absent(
        secret
    )


def emit_fork_skip_notice() -> None:
    print(GITHUB_NOTICE)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary:
        return
    path = Path(summary)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(FORK_SKIP_NOTICE + "\n")


def maybe_skip_for_fork_pr(secret: str | None) -> bool:
    """If this run should skip, emit the notice and return True."""
    if should_skip_secret_backed_check(secret=secret):
        emit_fork_skip_notice()
        return True
    return False
