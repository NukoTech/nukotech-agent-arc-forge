#!/usr/bin/env python3
"""Fail if any commit author or committer email is on the banned list.

Banned addresses are compared via HMAC-SHA256 using the repository Actions
secret ARCFORGE_AUTHOR_EMAIL_HMAC. The secret is JSON:

    {"v":1,"alg":"hmac-sha256","key_hex":"<64+ hex>","digests":["<64 hex>",...]}

A commit is banned when hmac-sha256(key, lowercased email) matches a digest
for the author or the committer. This script never prints a key, a digest,
or an email address; match failures report the commit SHA and which side
matched (author or committer). Missing or invalid configuration fails closed.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import subprocess
import sys
from pathlib import Path

import fork_secret_gate

ENV_VAR = "ARCFORGE_AUTHOR_EMAIL_HMAC"
CONFIG_ERROR = "author-email: ARCFORGE_AUTHOR_EMAIL_HMAC is missing or invalid"


class ConfigError(ValueError):
    """Fail-closed configuration error; message must not include secret material."""


def find_root(start: Path) -> Path:
    for candidate in [start, *start.parents]:
        if (candidate / ".git").exists():
            return candidate
    return start


def _is_hex(value: str, length: int | None = None) -> bool:
    if not value or any(c not in "0123456789abcdef" for c in value.lower()):
        return False
    if length is not None and len(value) != length:
        return False
    return True


def load_hmac_config(raw: str | None) -> tuple[bytes, tuple[str, ...]]:
    if raw is None or not str(raw).strip():
        raise ConfigError(CONFIG_ERROR)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(CONFIG_ERROR) from exc
    if not isinstance(payload, dict):
        raise ConfigError(CONFIG_ERROR)
    if payload.get("v") != 1:
        raise ConfigError(CONFIG_ERROR)
    if payload.get("alg") != "hmac-sha256":
        raise ConfigError(CONFIG_ERROR)
    key_hex = payload.get("key_hex")
    if not isinstance(key_hex, str) or not _is_hex(key_hex) or len(key_hex) % 2 != 0:
        raise ConfigError(CONFIG_ERROR)
    key = bytes.fromhex(key_hex)
    if len(key) < 32:
        raise ConfigError(CONFIG_ERROR)
    digests_raw = payload.get("digests")
    if not isinstance(digests_raw, list) or not digests_raw:
        raise ConfigError(CONFIG_ERROR)
    digests: list[str] = []
    for item in digests_raw:
        if not isinstance(item, str):
            raise ConfigError(CONFIG_ERROR)
        digest = item.strip().lower()
        if not _is_hex(digest, 64):
            raise ConfigError(CONFIG_ERROR)
        digests.append(digest)
    return key, tuple(digests)


def email_hmac(key: bytes, email: str) -> str:
    return hmac.new(
        key,
        email.strip().lower().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def digest_is_banned(candidate: str, digests: tuple[str, ...]) -> bool:
    matched = False
    for expected in digests:
        if hmac.compare_digest(candidate, expected):
            matched = True
    return matched


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def commit_exists(root: Path, sha: str) -> bool:
    if not sha:
        return False
    return subprocess.run(
        ["git", "-C", str(root), "cat-file", "-e", f"{sha}^{{commit}}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0


def resolve_range(root: Path, event_name: str, base_sha: str, head_sha: str, explicit: str | None) -> list[str]:
    """Return commit SHAs that should be checked, oldest first."""
    if explicit:
        out = git(root, "rev-list", "--reverse", explicit)
        return [s for s in out.splitlines() if s]

    if event_name == "pull_request" and base_sha and head_sha:
        if not commit_exists(root, base_sha):
            raise SystemExit(
                f"author-email: pull request base SHA {base_sha} is not in this checkout; "
                "fetch-depth: 0 is required."
            )
        if not commit_exists(root, head_sha):
            raise SystemExit(
                f"author-email: pull request head SHA {head_sha} is not in this checkout; "
                "fetch-depth: 0 is required."
            )
        out = git(root, "rev-list", "--reverse", f"{base_sha}..{head_sha}")
        return [s for s in out.splitlines() if s]

    # push to main, workflow_dispatch, or missing PR SHAs: full history.
    out = git(root, "rev-list", "--reverse", "--all")
    return [s for s in out.splitlines() if s]


def emails_for(root: Path, sha: str) -> tuple[str, str]:
    out = git(root, "log", "-1", "--format=%ae%n%ce", sha)
    parts = out.splitlines()
    if len(parts) < 2:
        raise SystemExit(f"author-email: could not read author/committer for {sha}")
    return parts[0], parts[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=None)
    parser.add_argument(
        "--range",
        default=None,
        help="git revision range to check (default: PR base..head, else --all)",
    )
    args = parser.parse_args(argv)

    secret = os.environ.get(ENV_VAR)
    if fork_secret_gate.maybe_skip_for_fork_pr(secret):
        return 0

    root = (args.root or find_root(Path.cwd())).resolve()
    try:
        key, digests = load_hmac_config(secret)
    except ConfigError:
        print(CONFIG_ERROR, file=sys.stderr)
        return 2

    event_name = os.environ.get("EVENT_NAME") or os.environ.get("GITHUB_EVENT_NAME") or ""
    base_sha = os.environ.get("BASE_SHA") or ""
    head_sha = os.environ.get("HEAD_SHA") or ""

    try:
        shas = resolve_range(root, event_name, base_sha, head_sha, args.range)
    except subprocess.CalledProcessError as exc:
        print(f"author-email: git rev-list failed: {exc}", file=sys.stderr)
        return 2

    hits: list[str] = []
    for sha in shas:
        author, committer = emails_for(root, sha)
        author_hit = digest_is_banned(email_hmac(key, author), digests)
        committer_hit = digest_is_banned(email_hmac(key, committer), digests)
        if author_hit or committer_hit:
            sides = []
            if author_hit:
                sides.append("author")
            if committer_hit:
                sides.append("committer")
            hits.append(f"{sha} ({', '.join(sides)})")

    if hits:
        print(
            f"author-email: {len(hits)} commit(s) have a banned author or committer email "
            f"(checked {len(shas)} commit(s)):"
        )
        for hit in hits[:100]:
            print(f"  {hit}")
        if len(hits) > 100:
            print(f"  … {len(hits) - 100} more")
        return 1

    print(f"author-email: no banned addresses ({len(shas)} commit(s) checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
