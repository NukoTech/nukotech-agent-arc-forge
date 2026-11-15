#!/usr/bin/env python3
"""Scan source trees and tar artifacts for concrete credential patterns."""

from __future__ import annotations

import re
import sys
import tarfile
from pathlib import Path
from typing import Iterable


PATTERNS = {
    "private-key": re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    "github-token": re.compile(rb"(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{30,})"),
    "aws-access-key": re.compile(rb"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    "slack-token": re.compile(rb"xox[baprs]-[A-Za-z0-9-]{20,}"),
    "openai-key": re.compile(rb"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    "pypi-token": re.compile(rb"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,}"),
    "google-api-key": re.compile(rb"AIza[A-Za-z0-9_-]{30,}"),
    "stripe-live-key": re.compile(rb"sk_live_[A-Za-z0-9]{20,}"),
    "basic-auth-url": re.compile(rb"https?://[^\s/:@]+:[^\s/@]+@"),
}
SKIP_PARTS = {".git", ".venv", "__pycache__", "build"}
MAX_TEXT_BYTES = 5 * 1024 * 1024


def regular_files(path: Path) -> Iterable[Path]:
    if path.is_file():
        yield path
        return
    for candidate in sorted(path.rglob("*")):
        if candidate.is_file() and not candidate.is_symlink() and not SKIP_PARTS.intersection(candidate.parts):
            yield candidate


def inspect(label: str, payload: bytes) -> list[str]:
    if len(payload) > MAX_TEXT_BYTES or b"\0" in payload:
        return []
    return [f"{label}: {name}" for name, pattern in PATTERNS.items() if pattern.search(payload)]


def main() -> int:
    if len(sys.argv) < 2:
        raise SystemExit("usage: credential_pattern_scan.py PATH [PATH ...]")
    findings: list[str] = []
    inspected = 0
    for value in sys.argv[1:]:
        path = Path(value).resolve()
        if path.is_file() and tarfile.is_tarfile(path):
            with tarfile.open(path, "r:*") as archive:
                for member in archive.getmembers():
                    if not member.isfile() or member.size > MAX_TEXT_BYTES:
                        continue
                    handle = archive.extractfile(member)
                    if handle is None:
                        continue
                    inspected += 1
                    findings.extend(inspect(f"{path.name}:{member.name}", handle.read()))
            continue
        for candidate in regular_files(path):
            inspected += 1
            findings.extend(inspect(str(candidate), candidate.read_bytes()))
    if findings:
        for finding in findings:
            print(f"CREDENTIAL_PATTERN: {finding}", file=sys.stderr)
        return 1
    print(f"PASS: no credential patterns in {inspected} inspected files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
