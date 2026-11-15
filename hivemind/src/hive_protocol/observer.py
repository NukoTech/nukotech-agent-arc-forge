"""Read-only repository observation with append-only external receipts."""

from __future__ import annotations

import os
import re
import stat
# The only child executable is a validated, fixed App helper; no shell is used.
import subprocess  # nosec B404
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from .core import ProtocolError, document_digest, validate_document
from .storage import atomic_write_json, read_json, utc_now


REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
REF_PATTERN = re.compile(r"^refs/heads/[A-Za-z0-9._/-]+$")


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError("OBSERVATION_TIME_INVALID", value) from exc
    if parsed.tzinfo is None:
        raise ProtocolError("OBSERVATION_TIME_INVALID", "timezone is required")
    return parsed.astimezone(timezone.utc)


def _validate_helper(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise ProtocolError("GIT_HELPER_BOUNDARY", "Git helper must be a regular file")
    mode = path.stat().st_mode
    if not mode & stat.S_IXUSR:
        raise ProtocolError("GIT_HELPER_BOUNDARY", "Git helper is not owner-executable")


def _ls_remote(helper: Path, repository: str, ref: str) -> str | None:
    if not REPOSITORY_PATTERN.fullmatch(repository) or not REF_PATTERN.fullmatch(ref):
        raise ProtocolError("ROSTER_TARGET_INVALID", f"unsafe repository target: {repository} {ref}")
    # Repository/ref syntax and the executable boundary are validated above. The
    # command is an argv list, never a shell string.
    completed = subprocess.run(  # nosec B603
        [
            str(helper),
            "--git",
            "ls-remote",
            f"https://github.com/{repository}.git",
            ref,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip().splitlines()[-1] if completed.stderr.strip() else "ls-remote failed"
        raise ProtocolError("REMOTE_OBSERVATION_FAILED", f"{repository}: {detail}")
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if not lines:
        return None
    if len(lines) != 1:
        raise ProtocolError("REMOTE_OBSERVATION_AMBIGUOUS", repository)
    fields = lines[0].split()
    if len(fields) != 2 or fields[1] != ref or not re.fullmatch(r"[0-9a-f]{40}", fields[0]):
        raise ProtocolError("REMOTE_OBSERVATION_INVALID", repository)
    return fields[0]


def observe_repositories(roster_path: Path, output_dir: Path, git_helper: Path) -> dict[str, Any]:
    namespace = os.environ.get("HIVE_PROCESS_NAMESPACE", "")
    if not namespace.startswith("HIVE-LAB-"):
        raise ProtocolError("PROCESS_NAMESPACE_DENIED", "HIVE-LAB process namespace is required")
    roster = read_json(roster_path)
    validate_document(roster, "repository-roster")
    _validate_helper(git_helper)
    now = datetime.now(timezone.utc)
    results: list[dict[str, Any]] = []

    for entry in roster["repositories"]:
        observed_commit: str | None
        if entry["transport"] == "github-app":
            observed_commit = _ls_remote(git_helper, entry["repository"], entry["ref"])
            if observed_commit is None:
                status = "EXPECTED_ABSENT" if entry.get("expected_absent") else "MISSING"
            elif entry.get("expected_absent"):
                status = "UNEXPECTED_PRESENT"
            elif entry.get("expected_commit") and observed_commit != entry["expected_commit"]:
                status = "DRIFTED"
            else:
                status = "CURRENT"
        else:
            observed_commit = entry["expected_commit"]
            observed_at = _parse_time(entry["evidence_observed_at"])
            age_hours = (now - observed_at).total_seconds() / 3600
            status = (
                "CURRENT_EVIDENCE"
                if 0 <= age_hours <= entry["evidence_max_age_hours"]
                else "STALE_EVIDENCE"
            )
        results.append(
            {
                "id": entry["id"],
                "repository": entry["repository"],
                "ref": entry["ref"],
                "role": entry["role"],
                "required": entry["required"],
                "transport": entry["transport"],
                "observed_commit": observed_commit,
                "expected_commit": entry.get("expected_commit"),
                "status": status,
            }
        )

    unhealthy = [
        result["id"]
        for result in results
        if result["required"] and result["status"] not in {"CURRENT", "CURRENT_EVIDENCE", "EXPECTED_ABSENT"}
    ]
    receipt = {
        "schema_version": "hive.repository-observation.v1",
        "observation_id": str(uuid4()),
        "observed_at": utc_now(),
        "process_id": os.getpid(),
        "process_namespace": namespace,
        "roster_sha256": document_digest(roster),
        "outcome": "HEALTHY" if not unhealthy else "DEGRADED",
        "unhealthy_required": unhealthy,
        "repositories": results,
        "mutation_policy": "OBSERVE_ONLY_NO_GIT_WRITE",
    }
    if output_dir.is_symlink():
        raise ProtocolError("OUTPUT_BOUNDARY", "observation output cannot be a symlink")
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    output_path = output_dir / f"repository-observation-{receipt['observation_id']}.json"
    atomic_write_json(output_path, receipt)
    return {**receipt, "receipt_path": str(output_path)}
