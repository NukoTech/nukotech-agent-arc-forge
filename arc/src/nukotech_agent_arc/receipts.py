"""Canonical composition and refusal receipts."""

from __future__ import annotations

import json
from typing import Any, Mapping

from .schema import ValidationIssue
from .security import SecurityDecision


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    """Serialize JSON identically for identical JSON-compatible values."""

    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n"
    ).encode("utf-8")


def issue_mapping(issue: ValidationIssue) -> dict[str, str]:
    return {"code": issue.code, "message": issue.message, "path": issue.path}


def decision_mapping(decision: SecurityDecision) -> dict[str, Any]:
    return {
        "code": decision.code,
        "decision": decision.decision.value,
        "evidence_hash": decision.evidence_hash,
        "provider": decision.provider,
        "reasons": list(decision.reasons),
        "stage": decision.stage.value,
    }
