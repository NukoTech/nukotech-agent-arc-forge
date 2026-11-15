"""Deterministic, proposal-only awareness candidate generation."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Iterable

from .core import ProtocolError


_KINDS = {
    "UNFINISHED",
    "CONTRADICTION",
    "STALE_DECISION",
    "REPEATED_TOPIC",
    "RELATED_CONTEXT",
}


def _candidate(kind: str, evidence_ids: list[str], reason: str) -> dict[str, Any]:
    if kind not in _KINDS:
        raise ProtocolError("AWARENESS_KIND", f"unsupported awareness kind: {kind}")
    seed = json.dumps([kind, sorted(evidence_ids), reason], separators=(",", ":"))
    return {
        "candidate_id": f"aware:{hashlib.sha256(seed.encode()).hexdigest()[:20]}",
        "kind": kind,
        "status": "PROPOSED",
        "external_action": False,
        "evidence_ids": sorted(evidence_ids),
        "reason": reason,
    }


def awareness_candidates(
    events: Iterable[dict[str, Any]], *, now: datetime | None = None, stale_days: int = 30
) -> list[dict[str, Any]]:
    """Derive candidates from supplied events; never inspect or act outside them."""

    current = now or datetime.now(timezone.utc)
    normalized = list(events)
    for event in normalized:
        if not isinstance(event.get("event_id"), str) or not event["event_id"]:
            raise ProtocolError("EVENT_ID_REQUIRED", "each awareness event requires event_id")
    candidates: list[dict[str, Any]] = []
    for event in normalized:
        if event.get("state") in {"OPEN", "PENDING", "BLOCKED"}:
            candidates.append(
                _candidate("UNFINISHED", [event["event_id"]], f"state={event['state']}")
            )
        if event.get("type") == "decision" and isinstance(event.get("review_at"), str):
            try:
                review_at = datetime.fromisoformat(event["review_at"].replace("Z", "+00:00"))
            except ValueError as exc:
                raise ProtocolError("EVENT_TIME_INVALID", "review_at must be ISO-8601") from exc
            if (current - review_at).days >= stale_days:
                candidates.append(
                    _candidate("STALE_DECISION", [event["event_id"]], "review date exceeded")
                )
    by_subject: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in normalized:
        if isinstance(event.get("subject"), str) and event["subject"]:
            by_subject[event["subject"]].append(event)
    for subject, group in sorted(by_subject.items()):
        values = {
            json.dumps(event.get("value"), sort_keys=True)
            for event in group
            if "value" in event
        }
        if len(values) > 1:
            candidates.append(
                _candidate(
                    "CONTRADICTION",
                    [event["event_id"] for event in group],
                    f"conflicting values for {subject}",
                )
            )
    topics = Counter(
        topic
        for event in normalized
        for topic in event.get("topics", [])
        if isinstance(topic, str) and topic
    )
    for topic, count in sorted(topics.items()):
        ids = [event["event_id"] for event in normalized if topic in event.get("topics", [])]
        if count >= 2:
            candidates.append(_candidate("REPEATED_TOPIC", ids, f"topic={topic}; count={count}"))
    for event in normalized:
        related = event.get("related_source_ids", [])
        if isinstance(related, list) and related:
            candidates.append(
                _candidate(
                    "RELATED_CONTEXT",
                    [event["event_id"], *[str(item) for item in related]],
                    "event declared related context",
                )
            )
    return sorted(candidates, key=lambda item: (item["kind"], item["candidate_id"]))
