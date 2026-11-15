"""Conservative local extraction of reviewable memory candidates."""

from __future__ import annotations

import copy
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol

from hive_protocol.core import ProtocolError

from .models import CognitionEvent, MemoryCandidate
from .scoring import ScoreFeatures, score_candidate


_LINE_KIND = {
    "Decision": "DECISION",
    "Commitment": "COMMITMENT",
    "Blocker": "BLOCKER",
    "Outcome": "OUTCOME",
}
_LINE_PATTERN = re.compile(
    r"^(Decision|Commitment|Blocker|Outcome):[ \t]+(.{1,4096})$"
)
_SOURCE_TRUST = {
    "CAPTURE_ADMITTED": 0.7,
    "RESEARCH_ARTIFACT": 1.0,
    "TASK_EVENT": 0.85,
    "PROJECT_EVENT": 0.9,
}
_SENSITIVITY = {
    "PERSONA_PRIVATE": "SENSITIVE",
    "SURFACE_PRIVATE": "PRIVATE",
    "PROJECT_PRIVATE": "INTERNAL",
    "SHARED_REVIEWED": "PUBLIC",
}


class CandidateProvider(Protocol):
    def propose(self, event_document: dict[str, Any]) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class ExtractionResult:
    event_id: str
    outcome: str
    candidates: tuple[MemoryCandidate, ...]
    provider_state: dict[str, Any]
    warnings: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider_state", copy.deepcopy(self.provider_state))

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "outcome": self.outcome,
            "candidates": [candidate.as_dict() for candidate in self.candidates],
            "provider_state": copy.deepcopy(self.provider_state),
            "warnings": list(self.warnings),
        }


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:  # already structurally validated; remain fail closed
        raise ProtocolError("COGNITION_EVENT_TIME_INVALID", "event timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise ProtocolError("COGNITION_EVENT_TIME_INVALID", "event timestamp lacks timezone")
    return parsed


def _format_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ProtocolError("COGNITION_EVENT_TIME_INVALID", "current time lacks timezone")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _line_claims(text: str, project_id: str) -> list[dict[str, Any]]:
    claims: list[dict[str, Any]] = []
    for line in text.splitlines():
        match = _LINE_PATTERN.fullmatch(line.strip())
        if match is None:
            continue
        prefix, narrative = match.groups()
        digest = hashlib.sha256(narrative.encode("utf-8")).hexdigest()[:16]
        claims.append(
            {
                "candidate_type": _LINE_KIND[prefix],
                "subject_id": f"project:{project_id}",
                "key": f"{prefix.lower()}.{digest}",
                "value": narrative,
                "narrative": narrative,
                "proposed_action": "CREATE",
                "supersedes": None,
                "revokes": None,
            }
        )
    return claims


def _validated_provider_claims(
    provider: CandidateProvider, event: CognitionEvent
) -> list[dict[str, Any]]:
    raw = provider.propose(event.as_dict())
    if not isinstance(raw, Mapping) or set(raw) != {"claims"}:
        raise ProtocolError(
            "COGNITION_PROVIDER_OUTPUT_INVALID",
            "provider may return only a claims array",
        )
    claims = raw["claims"]
    if not isinstance(claims, list):
        raise ProtocolError(
            "COGNITION_PROVIDER_OUTPUT_INVALID", "provider claims must be an array"
        )
    validation_document = event.as_dict()
    validation_document["text"] = ""
    validation_document["structured_claims"] = copy.deepcopy(claims)
    return copy.deepcopy(CognitionEvent.from_dict(validation_document).structured_claims)


class DeterministicCognitionExtractor:
    """Creates STAGING candidates only; it has no PRIME or review capability."""

    def __init__(self, provider: CandidateProvider | None = None):
        self.provider = provider

    def extract(
        self,
        event: CognitionEvent,
        *,
        now: datetime,
        repetition_counts: Mapping[str, int] | None = None,
        contradiction_node_ids: Mapping[str, list[str]] | None = None,
        current_project_id: str | None = None,
    ) -> ExtractionResult:
        event_document = event.as_dict()
        if now.tzinfo is None:
            raise ProtocolError("COGNITION_EVENT_TIME_INVALID", "current time lacks timezone")
        if not event.evidence:
            return ExtractionResult(
                event_id=event.event_id,
                outcome="NO_CANDIDATE",
                candidates=(),
                provider_state={"status": "ABSENT", "used": False},
                warnings=("EVIDENCE_REQUIRED",),
            )
        repetitions = dict(repetition_counts or {})
        contradictions = {
            key: sorted(set(values))
            for key, values in (contradiction_node_ids or {}).items()
        }
        local_claims = copy.deepcopy(event.structured_claims)
        local_claims.extend(_line_claims(event.text, event.project_id))
        provider_claims: list[dict[str, Any]] = []
        warnings: tuple[str, ...] = ()
        provider_state = {"status": "ABSENT", "used": False}
        if self.provider is not None:
            try:
                provider_claims = _validated_provider_claims(self.provider, event)
            except (ProtocolError, TypeError, ValueError, RuntimeError):
                provider_state = {"status": "REJECTED", "used": False}
                warnings = ("PROVIDER_OUTPUT_REJECTED",)
            else:
                provider_state = {"status": "ACCEPTED", "used": bool(provider_claims)}

        candidates: list[MemoryCandidate] = []
        identities: set[str] = set()
        for claim, mode in [
            *((item, "LOCAL_DETERMINISTIC") for item in local_claims),
            *((item, "OPTIONAL_PROVIDER_PROPOSED") for item in provider_claims),
        ]:
            key = claim["key"]
            feature_values = ScoreFeatures.from_context(
                evidence_count=len(event.evidence),
                repetition_count=repetitions.get(key, 1),
                occurred_at=_parse_timestamp(event.occurred_at),
                now=now,
                same_project=(current_project_id or event.project_id) == event.project_id,
                source_trust=_SOURCE_TRUST[event.event_type],
                contradiction_count=len(contradictions.get(key, [])),
                sensitivity=_SENSITIVITY[event.privacy_class],
            )
            document: dict[str, Any] = {
                "schema_version": "hive.memory-candidate.v1",
                "candidate_id": "memory:placeholder",
                "tenant_id": event.tenant_id,
                "project_id": event.project_id,
                "candidate_type": claim["candidate_type"],
                "proposed_action": claim["proposed_action"],
                "experience_scope": copy.deepcopy(event.experience_scope),
                "subject_id": claim["subject_id"],
                "claim": {
                    "key": key,
                    "value": copy.deepcopy(claim["value"]),
                    "narrative": claim["narrative"],
                },
                "evidence": sorted(
                    copy.deepcopy(event.evidence), key=lambda item: item["anchor_id"]
                ),
                "score": score_candidate(feature_values),
                "sensitivity": _SENSITIVITY[event.privacy_class],
                "contradictions": contradictions.get(key, []),
                "status": "PROPOSED",
                "source_event_ids": [event.event_id],
                "extractor": {
                    "id": "nukotech.hive.deterministic-extractor"
                    if mode == "LOCAL_DETERMINISTIC"
                    else "nukotech.hive.optional-provider-proposer",
                    "version": "1.0.0",
                    "mode": mode,
                },
                "supersedes": claim["supersedes"],
                "revokes": claim["revokes"],
                "retention_until": None,
                "created_at": _format_timestamp(now),
            }
            document["candidate_id"] = MemoryCandidate.identity_for(document)
            candidate = MemoryCandidate.from_dict(document)
            if candidate.candidate_id in identities:
                continue
            identities.add(candidate.candidate_id)
            candidates.append(candidate)
        return ExtractionResult(
            event_id=event_document["event_id"],
            outcome="PROPOSED" if candidates else "NO_CANDIDATE",
            candidates=tuple(candidates),
            provider_state=provider_state,
            warnings=warnings,
        )
