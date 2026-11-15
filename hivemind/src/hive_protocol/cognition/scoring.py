"""Explainable review-priority scoring for memory candidates."""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from hive_protocol.core import ProtocolError


SCORE_WEIGHTS = {
    "evidence_quality": 0.25,
    "repetition": 0.15,
    "recency": 0.15,
    "project_relevance": 0.15,
    "source_trust": 0.15,
    "contradiction": -0.1,
    "sensitivity": -0.05,
}
SENSITIVITY_VALUES = {
    "PUBLIC": 0.0,
    "INTERNAL": 0.25,
    "PRIVATE": 0.75,
    "SENSITIVE": 1.0,
}


def _bounded_number(value: Any, label: str) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(value)
        or value < 0
        or value > 1
    ):
        raise ProtocolError(
            "COGNITION_SCORE_CONTEXT_INVALID", f"{label} must be between zero and one"
        )
    return float(value)


@dataclass(frozen=True)
class ScoreFeatures:
    evidence_quality: float
    repetition: float
    recency: float
    project_relevance: float
    source_trust: float
    contradiction: float
    sensitivity: float

    def as_dict(self) -> dict[str, float]:
        return {
            "evidence_quality": self.evidence_quality,
            "repetition": self.repetition,
            "recency": self.recency,
            "project_relevance": self.project_relevance,
            "source_trust": self.source_trust,
            "contradiction": self.contradiction,
            "sensitivity": self.sensitivity,
        }

    @classmethod
    def from_context(
        cls,
        *,
        evidence_count: int,
        repetition_count: int,
        occurred_at: datetime,
        now: datetime,
        same_project: bool,
        source_trust: float,
        contradiction_count: int,
        sensitivity: str,
    ) -> "ScoreFeatures":
        for label, value in (
            ("evidence_count", evidence_count),
            ("repetition_count", repetition_count),
            ("contradiction_count", contradiction_count),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ProtocolError(
                    "COGNITION_SCORE_CONTEXT_INVALID",
                    f"{label} must be a nonnegative integer",
                )
        if not isinstance(same_project, bool):
            raise ProtocolError(
                "COGNITION_SCORE_CONTEXT_INVALID", "same_project must be boolean"
            )
        if (
            not isinstance(occurred_at, datetime)
            or occurred_at.tzinfo is None
            or not isinstance(now, datetime)
            or now.tzinfo is None
        ):
            raise ProtocolError(
                "COGNITION_SCORE_CONTEXT_INVALID",
                "score timestamps must be timezone-aware",
            )
        if sensitivity not in SENSITIVITY_VALUES:
            raise ProtocolError(
                "COGNITION_SCORE_CONTEXT_INVALID",
                "unsupported sensitivity classification",
            )
        age = max(timedelta(0), now - occurred_at)
        if age <= timedelta(days=1):
            recency = 1.0
        elif age <= timedelta(days=7):
            recency = 0.75
        elif age <= timedelta(days=30):
            recency = 0.5
        else:
            recency = 0.25
        return cls(
            evidence_quality=min(1.0, evidence_count / 2),
            repetition=min(1.0, repetition_count / 3),
            recency=recency,
            project_relevance=1.0 if same_project else 0.0,
            source_trust=_bounded_number(source_trust, "source_trust"),
            contradiction=1.0 if contradiction_count else 0.0,
            sensitivity=SENSITIVITY_VALUES[sensitivity],
        )


def score_candidate(features: ScoreFeatures) -> dict[str, Any]:
    values = features.as_dict()
    for name, value in values.items():
        _bounded_number(value, name)
    total = round(
        sum(values[name] * SCORE_WEIGHTS[name] for name in SCORE_WEIGHTS), 6
    )
    return {
        "features": values,
        "weights": dict(SCORE_WEIGHTS),
        "total": total,
    }
