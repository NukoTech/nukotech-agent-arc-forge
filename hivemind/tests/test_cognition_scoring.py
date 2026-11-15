from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from hive_protocol.cognition.scoring import ScoreFeatures, score_candidate
from hive_protocol.core import ProtocolError


NOW = datetime(2026, 9, 1, 6, 0, tzinfo=timezone.utc)


def test_score_stores_every_feature_weight_and_exact_total() -> None:
    features = ScoreFeatures.from_context(
        evidence_count=2,
        repetition_count=2,
        occurred_at=NOW - timedelta(hours=3),
        now=NOW,
        same_project=True,
        source_trust=0.8,
        contradiction_count=0,
        sensitivity="INTERNAL",
    )
    score = score_candidate(features)

    assert score == {
        "features": {
            "evidence_quality": 1.0,
            "repetition": 2 / 3,
            "recency": 1.0,
            "project_relevance": 1.0,
            "source_trust": 0.8,
            "contradiction": 0.0,
            "sensitivity": 0.25,
        },
        "weights": {
            "evidence_quality": 0.25,
            "repetition": 0.15,
            "recency": 0.15,
            "project_relevance": 0.15,
            "source_trust": 0.15,
            "contradiction": -0.1,
            "sensitivity": -0.05,
        },
        "total": 0.7575,
    }


def test_contradiction_and_sensitivity_lower_priority_without_rejecting() -> None:
    clean = ScoreFeatures.from_context(
        evidence_count=1,
        repetition_count=1,
        occurred_at=NOW,
        now=NOW,
        same_project=True,
        source_trust=0.9,
        contradiction_count=0,
        sensitivity="PUBLIC",
    )
    risky = ScoreFeatures.from_context(
        evidence_count=1,
        repetition_count=1,
        occurred_at=NOW,
        now=NOW,
        same_project=True,
        source_trust=0.9,
        contradiction_count=2,
        sensitivity="SENSITIVE",
    )
    assert score_candidate(risky)["total"] < score_candidate(clean)["total"]
    assert score_candidate(risky)["features"]["contradiction"] == 1.0
    assert score_candidate(risky)["features"]["sensitivity"] == 1.0


@pytest.mark.parametrize(
    "kwargs",
    [
        {"evidence_count": -1},
        {"repetition_count": -1},
        {"same_project": "yes"},
        {"source_trust": 1.1},
        {"contradiction_count": -1},
        {"sensitivity": "SECRET"},
        {"now": NOW.replace(tzinfo=None)},
    ],
)
def test_score_context_rejects_invalid_or_unstable_features(kwargs) -> None:
    values = {
        "evidence_count": 1,
        "repetition_count": 1,
        "occurred_at": NOW,
        "now": NOW,
        "same_project": True,
        "source_trust": 0.8,
        "contradiction_count": 0,
        "sensitivity": "INTERNAL",
    }
    values.update(kwargs)
    with pytest.raises(ProtocolError):
        ScoreFeatures.from_context(**values)
