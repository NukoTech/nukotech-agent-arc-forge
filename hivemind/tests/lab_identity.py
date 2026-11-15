"""Assigned lab identity for protocol tests; the bundled sample stays unassigned."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SAMPLE_LAB_CONTEXT = Path(__file__).resolve().parents[1] / "config" / "sample-lab-context.json"
ASSIGNED_PERSONA_ID = "Lab-Persona"
ASSIGNED_CONTINUITY_ID = "persona:lab-test"


def assigned_lab_identity() -> dict[str, Any]:
    identity = json.loads(SAMPLE_LAB_CONTEXT.read_text(encoding="utf-8"))
    identity["persona"]["id"] = ASSIGNED_PERSONA_ID
    identity["persona"]["continuity_id"] = ASSIGNED_CONTINUITY_ID
    identity["surface"]["persona_continuity_id"] = ASSIGNED_CONTINUITY_ID
    identity["agent_worker"]["acts_for_persona"] = ASSIGNED_PERSONA_ID
    return identity
