"""Assign a local lab persona without changing the bundled unassigned sample."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from hive_protocol.core import ProtocolError, require_assigned_persona, validate_identity_context
from hive_protocol.lab_context import (
    PERSONA_ASSIGN_COMMAND,
    assign_persona,
    bundled_sample_identity,
    validate_persona_name,
)
from hive_protocol.m003 import promote_turn, propose_turn, retrieve_next_turn, review_turn
from hive_protocol.product import cli as product_cli
from hive_protocol.turn import consume_turn, prepare_turn, route_turn

COMMIT = "d" * 40
NAMESPACE = "HIVE-LAB-PERSONA-ASSIGN-TEST"


def _write_sample(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bundled_sample_identity(), indent=2) + "\n", encoding="utf-8")
    return path


@pytest.mark.parametrize(
    "name",
    ["", "   ", "UNASSIGNED", "unassigned", "persona:UNASSIGNED", "has space", "bad/name", "../escape", "1leading"],
)
def test_persona_name_validation_rejects_unsafe_values(name: str) -> None:
    with pytest.raises(ProtocolError, match="PERSONA_NAME_INVALID"):
        validate_persona_name(name)


def test_assign_refuses_to_overwrite_without_force(tmp_path: Path) -> None:
    context = tmp_path / "lab-context.json"
    first = assign_persona("First-Persona", context_path=context)
    assert first["outcome"] == "ASSIGNED"
    assert first["persona"]["id"] == "First-Persona"
    with pytest.raises(ProtocolError, match="PERSONA_ALREADY_ASSIGNED"):
        assign_persona("Second-Persona", context_path=context)
    current = json.loads(context.read_text(encoding="utf-8"))
    assert current["persona"]["id"] == "First-Persona"
    replaced = assign_persona("Second-Persona", context_path=context, force=True)
    assert replaced["persona"]["id"] == "Second-Persona"
    current = json.loads(context.read_text(encoding="utf-8"))
    assert current["persona"]["id"] == "Second-Persona"
    assert current["persona"]["continuity_id"] == "persona:Second-Persona"
    assert current["surface"]["persona_continuity_id"] == "persona:Second-Persona"
    assert current["agent_worker"]["acts_for_persona"] == "Second-Persona"
    assert current["persona"]["governance_role"] == "QUEEN"
    validate_identity_context(current)
    require_assigned_persona(current)
    bundled = bundled_sample_identity()
    assert bundled["persona"]["id"] == "UNASSIGNED"


def test_cli_assign_force_refusal(tmp_path: Path) -> None:
    context = tmp_path / "lab-context.json"
    status = product_cli.main(["persona", "assign", "First-Persona", "--context", str(context)])
    assert status == 0
    status = product_cli.main(["persona", "assign", "Second-Persona", "--context", str(context)])
    assert status == 2


def test_sample_is_refused_then_assign_lets_a_full_turn_pass(tmp_path: Path) -> None:
    context = _write_sample(tmp_path / "context" / "lab-context.json")
    lab_root = tmp_path / "lab"
    env = {
        "HIVE_PROCESS_NAMESPACE": NAMESPACE,
        "HIVE_LAB_CONTEXT": str(context),
    }
    with patch.dict(os.environ, env):
        with patch("hive_protocol.turn.socket.gethostname", return_value="hive-lab-host"):
            with pytest.raises(ProtocolError, match="PERSONA_UNASSIGNED") as refused:
                prepare_turn(lab_root, COMMIT)
            assert PERSONA_ASSIGN_COMMAND in str(refused.value)
            assert "hive-local persona assign <name>" in refused.value.detail
            assert not lab_root.exists()
            assert json.loads(context.read_text(encoding="utf-8"))["persona"]["id"] == "UNASSIGNED"

            status = product_cli.main(
                ["persona", "assign", "Lab-Operator", "--context", str(context)]
            )
            assert status == 0
            assigned = json.loads(context.read_text(encoding="utf-8"))
            assert assigned["persona"]["id"] == "Lab-Operator"
            assert bundled_sample_identity()["persona"]["id"] == "UNASSIGNED"

            prepared = prepare_turn(lab_root, COMMIT)
            run_dir = Path(str(prepared["run_dir"]))
            assert route_turn(run_dir)["outcome"] == "DELIVERED"
            acknowledgment, exit_status = consume_turn(run_dir)
            assert acknowledgment["outcome"] == "APPLIED"
            assert exit_status == 0
            assert propose_turn(run_dir)["outcome"] == "STAGED_PROPOSALS"
            assert review_turn(run_dir)["outcome"] == "APPROVED"
            promotion = promote_turn(run_dir)
            assert promotion["unreviewed_remaining"] == 0
            retrieval = retrieve_next_turn(run_dir)
            assert retrieval["outcome"] == "RETRIEVED_NEXT_TURN"
