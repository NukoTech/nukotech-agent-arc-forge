from __future__ import annotations

import copy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.agents import AgentOperations, public_pem
from hive_protocol.core import ProtocolError, document_digest, public_key_id
from hive_protocol.workflows.matching import match_agents


def _agent(
    agent_id: str,
    key: Ed25519PrivateKey,
    capabilities: list[str],
    *,
    active: bool = True,
    trust: str = "ATTENDED",
    machine_id: str | None = "machine:hive-lab-host",
    surface_id: str | None = None,
    project_ids: list[str] | None = None,
) -> dict[str, object]:
    record: dict[str, object] = {
        "agent_id": agent_id,
        "tenant_id": "tenant-a",
        "workspace_id": "alpha",
        "persona_id": f"persona:{agent_id}",
        "surface_id": surface_id or f"surface:{agent_id}",
        "capabilities": capabilities,
        "trust_level": trust,
        "recipient_aliases": [],
        "key_id": public_key_id(key.public_key()),
        "public_key_pem": public_pem(key),
        "active": active,
    }
    if machine_id is not None:
        record["machine_id"] = machine_id
    if project_ids is not None:
        record["project_ids"] = project_ids
        record["app_actor"] = f"app:{agent_id}"
    return record


def _step(
    *,
    capabilities: list[str] | None = None,
    trust: str = "ATTENDED",
    machine_id: str | None = "machine:hive-lab-host",
    surface_id: str | None = None,
) -> dict[str, object]:
    return {
        "step_id": "research",
        "required_capabilities": capabilities or ["vault:search"],
        "required_trust": trust,
        "target": {
            "project_id": "HiveMind",
            "machine_id": machine_id,
            "surface_id": surface_id,
        },
    }


def test_matching_intersects_scope_capability_trust_and_targets_without_mutation(
    tmp_path: Path,
) -> None:
    ops = AgentOperations(tmp_path / "ops")
    exact_key = Ed25519PrivateKey.generate()
    extra_key = Ed25519PrivateKey.generate()
    ops.register(
        _agent(
            "exact",
            exact_key,
            ["vault:search"],
            project_ids=["HiveMind"],
        )
    )
    ops.register(
        _agent(
            "extra",
            extra_key,
            ["memory:review", "vault:search"],
            project_ids=["HiveMind"],
        )
    )
    before = ops.registry_snapshot()

    matches = match_agents(
        before,
        _step(),
        tenant_id="tenant-a",
        workspace_id="alpha",
        project_id="HiveMind",
    )

    assert [match["agent_id"] for match in matches] == ["exact", "extra"]
    assert matches[0]["matched_capabilities"] == ["vault:search"]
    assert document_digest(before) == document_digest(ops.registry_snapshot())


def test_missing_or_mismatched_metadata_and_grants_never_match(tmp_path: Path) -> None:
    ops = AgentOperations(tmp_path / "ops")
    fixtures = [
        _agent("legacy", Ed25519PrivateKey.generate(), ["vault:search"], project_ids=None),
        _agent("inactive", Ed25519PrivateKey.generate(), ["vault:search"], active=False, project_ids=["HiveMind"]),
        _agent("wrong-project", Ed25519PrivateKey.generate(), ["vault:search"], project_ids=["Other"]),
        _agent("wrong-machine", Ed25519PrivateKey.generate(), ["vault:search"], machine_id="machine:other", project_ids=["HiveMind"]),
        _agent("wrong-capability", Ed25519PrivateKey.generate(), ["memory:review"], project_ids=["HiveMind"]),
        _agent("low-trust", Ed25519PrivateKey.generate(), ["vault:search"], trust="PROPOSE", project_ids=["HiveMind"]),
    ]
    for record in fixtures:
        ops.register(record)

    assert (
        match_agents(
            ops.registry_snapshot(),
            _step(),
            tenant_id="tenant-a",
            workspace_id="alpha",
            project_id="HiveMind",
        )
        == []
    )


def test_surface_target_and_unconstrained_machine_are_deterministic(tmp_path: Path) -> None:
    ops = AgentOperations(tmp_path / "ops")
    for agent_id, machine in [("b-agent", None), ("a-agent", "machine:other")]:
        ops.register(
            _agent(
                agent_id,
                Ed25519PrivateKey.generate(),
                ["vault:search"],
                machine_id=machine,
                surface_id="surface:shared",
                project_ids=["HiveMind"],
            )
        )
    matches = match_agents(
        ops.registry_snapshot(),
        _step(machine_id=None, surface_id="surface:shared"),
        tenant_id="tenant-a",
        workspace_id="alpha",
        project_id="HiveMind",
    )
    assert [match["agent_id"] for match in matches] == ["a-agent", "b-agent"]


def test_wrong_requested_project_and_forged_key_fail_closed(tmp_path: Path) -> None:
    ops = AgentOperations(tmp_path / "ops")
    key = Ed25519PrivateKey.generate()
    ops.register(_agent("agent", key, ["vault:search"], project_ids=["HiveMind"]))
    registry = ops.registry_snapshot()
    with pytest.raises(ProtocolError):
        match_agents(
            registry,
            _step(),
            tenant_id="tenant-a",
            workspace_id="alpha",
            project_id="Other",
        )

    forged = copy.deepcopy(registry)
    forged["agents"]["agent"]["key_id"] = "ed25519:" + "0" * 24
    with pytest.raises(ProtocolError):
        match_agents(
            forged,
            _step(),
            tenant_id="tenant-a",
            workspace_id="alpha",
            project_id="HiveMind",
        )


def test_registry_rejects_shared_signing_key_and_identity_collapse(tmp_path: Path) -> None:
    ops = AgentOperations(tmp_path / "ops")
    shared = Ed25519PrivateKey.generate()
    ops.register(_agent("first", shared, ["vault:search"], project_ids=["HiveMind"]))
    with pytest.raises(ProtocolError):
        ops.register(_agent("second", shared, ["vault:search"], project_ids=["HiveMind"]))

    collapsed = _agent(
        "collapsed",
        Ed25519PrivateKey.generate(),
        ["vault:search"],
        project_ids=["HiveMind"],
    )
    collapsed["machine_id"] = collapsed["surface_id"]
    with pytest.raises(ProtocolError):
        ops.register(collapsed)
