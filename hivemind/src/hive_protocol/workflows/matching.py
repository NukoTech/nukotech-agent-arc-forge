"""Read-only, capability-aware workflow agent matching."""

from __future__ import annotations

from typing import Any, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from hive_protocol.agents import validate_agent_registry
from hive_protocol.core import ProtocolError, public_key_id


_TRUST = {"OBSERVE": 0, "PROPOSE": 1, "ATTENDED": 2, "BOUNDED": 3}


def _validate_registry_identities(registry: Mapping[str, Any]) -> None:
    key_owners: dict[tuple[str, str, str], str] = {}
    for agent_id, record in registry["agents"].items():
        try:
            public_key = serialization.load_pem_public_key(
                record["public_key_pem"].encode("utf-8")
            )
        except (TypeError, ValueError) as exc:
            raise ProtocolError(
                "WORKFLOW_AGENT_KEY_INVALID", "agent registry public key is invalid"
            ) from exc
        if not isinstance(public_key, Ed25519PublicKey):
            raise ProtocolError(
                "WORKFLOW_AGENT_KEY_INVALID", "workflow agents require Ed25519 keys"
            )
        if public_key_id(public_key) != record["key_id"]:
            raise ProtocolError(
                "WORKFLOW_AGENT_KEY_MISMATCH",
                "agent key ID does not bind its public key",
            )
        dimensions = [record["agent_id"], record["persona_id"], record["surface_id"]]
        for optional in ("machine_id", "app_actor"):
            if optional in record:
                dimensions.append(record[optional])
        if len(dimensions) != len(set(dimensions)):
            raise ProtocolError(
                "WORKFLOW_AGENT_IDENTITY_COLLAPSE",
                "workflow agent identity dimensions must remain distinct",
            )
        marker = (record["tenant_id"], record["workspace_id"], record["key_id"])
        if marker in key_owners and key_owners[marker] != agent_id:
            raise ProtocolError(
                "WORKFLOW_AGENT_KEY_COLLISION",
                "one scoped key may not identify multiple workflow agents",
            )
        key_owners[marker] = agent_id


def match_agents(
    registry: Mapping[str, Any],
    step: Mapping[str, Any],
    *,
    tenant_id: str,
    workspace_id: str,
    project_id: str,
) -> list[dict[str, Any]]:
    """Return deterministic eligible records; never assign or mutate authority."""

    validate_agent_registry(registry)
    _validate_registry_identities(registry)
    required = step.get("required_capabilities")
    required_trust = step.get("required_trust")
    target = step.get("target")
    if (
        not isinstance(required, list)
        or not required
        or len(required) != len(set(required))
        or required_trust not in _TRUST
        or not isinstance(target, Mapping)
        or target.get("project_id") != project_id
    ):
        raise ProtocolError(
            "WORKFLOW_MATCH_REQUEST_INVALID",
            "workflow step and requested project do not bind",
        )
    target_machine = target.get("machine_id")
    target_surface = target.get("surface_id")
    matches: list[dict[str, Any]] = []
    required_set = set(required)
    for record in registry["agents"].values():
        if (
            not record["active"]
            or record["tenant_id"] != tenant_id
            or record["workspace_id"] != workspace_id
            or project_id not in record.get("project_ids", [])
            or not required_set.issubset(set(record["capabilities"]))
            or _TRUST[record["trust_level"]] < _TRUST[required_trust]
            or (
                target_machine is not None
                and record.get("machine_id") != target_machine
            )
            or (
                target_surface is not None
                and record["surface_id"] != target_surface
            )
        ):
            continue
        capabilities = set(record["capabilities"])
        matches.append(
            {
                key: value
                for key, value in record.items()
                if key != "public_key_pem"
            }
            | {
                "matched_capabilities": sorted(required_set),
                "capability_excess": len(capabilities - required_set),
                "selection_authority": False,
            }
        )
    return sorted(
        matches,
        key=lambda item: (item["capability_excess"], item["agent_id"]),
    )
