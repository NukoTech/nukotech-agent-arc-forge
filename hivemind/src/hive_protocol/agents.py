"""Scoped agent registry and signed, replay-safe local task operations."""

from __future__ import annotations

import copy
import json
import re
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path
from typing import Any, Callable, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker

from .core import (
    ProtocolError,
    canonical_bytes,
    document_digest,
    public_key_id,
    sign_document,
    verify_document,
)
from .storage import ReplayLedger, atomic_write_json, exclusive_lock, read_json, utc_now


_SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SCHEMAS = {
    "registry": "agent-registry.v1.schema.json",
    "task": "task-envelope.v1.schema.json",
    "ack": "task-acknowledgment.v1.schema.json",
    "grant": "capability-grant.v1.schema.json",
}
_TRUST = {"OBSERVE": 0, "PROPOSE": 1, "ATTENDED": 2, "BOUNDED": 3}


def _validate(document: Mapping[str, Any], kind: str) -> None:
    schema = json.loads(files("hive_protocol.schemas").joinpath(_SCHEMAS[kind]).read_text())
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(document),
        key=lambda error: list(error.path),
    )
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "$"
        raise ProtocolError("SCHEMA_INVALID", f"{location}: {error.message}")


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError("TIME_INVALID", "timestamp must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ProtocolError("TIME_INVALID", "timestamp must contain a timezone")
    return parsed


def _load_public_pem(value: str) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(value.encode("utf-8"))
    except ValueError as exc:
        raise ProtocolError("PUBLIC_KEY_INVALID", "registry public key is invalid") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ProtocolError("PUBLIC_KEY_TYPE", "registry key must be Ed25519")
    return key


def public_pem(private_key: Ed25519PrivateKey) -> str:
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def validate_agent_registry(document: Mapping[str, Any]) -> None:
    """Validate a read-only registry snapshot for workflow consumers."""

    _validate(document, "registry")


def build_signed_task(document: Mapping[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    task = dict(document)
    payload = task.get("payload")
    if not isinstance(payload, Mapping):
        raise ProtocolError("TASK_PAYLOAD_INVALID", "task payload must be an object")
    task["payload_sha256"] = document_digest(payload)
    signed = sign_document(task, key)
    _validate(signed, "task")
    return signed


def build_signed_ack(document: Mapping[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    signed = sign_document(document, key)
    _validate(signed, "ack")
    if signed["changed"] and signed["outcome"] != "APPLIED":
        raise ProtocolError("ACK_STATE_INVALID", "only APPLIED may report changed state")
    if signed["changed"] != (signed["state_sha256"] is not None):
        raise ProtocolError("ACK_STATE_INVALID", "changed state requires exactly one state digest")
    return signed


def build_signed_capability_grant(
    document: Mapping[str, Any], key: Ed25519PrivateKey
) -> dict[str, Any]:
    signed = sign_document(document, key)
    _validate(signed, "grant")
    if signed["capabilities"] != sorted(signed["capabilities"]):
        raise ProtocolError(
            "CAPABILITY_GRANT_INVALID", "grant capabilities must be sorted"
        )
    if _parse_time(signed["issued_at"]) >= _parse_time(signed["expires_at"]):
        raise ProtocolError(
            "CAPABILITY_GRANT_TIME_INVALID", "grant expiry must follow issue time"
        )
    return signed


def verify_capability_grant(
    document: Mapping[str, Any],
    trusted_keys: Mapping[str, Ed25519PublicKey],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    _validate(document, "grant")
    if document["capabilities"] != sorted(document["capabilities"]):
        raise ProtocolError(
            "CAPABILITY_GRANT_INVALID", "grant capabilities must be sorted"
        )
    issued_at = _parse_time(document["issued_at"])
    expires_at = _parse_time(document["expires_at"])
    if issued_at >= expires_at:
        raise ProtocolError(
            "CAPABILITY_GRANT_TIME_INVALID", "grant expiry must follow issue time"
        )
    observed_at = now if now is not None else datetime.now(timezone.utc)
    if observed_at.tzinfo is None:
        raise ProtocolError(
            "CAPABILITY_GRANT_TIME_INVALID", "grant verification time requires timezone"
        )
    if observed_at < issued_at or observed_at >= expires_at:
        raise ProtocolError(
            "CAPABILITY_GRANT_EXPIRED", "capability grant is not currently valid"
        )
    verify_document(document, trusted_keys)
    return copy.deepcopy(dict(document))


class AgentOperations:
    """Persist local task delivery without granting task execution authority."""

    def __init__(self, root: Path, *, initialize: bool = True) -> None:
        if root.exists() and root.is_symlink():
            raise ProtocolError("AGENT_ROOT_BOUNDARY", "agent root may not be a symlink")
        self.root = root
        self.registry_path = root / "registry.json"
        self.lock_path = root / ".operations.lock"
        self.task_replay = ReplayLedger(root / "replay" / "tasks.json")
        self.ack_replay = ReplayLedger(root / "replay" / "acks.json")
        if initialize:
            root.mkdir(parents=True, exist_ok=True)
        if initialize and not self.registry_path.exists():
            atomic_write_json(
                self.registry_path,
                {"schema_version": "hive.agent-registry.v1", "agents": {}},
            )

    def _registry(self) -> dict[str, Any]:
        registry = read_json(self.registry_path)
        _validate(registry, "registry")
        return registry

    def register(self, agent: Mapping[str, Any]) -> None:
        agent_id = agent.get("agent_id")
        if not isinstance(agent_id, str) or not _SAFE_ID.fullmatch(agent_id):
            raise ProtocolError("AGENT_ID_INVALID", "agent_id is not path-safe")
        key = _load_public_pem(str(agent.get("public_key_pem", "")))
        if agent.get("key_id") != public_key_id(key):
            raise ProtocolError("KEY_PIN_MISMATCH", "agent key ID does not match public key")
        with exclusive_lock(self.lock_path):
            registry = self._registry()
            updated = dict(registry)
            updated["agents"] = dict(registry["agents"])
            updated["agents"][agent_id] = dict(agent)
            _validate(updated, "registry")
            aliases: dict[tuple[str, str, str], str] = {}
            signing_keys: dict[tuple[str, str, str], str] = {}
            for record in updated["agents"].values():
                dimensions = [
                    record["agent_id"],
                    record["persona_id"],
                    record["surface_id"],
                ]
                for optional in ("machine_id", "app_actor"):
                    if optional in record:
                        dimensions.append(record[optional])
                if len(dimensions) != len(set(dimensions)):
                    raise ProtocolError(
                        "AGENT_IDENTITY_COLLAPSE",
                        "agent, persona, surface, machine, and App actor must differ",
                    )
                if ("project_ids" in record) != ("app_actor" in record):
                    raise ProtocolError(
                        "AGENT_WORKFLOW_METADATA_INVALID",
                        "workflow project metadata and App actor must be declared together",
                    )
                if "project_ids" in record and record["project_ids"] != sorted(
                    record["project_ids"]
                ):
                    raise ProtocolError(
                        "AGENT_PROJECTS_NONCANONICAL",
                        "agent project IDs must be unique and sorted",
                    )
                key_marker = (
                    record["tenant_id"],
                    record["workspace_id"],
                    record["key_id"],
                )
                if (
                    key_marker in signing_keys
                    and signing_keys[key_marker] != record["agent_id"]
                ):
                    raise ProtocolError(
                        "AGENT_SIGNING_KEY_COLLISION",
                        "one scoped signing key may not identify multiple agents",
                    )
                signing_keys[key_marker] = record["agent_id"]
                for alias in [record["agent_id"], *record["recipient_aliases"]]:
                    marker = (record["tenant_id"], record["workspace_id"], alias)
                    if marker in aliases and aliases[marker] != record["agent_id"]:
                        raise ProtocolError("RECIPIENT_ALIAS_COLLISION", f"ambiguous alias: {alias}")
                    aliases[marker] = record["agent_id"]
            atomic_write_json(self.registry_path, updated)

    def registry_snapshot(self) -> dict[str, Any]:
        """Return a detached, validated registry snapshot without mutation."""

        return copy.deepcopy(self._registry())

    def resolve_recipient(self, tenant_id: str, workspace_id: str, recipient: str) -> dict[str, Any]:
        registry = self._registry()
        matches = [
            agent
            for agent in registry["agents"].values()
            if agent["tenant_id"] == tenant_id
            and agent["workspace_id"] == workspace_id
            and recipient in [agent["agent_id"], *agent["recipient_aliases"]]
        ]
        if len(matches) != 1 or not matches[0]["active"]:
            raise ProtocolError("RECIPIENT_INVALID", "recipient does not resolve to one active scoped agent")
        return matches[0]

    def _agent(self, agent_id: str, tenant_id: str, workspace_id: str) -> dict[str, Any]:
        record = self._registry()["agents"].get(agent_id)
        if (
            not isinstance(record, dict)
            or not record.get("active")
            or record.get("tenant_id") != tenant_id
            or record.get("workspace_id") != workspace_id
        ):
            raise ProtocolError("AGENT_SCOPE_INVALID", "agent is absent, inactive, or outside scope")
        return record

    def _verify_task(
        self,
        task: Mapping[str, Any],
        *,
        enforce_expiry: bool = True,
        now: datetime | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        _validate(task, "task")
        if document_digest(task["payload"]) != task["payload_sha256"]:
            raise ProtocolError("TASK_PAYLOAD_TAMPERED", "payload digest does not match")
        if _parse_time(task["issued_at"]) >= _parse_time(task["expires_at"]):
            raise ProtocolError("TASK_TIME_INVALID", "task expiry must follow issue time")
        observed_at = now if now is not None else datetime.now(timezone.utc)
        if observed_at.tzinfo is None:
            raise ProtocolError("TASK_TIME_INVALID", "verification time must contain a timezone")
        if enforce_expiry and observed_at >= _parse_time(task["expires_at"]):
            raise ProtocolError("TASK_EXPIRED", "task has expired")
        sender = self._agent(task["sender_agent"], task["tenant_id"], task["workspace_id"])
        recipient = self.resolve_recipient(
            task["tenant_id"], task["workspace_id"], task["recipient_agent"]
        )
        if recipient["agent_id"] != task["recipient_agent"]:
            raise ProtocolError("RECIPIENT_NOT_CANONICAL", "signed task must name canonical recipient")
        required = set(task["required_capabilities"])
        if not required.issubset(set(sender["capabilities"])):
            raise ProtocolError("CAPABILITY_ESCALATION", "sender lacks a required capability")
        if not required.issubset(set(recipient["capabilities"])):
            raise ProtocolError("RECIPIENT_CAPABILITY_MISSING", "recipient lacks a required capability")
        if _TRUST[recipient["trust_level"]] < _TRUST[task["required_trust"]]:
            raise ProtocolError("RECIPIENT_TRUST_INSUFFICIENT", "recipient trust is below task requirement")
        sender_key = _load_public_pem(sender["public_key_pem"])
        verify_document(task, {sender["key_id"]: sender_key})
        return sender, recipient

    def deliver(
        self,
        task: Mapping[str, Any],
        *,
        now: datetime | None = None,
        after_claim: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        _, recipient = self._verify_task(task, now=now)
        task_path = self.root / "inbox" / recipient["agent_id"] / f"{task['task_id']}.json"
        with exclusive_lock(self.lock_path):
            claim = self.task_replay.begin(task["task_id"], task["nonce"])
            if claim == "RESUME" and task_path.exists():
                if document_digest(read_json(task_path)) != document_digest(task):
                    raise ProtocolError(
                        "CRASH_RECOVERY_CONFLICT", "pending task differs from durable task"
                    )
            else:
                if after_claim is not None:
                    after_claim()
                atomic_write_json(task_path, task)
            self.task_replay.complete(task["task_id"], task["nonce"])
        return {
            "status": "DELIVERED",
            "task_id": task["task_id"],
            "recipient_agent": recipient["agent_id"],
            "task_sha256": document_digest(task),
        }

    def acknowledge(
        self,
        ack: Mapping[str, Any],
        *,
        after_claim: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        _validate(ack, "ack")
        if ack["changed"] and ack["outcome"] != "APPLIED":
            raise ProtocolError("ACK_STATE_INVALID", "only APPLIED may report changed state")
        if ack["changed"] != (ack["state_sha256"] is not None):
            raise ProtocolError("ACK_STATE_INVALID", "changed state requires exactly one state digest")
        recipient = self._agent(ack["recipient_agent"], ack["tenant_id"], ack["workspace_id"])
        task_path = self.root / "inbox" / recipient["agent_id"] / f"{ack['task_id']}.json"
        task = read_json(task_path)
        self._verify_task(task)
        if task["recipient_agent"] != ack["recipient_agent"]:
            raise ProtocolError("ACK_RECIPIENT_MISMATCH", "ack signer is not the task recipient")
        verify_document(ack, {recipient["key_id"]: _load_public_pem(recipient["public_key_pem"])})
        ack_path = self.root / "receipts" / f"{ack['task_id']}.json"
        with exclusive_lock(self.lock_path):
            claim = self.ack_replay.begin(ack["ack_id"], ack["nonce"])
            if claim == "RESUME" and ack_path.exists():
                if document_digest(read_json(ack_path)) != document_digest(ack):
                    raise ProtocolError(
                        "CRASH_RECOVERY_CONFLICT", "pending ack differs from durable ack"
                    )
            else:
                if after_claim is not None:
                    after_claim()
                atomic_write_json(ack_path, ack)
            self.ack_replay.complete(ack["ack_id"], ack["nonce"])
        return {
            "status": "ACKNOWLEDGED",
            "task_id": ack["task_id"],
            "ack_sha256": document_digest(ack),
            "changed": ack["changed"],
        }

    def retrieve_next_turn(
        self, task_id: str, *, tenant_id: str, workspace_id: str, recipient_agent: str
    ) -> dict[str, Any]:
        if not _SAFE_ID.fullmatch(recipient_agent):
            raise ProtocolError("AGENT_ID_INVALID", "recipient_agent is not path-safe")
        recipient = self._agent(recipient_agent, tenant_id, workspace_id)
        task_path = self.root / "inbox" / recipient_agent / f"{task_id}.json"
        ack_path = self.root / "receipts" / f"{task_id}.json"
        task = read_json(task_path)
        ack = read_json(ack_path)
        self._verify_task(task, enforce_expiry=False)
        _validate(ack, "ack")
        if ack["changed"] and ack["outcome"] != "APPLIED":
            raise ProtocolError(
                "ACK_STATE_INVALID", "only APPLIED may report changed state"
            )
        if ack["changed"] != (ack["state_sha256"] is not None):
            raise ProtocolError(
                "ACK_STATE_INVALID",
                "changed state requires exactly one state digest",
            )
        verify_document(ack, {recipient["key_id"]: _load_public_pem(recipient["public_key_pem"])})
        if (
            task["task_id"] != task_id
            or task["task_id"] != ack["task_id"]
            or task["tenant_id"] != tenant_id
            or task["workspace_id"] != workspace_id
            or task["recipient_agent"] != recipient_agent
            or ack["tenant_id"] != tenant_id
            or ack["workspace_id"] != workspace_id
            or ack["recipient_agent"] != recipient_agent
        ):
            raise ProtocolError("NEXT_TURN_SCOPE_INVALID", "persisted task and acknowledgment do not bind")
        return {
            "status": "PERSISTED_NEXT_TURN",
            "task": task,
            "acknowledgment": ack,
            "task_sha256": document_digest(task),
            "ack_sha256": document_digest(ack),
        }
