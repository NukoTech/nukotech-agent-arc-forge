"""Replay-safe routing adapter for the pre-existing fleet mailbox transports.

This module does not poll Drive, GitHub, or legacy lanes and does not wake an
agent.  It supplies the receiver registry, durable cursors, quarantine, signed
receipts, and fail-closed admission needed by those existing transports.
"""

from __future__ import annotations

import json
from importlib.resources import files
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ..core import ProtocolError, document_digest, sign_document, verify_document
from ..storage import utc_now
from .containment import GovernedRoot, validate_identifier


ACTIVE_MAILBOX_NAMES = (
    "01 Research and Architecture",
    "02 LeadA Active Build",
    "03 Reviews and Decisions",
    "04 Verification and Release Receipts",
)

LEGACY_ROUTE_NAMES = (
    "channel_in/from_node_a",
    "channel_in/from_node_b",
    "channel_in/from_queen",
    "peer_outbox/to_group",
    "peer_outbox/from_peers",
    "shared-work-channel",
)

GITHUB_ROUTE_NAMES = ("github:issue", "github:pull_request")


@dataclass(frozen=True)
class SurfaceEnrollment:
    surface_id: str
    persona_id: str
    machine_id: str
    project_id: str
    device_director: str
    current_project_lead: str
    runtime_adapter: str
    app_actor: str
    verification_key_id: str
    authority_state: str
    technical_admission: str
    supreme_authority: str = "Owner"
    future_hierarchy: str = "DOCUMENTED_INACTIVE"
    network_membership_authorizes: bool = False
    voting_state: str = "DOCUMENTED_INACTIVE"


@dataclass(frozen=True)
class RuntimeAuthorityBinding:
    runtime_adapter: str
    app_actor: str
    verification_key_id: str


def _authority_roster(roster: Mapping[str, tuple[str, str, str, str]] | None = None) -> dict[str, tuple[str, str, str, str]]:
    """Load operator-trusted configuration; never take roster data from an envelope.

    The bundled file is synthetic sample data, not a live deployment topology.
    Runtime keys and enrollments are always explicit and mandatory.
    """
    if roster is None:
        roster = json.loads(files(__package__).joinpath("sample-roster.json").read_text(encoding="utf-8"))
    if not isinstance(roster, Mapping) or not roster:
        raise ProtocolError("AUTHORITY_ROSTER_INVALID", "roster must be a non-empty mapping")
    result = {}
    for surface, fields in roster.items():
        validate_identifier(surface, "surface_id")
        if not isinstance(fields, (list, tuple)) or len(fields) != 4:
            raise ProtocolError("AUTHORITY_ROSTER_INVALID", "each surface requires persona, machine, director and state")
        for field in fields:
            _validate_authority_text(field, "roster_field")
        result[surface] = tuple(fields)
    if len({surface.casefold() for surface in result}) != len(result):
        raise ProtocolError("AUTHORITY_ROSTER_INVALID", "roster surface identifiers must be unique")
    for fields in result.values():
        if fields[2] not in result:
            raise ProtocolError("AUTHORITY_ROSTER_INVALID", "each device director must be in the roster")
    return result



def _validate_authority_text(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 256
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ProtocolError("AUTHORITY_FIELD_INVALID", f"{field} is invalid")
    return value


def default_enrollments(
    runtime_bindings: Mapping[str, RuntimeAuthorityBinding],
    *,
    authority_roster: Mapping[str, tuple[str, str, str, str]] | None = None,
    project_id: str = "hivemind-sample",
    project_lead: str = "LeadA",
    supreme_authority: str = "Owner",
) -> tuple[SurfaceEnrollment, ...]:
    blueprint = _authority_roster(authority_roster)
    if project_lead not in blueprint:
        raise ProtocolError("PROJECT_AUTHORITY_INVALID", "project lead must be in the configured roster")
    if set(runtime_bindings) != set(blueprint):
        raise ProtocolError(
            "AUTHORITY_BINDING_INCOMPLETE", "every current device surface requires a runtime binding"
        )
    records = []
    for surface_id, (persona, machine, director, authority_state) in blueprint.items():
        binding = runtime_bindings[surface_id]
        for field, value in (
            ("surface_id", surface_id),
        ):
            validate_identifier(value, field)
        for field, value in (
            ("runtime_adapter", binding.runtime_adapter),
            ("app_actor", binding.app_actor),
            ("verification_key_id", binding.verification_key_id),
        ):
            _validate_authority_text(value, field)
        records.append(
            SurfaceEnrollment(
                surface_id=surface_id,
                persona_id=persona,
                machine_id=machine,
                project_id=project_id,
                device_director=director,
                current_project_lead=project_lead,
                supreme_authority=supreme_authority,
                runtime_adapter=binding.runtime_adapter,
                app_actor=binding.app_actor,
                verification_key_id=binding.verification_key_id,
                authority_state=authority_state,
                technical_admission=(
                    "HELD_ADMISSION" if authority_state == "HELD" else "ACTIVE"
                ),
            )
        )
    return tuple(records)


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str):
        raise ProtocolError("RECEIVER_TIME_INVALID", "timestamp must be a string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError("RECEIVER_TIME_INVALID", "timestamp must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ProtocolError("RECEIVER_TIME_INVALID", "timestamp must contain a timezone")
    return parsed


class ReceiverMatrix:
    """Admit signed envelopes and persist per-recipient delivery state."""

    def __init__(
        self,
        root: Path,
        trusted_keys: Mapping[str, Ed25519PublicKey],
        receipt_key: Ed25519PrivateKey,
        *,
        enrollments: tuple[SurfaceEnrollment, ...] | None = None,
        max_attempts: int = 3,
        github_app_actors: set[str] | frozenset[str] | None = None,
        project_id: str = "hivemind-sample",
        authority_roster: Mapping[str, tuple[str, str, str, str]] | None = None,
        project_lead: str = "LeadA",
        supreme_authority: str = "Owner",
    ) -> None:
        if root.exists() and root.is_symlink():
            raise ProtocolError("RECEIVER_ROOT_BOUNDARY", "receiver root may not be a symlink")
        if max_attempts < 1 or max_attempts > 10:
            raise ProtocolError("RETRY_BOUND_INVALID", "max_attempts must be between 1 and 10")
        if enrollments is None:
            raise ProtocolError("AUTHORITY_BINDING_REQUIRED", "receiver enrollments must be explicit")
        self.root = root
        self.fs = GovernedRoot(root)
        self.trusted_keys = dict(trusted_keys)
        self.receipt_key = receipt_key
        self.max_attempts = max_attempts
        self.github_app_actors = frozenset(github_app_actors or ())
        self.project_id = validate_identifier(project_id, "project_id")
        self.authority_roster = _authority_roster(authority_roster)
        self.project_lead = _validate_authority_text(project_lead, "project_lead")
        self.supreme_authority = _validate_authority_text(supreme_authority, "supreme_authority")
        if self.project_lead not in self.authority_roster:
            raise ProtocolError("PROJECT_AUTHORITY_INVALID", "project lead must be in the configured roster")
        records = enrollments
        self.enrollments = {record.surface_id.casefold(): record for record in records}
        if len(self.enrollments) != len(records):
            raise ProtocolError("RECEIVER_COLLISION", "surface IDs must be unique")
        for record in records:
            self._validate_enrollment(record)

    def _validate_enrollment(self, record: SurfaceEnrollment) -> None:
        validate_identifier(record.surface_id, "surface_id")
        for field in (
            "persona_id",
            "machine_id",
            "project_id",
            "device_director",
            "current_project_lead",
            "runtime_adapter",
            "app_actor",
            "verification_key_id",
            "authority_state",
            "technical_admission",
            "supreme_authority",
            "future_hierarchy",
            "voting_state",
        ):
            _validate_authority_text(getattr(record, field), field)
        if record.project_id != self.project_id or record.current_project_lead != self.project_lead:
            raise ProtocolError("PROJECT_AUTHORITY_INVALID", "project lead must match configured roster")
        if record.supreme_authority != self.supreme_authority:
            raise ProtocolError("SUPREME_AUTHORITY_INVALID", "supreme authority must match operator configuration")
        if record.future_hierarchy != "DOCUMENTED_INACTIVE" or record.voting_state != "DOCUMENTED_INACTIVE":
            raise ProtocolError("FUTURE_AUTHORITY_ACTIVE", "future hierarchy and voting must remain inactive")
        if record.network_membership_authorizes is not False:
            raise ProtocolError("NETWORK_AUTHORITY_INVALID", "Network membership grants no authority")
        blueprint = self.authority_roster.get(record.surface_id)
        if blueprint is None:
            raise ProtocolError("SURFACE_AUTHORITY_UNKNOWN", "surface lacks a current authority record")
        expected_director = blueprint[2]
        if (record.persona_id, record.machine_id, record.authority_state) != (blueprint[0], blueprint[1], blueprint[3]):
            raise ProtocolError("SURFACE_AUTHORITY_INVALID", "surface identity must match configured roster")
        if record.device_director != expected_director:
            raise ProtocolError("DEVICE_AUTHORITY_INVALID", "device director binding is incorrect")

    def resolve(self, surface_id: object) -> SurfaceEnrollment:
        surface_id = validate_identifier(surface_id, "recipient_surface")
        record = self.enrollments.get(surface_id.casefold())
        if record is None:
            raise ProtocolError("RECIPIENT_UNKNOWN", "recipient is not enrolled")
        if record.technical_admission != "ACTIVE":
            raise ProtocolError("RECIPIENT_HELD", "recipient is held pending admission")
        return record

    def _resolve_sender(self, authority: Mapping[str, Any]) -> SurfaceEnrollment:
        if set(authority) != {
            "project_id",
            "sender_surface",
            "sender_machine",
            "claimed_device_director",
            "claimed_project_lead",
            "supreme_authority",
            "network_membership_authorizes",
            "future_hierarchy",
            "voting_state",
        }:
            raise ProtocolError("AUTHORITY_ENVELOPE_INVALID", "authority envelope is malformed")
        sender_surface = validate_identifier(authority.get("sender_surface"), "sender_surface")
        sender = self.enrollments.get(sender_surface.casefold())
        if sender is None or sender.technical_admission != "ACTIVE":
            raise ProtocolError("SENDER_AUTHORITY_INVALID", "sender is absent or technically held")
        if authority.get("project_id") != sender.project_id or sender.project_id != self.project_id:
            raise ProtocolError("PROJECT_AUTHORITY_INVALID", "sender project authority does not match")
        if authority.get("sender_machine") != sender.machine_id:
            raise ProtocolError("CROSS_DEVICE_AUTHORITY_MISUSE", "sender machine authority does not match")
        if authority.get("claimed_device_director") != sender.device_director:
            raise ProtocolError("CROSS_DEVICE_AUTHORITY_MISUSE", "sender claims another device director")
        if authority.get("claimed_project_lead") != sender.current_project_lead:
            raise ProtocolError("PROJECT_LEAD_INVALID", "sender project-lead claim is wrong")
        if authority.get("supreme_authority") != self.supreme_authority:
            raise ProtocolError("SUPREME_AUTHORITY_INVALID", "supreme authority must match operator configuration")
        if authority.get("network_membership_authorizes") is not False:
            raise ProtocolError("NETWORK_AUTHORITY_INVALID", "Network membership is transport evidence only")
        if authority.get("future_hierarchy") != "DOCUMENTED_INACTIVE":
            raise ProtocolError("FUTURE_AUTHORITY_ACTIVE", "future hierarchy is not active")
        if authority.get("voting_state") != "DOCUMENTED_INACTIVE":
            raise ProtocolError("VOTING_INACTIVE", "voting is documented but inactive")
        return sender

    def validate_envelope(self, envelope: Mapping[str, Any]) -> SurfaceEnrollment:
        required = {
            "schema_version",
            "message_id",
            "nonce",
            "recipient_surface",
            "created_at",
            "expires_at",
            "payload_sha256",
            "source_channel",
            "delivery",
            "authority",
            "signature",
        }
        if set(envelope) != required or envelope.get("schema_version") != "hive.receiver-envelope.v1":
            raise ProtocolError("RECEIVER_ENVELOPE_INVALID", "envelope shape or version is invalid")
        for field in ("message_id", "nonce", "payload_sha256", "source_channel"):
            if not isinstance(envelope.get(field), str) or not envelope[field]:
                raise ProtocolError("RECEIVER_ENVELOPE_INVALID", f"{field} must be nonempty")
        validate_identifier(envelope["message_id"], "message_id")
        validate_identifier(envelope["nonce"], "nonce")
        if len(envelope["payload_sha256"]) != 64 or any(
            character not in "0123456789abcdef" for character in envelope["payload_sha256"]
        ):
            raise ProtocolError("RECEIVER_ENVELOPE_INVALID", "payload_sha256 must be lowercase SHA-256")
        allowed_channels = set(ACTIVE_MAILBOX_NAMES + LEGACY_ROUTE_NAMES + GITHUB_ROUTE_NAMES)
        if envelope["source_channel"] not in allowed_channels:
            raise ProtocolError("SOURCE_CHANNEL_UNAUTHORIZED", "source channel is not allowlisted")
        delivery = envelope.get("delivery")
        if not isinstance(delivery, Mapping) or set(delivery) != {
            "wake_mode",
            "dependency_ids",
            "transport_kind",
            "transport_actor",
            "authorized",
        }:
            raise ProtocolError("DELIVERY_CONTRACT_INVALID", "delivery contract is malformed")
        if delivery.get("wake_mode") not in {"EVENT", "DEPENDENCY", "HEARTBEAT"}:
            raise ProtocolError("WAKE_MODE_INVALID", "wake mode is not supported")
        dependencies = delivery.get("dependency_ids")
        if not isinstance(dependencies, list) or any(
            not isinstance(item, str) or not item for item in dependencies
        ):
            raise ProtocolError("DEPENDENCY_CONTRACT_INVALID", "dependency IDs must be strings")
        if delivery.get("authorized") is not True:
            raise ProtocolError("DELIVERY_UNAUTHORIZED", "delivery lacks explicit authorization")
        transport_kind = delivery.get("transport_kind")
        transport_actor = delivery.get("transport_actor")
        if transport_kind not in {"FILES_01_04", "GITHUB_APP", "LEGACY_LANE", "HEARTBEAT"}:
            raise ProtocolError("TRANSPORT_KIND_INVALID", "transport kind is not supported")
        if not isinstance(transport_actor, str) or not transport_actor:
            raise ProtocolError("TRANSPORT_ACTOR_INVALID", "transport actor must be nonempty")
        if transport_kind == "GITHUB_APP" and not transport_actor.endswith("[bot]"):
            raise ProtocolError("GITHUB_APP_REQUIRED", "GitHub discovery requires an App bot actor")
        if transport_kind == "GITHUB_APP" and transport_actor not in self.github_app_actors:
            raise ProtocolError("GITHUB_APP_UNTRUSTED", "GitHub App actor is not allowlisted")
        created = _parse_time(envelope["created_at"])
        expires = _parse_time(envelope["expires_at"])
        if created >= expires or datetime.now(timezone.utc) >= expires:
            raise ProtocolError("RECEIVER_ENVELOPE_EXPIRED", "envelope is expired or time-invalid")
        authority = envelope.get("authority")
        if not isinstance(authority, Mapping):
            raise ProtocolError("AUTHORITY_ENVELOPE_INVALID", "authority envelope is absent")
        sender = self._resolve_sender(authority)
        recipient = self.resolve(envelope["recipient_surface"])
        if transport_kind == "GITHUB_APP" and transport_actor != sender.app_actor:
            raise ProtocolError("GITHUB_APP_UNTRUSTED", "GitHub App actor does not bind the sender")
        signature = envelope.get("signature")
        if not isinstance(signature, Mapping) or signature.get("key_id") != sender.verification_key_id:
            raise ProtocolError(
                "SENDER_KEY_MISMATCH", "signature key does not bind the enrolled sender surface"
            )
        verify_document(envelope, self.trusted_keys)
        return recipient

    def _replay_begin(self, message_id: str, nonce: str) -> str:
        ledger = self.fs.read_json(("state", "replay.json"), optional=True) or {
            "schema_version": "hive.replay-ledger.v1",
            "messages": {},
            "nonces": {},
        }
        messages = ledger.get("messages")
        nonces = ledger.get("nonces")
        if not isinstance(messages, dict) or not isinstance(nonces, dict):
            raise ProtocolError("REPLAY_LEDGER_INVALID", "replay ledger is malformed")
        existing = messages.get(message_id)
        if existing is not None:
            if (
                isinstance(existing, dict)
                and existing.get("nonce") == nonce
                and existing.get("state") == "PENDING"
            ):
                return "RESUME"
            raise ProtocolError("REPLAY_MESSAGE_ID", "message ID was already consumed", 3)
        if nonce in nonces:
            raise ProtocolError("REPLAY_NONCE", "nonce was already consumed", 3)
        claimed_at = utc_now()
        messages[message_id] = {
            "nonce": nonce,
            "state": "PENDING",
            "claimed_at": claimed_at,
            "completed_at": None,
        }
        nonces[nonce] = {"message_id": message_id, "claimed_at": claimed_at}
        self.fs.write_json(("state", "replay.json"), ledger)
        return "NEW"

    def _replay_complete(self, message_id: str, nonce: str) -> None:
        ledger = self.fs.read_json(("state", "replay.json"))
        if ledger is None:
            raise ProtocolError("REPLAY_LEDGER_INVALID", "replay ledger is absent")
        existing = ledger.get("messages", {}).get(message_id)
        if (
            not isinstance(existing, dict)
            or existing.get("nonce") != nonce
            or existing.get("state") != "PENDING"
        ):
            raise ProtocolError("REPLAY_LEDGER_INVALID", "pending replay claim is absent")
        existing["state"] = "COMPLETE"
        existing["completed_at"] = utc_now()
        self.fs.write_json(("state", "replay.json"), ledger)

    def _signed_receipt(
        self, envelope: Mapping[str, Any], recipient: SurfaceEnrollment, status: str, attempt: int
    ) -> dict[str, Any]:
        return sign_document(
            {
                "schema_version": "hive.receiver-receipt.v1",
                "message_id": envelope["message_id"],
                "recipient_surface": recipient.surface_id,
                "machine_id": recipient.machine_id,
                "status": status,
                "attempt": attempt,
                "envelope_sha256": document_digest(envelope),
                "recorded_at": utc_now(),
            },
            self.receipt_key,
        )

    def route(
        self,
        envelope: Mapping[str, Any],
        deliver: Callable[[Mapping[str, Any], SurfaceEnrollment], None],
    ) -> dict[str, Any]:
        recipient = self.validate_envelope(envelope)
        message_id = envelope["message_id"]
        nonce = envelope["nonce"]
        with self.fs.lock(("state", "receiver.lock")):
            claim = self._replay_begin(message_id, nonce)
            retry_path = ("state", "retries", f"{message_id}.json")
            retry = self.fs.read_json(retry_path, optional=True) or {"attempts": 0}
            attempt = int(retry.get("attempts", 0)) + 1
            try:
                deliver(envelope, recipient)
            except Exception as exc:
                retry = {
                    "schema_version": "hive.receiver-retry.v1",
                    "message_id": message_id,
                    "attempts": attempt,
                    "last_error_type": type(exc).__name__,
                    "updated_at": utc_now(),
                }
                self.fs.write_json(retry_path, retry)
                if attempt < self.max_attempts:
                    raise ProtocolError("DELIVERY_RETRY", "delivery failed; bounded retry remains") from exc
                receipt = self._signed_receipt(envelope, recipient, "QUARANTINED", attempt)
                self.fs.write_json(("quarantine", f"{message_id}.json"), envelope)
                self.fs.write_json(("failure_receipts", f"{message_id}.json"), receipt)
                self._replay_complete(message_id, nonce)
                return receipt

            inbox_path = ("inbox", recipient.surface_id, f"{message_id}.json")
            persisted = self.fs.read_json(inbox_path, optional=True)
            if claim == "RESUME" and persisted is not None:
                if document_digest(persisted) != document_digest(envelope):
                    raise ProtocolError("CRASH_RECOVERY_CONFLICT", "durable envelope differs")
            else:
                self.fs.write_json(inbox_path, envelope)
            cursor_path = ("state", "cursors", f"{recipient.surface_id}.json")
            cursor = self.fs.read_json(cursor_path, optional=True) or {"delivered": 0}
            self.fs.write_json(
                cursor_path,
                {
                    "schema_version": "hive.receiver-cursor.v1",
                    "recipient_surface": recipient.surface_id,
                    "delivered": int(cursor.get("delivered", 0)) + 1,
                    "last_message_id": message_id,
                    "updated_at": utc_now(),
                },
            )
            receipt = self._signed_receipt(envelope, recipient, "DELIVERED", attempt)
            self.fs.write_json(("ack_receipts", f"{message_id}.json"), receipt)
            self._replay_complete(message_id, nonce)
            return receipt
