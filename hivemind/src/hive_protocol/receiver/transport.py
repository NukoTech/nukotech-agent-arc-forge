"""Invocation adapter for the deployed heartbeat and drop-watcher transports.

There is intentionally no loop, timer, daemon, network client, or service entry
point here.  The existing watcher may invoke ``process`` for filesystem/GitHub
events and the existing heartbeat may invoke ``heartbeat_fallback``.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from uuid import NAMESPACE_URL, uuid5

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..core import ProtocolError, canonical_bytes, document_digest, sign_document
from ..storage import utc_now
from .containment import GovernedRoot
from .matrix import (
    ACTIVE_MAILBOX_NAMES,
    GITHUB_ROUTE_NAMES,
    LEGACY_ROUTE_NAMES,
    ReceiverMatrix,
    SurfaceEnrollment,
)


_SAFE_ACTOR = re.compile(r"^[a-z0-9][a-z0-9-]*\[bot\]$")
_WAKE_MODES = {"EVENT", "DEPENDENCY", "HEARTBEAT"}


@dataclass(frozen=True)
class MachineAppIdentity:
    actor: str
    app_id: int
    installation_id: int

    def __post_init__(self) -> None:
        if not _SAFE_ACTOR.fullmatch(self.actor):
            raise ProtocolError("MACHINE_APP_REQUIRED", "GitHub transport must use a machine App bot")
        if self.app_id <= 0 or self.installation_id <= 0:
            raise ProtocolError("MACHINE_APP_INVALID", "App and installation IDs must be positive")


@dataclass(frozen=True)
class DiscoveredWork:
    message_id: str
    nonce: str
    recipient_surface: str
    payload_sha256: str
    source_channel: str
    transport_kind: str
    transport_actor: str
    wake_mode: str = "EVENT"
    dependency_ids: tuple[str, ...] = ()
    authorized: bool = True
    created_at: str | None = None
    expires_at: str | None = None


class FileRouteDiscovery:
    """Convert existing transport files to content-addressed work metadata."""

    def discover(
        self,
        routes: Mapping[str, Path],
        resolve_recipient: Callable[[Path], str | None],
        *,
        now: datetime | None = None,
    ) -> list[DiscoveredWork]:
        timestamp = now or datetime.now(timezone.utc)
        allowed = set(ACTIVE_MAILBOX_NAMES + LEGACY_ROUTE_NAMES)
        discovered: list[DiscoveredWork] = []
        for channel, root in sorted(routes.items()):
            if channel not in allowed:
                raise ProtocolError("SOURCE_CHANNEL_UNAUTHORIZED", "file discovery route is not allowlisted")
            if root.is_symlink() or not root.is_dir():
                raise ProtocolError("DISCOVERY_ROOT_INVALID", "discovery root must be a regular directory")
            for path in sorted(root.rglob("*")):
                if path.is_symlink() or not path.is_file():
                    continue
                recipient = resolve_recipient(path)
                if recipient is None:
                    continue
                payload_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
                relative = path.relative_to(root).as_posix()
                binding = f"{channel}:{relative}:{payload_sha256}"
                discovered.append(
                    DiscoveredWork(
                        message_id=str(uuid5(NAMESPACE_URL, binding)),
                        nonce=hashlib.sha256(f"nonce:{binding}".encode()).hexdigest(),
                        recipient_surface=recipient,
                        payload_sha256=payload_sha256,
                        source_channel=channel,
                        transport_kind=(
                            "FILES_01_04" if channel in ACTIVE_MAILBOX_NAMES else "LEGACY_LANE"
                        ),
                        transport_actor="existing-local-filesystem",
                        created_at=timestamp.isoformat().replace("+00:00", "Z"),
                        expires_at=(timestamp + timedelta(hours=24)).isoformat().replace("+00:00", "Z"),
                    )
                )
        return discovered


class GitHubAssignmentDiscovery:
    """Normalize read-only issue/PR assignment records obtained through an App."""

    def __init__(self, identity: MachineAppIdentity) -> None:
        self.identity = identity

    def discover(self, records: Sequence[Mapping[str, Any]], recipient_surface: str) -> list[DiscoveredWork]:
        discovered: list[DiscoveredWork] = []
        for record in records:
            if set(record) != {"kind", "number", "repository", "updated_at", "assigned"}:
                raise ProtocolError("GITHUB_RECORD_INVALID", "GitHub assignment shape is invalid")
            kind = record.get("kind")
            if kind not in {"issue", "pull_request"} or record.get("assigned") is not True:
                continue
            number = record.get("number")
            repository = record.get("repository")
            updated_at = record.get("updated_at")
            if not isinstance(number, int) or number < 1 or not isinstance(repository, str):
                raise ProtocolError("GITHUB_RECORD_INVALID", "GitHub assignment identity is invalid")
            try:
                created = datetime.fromisoformat(str(updated_at).replace("Z", "+00:00"))
            except ValueError as exc:
                raise ProtocolError("GITHUB_RECORD_INVALID", "updated_at is invalid") from exc
            if created.tzinfo is None:
                raise ProtocolError("GITHUB_RECORD_INVALID", "updated_at must contain a timezone")
            binding = canonical_bytes(
                {"kind": kind, "number": number, "repository": repository, "updated_at": updated_at}
            )
            payload_sha256 = hashlib.sha256(binding).hexdigest()
            stable = f"github:{repository}:{kind}:{number}:{updated_at}"
            discovered.append(
                DiscoveredWork(
                    message_id=str(uuid5(NAMESPACE_URL, stable)),
                    nonce=hashlib.sha256(f"nonce:{stable}".encode()).hexdigest(),
                    recipient_surface=recipient_surface,
                    payload_sha256=payload_sha256,
                    source_channel=f"github:{kind}",
                    transport_kind="GITHUB_APP",
                    transport_actor=self.identity.actor,
                    created_at=created.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                    expires_at=(datetime.now(timezone.utc) + timedelta(hours=24)).isoformat().replace(
                        "+00:00", "Z"
                    ),
                )
            )
        return discovered


class SingleWriterGitTransport:
    """Serialize injected Git writes and bind them to a machine App identity."""

    def __init__(
        self,
        state_root: Path,
        identity: MachineAppIdentity,
        receipt_key: Ed25519PrivateKey,
        authority: SurfaceEnrollment,
    ) -> None:
        if authority.technical_admission != "ACTIVE" or authority.app_actor != identity.actor:
            raise ProtocolError(
                "GIT_AUTHORITY_MISMATCH", "machine App identity does not bind active surface authority"
            )
        self.state_root = state_root
        self.fs = GovernedRoot(state_root)
        self.identity = identity
        self.receipt_key = receipt_key
        self.authority = authority

    def execute(
        self,
        operation_identity: MachineAppIdentity,
        operation: Callable[[MachineAppIdentity], Mapping[str, Any]],
    ) -> Mapping[str, Any]:
        if operation_identity != self.identity:
            raise ProtocolError(
                "GIT_AUTHORITY_MISMATCH", "Git operation identity mismatches before execution"
            )
        with self.fs.lock(("locks", "github-app-git-writer.lock")):
            result = operation(self.identity)
            if not isinstance(result, Mapping) or result.get("actor") != self.identity.actor:
                raise ProtocolError(
                    "GIT_ACTOR_MISMATCH", "remote write readback does not match the machine App actor"
                )
            self.fs.write_json(
                ("receipts", "last-git-write.json"),
                sign_document(
                    {
                        "schema_version": "hive.machine-app-git-write.v1",
                        "actor": self.identity.actor,
                        "app_id": self.identity.app_id,
                        "installation_id": self.identity.installation_id,
                        "readback_sha256": document_digest(result),
                        "completed_at": utc_now(),
                    },
                    self.receipt_key,
                ),
            )
            return result


class ExistingTransportAdapter:
    """Route discovered work through ReceiverMatrix without owning a poll loop."""

    def __init__(
        self,
        root: Path,
        matrix: ReceiverMatrix,
        sender_key: Ed25519PrivateKey,
        sender_surface: str,
    ) -> None:
        self.root = root
        self.fs = GovernedRoot(root)
        self.matrix = matrix
        self.sender_key = sender_key
        self.sender = matrix.resolve(sender_surface)

    def _envelope(self, work: DiscoveredWork) -> dict[str, Any]:
        if work.wake_mode not in _WAKE_MODES:
            raise ProtocolError("WAKE_MODE_INVALID", "wake mode is not supported")
        now = datetime.now(timezone.utc)
        return sign_document(
            {
                "schema_version": "hive.receiver-envelope.v1",
                "message_id": work.message_id,
                "nonce": work.nonce,
                "recipient_surface": work.recipient_surface,
                "created_at": work.created_at or now.isoformat().replace("+00:00", "Z"),
                "expires_at": work.expires_at
                or (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
                "payload_sha256": work.payload_sha256,
                "source_channel": work.source_channel,
                "delivery": {
                    "wake_mode": work.wake_mode,
                    "dependency_ids": list(work.dependency_ids),
                    "transport_kind": work.transport_kind,
                    "transport_actor": work.transport_actor,
                    "authorized": work.authorized,
                },
                "authority": {
                    "project_id": self.sender.project_id,
                    "sender_surface": self.sender.surface_id,
                    "sender_machine": self.sender.machine_id,
                    "claimed_device_director": self.sender.device_director,
                    "claimed_project_lead": self.sender.current_project_lead,
                    "supreme_authority": self.sender.supreme_authority,
                    "network_membership_authorizes": False,
                    "future_hierarchy": "DOCUMENTED_INACTIVE",
                    "voting_state": "DOCUMENTED_INACTIVE",
                },
            },
            self.sender_key,
        )

    def process(
        self,
        work: DiscoveredWork,
        wake: Callable[[Mapping[str, Any], SurfaceEnrollment, str], bool],
        *,
        dependency_state: Mapping[str, bool] | None = None,
        directly_wakeable: bool = True,
    ) -> dict[str, Any]:
        envelope = self._envelope(work)
        outcome: dict[str, str] = {"wake_status": "UNSET"}

        def deliver(message: Mapping[str, Any], recipient: SurfaceEnrollment) -> None:
            dependencies = message["delivery"]["dependency_ids"]
            ready = all((dependency_state or {}).get(item, False) for item in dependencies)
            if message["delivery"]["wake_mode"] == "DEPENDENCY" and not ready:
                outcome["wake_status"] = "WAITING_DEPENDENCY"
            elif not directly_wakeable:
                outcome["wake_status"] = "DURABLE_UNREAD"
            else:
                reason = message["delivery"]["wake_mode"]
                outcome["wake_status"] = "AWAKENED" if wake(message, recipient, reason) else "DURABLE_UNREAD"
            if outcome["wake_status"] != "AWAKENED":
                self.fs.write_json(
                    ("unread", recipient.surface_id, f"{message['message_id']}.json"),
                    {
                        "schema_version": "hive.durable-unread.v1",
                        "envelope": dict(message),
                        "wake_status": outcome["wake_status"],
                        "recorded_at": utc_now(),
                    },
                )

        receipt = self.matrix.route(envelope, deliver)
        return {"receipt": receipt, **outcome}

    def _retry_unread(
        self,
        wake: Callable[[Mapping[str, Any], SurfaceEnrollment, str], bool],
        *,
        dependency_state: Mapping[str, bool] | None,
        reason: str,
    ) -> list[str]:
        awakened: list[str] = []
        for enrollment in self.matrix.enrollments.values():
            if enrollment.technical_admission != "ACTIVE":
                continue
            for filename in self.fs.list_json(("unread", enrollment.surface_id)):
                path = ("unread", enrollment.surface_id, filename)
                unread = self.fs.read_json(path)
                if unread is None:
                    raise ProtocolError("UNREAD_INVALID", "durable unread record is absent")
                envelope = unread.get("envelope")
                if not isinstance(envelope, Mapping):
                    raise ProtocolError("UNREAD_INVALID", "durable unread envelope is absent")
                recipient = self.matrix.validate_envelope(envelope)
                if reason == "DEPENDENCY" and envelope["delivery"]["wake_mode"] != "DEPENDENCY":
                    continue
                dependencies = envelope["delivery"]["dependency_ids"]
                if reason == "DEPENDENCY" and not all(
                    (dependency_state or {}).get(item, False) for item in dependencies
                ):
                    continue
                if wake(envelope, recipient, reason):
                    self.fs.write_json(
                        ("wake_receipts", f"{envelope['message_id']}.json"),
                        sign_document(
                            {
                                "schema_version": "hive.wake-receipt.v1",
                                "message_id": envelope["message_id"],
                                "recipient_surface": recipient.surface_id,
                                "reason": reason,
                                "awakened_at": utc_now(),
                            },
                            self.sender_key,
                        ),
                    )
                    self.fs.unlink(path)
                    awakened.append(envelope["message_id"])
        return awakened

    def dependency_wake(
        self,
        dependency_state: Mapping[str, bool],
        wake: Callable[[Mapping[str, Any], SurfaceEnrollment, str], bool],
    ) -> list[str]:
        return self._retry_unread(wake, dependency_state=dependency_state, reason="DEPENDENCY")

    def heartbeat_fallback(
        self, wake: Callable[[Mapping[str, Any], SurfaceEnrollment, str], bool]
    ) -> list[str]:
        return self._retry_unread(wake, dependency_state=None, reason="HEARTBEAT")
