"""Fail-closed authority intersection for application adapter invocations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from hive_protocol.adapters.manifest import AdapterManifest
from hive_protocol.adapters.models import AdapterRequest
from hive_protocol.core import ProtocolError


@dataclass(frozen=True)
class InvocationContext:
    project_id: str
    authorization_ref: str
    identity: dict[str, str]
    granted_capabilities: frozenset[str]
    granted_permissions: frozenset[str]
    allowed_data_classifications: frozenset[str]
    allowed_network_destinations: frozenset[str]
    available_credential_references: frozenset[str]


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    adapter_id: str
    request_id: str
    effective_capabilities: tuple[str, ...]
    effective_permissions: tuple[str, ...]
    effective_network_destinations: tuple[str, ...]


def _expiry(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError(
            "ADAPTER_REQUEST_EXPIRY_INVALID",
            "request expiry is not a valid date-time",
        ) from exc
    if parsed.tzinfo is None:
        raise ProtocolError(
            "ADAPTER_REQUEST_EXPIRY_INVALID",
            "request expiry must include a timezone",
        )
    return parsed.astimezone(timezone.utc)


def authorize_adapter_request(
    manifest: AdapterManifest,
    request: AdapterRequest,
    context: InvocationContext,
    *,
    revoked: bool,
    evaluated_at: datetime | None = None,
) -> PolicyDecision:
    if revoked:
        raise ProtocolError("ADAPTER_REVOKED", "adapter has been revoked")
    if request.project_id != context.project_id:
        raise ProtocolError(
            "ADAPTER_PROJECT_DENIED",
            "request project does not match the invocation context",
        )
    if request.authorization_ref != context.authorization_ref:
        raise ProtocolError(
            "ADAPTER_AUTHORIZATION_DENIED",
            "request authorization does not match the invocation context",
        )
    if request.sender != context.identity:
        raise ProtocolError(
            "ADAPTER_IDENTITY_DENIED",
            "request sender does not match the invocation identity",
        )
    if (
        request.capability_id not in manifest.capability_ids
        or request.capability_id not in context.granted_capabilities
    ):
        raise ProtocolError(
            "ADAPTER_CAPABILITY_DENIED",
            "requested capability is not both declared and granted",
        )
    if not set(manifest.required_permissions) <= context.granted_permissions:
        raise ProtocolError(
            "ADAPTER_PERMISSION_DENIED",
            "adapter permissions are not fully granted",
        )
    if (
        request.data_classification not in manifest.accepted_data_classifications
        or request.data_classification not in context.allowed_data_classifications
    ):
        raise ProtocolError(
            "ADAPTER_DATA_CLASS_DENIED",
            "data classification is not both accepted and allowed",
        )
    if not set(manifest.network_destinations) <= context.allowed_network_destinations:
        raise ProtocolError(
            "ADAPTER_EGRESS_DENIED",
            "adapter network destinations are not fully allowed",
        )
    if not set(manifest.credential_references) <= context.available_credential_references:
        raise ProtocolError(
            "ADAPTER_CREDENTIAL_REFERENCE_DENIED",
            "required credential references are unavailable",
        )
    if request.adapter_id != manifest.adapter_id:
        raise ProtocolError(
            "ADAPTER_ID_MISMATCH",
            "request adapter ID does not match the manifest",
        )
    if request.adapter_version != manifest.version:
        raise ProtocolError(
            "ADAPTER_VERSION_MISMATCH",
            "request adapter version does not match the manifest",
        )
    evaluation_time = evaluated_at or datetime.now(timezone.utc)
    if evaluation_time.tzinfo is None:
        raise ProtocolError(
            "ADAPTER_POLICY_TIME_INVALID",
            "policy evaluation time must include a timezone",
        )
    if _expiry(request.expires_at) <= evaluation_time.astimezone(timezone.utc):
        raise ProtocolError("ADAPTER_REQUEST_EXPIRED", "request has expired")
    return PolicyDecision(
        allowed=True,
        adapter_id=manifest.adapter_id,
        request_id=request.request_id,
        effective_capabilities=(request.capability_id,),
        effective_permissions=tuple(sorted(manifest.required_permissions)),
        effective_network_destinations=tuple(sorted(manifest.network_destinations)),
    )
