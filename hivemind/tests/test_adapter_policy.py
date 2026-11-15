from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from hive_protocol.adapters.manifest import load_manifest
from hive_protocol.adapters.models import AdapterRequest
from hive_protocol.adapters.policy import InvocationContext, authorize_adapter_request
from hive_protocol.core import ProtocolError


IDENTITY = {
    "persona_id": "Director",
    "surface_id": "LeadA",
    "machine_id": "hive-lab-host",
    "project_id": "HiveMind",
    "app_actor": "hive-builda-app",
}


@pytest.fixture
def manifest():
    root = Path(__file__).parents[1]
    document = json.loads(
        (
            root
            / "tests/fixtures/adapters/sample-heartbeat.manifest.json"
        ).read_text(encoding="utf-8")
    )
    document["adapter_id"] = "nukotech.hive.test-adapter"
    document["version"] = "1.0.0"
    document["capability_ids"] = ["capture.text"]
    document["required_permissions"] = ["filesystem.write.adapter-state"]
    document["accepted_data_classifications"] = ["PROJECT_PRIVATE"]
    document["network_destinations"] = ["https://research.example.invalid"]
    document["credential_references"] = ["secret-service:hive/research"]
    return load_manifest(document)


@pytest.fixture
def adapter_request() -> AdapterRequest:
    return AdapterRequest(
        request_id="request-001",
        adapter_id="nukotech.hive.test-adapter",
        adapter_version="1.0.0",
        sender=dict(IDENTITY),
        project_id="HiveMind",
        capability_id="capture.text",
        data_classification="PROJECT_PRIVATE",
        authorization_ref="grant:hivemind:capture",
        evidence_sha256=["a" * 64],
        payload={"kind": "text", "text": "bounded evidence"},
        nonce="request-nonce-001",
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5))
        .isoformat()
        .replace("+00:00", "Z"),
    )


@pytest.fixture
def context() -> InvocationContext:
    return InvocationContext(
        project_id="HiveMind",
        authorization_ref="grant:hivemind:capture",
        identity=dict(IDENTITY),
        granted_capabilities=frozenset({"capture.text"}),
        granted_permissions=frozenset({"filesystem.write.adapter-state"}),
        allowed_data_classifications=frozenset({"PROJECT_PRIVATE"}),
        allowed_network_destinations=frozenset(
            {"https://research.example.invalid"}
        ),
        available_credential_references=frozenset(
            {"secret-service:hive/research"}
        ),
    )


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"granted_capabilities": frozenset()}, "ADAPTER_CAPABILITY_DENIED"),
        ({"granted_permissions": frozenset()}, "ADAPTER_PERMISSION_DENIED"),
        (
            {"allowed_data_classifications": frozenset({"NON_PRIVATE"})},
            "ADAPTER_DATA_CLASS_DENIED",
        ),
        ({"allowed_network_destinations": frozenset()}, "ADAPTER_EGRESS_DENIED"),
        ({"project_id": "AnotherProject"}, "ADAPTER_PROJECT_DENIED"),
        (
            {"authorization_ref": "grant:other"},
            "ADAPTER_AUTHORIZATION_DENIED",
        ),
        (
            {"available_credential_references": frozenset()},
            "ADAPTER_CREDENTIAL_REFERENCE_DENIED",
        ),
    ],
)
def test_policy_intersection_fails_closed(
    manifest, adapter_request, context, change, reason
) -> None:
    changed = dataclasses.replace(context, **change)
    with pytest.raises(ProtocolError, match=reason):
        authorize_adapter_request(manifest, adapter_request, changed, revoked=False)


def test_policy_rejects_revocation_identity_version_and_expiry(
    manifest, adapter_request, context
) -> None:
    with pytest.raises(ProtocolError, match="ADAPTER_REVOKED"):
        authorize_adapter_request(manifest, adapter_request, context, revoked=True)

    wrong_identity = dataclasses.replace(
        context, identity={**IDENTITY, "surface_id": "LeadB"}
    )
    with pytest.raises(ProtocolError, match="ADAPTER_IDENTITY_DENIED"):
        authorize_adapter_request(manifest, adapter_request, wrong_identity, revoked=False)

    wrong_version = dataclasses.replace(adapter_request, adapter_version="2.0.0")
    with pytest.raises(ProtocolError, match="ADAPTER_VERSION_MISMATCH"):
        authorize_adapter_request(manifest, wrong_version, context, revoked=False)

    expired = dataclasses.replace(
        adapter_request,
        expires_at=(datetime.now(timezone.utc) - timedelta(seconds=1))
        .isoformat()
        .replace("+00:00", "Z"),
    )
    with pytest.raises(ProtocolError, match="ADAPTER_REQUEST_EXPIRED"):
        authorize_adapter_request(manifest, expired, context, revoked=False)


def test_policy_returns_only_effective_authority(
    manifest, adapter_request, context
) -> None:
    decision = authorize_adapter_request(
        manifest, adapter_request, context, revoked=False
    )
    assert decision.allowed is True
    assert decision.effective_capabilities == ("capture.text",)
    assert decision.effective_permissions == ("filesystem.write.adapter-state",)
    assert decision.effective_network_destinations == (
        "https://research.example.invalid",
    )


def test_recovery_can_recheck_policy_at_original_preparation_time(
    manifest, adapter_request, context
) -> None:
    expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    prepared_at = expires_at - timedelta(seconds=1)
    expired_now = dataclasses.replace(
        adapter_request,
        expires_at=expires_at.isoformat().replace("+00:00", "Z"),
    )

    decision = authorize_adapter_request(
        manifest,
        expired_now,
        context,
        revoked=False,
        evaluated_at=prepared_at,
    )

    assert decision.allowed is True
