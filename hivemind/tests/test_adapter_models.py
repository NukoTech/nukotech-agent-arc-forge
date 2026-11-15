from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from hive_protocol.adapters.models import (
    AdapterOutcome,
    AdapterRequest,
    adapter_document_digest,
    validate_adapter_document,
)
from hive_protocol.core import ProtocolError


def request_document() -> dict:
    expires = datetime.now(timezone.utc) + timedelta(minutes=5)
    return AdapterRequest(
        request_id="req-001",
        adapter_id="nukotech.hive.local-capture",
        adapter_version="1.0.0",
        sender={
            "persona_id": "Director",
            "surface_id": "LeadA",
            "machine_id": "hive-lab-host",
            "project_id": "HiveMind",
            "app_actor": "hive-builda-app",
        },
        project_id="HiveMind",
        capability_id="capture.text",
        data_classification="PROJECT_PRIVATE",
        authorization_ref="grant:hivemind:capture",
        evidence_sha256=["a" * 64],
        payload={"text": "bounded evidence"},
        nonce="nonce-0000000001",
        expires_at=expires.isoformat().replace("+00:00", "Z"),
    ).as_dict()


def test_request_round_trip_is_stable() -> None:
    document = request_document()
    validate_adapter_document("adapter-request.v1.schema.json", document)
    assert AdapterRequest.from_dict(document).as_dict() == document
    assert len(adapter_document_digest(document)) == 64


def test_request_schema_rejects_unknown_authority_field() -> None:
    document = request_document()
    document["implied_admin"] = True
    with pytest.raises(ProtocolError, match="ADAPTER_DOCUMENT_SCHEMA_INVALID"):
        validate_adapter_document("adapter-request.v1.schema.json", document)


def test_outcome_values_are_closed() -> None:
    assert {item.value for item in AdapterOutcome} == {
        "APPLIED",
        "NO_OP",
        "REFUSED",
        "DEGRADED",
        "FAILED",
    }
