from __future__ import annotations

import pytest

from hive_protocol.adapters.security import reject_credential_values
from hive_protocol.core import ProtocolError


@pytest.mark.parametrize(
    "document",
    [
        {"payload": {"api_key": "live-value"}},
        {"detail": "Authorization: Bearer abcdefghijklmnop"},
        {"detail": "service_token=abcdefghijklmnop"},
        {"detail": "-----BEGIN " + "PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"},
        {"detail": "sk" + "-abcdefghijklmnop123456"},
    ],
)
def test_credential_values_are_rejected_recursively(document: dict) -> None:
    with pytest.raises(ProtocolError, match="ADAPTER_CREDENTIAL_VALUE_DENIED"):
        reject_credential_values(document, location="test-document")


def test_protected_credential_references_are_allowed() -> None:
    reject_credential_values(
        {
            "credential_references": [
                "keychain:hivemind/local",
                "secret-service:hivemind/local",
                "credential-manager:hivemind/local",
                "manual:hivemind/local",
            ],
            "credential_reference": "keychain:hivemind/local",
            "detail": {"credential_state": "NOT_REQUIRED"},
        },
        location="manifest",
    )


def test_raw_value_in_credential_references_is_rejected() -> None:
    with pytest.raises(ProtocolError, match="ADAPTER_CREDENTIAL_VALUE_DENIED"):
        reject_credential_values(
            {"credential_references": ["plaintext-value"]}, location="manifest"
        )


@pytest.mark.parametrize(
    "document",
    [
        {"credential_reference": "opaque-plaintext-value"},
        {"credential_state": "opaque-plaintext-value"},
    ],
)
def test_singular_credential_metadata_rejects_opaque_values(document: dict) -> None:
    with pytest.raises(ProtocolError, match="ADAPTER_CREDENTIAL_VALUE_DENIED"):
        reject_credential_values(document, location="adapter-document")


@pytest.mark.parametrize("state", ["AVAILABLE", "MISSING", "NOT_REQUIRED"])
def test_credential_state_accepts_only_public_status_values(state: str) -> None:
    reject_credential_values({"credential_state": state}, location="adapter-status")
