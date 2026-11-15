from __future__ import annotations

import copy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.adapters.lifecycle_state import LifecycleOperationStore
from hive_protocol.core import ProtocolError, public_key_id
from hive_protocol.storage import atomic_write_json, read_json


def test_lifecycle_terminal_record_is_signed_and_tamper_evident(
    tmp_path: Path,
) -> None:
    signing_key = Ed25519PrivateKey.generate()
    key_id = public_key_id(signing_key.public_key())
    store = LifecycleOperationStore(
        tmp_path / "state",
        "nukotech.hive.test",
        signing_key=signing_key,
        trusted_state_keys={key_id: signing_key.public_key()},
    )
    operation_key = "a" * 64
    operation_input = {"rollback_ref": "capture-delta:test"}
    result = {
        "outcome": "APPLIED",
        "evidence_refs": [],
        "side_effects": ["workspace:source"],
        "resource_use": {"writes": 1},
        "rollback_ref": None,
        "detail": {},
    }
    assert store.begin("rollback", operation_key, operation_input) is None
    store.finish("rollback", operation_key, operation_input, result)
    path = store._path("rollback", operation_key)
    durable = read_json(path)
    assert durable["signature"]["key_id"] == key_id
    assert store.recover("rollback", operation_key) == result

    tampered = copy.deepcopy(durable)
    tampered["result"]["side_effects"] = []
    atomic_write_json(path, tampered, mode=0o600)

    with pytest.raises(ProtocolError, match="ADAPTER_LIFECYCLE_OPERATION_MISMATCH"):
        store.recover("rollback", operation_key)
