from __future__ import annotations

import copy
import json
import os
import stat
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.adapters.models import AdapterRequest
from hive_protocol.adapters.policy import InvocationContext
from hive_protocol.adapters.registry import AdapterRegistry
from hive_protocol.adapters.runtime import AdapterRuntime
from hive_protocol.core import (
    ProtocolError,
    document_digest,
    public_key_id,
    sign_document,
    verify_document,
)


IDENTITY = {
    "persona_id": "Director",
    "surface_id": "LeadA",
    "machine_id": "hive-lab-host",
    "project_id": "HiveMind",
    "app_actor": "hive-builda-app",
}


class PlanningAdapter:
    def __init__(self) -> None:
        self.sleep_seconds = 0.0

    def health(self) -> dict:
        return {"status": "HEALTHY", "evidence": []}

    def plan(self, payload: dict) -> dict:
        if self.sleep_seconds:
            time.sleep(self.sleep_seconds)
        return {
            "side_effects": ["workspace:receipt"],
            "network_destinations": [],
            "requires_approval": False,
            "payload": copy.deepcopy(payload),
        }

    def apply(self, payload: dict, *, operation_key: str) -> dict:
        raise AssertionError("planning must not call apply")

    def recover(self, operation_key: str) -> dict | None:
        return None

    def export(self, scope: dict, *, operation_key: str) -> dict:
        return {"outcome": "NO_OP"}

    def rollback(self, rollback_ref: str, *, operation_key: str) -> dict:
        return {"outcome": "NO_OP"}

    def recover_lifecycle(self, operation: str, operation_key: str) -> dict | None:
        return None


@pytest.fixture
def runtime_bundle(tmp_path: Path):
    root = Path(__file__).parents[1]
    manifest = json.loads(
        (
            root
            / "tests/fixtures/adapters/sample-heartbeat.manifest.json"
        ).read_text(encoding="utf-8")
    )
    manifest["adapter_id"] = "nukotech.hive.planning-test"
    manifest["name"] = "Planning Test"
    manifest["version"] = "1.0.0"
    manifest["capability_ids"] = ["capture.text"]
    manifest["required_permissions"] = ["filesystem.write.adapter-state"]
    manifest["accepted_data_classifications"] = ["PROJECT_PRIVATE"]
    manifest["network_destinations"] = []
    manifest["credential_references"] = []
    registry = AdapterRegistry(
        tmp_path,
        tmp_path / "policy",
        os_name="linux",
        architecture="aarch64",
        runtime="python>=3.11",
    )
    registry.register(PlanningAdapter(), manifest)
    request_key = Ed25519PrivateKey.generate()
    runtime_key = Ed25519PrivateKey.generate()
    runtime = AdapterRuntime(
        tmp_path,
        registry,
        {public_key_id(request_key.public_key()): request_key.public_key()},
        {},
        runtime_key,
        trusted_approver_identities={},
    )
    request = AdapterRequest(
        request_id="planning-request-001",
        adapter_id="nukotech.hive.planning-test",
        adapter_version="1.0.0",
        sender=dict(IDENTITY),
        project_id="HiveMind",
        capability_id="capture.text",
        data_classification="PROJECT_PRIVATE",
        authorization_ref="grant:hivemind:capture",
        evidence_sha256=["a" * 64],
        payload={"kind": "text", "text": "bounded evidence"},
        nonce="planning-nonce-001",
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5))
        .isoformat()
        .replace("+00:00", "Z"),
    )
    signed_request = sign_document(request.as_dict(), request_key)
    context = InvocationContext(
        project_id="HiveMind",
        authorization_ref="grant:hivemind:capture",
        identity=dict(IDENTITY),
        granted_capabilities=frozenset({"capture.text"}),
        granted_permissions=frozenset({"filesystem.write.adapter-state"}),
        allowed_data_classifications=frozenset({"PROJECT_PRIVATE"}),
        allowed_network_destinations=frozenset(),
        available_credential_references=frozenset(),
    )
    return runtime, signed_request, context, runtime_key.public_key(), request_key


def test_plan_is_signed_and_has_no_adapter_side_effect(
    tmp_path: Path, runtime_bundle
) -> None:
    runtime, signed_request, context, runtime_public_key, _ = runtime_bundle
    before = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
        if path.is_file()
    )
    plan = runtime.plan(signed_request, context)
    after = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
        if path.is_file()
    )
    assert plan["schema_version"] == "hive.adapter-plan.v1"
    assert plan["request_digest"] == document_digest(signed_request)
    assert plan["signature"]["key_id"] == runtime.key_id
    assert [path for path in after if path not in before] == [
        f"plans/{plan['plan_id']}.json"
    ]
    verify_document(plan, {runtime.key_id: runtime_public_key})


def test_plan_rejects_tampered_request(runtime_bundle) -> None:
    runtime, signed_request, context, _, _ = runtime_bundle
    signed_request["payload"]["text"] = "tampered"
    with pytest.raises(ProtocolError, match="SIGNATURE_INVALID"):
        runtime.plan(signed_request, context)


def test_plan_rejects_expired_request(runtime_bundle) -> None:
    runtime, signed_request, context, _, request_key = runtime_bundle
    expired = dict(signed_request)
    expired["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1))
    expired["expires_at"] = expired["expires_at"].isoformat().replace("+00:00", "Z")
    expired = sign_document(expired, request_key)
    with pytest.raises(ProtocolError, match="ADAPTER_REQUEST_EXPIRED"):
        runtime.plan(expired, context)


def test_plan_enforces_manifest_timeout(runtime_bundle) -> None:
    runtime, signed_request, context, _, _ = runtime_bundle
    entry = runtime.registry.require(
        signed_request["adapter_id"], signed_request["adapter_version"]
    )
    entry.manifest.resource_limits["timeout_seconds"] = 1
    entry.adapter.sleep_seconds = 2
    started = time.monotonic()

    with pytest.raises(ProtocolError, match="ADAPTER_TIMEOUT_EXCEEDED"):
        runtime.plan(signed_request, context)

    assert time.monotonic() - started < 1.8
    assert not runtime.plans.exists()


def test_plan_rejects_credential_value_before_persistence(runtime_bundle) -> None:
    runtime, signed_request, context, _, request_key = runtime_bundle
    unsafe = copy.deepcopy(signed_request)
    unsafe["payload"] = {"api_key": "live-value"}
    unsafe = sign_document(unsafe, request_key)

    with pytest.raises(ProtocolError, match="ADAPTER_CREDENTIAL_VALUE_DENIED"):
        runtime.plan(unsafe, context)

    assert not runtime.plans.exists()


def test_plan_rejects_oversized_full_request_envelope(runtime_bundle) -> None:
    runtime, signed_request, context, _, request_key = runtime_bundle
    entry = runtime.registry.require(
        signed_request["adapter_id"], signed_request["adapter_version"]
    )
    entry.manifest.resource_limits["max_input_bytes"] = 1024
    oversized = copy.deepcopy(signed_request)
    oversized["evidence_sha256"] = [f"{index:064x}" for index in range(1200)]
    oversized = sign_document(oversized, request_key)

    with pytest.raises(ProtocolError, match="ADAPTER_INPUT_LIMIT_EXCEEDED"):
        runtime.plan(oversized, context)

    assert not runtime.plans.exists()


def test_plan_rejects_excessive_request_depth_as_protocol_error(
    runtime_bundle,
) -> None:
    runtime, signed_request, context, _, request_key = runtime_bundle
    nested: dict = {"value": "bounded"}
    for _ in range(80):
        nested = {"nested": nested}
    too_deep = copy.deepcopy(signed_request)
    too_deep["payload"] = nested
    too_deep = sign_document(too_deep, request_key)

    with pytest.raises(ProtocolError, match="ADAPTER_INPUT_DEPTH_EXCEEDED"):
        runtime.plan(too_deep, context)

    assert not runtime.plans.exists()


def test_runtime_rejects_symlinked_ancestor_without_writing_target(
    tmp_path: Path, runtime_bundle
) -> None:
    runtime, _, _, _, _ = runtime_bundle
    outside = tmp_path / "outside"
    outside.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(outside, target_is_directory=True)
    target = linked / "runtime"

    with pytest.raises(ProtocolError, match="ADAPTER_RUNTIME_ROOT_BOUNDARY"):
        AdapterRuntime(
            target,
            runtime.registry,
            runtime.trusted_request_keys,
            runtime.trusted_approver_keys,
            runtime.signing_key,
            trusted_approver_identities=runtime.trusted_approver_identities,
        )

    assert not (outside / "runtime").exists()


def test_runtime_state_is_private_under_permissive_umask(
    tmp_path: Path, runtime_bundle
) -> None:
    runtime, signed_request, context, _, _ = runtime_bundle
    previous_umask = os.umask(0o022)
    try:
        plan = runtime.plan(signed_request, context)
    finally:
        os.umask(previous_umask)

    assert stat.S_IMODE(runtime.root.stat().st_mode) == 0o700
    assert stat.S_IMODE(runtime.plans.stat().st_mode) == 0o700
    assert stat.S_IMODE(
        (runtime.plans / f"{plan['plan_id']}.json").stat().st_mode
    ) == 0o600
