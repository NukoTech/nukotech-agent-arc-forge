from __future__ import annotations

import copy
import json
import multiprocessing
import stat
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import hive_protocol.adapters.runtime as runtime_module
from hive_protocol.adapters.models import AdapterApproval, AdapterRequest
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
from hive_protocol.storage import atomic_write_json, read_json


IDENTITY = {
    "persona_id": "Director",
    "surface_id": "LeadA",
    "machine_id": "hive-lab-host",
    "project_id": "HiveMind",
    "app_actor": "hive-builda-app",
}


class MutatingAdapter:
    def __init__(self) -> None:
        self.raise_on_apply = False
        self.apply_calls = 0
        self.operation_results: dict[str, dict] = {}
        self.sleep_seconds = 0.0
        self.detail_text = ""

    def health(self) -> dict:
        return {"status": "HEALTHY", "evidence": []}

    def plan(self, payload: dict) -> dict:
        return {
            "side_effects": ["workspace:receipt"],
            "network_destinations": [],
            "requires_approval": True,
            "payload": copy.deepcopy(payload),
        }

    def apply(self, payload: dict, *, operation_key: str) -> dict:
        self.apply_calls += 1
        if operation_key in self.operation_results:
            return copy.deepcopy(self.operation_results[operation_key])
        if self.sleep_seconds:
            time.sleep(self.sleep_seconds)
        if self.raise_on_apply:
            raise RuntimeError("injected adapter failure")
        result = {
            "outcome": "APPLIED",
            "evidence_refs": [],
            "side_effects": ["workspace:receipt"],
            "resource_use": {"writes": 1},
            "rollback_ref": None,
            "detail": {"text": self.detail_text or payload["text"]},
        }
        self.operation_results[operation_key] = copy.deepcopy(result)
        return result

    def recover(self, operation_key: str) -> dict | None:
        result = self.operation_results.get(operation_key)
        return copy.deepcopy(result) if result is not None else None

    def export(self, scope: dict, *, operation_key: str) -> dict:
        return {"outcome": "NO_OP"}

    def rollback(self, rollback_ref: str, *, operation_key: str) -> dict:
        return {"outcome": "NO_OP"}

    def recover_lifecycle(self, operation: str, operation_key: str) -> dict | None:
        return None


class CrashRecoveringAdapter(MutatingAdapter):
    def __init__(self, owned_root: Path) -> None:
        super().__init__()
        self.owned_root = owned_root
        self.output_path = owned_root / "output.txt"
        self.marker_path = owned_root / "idempotency.json"
        self.apply_count_path = owned_root / "apply-count.txt"
        self.raise_after_marker = True

    def plan(self, payload: dict) -> dict:
        return {
            "side_effects": ["owned:output"],
            "network_destinations": [],
            "requires_approval": True,
            "payload": copy.deepcopy(payload),
        }

    def apply(self, payload: dict, *, operation_key: str) -> dict:
        self.owned_root.mkdir(parents=True, exist_ok=True)
        calls = (
            int(self.apply_count_path.read_text(encoding="utf-8"))
            if self.apply_count_path.exists()
            else 0
        )
        self.apply_count_path.write_text(str(calls + 1), encoding="utf-8")
        if self.marker_path.exists():
            marker = json.loads(self.marker_path.read_text(encoding="utf-8"))
            if marker["operation_key"] != operation_key:
                raise AssertionError("operation key crossed the adapter marker")
            return marker["result"]
        if self.output_path.exists():
            raise AssertionError("recovery duplicated the owned output")
        self.output_path.write_text(payload["text"], encoding="utf-8")
        applied = {
            "outcome": "APPLIED",
            "evidence_refs": [],
            "side_effects": ["owned:output"],
            "resource_use": {"writes": 1},
            "rollback_ref": None,
            "detail": {"idempotency_marker": self.marker_path.name},
        }
        atomic_write_json(
            self.marker_path,
            {"operation_key": operation_key, "result": applied},
        )
        if self.raise_after_marker:
            raise RuntimeError("failure after owned output")
        return applied

    def recover(self, operation_key: str) -> dict | None:
        if not self.marker_path.exists():
            return None
        marker = read_json(self.marker_path)
        if marker.get("operation_key") != operation_key:
            raise ProtocolError(
                "ADAPTER_OPERATION_KEY_MISMATCH",
                "adapter marker belongs to another operation",
            )
        return copy.deepcopy(marker["result"])


def _build_runtime_bundle(
    tmp_path: Path,
    adapter: MutatingAdapter,
    *,
    request_id: str = "invoke-request-001",
):
    root = Path(__file__).parents[1]
    manifest = json.loads(
        (
            root
            / "tests/fixtures/adapters/sample-heartbeat.manifest.json"
        ).read_text(encoding="utf-8")
    )
    manifest["adapter_id"] = "nukotech.hive.invoke-test"
    manifest["name"] = "Invoke Test"
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
    registry.register(adapter, manifest)
    request_key = Ed25519PrivateKey.generate()
    approver_key = Ed25519PrivateKey.generate()
    runtime_key = Ed25519PrivateKey.generate()
    runtime = AdapterRuntime(
        tmp_path,
        registry,
        {public_key_id(request_key.public_key()): request_key.public_key()},
        {public_key_id(approver_key.public_key()): approver_key.public_key()},
        runtime_key,
        trusted_approver_identities={
            public_key_id(approver_key.public_key()): IDENTITY
        },
    )
    request = AdapterRequest(
        request_id=request_id,
        adapter_id="nukotech.hive.invoke-test",
        adapter_version="1.0.0",
        sender=dict(IDENTITY),
        project_id="HiveMind",
        capability_id="capture.text",
        data_classification="PROJECT_PRIVATE",
        authorization_ref="grant:hivemind:capture",
        evidence_sha256=["a" * 64],
        payload={"text": "approved mutation"},
        nonce="invoke-nonce-0001",
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
    return runtime, signed_request, context, approver_key


@pytest.fixture
def runtime_bundle(tmp_path: Path):
    return _build_runtime_bundle(tmp_path, MutatingAdapter())


@pytest.fixture
def crash_runtime_bundle(tmp_path: Path):
    adapter = CrashRecoveringAdapter(tmp_path / "adapter-owned")
    return (*_build_runtime_bundle(
        tmp_path,
        adapter,
        request_id="crash-request-001",
    ), adapter)


def _approval(plan: dict, context: InvocationContext, approver_key) -> dict:
    return sign_document(
        AdapterApproval(
            approval_id="approval-001",
            plan_digest=document_digest(plan),
            approver=dict(context.identity),
            decision="APPROVED",
            expires_at=plan["expires_at"],
            nonce="approval-nonce-001",
        ).as_dict(),
        approver_key,
    )


def _invoke_worker(runtime, request, plan, context, approval, outcomes) -> None:
    try:
        outcomes.put(runtime.invoke(request, plan, context, approval)["outcome"])
    except ProtocolError as exc:
        outcomes.put(exc.code)
    except Exception as exc:  # pragma: no cover - diagnostic if process setup fails
        outcomes.put(f"{type(exc).__name__}:{exc}")


def test_invoke_requires_exact_approval_for_mutating_plan(runtime_bundle) -> None:
    runtime, signed_request, context, approver_key = runtime_bundle
    plan = runtime.plan(signed_request, context)
    with pytest.raises(ProtocolError, match="ADAPTER_APPROVAL_REQUIRED"):
        runtime.invoke(signed_request, plan, context, approval_document=None)
    approval = _approval(plan, context, approver_key)
    result = runtime.invoke(signed_request, plan, context, approval_document=approval)
    assert result["outcome"] == "APPLIED"
    with pytest.raises(ProtocolError, match="REPLAY_MESSAGE_ID"):
        runtime.invoke(signed_request, plan, context, approval_document=approval)


def test_approval_cannot_authorize_changed_plan(runtime_bundle) -> None:
    runtime, signed_request, context, approver_key = runtime_bundle
    plan = runtime.plan(signed_request, context)
    approval = _approval(plan, context, approver_key)
    plan["side_effects"] = ["different:path"]
    with pytest.raises(ProtocolError, match="SIGNATURE_INVALID|APPROVAL_PLAN_MISMATCH"):
        runtime.invoke(signed_request, plan, context, approval_document=approval)


def test_validly_signed_approval_must_bind_exact_plan(runtime_bundle) -> None:
    runtime, signed_request, context, approver_key = runtime_bundle
    plan = runtime.plan(signed_request, context)
    wrong_approval = sign_document(
        AdapterApproval(
            approval_id="approval-wrong-plan",
            plan_digest="0" * 64,
            approver=dict(context.identity),
            decision="APPROVED",
            expires_at=plan["expires_at"],
            nonce="approval-wrong-plan-nonce",
        ).as_dict(),
        approver_key,
    )
    with pytest.raises(ProtocolError, match="APPROVAL_PLAN_MISMATCH"):
        runtime.invoke(
            signed_request,
            plan,
            context,
            approval_document=wrong_approval,
        )


def test_trusted_approval_key_cannot_claim_another_bound_identity(
    runtime_bundle,
) -> None:
    runtime, signed_request, context, _ = runtime_bundle
    other_key = Ed25519PrivateKey.generate()
    other_key_id = public_key_id(other_key.public_key())
    runtime.trusted_approver_keys[other_key_id] = other_key.public_key()
    runtime.trusted_approver_identities = {
        other_key_id: {
            **dict(context.identity),
            "persona_id": "OtherPersona",
            "surface_id": "OtherSurface",
        }
    }
    plan = runtime.plan(signed_request, context)
    forged_identity = sign_document(
        AdapterApproval(
            approval_id="approval-cross-identity",
            plan_digest=document_digest(plan),
            approver=dict(context.identity),
            decision="APPROVED",
            expires_at=plan["expires_at"],
            nonce="approval-cross-identity-nonce",
        ).as_dict(),
        other_key,
    )

    with pytest.raises(ProtocolError, match="ADAPTER_APPROVER_IDENTITY_MISMATCH"):
        runtime.invoke(
            signed_request,
            plan,
            context,
            approval_document=forged_identity,
        )


def test_expired_plan_is_refused_before_replay_claim(
    tmp_path: Path, runtime_bundle
) -> None:
    runtime, signed_request, context, _ = runtime_bundle
    plan = runtime.plan(signed_request, context)
    plan["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1))
    plan["expires_at"] = plan["expires_at"].isoformat().replace("+00:00", "Z")
    expired_plan = sign_document(plan, runtime.signing_key)
    atomic_write_json(
        tmp_path / "plans" / f"{expired_plan['plan_id']}.json", expired_plan
    )
    with pytest.raises(ProtocolError, match="ADAPTER_PLAN_EXPIRED"):
        runtime.invoke(
            signed_request,
            expired_plan,
            context,
            approval_document=None,
        )
    assert not (tmp_path / "replay.json").exists()


def test_expired_approval_is_refused_before_replay_claim(
    tmp_path: Path, runtime_bundle
) -> None:
    runtime, signed_request, context, approver_key = runtime_bundle
    plan = runtime.plan(signed_request, context)
    expired_approval = sign_document(
        AdapterApproval(
            approval_id="approval-expired",
            plan_digest=document_digest(plan),
            approver=dict(context.identity),
            decision="APPROVED",
            expires_at=(datetime.now(timezone.utc) - timedelta(seconds=1))
            .isoformat()
            .replace("+00:00", "Z"),
            nonce="approval-expired-nonce",
        ).as_dict(),
        approver_key,
    )
    with pytest.raises(ProtocolError, match="ADAPTER_APPROVAL_EXPIRED"):
        runtime.invoke(
            signed_request,
            plan,
            context,
            approval_document=expired_approval,
        )
    assert not (tmp_path / "replay.json").exists()


def test_invoke_refuses_plan_that_differs_from_durable_copy(
    tmp_path: Path, runtime_bundle
) -> None:
    runtime, signed_request, context, approver_key = runtime_bundle
    plan = runtime.plan(signed_request, context)
    stored_plan = copy.deepcopy(plan)
    stored_plan["payload"]["text"] = "different durable bytes"
    atomic_write_json(tmp_path / "plans" / f"{plan['plan_id']}.json", stored_plan)
    with pytest.raises(ProtocolError, match="ADAPTER_STORED_PLAN_MISMATCH"):
        runtime.invoke(
            signed_request,
            plan,
            context,
            approval_document=_approval(plan, context, approver_key),
        )
    assert not (tmp_path / "replay.json").exists()


def test_success_result_is_durable_before_claim_and_journal_complete(
    tmp_path: Path, runtime_bundle
) -> None:
    runtime, signed_request, context, approver_key = runtime_bundle
    plan = runtime.plan(signed_request, context)
    approval = _approval(plan, context, approver_key)
    result = runtime.invoke(
        signed_request,
        plan,
        context,
        approval_document=approval,
    )
    verify_document(result, {runtime.key_id: runtime.signing_key.public_key()})
    assert read_json(tmp_path / "results" / f"{result['result_id']}.json") == result
    replay = read_json(tmp_path / "replay.json")
    assert replay["messages"][signed_request["request_id"]]["state"] == "COMPLETE"
    journal = read_json(
        tmp_path / "recovery" / f"{signed_request['request_id']}.json"
    )
    assert journal["state"] == "TERMINAL"
    assert journal["result_id"] == result["result_id"]
    assert journal["approval"] == approval
    assert journal["operation_key"]
    assert journal["signature"]["key_id"] == runtime.key_id
    for directory in (runtime.root, runtime.plans, runtime.recovery, runtime.results):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    for private_file in (
        runtime.plans / f"{plan['plan_id']}.json",
        runtime.recovery / f"{signed_request['request_id']}.json",
        runtime.results / f"{result['result_id']}.json",
        runtime.replay.ledger_path,
    ):
        assert stat.S_IMODE(private_file.stat().st_mode) == 0o600


def test_invalid_apply_side_effect_keeps_effect_state_pending(runtime_bundle) -> None:
    runtime, signed_request, context, approver_key = runtime_bundle
    adapter = runtime.registry.require(
        signed_request["adapter_id"], signed_request["adapter_version"]
    ).adapter
    adapter.apply = lambda payload, *, operation_key: {
        "outcome": "APPLIED",
        "evidence_refs": [],
        "side_effects": ["outside:plan"],
        "resource_use": {},
        "rollback_ref": None,
        "detail": {},
    }
    plan = runtime.plan(signed_request, context)
    with pytest.raises(ProtocolError, match="ADAPTER_EFFECT_STATE_PENDING"):
        runtime.invoke(
            signed_request,
            plan,
            context,
            approval_document=_approval(plan, context, approver_key),
        )


def test_invalid_apply_outcome_keeps_effect_state_pending(runtime_bundle) -> None:
    runtime, signed_request, context, approver_key = runtime_bundle
    adapter = runtime.registry.require(
        signed_request["adapter_id"], signed_request["adapter_version"]
    ).adapter
    adapter.apply = lambda payload, *, operation_key: {
        "outcome": "SUCCESS",
        "evidence_refs": [],
        "side_effects": [],
        "resource_use": {},
        "rollback_ref": None,
        "detail": {},
    }
    plan = runtime.plan(signed_request, context)
    with pytest.raises(ProtocolError, match="ADAPTER_EFFECT_STATE_PENDING"):
        runtime.invoke(
            signed_request,
            plan,
            context,
            approval_document=_approval(plan, context, approver_key),
        )


def test_apply_exception_without_recoverable_effect_keeps_claim_pending(
    tmp_path: Path, runtime_bundle
) -> None:
    runtime, signed_request, context, approver_key = runtime_bundle
    adapter = runtime.registry.require(
        signed_request["adapter_id"], signed_request["adapter_version"]
    ).adapter
    adapter.raise_on_apply = True
    plan = runtime.plan(signed_request, context)
    with pytest.raises(ProtocolError, match="ADAPTER_EFFECT_STATE_PENDING"):
        runtime.invoke(
            signed_request,
            plan,
            context,
            approval_document=_approval(plan, context, approver_key),
        )
    assert not list(runtime.results.glob("*.json"))
    replay = read_json(tmp_path / "replay.json")
    assert replay["messages"][signed_request["request_id"]]["state"] == "PENDING"
    journal = read_json(
        tmp_path / "recovery" / f"{signed_request['request_id']}.json"
    )
    assert journal["state"] == "CLAIMED"
    assert journal["result_id"] is None
    assert adapter.apply_calls == 1


def test_exception_after_durable_effect_adopts_adapter_recovery(
    tmp_path: Path, crash_runtime_bundle
) -> None:
    runtime, signed_request, context, approver_key, adapter = crash_runtime_bundle
    plan = runtime.plan(signed_request, context)

    result = runtime.invoke(
        signed_request,
        plan,
        context,
        approval_document=_approval(plan, context, approver_key),
    )

    assert result["outcome"] == "APPLIED"
    assert result["side_effects"] == ["owned:output"]
    assert adapter.output_path.read_text(encoding="utf-8") == "approved mutation"
    assert adapter.apply_count_path.read_text(encoding="utf-8") == "1"
    assert read_json(
        tmp_path / "recovery" / f"{signed_request['request_id']}.json"
    )["state"] == "TERMINAL"


def test_two_processes_apply_once_and_refuse_replay(runtime_bundle) -> None:
    runtime, signed_request, context, approver_key = runtime_bundle
    plan = runtime.plan(signed_request, context)
    approval = _approval(plan, context, approver_key)
    process_context = multiprocessing.get_context("fork")
    outcomes = process_context.Queue()
    processes = [
        process_context.Process(
            target=_invoke_worker,
            args=(runtime, signed_request, plan, context, approval, outcomes),
        )
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=10)
        assert process.exitcode == 0
    assert sorted(outcomes.get(timeout=2) for _ in processes) == [
        "APPLIED",
        "REPLAY_MESSAGE_ID",
    ]


def test_recover_pending_adopts_adapter_result_without_reapplying(
    tmp_path: Path, crash_runtime_bundle, monkeypatch
) -> None:
    runtime, signed_request, context, approver_key, adapter = crash_runtime_bundle
    adapter.raise_after_marker = False
    plan = runtime.plan(signed_request, context)
    write_result = runtime._write_result

    def crash_after_adapter_result(*args, **kwargs):
        raise RuntimeError("process crash before runtime result")

    monkeypatch.setattr(runtime, "_write_result", crash_after_adapter_result)
    with pytest.raises(ProtocolError, match="ADAPTER_EFFECT_STATE_PENDING"):
        runtime.invoke(
            signed_request,
            plan,
            context,
            approval_document=_approval(plan, context, approver_key),
        )
    assert adapter.output_path.read_text(encoding="utf-8") == "approved mutation"
    monkeypatch.setattr(runtime, "_write_result", write_result)
    recovered = runtime.recover_pending()
    assert [result["outcome"] for result in recovered] == ["APPLIED"]
    assert adapter.output_path.read_text(encoding="utf-8") == "approved mutation"
    assert adapter.apply_count_path.read_text(encoding="utf-8") == "1"
    assert runtime.recover_pending() == []
    journal = read_json(
        tmp_path / "recovery" / f"{signed_request['request_id']}.json"
    )
    assert journal["state"] == "TERMINAL"
    replay = read_json(tmp_path / "replay.json")
    assert replay["messages"][signed_request["request_id"]]["state"] == "COMPLETE"


def test_recovery_resumes_from_durable_prepared_journal_after_claim_crash(
    tmp_path: Path, crash_runtime_bundle, monkeypatch
) -> None:
    runtime, signed_request, context, approver_key, adapter = crash_runtime_bundle
    adapter.raise_after_marker = False
    plan = runtime.plan(signed_request, context)
    approval = _approval(plan, context, approver_key)
    begin = runtime.replay.begin

    def crash_after_claim(message_id: str, nonce: str) -> str:
        outcome = begin(message_id, nonce)
        raise SystemExit(f"process crash after {outcome} claim")

    monkeypatch.setattr(runtime.replay, "begin", crash_after_claim)
    with pytest.raises(SystemExit, match="process crash after NEW claim"):
        runtime.invoke(signed_request, plan, context, approval_document=approval)

    monkeypatch.setattr(runtime.replay, "begin", begin)
    recovered = runtime.recover_pending()
    assert [result["outcome"] for result in recovered] == ["APPLIED"]
    assert adapter.output_path.read_text(encoding="utf-8") == "approved mutation"
    assert adapter.apply_count_path.read_text(encoding="utf-8") == "1"
    journal = read_json(
        tmp_path / "recovery" / f"{signed_request['request_id']}.json"
    )
    assert journal["state"] == "TERMINAL"


def test_oversized_terminal_contribution_remains_pending(runtime_bundle) -> None:
    runtime, signed_request, context, approver_key = runtime_bundle
    entry = runtime.registry.require(
        signed_request["adapter_id"], signed_request["adapter_version"]
    )
    entry.manifest.resource_limits["max_output_bytes"] = 4096
    entry.adapter.detail_text = "x" * 10000
    plan = runtime.plan(signed_request, context)

    with pytest.raises(ProtocolError, match="ADAPTER_EFFECT_STATE_PENDING"):
        runtime.invoke(
            signed_request,
            plan,
            context,
            approval_document=_approval(plan, context, approver_key),
        )
    assert not list(runtime.results.glob("*.json"))


def test_manifest_timeout_keeps_unknown_effect_state_pending(runtime_bundle) -> None:
    runtime, signed_request, context, approver_key = runtime_bundle
    entry = runtime.registry.require(
        signed_request["adapter_id"], signed_request["adapter_version"]
    )
    entry.manifest.resource_limits["timeout_seconds"] = 1
    entry.adapter.sleep_seconds = 2
    plan = runtime.plan(signed_request, context)
    started = time.monotonic()

    with pytest.raises(ProtocolError, match="ADAPTER_EFFECT_STATE_PENDING"):
        runtime.invoke(
            signed_request,
            plan,
            context,
            approval_document=_approval(plan, context, approver_key),
        )
    assert time.monotonic() - started < 1.8


def test_credential_value_in_adapter_result_is_not_persisted(runtime_bundle) -> None:
    runtime, signed_request, context, approver_key = runtime_bundle
    entry = runtime.registry.require(
        signed_request["adapter_id"], signed_request["adapter_version"]
    )
    entry.adapter.detail_text = "Authorization: Bearer abcdefghijklmnop"
    plan = runtime.plan(signed_request, context)

    with pytest.raises(ProtocolError, match="ADAPTER_EFFECT_STATE_PENDING"):
        runtime.invoke(
            signed_request,
            plan,
            context,
            approval_document=_approval(plan, context, approver_key),
        )
    persisted = b"\n".join(
        path.read_bytes() for path in runtime.root.rglob("*") if path.is_file()
    )
    assert b"abcdefghijklmnop" not in persisted


def test_recover_pending_refuses_changed_journal(
    tmp_path: Path, crash_runtime_bundle
) -> None:
    runtime, signed_request, context, approver_key, adapter = crash_runtime_bundle
    plan = runtime.plan(signed_request, context)
    failed = runtime.invoke(
        signed_request,
        plan,
        context,
        approval_document=_approval(plan, context, approver_key),
    )
    assert failed["outcome"] == "APPLIED"
    journal_path = tmp_path / "recovery" / f"{signed_request['request_id']}.json"
    journal = read_json(journal_path)
    journal["plan"]["payload"]["text"] = "changed after claim"
    atomic_write_json(journal_path, journal)
    with pytest.raises(ProtocolError, match="ADAPTER_RECOVERY_MISMATCH"):
        runtime.recover_pending()
    assert adapter.apply_count_path.read_text(encoding="utf-8") == "1"


def test_recover_pending_does_not_trust_changed_complete_state(
    tmp_path: Path, crash_runtime_bundle
) -> None:
    runtime, signed_request, context, approver_key, adapter = crash_runtime_bundle
    plan = runtime.plan(signed_request, context)
    failed = runtime.invoke(
        signed_request,
        plan,
        context,
        approval_document=_approval(plan, context, approver_key),
    )
    assert failed["outcome"] == "APPLIED"
    journal_path = tmp_path / "recovery" / f"{signed_request['request_id']}.json"
    journal = read_json(journal_path)
    journal["state"] = "COMPLETE"
    atomic_write_json(journal_path, journal)
    with pytest.raises(ProtocolError, match="ADAPTER_RECOVERY_MISMATCH"):
        runtime.recover_pending()
    assert adapter.apply_count_path.read_text(encoding="utf-8") == "1"


def test_recovery_adopts_durable_result_after_completion_crash(
    tmp_path: Path, runtime_bundle, monkeypatch
) -> None:
    runtime, signed_request, context, approver_key = runtime_bundle
    adapter = runtime.registry.require(
        signed_request["adapter_id"], signed_request["adapter_version"]
    ).adapter
    plan = runtime.plan(signed_request, context)
    complete = runtime.replay.complete

    def crash_before_replay_completion(message_id: str, nonce: str) -> None:
        raise RuntimeError("crash after durable result")

    monkeypatch.setattr(runtime.replay, "complete", crash_before_replay_completion)
    with pytest.raises(RuntimeError, match="crash after durable result"):
        runtime.invoke(
            signed_request,
            plan,
            context,
            approval_document=_approval(plan, context, approver_key),
        )
    stored_results = sorted((tmp_path / "results").glob("*.json"))
    assert len(stored_results) == 1
    durable_result = read_json(stored_results[0])
    assert durable_result["outcome"] == "APPLIED"

    monkeypatch.setattr(runtime.replay, "complete", complete)
    adapter.raise_on_apply = True
    assert runtime.recover_pending() == [durable_result]
    assert sorted((tmp_path / "results").glob("*.json")) == stored_results
    journal = read_json(
        tmp_path / "recovery" / f"{signed_request['request_id']}.json"
    )
    assert journal["state"] == "TERMINAL"
    assert journal["result_id"] == durable_result["result_id"]


def test_recovery_adopts_durable_result_when_journal_missed_result_id(
    tmp_path: Path, runtime_bundle, monkeypatch
) -> None:
    runtime, signed_request, context, approver_key = runtime_bundle
    adapter = runtime.registry.require(
        signed_request["adapter_id"], signed_request["adapter_version"]
    ).adapter
    plan = runtime.plan(signed_request, context)
    atomic_write = runtime_module.atomic_write_json

    def crash_before_result_journal(
        path: Path, document: dict, mode: int = 0o644
    ) -> None:
        if path.parent == runtime.recovery and document.get("state") == "RESULT_WRITTEN":
            raise RuntimeError("crash before result ID reached journal")
        atomic_write(path, document, mode=mode)

    monkeypatch.setattr(runtime_module, "atomic_write_json", crash_before_result_journal)
    with pytest.raises(RuntimeError, match="crash before result ID reached journal"):
        runtime.invoke(
            signed_request,
            plan,
            context,
            approval_document=_approval(plan, context, approver_key),
        )
    stored_results = sorted((tmp_path / "results").glob("*.json"))
    assert len(stored_results) == 1
    durable_result = read_json(stored_results[0])
    journal_path = tmp_path / "recovery" / f"{signed_request['request_id']}.json"
    assert read_json(journal_path)["result_id"] is None

    monkeypatch.setattr(runtime_module, "atomic_write_json", atomic_write)
    adapter.raise_on_apply = True
    assert runtime.recover_pending() == [durable_result]
    assert sorted((tmp_path / "results").glob("*.json")) == stored_results
    journal = read_json(journal_path)
    assert journal["state"] == "TERMINAL"
    assert journal["result_id"] == durable_result["result_id"]


def test_recovery_finishes_journal_when_replay_is_already_complete(
    tmp_path: Path, runtime_bundle, monkeypatch
) -> None:
    runtime, signed_request, context, approver_key = runtime_bundle
    adapter = runtime.registry.require(
        signed_request["adapter_id"], signed_request["adapter_version"]
    ).adapter
    plan = runtime.plan(signed_request, context)
    atomic_write = runtime_module.atomic_write_json

    def crash_on_complete_journal(path: Path, document: dict, mode: int = 0o644) -> None:
        if path.parent == runtime.recovery and document.get("state") == "TERMINAL":
            raise RuntimeError("crash after replay completion")
        atomic_write(path, document, mode=mode)

    monkeypatch.setattr(runtime_module, "atomic_write_json", crash_on_complete_journal)
    with pytest.raises(RuntimeError, match="crash after replay completion"):
        runtime.invoke(
            signed_request,
            plan,
            context,
            approval_document=_approval(plan, context, approver_key),
        )
    replay = read_json(tmp_path / "replay.json")
    assert replay["messages"][signed_request["request_id"]]["state"] == "COMPLETE"
    journal_path = tmp_path / "recovery" / f"{signed_request['request_id']}.json"
    claimed_journal = read_json(journal_path)
    assert claimed_journal["state"] == "RESULT_WRITTEN"
    assert isinstance(claimed_journal["result_id"], str)
    durable_result = read_json(
        tmp_path / "results" / f"{claimed_journal['result_id']}.json"
    )

    monkeypatch.setattr(runtime_module, "atomic_write_json", atomic_write)
    adapter.raise_on_apply = True
    assert runtime.recover_pending() == [durable_result]
    assert read_json(journal_path)["state"] == "TERMINAL"
