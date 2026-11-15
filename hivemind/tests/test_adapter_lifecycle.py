from __future__ import annotations

import copy
import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import hive_protocol.adapters.lifecycle as lifecycle_module
from hive_protocol.adapters.lifecycle import AdapterLifecycle
from hive_protocol.adapters.models import AdapterApproval, AdapterRequest, AdapterResult
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


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class LifecycleAdapter:
    def __init__(self) -> None:
        self.export_calls = 0
        self.rollback_calls: list[str] = []
        self.mutate_unrelated = False
        self.uninstall_calls = 0
        self.export_delay_seconds = 0.0
        self.export_detail: dict = {"portable": True}
        self.lifecycle_results: dict[tuple[str, str], dict] = {}
        self.raise_after_rollback_marker = False

    def health(self) -> dict:
        return {"status": "HEALTHY", "evidence": []}

    def plan(self, payload: dict) -> dict:
        return {
            "side_effects": ["adapter:owned-paths"],
            "network_destinations": [],
            "requires_approval": payload.get("operation") != "export",
            "payload": copy.deepcopy(payload),
        }

    def apply(self, payload: dict, *, operation_key: str) -> dict:
        raise AssertionError("lifecycle tests must not call apply")

    def recover(self, operation_key: str) -> dict | None:
        return None

    def export(self, scope: dict, *, operation_key: str) -> dict:
        existing = self.lifecycle_results.get(("export", operation_key))
        if existing is not None:
            return copy.deepcopy(existing)
        self.export_calls += 1
        if self.export_delay_seconds:
            time.sleep(self.export_delay_seconds)
        root = Path(scope["root"])
        root.mkdir(parents=True, exist_ok=True)
        bundle = root / "bundle.bin"
        bundle.write_bytes(b"portable export\x00bytes")
        result = {
            "outcome": "APPLIED",
            "files": [bundle.name],
            "side_effects": ["adapter:owned-paths"],
            "resource_use": {"writes": 1},
            "rollback_ref": None,
            "detail": copy.deepcopy(self.export_detail),
        }
        self.lifecycle_results[("export", operation_key)] = copy.deepcopy(result)
        return result

    def rollback(self, rollback_ref: str, *, operation_key: str) -> dict:
        existing = self.lifecycle_results.get(("rollback", operation_key))
        if existing is not None:
            return copy.deepcopy(existing)
        self.rollback_calls.append(rollback_ref)
        result = {
            "outcome": "APPLIED",
            "evidence_refs": [],
            "side_effects": ["adapter:owned-paths"],
            "resource_use": {"writes": 1},
            "rollback_ref": None,
            "detail": {"restored": rollback_ref},
        }
        self.lifecycle_results[("rollback", operation_key)] = copy.deepcopy(result)
        if self.raise_after_rollback_marker:
            raise RuntimeError("failure after durable rollback marker")
        return result

    def recover_lifecycle(self, operation: str, operation_key: str) -> dict | None:
        result = self.lifecycle_results.get((operation, operation_key))
        return copy.deepcopy(result) if result is not None else None

    def uninstall(self, ownership_manifest: Path) -> dict:
        self.uninstall_calls += 1
        document = json.loads(ownership_manifest.read_text(encoding="utf-8"))
        root = Path(document["root"])
        if self.mutate_unrelated:
            (root / "keep.txt").write_text("tampered", encoding="utf-8")
        removed: list[str] = []
        for entry in sorted(
            document["paths"],
            key=lambda item: len(Path(item["path"]).parts),
            reverse=True,
        ):
            path = root / entry["path"]
            if entry["kind"] == "file":
                path.unlink()
            else:
                path.rmdir()
            removed.append(entry["path"])
        return {
            "outcome": "APPLIED",
            "evidence_refs": [],
            "side_effects": ["adapter:owned-paths"],
            "resource_use": {"removed": len(removed)},
            "rollback_ref": None,
            "detail": {"removed": removed},
        }


@pytest.fixture
def lifecycle_bundle(tmp_path: Path):
    repository = Path(__file__).parents[1]
    manifest = json.loads(
        (
            repository
            / "tests/fixtures/adapters/sample-heartbeat.manifest.json"
        ).read_text(encoding="utf-8")
    )
    manifest["adapter_id"] = "nukotech.hive.test"
    manifest["name"] = "Lifecycle Test"
    manifest["version"] = "1.0.0"
    manifest["capability_ids"] = [
        "lifecycle.export",
        "lifecycle.rollback",
        "lifecycle.uninstall",
    ]
    manifest["required_permissions"] = ["filesystem.write.adapter-state"]
    manifest["accepted_data_classifications"] = ["PROJECT_PRIVATE"]
    manifest["network_destinations"] = []
    manifest["credential_references"] = []
    adapter = LifecycleAdapter()
    runtime_root = tmp_path / "runtime"
    registry = AdapterRegistry(
        runtime_root,
        runtime_root / "policy",
        os_name="linux",
        architecture="aarch64",
        runtime="python>=3.11",
    )
    registry.register(adapter, manifest)
    request_key = Ed25519PrivateKey.generate()
    approver_key = Ed25519PrivateKey.generate()
    runtime_key = Ed25519PrivateKey.generate()
    runtime = AdapterRuntime(
        runtime_root,
        registry,
        {public_key_id(request_key.public_key()): request_key.public_key()},
        {public_key_id(approver_key.public_key()): approver_key.public_key()},
        runtime_key,
        trusted_approver_identities={
            public_key_id(approver_key.public_key()): IDENTITY
        },
    )
    context = InvocationContext(
        project_id="HiveMind",
        authorization_ref="grant:hivemind:lifecycle",
        identity=dict(IDENTITY),
        granted_capabilities=frozenset(
            {"lifecycle.export", "lifecycle.rollback", "lifecycle.uninstall"}
        ),
        granted_permissions=frozenset({"filesystem.write.adapter-state"}),
        allowed_data_classifications=frozenset({"PROJECT_PRIVATE"}),
        allowed_network_destinations=frozenset(),
        available_credential_references=frozenset(),
    )
    return (
        AdapterLifecycle(runtime),
        runtime,
        context,
        request_key,
        approver_key,
        adapter,
    )


@pytest.fixture
def ownership_manifest(tmp_path: Path) -> dict:
    owned_file = tmp_path / "owned.txt"
    owned_file.write_text("adapter-owned", encoding="utf-8")
    return {
        "schema_version": "hive.adapter-ownership-manifest.v1",
        "installation_id": "installation-001",
        "adapter_id": "nukotech.hive.test",
        "adapter_version": "1.0.0",
        "root": str(tmp_path.resolve()),
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "paths": [
            {
                "path": "owned.txt",
                "kind": "file",
                "sha256": _sha256(owned_file),
            }
        ],
    }


@pytest.fixture
def approved_uninstall(lifecycle_bundle, ownership_manifest):
    _, runtime, context, request_key, approver_key, _ = lifecycle_bundle
    request = AdapterRequest(
        request_id="uninstall-request-001",
        adapter_id="nukotech.hive.test",
        adapter_version="1.0.0",
        sender=dict(IDENTITY),
        project_id="HiveMind",
        capability_id="lifecycle.uninstall",
        data_classification="PROJECT_PRIVATE",
        authorization_ref="grant:hivemind:lifecycle",
        evidence_sha256=[document_digest(ownership_manifest)],
        payload={
            "operation": "uninstall",
            "installation_id": ownership_manifest["installation_id"],
            "ownership_manifest_digest": document_digest(ownership_manifest),
        },
        nonce="uninstall-request-nonce-001",
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5))
        .isoformat()
        .replace("+00:00", "Z"),
    )
    plan = runtime.plan(sign_document(request.as_dict(), request_key), context)
    approval = sign_document(
        AdapterApproval(
            approval_id="uninstall-approval-001",
            plan_digest=document_digest(plan),
            approver=dict(IDENTITY),
            decision="APPROVED",
            expires_at=plan["expires_at"],
            nonce="uninstall-approval-nonce-001",
        ).as_dict(),
        approver_key,
    )
    return plan, approval


def test_uninstall_preserves_unrelated_files(
    tmp_path: Path,
    lifecycle_bundle,
    ownership_manifest,
    approved_uninstall,
) -> None:
    lifecycle, _, _, _, _, _ = lifecycle_bundle
    unrelated = tmp_path / "keep.txt"
    unrelated.write_text("preserve", encoding="utf-8")
    plan, approval = approved_uninstall
    receipt = lifecycle.uninstall(
        "nukotech.hive.test", ownership_manifest, plan, approval
    )
    assert receipt["outcome"] == "APPLIED"
    assert unrelated.read_text(encoding="utf-8") == "preserve"
    assert lifecycle_bundle[-1].uninstall_calls == 0


def test_uninstall_refuses_altered_owned_file_before_any_mutation(
    tmp_path: Path,
    lifecycle_bundle,
    ownership_manifest,
    approved_uninstall,
) -> None:
    lifecycle, _, _, _, _, adapter = lifecycle_bundle
    owned = tmp_path / "owned.txt"
    owned.write_text("altered", encoding="utf-8")
    keep = tmp_path / "keep.txt"
    keep.write_text("preserve", encoding="utf-8")
    plan, approval = approved_uninstall

    with pytest.raises(ProtocolError, match="ADAPTER_OWNERSHIP_BOUNDARY"):
        lifecycle.uninstall("nukotech.hive.test", ownership_manifest, plan, approval)

    assert adapter.uninstall_calls == 0
    assert owned.read_text(encoding="utf-8") == "altered"
    assert keep.read_text(encoding="utf-8") == "preserve"


def test_lifecycle_refuses_symlink_and_tampered_manifest(
    tmp_path: Path,
    lifecycle_bundle,
    ownership_manifest,
    approved_uninstall,
) -> None:
    lifecycle, _, _, _, _, _ = lifecycle_bundle
    target = tmp_path / "outside"
    target.mkdir()
    link = tmp_path / "owned-link"
    link.symlink_to(target, target_is_directory=True)
    ownership_manifest["paths"].append(
        {"path": "owned-link", "kind": "directory", "sha256": "0" * 64}
    )
    plan, approval = approved_uninstall
    with pytest.raises(ProtocolError, match="ADAPTER_OWNERSHIP_BOUNDARY"):
        lifecycle.uninstall("nukotech.hive.test", ownership_manifest, plan, approval)


def _plan_and_approval(
    lifecycle_bundle,
    *,
    capability_id: str,
    payload: dict,
    request_id: str,
) -> tuple[dict, dict | None]:
    _, runtime, context, request_key, approver_key, _ = lifecycle_bundle
    request = AdapterRequest(
        request_id=request_id,
        adapter_id="nukotech.hive.test",
        adapter_version="1.0.0",
        sender=dict(IDENTITY),
        project_id="HiveMind",
        capability_id=capability_id,
        data_classification="PROJECT_PRIVATE",
        authorization_ref="grant:hivemind:lifecycle",
        evidence_sha256=[document_digest(payload)],
        payload=copy.deepcopy(payload),
        nonce=f"{request_id}-nonce-value",
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5))
        .isoformat()
        .replace("+00:00", "Z"),
    )
    plan = runtime.plan(sign_document(request.as_dict(), request_key), context)
    if not plan["requires_approval"]:
        return plan, None
    approval = sign_document(
        AdapterApproval(
            approval_id=f"{request_id}-approval",
            plan_digest=document_digest(plan),
            approver=dict(IDENTITY),
            decision="APPROVED",
            expires_at=plan["expires_at"],
            nonce=f"{request_id}-approval-nonce",
        ).as_dict(),
        approver_key,
    )
    return plan, approval


def _signed_applied_result(runtime: AdapterRuntime, *, project_id: str = "HiveMind") -> dict:
    return sign_document(
        AdapterResult(
            result_id="prior-result-001",
            request_digest="a" * 64,
            plan_digest="b" * 64,
            adapter_id="nukotech.hive.test",
            adapter_version="1.0.0",
            project_id=project_id,
            outcome="APPLIED",
            evidence_refs=[],
            side_effects=["adapter:owned-paths"],
            resource_use={"writes": 1},
            rollback_ref="checkpoint-001",
            detail={},
        ).as_dict(),
        runtime.signing_key,
    )


def test_export_binds_file_hashes_in_signed_result(
    tmp_path: Path, lifecycle_bundle
) -> None:
    lifecycle, runtime, _, _, _, _ = lifecycle_bundle
    export_root = tmp_path / "exports"
    export_root.mkdir()
    scope = {"root": str(export_root.resolve())}
    plan, approval = _plan_and_approval(
        lifecycle_bundle,
        capability_id="lifecycle.export",
        payload={"operation": "export", "scope": scope},
        request_id="export-request-001",
    )
    assert approval is None
    result = lifecycle.export("nukotech.hive.test", scope, plan)
    exported = Path(scope["root"]) / "bundle.bin"
    assert result["outcome"] == "APPLIED"
    assert result["evidence_refs"] == [
        {
            "path": "bundle.bin",
            "sha256": _sha256(exported),
            "size_bytes": exported.stat().st_size,
        }
    ]
    verify_document(result, {runtime.key_id: runtime.signing_key.public_key()})


def test_lifecycle_creates_and_attended_approves_stored_plan(
    tmp_path: Path, lifecycle_bundle, ownership_manifest
) -> None:
    lifecycle, runtime, _, _, approver_key, _ = lifecycle_bundle
    plan = lifecycle.plan(
        "nukotech.hive.test",
        "uninstall",
        ownership_manifest,
        "HiveMind",
    )
    approval = lifecycle.approve(plan, IDENTITY, approver_key)

    assert plan["capability_id"] == "lifecycle.uninstall"
    assert plan["requires_approval"] is True
    assert approval["plan_digest"] == document_digest(plan)
    assert (runtime.plans / f"{plan['plan_id']}.json").is_file()
    assert (lifecycle.root / "approvals" / f"{approval['approval_id']}.json").is_file()


def test_lifecycle_approver_key_cannot_claim_another_bound_identity(
    lifecycle_bundle, ownership_manifest
) -> None:
    lifecycle, runtime, _, _, _, _ = lifecycle_bundle
    other_key = Ed25519PrivateKey.generate()
    other_key_id = public_key_id(other_key.public_key())
    runtime.trusted_approver_keys[other_key_id] = other_key.public_key()
    runtime.trusted_approver_identities[other_key_id] = {
        **IDENTITY,
        "persona_id": "OtherPersona",
        "surface_id": "OtherSurface",
    }
    plan = lifecycle.plan(
        "nukotech.hive.test", "uninstall", ownership_manifest, "HiveMind"
    )

    with pytest.raises(ProtocolError, match="ADAPTER_APPROVER_IDENTITY_MISMATCH"):
        lifecycle.approve(plan, IDENTITY, other_key)


def test_lifecycle_journal_is_runtime_signed(
    tmp_path: Path, lifecycle_bundle
) -> None:
    lifecycle, runtime, _, _, _, _ = lifecycle_bundle
    export_root = tmp_path / "signed-journal-export"
    export_root.mkdir()
    scope = {"root": str(export_root.resolve())}
    plan = lifecycle.plan("nukotech.hive.test", "export", scope, "HiveMind")

    lifecycle.export("nukotech.hive.test", scope, plan)

    journal = json.loads(
        (lifecycle.journals / f"{plan['plan_id']}.json").read_text(
            encoding="utf-8"
        )
    )
    assert journal["signature"]["key_id"] == runtime.key_id


def test_export_refuses_symlink_root_before_calling_adapter(
    tmp_path: Path, lifecycle_bundle
) -> None:
    lifecycle, _, _, _, _, adapter = lifecycle_bundle
    outside = tmp_path / "outside"
    outside.mkdir()
    linked = tmp_path / "linked-export"
    linked.symlink_to(outside, target_is_directory=True)
    scope = {"root": str(linked)}
    plan, _ = _plan_and_approval(
        lifecycle_bundle,
        capability_id="lifecycle.export",
        payload={"operation": "export", "scope": scope},
        request_id="export-request-symlink",
    )
    with pytest.raises(ProtocolError, match="ADAPTER_EXPORT_BOUNDARY"):
        lifecycle.export("nukotech.hive.test", scope, plan)
    assert adapter.export_calls == 0
    assert not (outside / "bundle.bin").exists()


def test_rollback_requires_exact_result_project_and_approval(lifecycle_bundle) -> None:
    lifecycle, runtime, _, _, _, adapter = lifecycle_bundle
    prior = _signed_applied_result(runtime)
    payload = {
        "operation": "rollback",
        "result_digest": document_digest(prior),
        "rollback_ref": prior["rollback_ref"],
    }
    plan, approval = _plan_and_approval(
        lifecycle_bundle,
        capability_id="lifecycle.rollback",
        payload=payload,
        request_id="rollback-request-001",
    )
    assert approval is not None
    result = lifecycle.rollback(prior, plan, approval)
    assert result["outcome"] == "APPLIED"
    assert adapter.rollback_calls == ["checkpoint-001"]

    with pytest.raises(ProtocolError, match="REPLAY_MESSAGE_ID|REPLAY_NONCE"):
        lifecycle.rollback(prior, plan, approval)

    crossed = _signed_applied_result(runtime, project_id="OtherProject")
    with pytest.raises(ProtocolError, match="ADAPTER_LIFECYCLE_PLAN_MISMATCH"):
        lifecycle.rollback(crossed, plan, approval)


def test_lifecycle_exception_after_effect_adopts_authenticated_recovery(
    lifecycle_bundle,
) -> None:
    lifecycle, runtime, _, _, _, adapter = lifecycle_bundle
    prior = _signed_applied_result(runtime)
    payload = {
        "operation": "rollback",
        "result_digest": document_digest(prior),
        "rollback_ref": prior["rollback_ref"],
    }
    plan, approval = _plan_and_approval(
        lifecycle_bundle,
        capability_id="lifecycle.rollback",
        payload=payload,
        request_id="rollback-request-recover-marker",
    )
    assert approval is not None
    adapter.raise_after_rollback_marker = True

    result = lifecycle.rollback(prior, plan, approval)

    assert result["outcome"] == "APPLIED"
    assert result["side_effects"] == ["adapter:owned-paths"]
    assert adapter.rollback_calls == ["checkpoint-001"]


def test_lifecycle_recovers_export_result_without_duplicate_effect(
    tmp_path: Path, lifecycle_bundle, monkeypatch
) -> None:
    lifecycle, _, _, _, _, adapter = lifecycle_bundle
    export_root = tmp_path / "recover-export"
    export_root.mkdir()
    scope = {"root": str(export_root.resolve())}
    plan = lifecycle.plan("nukotech.hive.test", "export", scope, "HiveMind")
    write_result = lifecycle._write_result

    def crash_before_lifecycle_result(*args, **kwargs):
        raise SystemExit("process crash before lifecycle result")

    monkeypatch.setattr(lifecycle, "_write_result", crash_before_lifecycle_result)
    with pytest.raises(SystemExit, match="process crash before lifecycle result"):
        lifecycle.export("nukotech.hive.test", scope, plan)

    monkeypatch.setattr(lifecycle, "_write_result", write_result)
    recovered = lifecycle.recover_pending()

    assert [result["outcome"] for result in recovered] == ["APPLIED"]
    assert adapter.export_calls == 1
    assert lifecycle.recover_pending() == []


def test_lifecycle_prepared_journal_recovery_applies_once(
    tmp_path: Path, lifecycle_bundle, monkeypatch
) -> None:
    lifecycle, _, _, _, _, adapter = lifecycle_bundle
    export_root = tmp_path / "recover-prepared-export"
    export_root.mkdir()
    scope = {"root": str(export_root.resolve())}
    plan = lifecycle.plan("nukotech.hive.test", "export", scope, "HiveMind")
    replay_begin = lifecycle.replay.begin

    def crash_before_claim(*args, **kwargs):
        raise SystemExit("process crash before lifecycle replay claim")

    monkeypatch.setattr(lifecycle.replay, "begin", crash_before_claim)
    with pytest.raises(SystemExit, match="before lifecycle replay claim"):
        lifecycle.export("nukotech.hive.test", scope, plan)
    assert adapter.export_calls == 0

    monkeypatch.setattr(lifecycle.replay, "begin", replay_begin)
    recovered = lifecycle.recover_pending()

    assert [result["outcome"] for result in recovered] == ["APPLIED"]
    assert adapter.export_calls == 1
    assert lifecycle.recover_pending() == []


def test_lifecycle_prepared_journal_with_pending_claim_recovery_applies_once(
    tmp_path: Path, lifecycle_bundle, monkeypatch
) -> None:
    lifecycle, _, _, _, _, adapter = lifecycle_bundle
    export_root = tmp_path / "recover-prepared-pending-claim-export"
    export_root.mkdir()
    scope = {"root": str(export_root.resolve())}
    plan = lifecycle.plan("nukotech.hive.test", "export", scope, "HiveMind")
    write_journal = lifecycle._write_journal

    def crash_before_claimed_journal(path, journal):
        if journal["state"] == "CLAIMED":
            raise SystemExit("process crash before claimed lifecycle journal")
        write_journal(path, journal)

    monkeypatch.setattr(lifecycle, "_write_journal", crash_before_claimed_journal)
    with pytest.raises(SystemExit, match="before claimed lifecycle journal"):
        lifecycle.export("nukotech.hive.test", scope, plan)
    assert adapter.export_calls == 0

    monkeypatch.setattr(lifecycle, "_write_journal", write_journal)
    recovered = lifecycle.recover_pending()

    assert [result["outcome"] for result in recovered] == ["APPLIED"]
    assert adapter.export_calls == 1
    assert lifecycle.recover_pending() == []


def test_lifecycle_recovers_after_durable_result_write_without_duplicate_effect(
    tmp_path: Path, lifecycle_bundle, monkeypatch
) -> None:
    lifecycle, _, _, _, _, adapter = lifecycle_bundle
    export_root = tmp_path / "recover-after-result"
    export_root.mkdir()
    scope = {"root": str(export_root.resolve())}
    plan = lifecycle.plan("nukotech.hive.test", "export", scope, "HiveMind")
    write_result = lifecycle._write_result

    def crash_after_lifecycle_result(*args, **kwargs):
        write_result(*args, **kwargs)
        raise SystemExit("process crash after lifecycle result")

    monkeypatch.setattr(lifecycle, "_write_result", crash_after_lifecycle_result)
    with pytest.raises(SystemExit, match="process crash after lifecycle result"):
        lifecycle.export("nukotech.hive.test", scope, plan)

    monkeypatch.setattr(lifecycle, "_write_result", write_result)
    recovered = lifecycle.recover_pending()

    assert [result["outcome"] for result in recovered] == ["APPLIED"]
    assert adapter.export_calls == 1
    assert lifecycle.recover_pending() == []


def test_lifecycle_timeout_keeps_unknown_effect_state_pending(
    tmp_path: Path, lifecycle_bundle
) -> None:
    lifecycle, _, _, _, _, adapter = lifecycle_bundle
    export_root = tmp_path / "timeout-export"
    export_root.mkdir()
    scope = {"root": str(export_root.resolve())}
    plan = lifecycle.plan("nukotech.hive.test", "export", scope, "HiveMind")
    entry = lifecycle.registry.require_current("nukotech.hive.test")
    entry.manifest.resource_limits["timeout_seconds"] = 1
    adapter.export_delay_seconds = 2

    with pytest.raises(ProtocolError, match="ADAPTER_EFFECT_STATE_PENDING"):
        lifecycle.export("nukotech.hive.test", scope, plan)

    assert adapter.export_calls == 1


def test_lifecycle_unknown_effect_is_never_reissued(
    tmp_path: Path, lifecycle_bundle, monkeypatch
) -> None:
    lifecycle, _, _, _, _, adapter = lifecycle_bundle
    export_root = tmp_path / "ambiguous-export"
    export_root.mkdir()
    scope = {"root": str(export_root.resolve())}
    plan = lifecycle.plan("nukotech.hive.test", "export", scope, "HiveMind")
    calls = 0

    def ambiguous_export(scope, *, operation_key):
        nonlocal calls
        calls += 1
        (Path(scope["root"]) / f"effect-{calls}.txt").write_text(
            "effect state is unknown", encoding="utf-8"
        )
        raise RuntimeError("failure after an unrecorded effect")

    monkeypatch.setattr(adapter, "export", ambiguous_export)

    with pytest.raises(ProtocolError, match="ADAPTER_EFFECT_STATE_PENDING"):
        lifecycle.export("nukotech.hive.test", scope, plan)
    assert calls == 1

    with pytest.raises(ProtocolError, match="ADAPTER_EFFECT_STATE_PENDING"):
        lifecycle.recover_pending()
    assert calls == 1


def test_lifecycle_plan_rejects_excessive_scope_depth(
    tmp_path: Path, lifecycle_bundle
) -> None:
    lifecycle, _, _, _, _, _ = lifecycle_bundle
    export_root = tmp_path / "deep-plan-export"
    export_root.mkdir()
    nested: dict = {"value": "bounded"}
    for _ in range(1200):
        nested = {"nested": nested}
    scope = {"root": str(export_root.resolve()), "nested": nested}

    with pytest.raises(ProtocolError, match="ADAPTER_INPUT_DEPTH_EXCEEDED"):
        lifecycle.plan("nukotech.hive.test", "export", scope, "HiveMind")


def test_lifecycle_execution_rejects_excessive_scope_depth(
    tmp_path: Path, lifecycle_bundle
) -> None:
    lifecycle, _, _, _, _, _ = lifecycle_bundle
    export_root = tmp_path / "deep-execution-export"
    export_root.mkdir()
    scope = {"root": str(export_root.resolve())}
    plan = lifecycle.plan("nukotech.hive.test", "export", scope, "HiveMind")
    nested: dict = {"value": "bounded"}
    for _ in range(1200):
        nested = {"nested": nested}
    deep_scope = {"root": str(export_root.resolve()), "nested": nested}

    with pytest.raises(ProtocolError, match="ADAPTER_INPUT_DEPTH_EXCEEDED"):
        lifecycle.export("nukotech.hive.test", deep_scope, plan)


def test_lifecycle_plan_bounds_oversized_scope_before_recursive_validation(
    tmp_path: Path, lifecycle_bundle, monkeypatch
) -> None:
    lifecycle, _, _, _, _, _ = lifecycle_bundle
    entry = lifecycle.registry.require_current("nukotech.hive.test")
    entry.manifest.resource_limits["max_input_bytes"] = 1024
    export_root = tmp_path / "oversized-plan-export"
    export_root.mkdir()
    original = lifecycle_module.reject_credential_values

    def guarded_rejection(value, *, location):
        if location == "lifecycle planning input":
            pytest.fail("recursive validation ran before the lifecycle size bound")
        return original(value, location=location)

    monkeypatch.setattr(lifecycle_module, "reject_credential_values", guarded_rejection)
    scope = {"root": str(export_root.resolve()), "padding": "x" * 4096}

    with pytest.raises(ProtocolError, match="ADAPTER_INPUT_LIMIT_EXCEEDED"):
        lifecycle.plan("nukotech.hive.test", "export", scope, "HiveMind")


def test_lifecycle_execution_bounds_oversized_scope_before_recursive_validation(
    tmp_path: Path, lifecycle_bundle, monkeypatch
) -> None:
    lifecycle, _, _, _, _, _ = lifecycle_bundle
    export_root = tmp_path / "oversized-execution-export"
    export_root.mkdir()
    scope = {"root": str(export_root.resolve())}
    plan = lifecycle.plan("nukotech.hive.test", "export", scope, "HiveMind")
    lifecycle.registry.require_current("nukotech.hive.test").manifest.resource_limits[
        "max_input_bytes"
    ] = 1024
    original = lifecycle_module.reject_credential_values

    def guarded_rejection(value, *, location, **options):
        if location == "lifecycle execution input":
            pytest.fail("recursive validation ran before the lifecycle size bound")
        return original(value, location=location, **options)

    monkeypatch.setattr(lifecycle_module, "reject_credential_values", guarded_rejection)
    oversized_scope = {"root": str(export_root.resolve()), "padding": "x" * 4096}

    with pytest.raises(ProtocolError, match="ADAPTER_INPUT_LIMIT_EXCEEDED"):
        lifecycle.export("nukotech.hive.test", oversized_scope, plan)


def test_lifecycle_output_limit_keeps_effect_state_pending(
    tmp_path: Path, lifecycle_bundle
) -> None:
    lifecycle, _, _, _, _, adapter = lifecycle_bundle
    export_root = tmp_path / "large-export"
    export_root.mkdir()
    scope = {"root": str(export_root.resolve())}
    plan = lifecycle.plan("nukotech.hive.test", "export", scope, "HiveMind")
    lifecycle.registry.require_current("nukotech.hive.test").manifest.resource_limits[
        "max_output_bytes"
    ] = 2048
    adapter.export_detail = {"padding": "x" * 4096}

    with pytest.raises(ProtocolError, match="ADAPTER_EFFECT_STATE_PENDING"):
        lifecycle.export("nukotech.hive.test", scope, plan)


def test_lifecycle_rejects_adapter_secret_without_persisting_it(
    tmp_path: Path, lifecycle_bundle
) -> None:
    lifecycle, runtime, _, _, _, adapter = lifecycle_bundle
    export_root = tmp_path / "secret-export"
    export_root.mkdir()
    scope = {"root": str(export_root.resolve())}
    plan = lifecycle.plan("nukotech.hive.test", "export", scope, "HiveMind")
    secret = "sk" + "-lifecycle-must-not-persist"
    adapter.export_detail = {"api_key": secret}

    with pytest.raises(ProtocolError, match="ADAPTER_EFFECT_STATE_PENDING"):
        lifecycle.export("nukotech.hive.test", scope, plan)
    persisted = b"\n".join(
        path.read_bytes() for path in runtime.root.rglob("*") if path.is_file()
    )
    assert secret.encode("utf-8") not in persisted


def test_lifecycle_recovery_refuses_tampered_journal_metadata(
    tmp_path: Path, lifecycle_bundle, monkeypatch
) -> None:
    lifecycle, _, _, _, _, _ = lifecycle_bundle
    export_root = tmp_path / "tampered-journal-export"
    export_root.mkdir()
    scope = {"root": str(export_root.resolve())}
    plan = lifecycle.plan("nukotech.hive.test", "export", scope, "HiveMind")

    def crash_before_result(*args, **kwargs):
        raise SystemExit("process crash before result")

    monkeypatch.setattr(lifecycle, "_write_result", crash_before_result)
    with pytest.raises(SystemExit, match="process crash before result"):
        lifecycle.export("nukotech.hive.test", scope, plan)

    journal_path = lifecycle.journals / f"{plan['plan_id']}.json"
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    journal["result_id"] = "attacker-selected-result"
    journal_path.write_text(json.dumps(journal), encoding="utf-8")
    monkeypatch.undo()

    with pytest.raises(ProtocolError, match="ADAPTER_LIFECYCLE_RECOVERY_MISMATCH"):
        lifecycle.recover_pending()


def test_lifecycle_resumes_orchestrator_uninstall_after_process_crash(
    tmp_path: Path,
    lifecycle_bundle,
    ownership_manifest,
    approved_uninstall,
    monkeypatch,
) -> None:
    lifecycle, _, _, _, _, adapter = lifecycle_bundle
    keep = tmp_path / "keep-after-crash.txt"
    keep.write_text("preserve", encoding="utf-8")
    plan, approval = approved_uninstall
    atomic_write_json = lifecycle_module.atomic_write_json
    crashed = False

    def crash_after_owned_file_removed(path, document, mode=0o644) -> None:
        nonlocal crashed
        removals = document.get("removals") if isinstance(document, dict) else None
        removed = bool(removals and removals[0].get("state") == "REMOVED")
        if document.get("state") == "CLAIMED" and removed and not crashed:
            crashed = True
            raise SystemExit("process crash during orchestrator uninstall")
        atomic_write_json(path, document, mode=mode)

    monkeypatch.setattr(lifecycle_module, "atomic_write_json", crash_after_owned_file_removed)
    with pytest.raises(SystemExit, match="process crash during orchestrator uninstall"):
        lifecycle.uninstall("nukotech.hive.test", ownership_manifest, plan, approval)

    assert not (tmp_path / "owned.txt").exists()
    monkeypatch.setattr(lifecycle_module, "atomic_write_json", atomic_write_json)
    recovered = lifecycle.recover_pending()

    assert [result["outcome"] for result in recovered] == ["APPLIED"]
    assert adapter.uninstall_calls == 0
    assert keep.read_text(encoding="utf-8") == "preserve"
    assert lifecycle.recover_pending() == []


def test_uninstall_rejects_changed_approval_and_never_calls_adapter(
    tmp_path: Path,
    lifecycle_bundle,
    ownership_manifest,
    approved_uninstall,
) -> None:
    lifecycle, _, _, _, approver_key, adapter = lifecycle_bundle
    plan, approval = approved_uninstall
    changed = copy.deepcopy(approval)
    changed["plan_digest"] = "f" * 64
    changed = sign_document(changed, approver_key)
    with pytest.raises(ProtocolError, match="APPROVAL_PLAN_MISMATCH"):
        lifecycle.uninstall("nukotech.hive.test", ownership_manifest, plan, changed)

    keep = tmp_path / "keep.txt"
    keep.write_text("preserve", encoding="utf-8")
    adapter.mutate_unrelated = True
    result = lifecycle.uninstall(
        "nukotech.hive.test", ownership_manifest, plan, approval
    )
    assert result["outcome"] == "APPLIED"
    assert adapter.uninstall_calls == 0
    assert keep.read_text(encoding="utf-8") == "preserve"


@pytest.mark.parametrize("unsafe_path", ["../outside", "/tmp/outside", "owned.txt/../x"])
def test_ownership_manifest_rejects_noncanonical_paths(
    lifecycle_bundle,
    ownership_manifest,
    approved_uninstall,
    unsafe_path: str,
) -> None:
    lifecycle, _, _, _, _, _ = lifecycle_bundle
    ownership_manifest["paths"][0]["path"] = unsafe_path
    plan, approval = approved_uninstall
    with pytest.raises(ProtocolError, match="ADAPTER_OWNERSHIP_BOUNDARY"):
        lifecycle.uninstall("nukotech.hive.test", ownership_manifest, plan, approval)
