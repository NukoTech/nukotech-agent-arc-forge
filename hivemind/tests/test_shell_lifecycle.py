from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
from pathlib import Path
from uuid import uuid4

import pytest

from hive_protocol.core import document_digest
from hive_protocol.product.agent_adapter import (
    adapter_invocation_context,
    product_adapter_services,
)
from hive_protocol.product.api import OperatorAPI
from hive_protocol.product.shell_contracts import OperatorRequest, route_for
from hive_protocol.product.shell_service import ShellService
from hive_protocol.product.workspace import HiveWorkspace
from hive_protocol.storage import read_json
from hive_protocol.storage import atomic_write_json


NOW = datetime(2026, 9, 1, 18, 0, tzinfo=timezone.utc)
SESSION_DIGEST = "f" * 64


def _request(
    action: str,
    input_document: dict,
    *,
    expected_version: str,
    key: str,
) -> dict:
    return {
        "schema_version": "hive.operator-request.v1",
        "request_id": str(uuid4()),
        "tenant_id": "local-user",
        "project_id": "HiveMind",
        "action": action,
        "expected_version": expected_version,
        "idempotency_key": key,
        "input": input_document,
    }


def _dispatch(api: OperatorAPI, path: str, request: dict):
    return api.dispatch_mutation(
        "POST",
        path,
        request,
        session_digest=SESSION_DIGEST,
        idempotency_key=request["idempotency_key"],
        expected_version=request["expected_version"],
    )


def _document(result) -> dict:
    return result.response.as_dict()


def _current_version(
    service: ShellService, path: str, request_document: dict
) -> str:
    return service.current_version(
        route_for("POST", path), OperatorRequest.from_dict(request_document)
    )


def _shell(tmp_path: Path, *, fault_hook=None):
    workspace = HiveWorkspace.create(tmp_path / "hive")
    service = ShellService(
        workspace,
        tenant_id="local-user",
        project_ids={"HiveMind"},
        now=NOW,
        settings_lifecycle_fault_hook=fault_hook,
    )
    api = OperatorAPI(
        workspace.root,
        service,
        tenant_id="local-user",
        project_ids={"HiveMind"},
    )
    return workspace, service, api


def _portable_bytes(workspace: HiveWorkspace) -> dict[str, bytes]:
    roots = (
        workspace.sources,
        workspace.assets,
        workspace.staging,
        workspace.research,
        workspace.prime,
        workspace.workflows,
        workspace.provenance,
    )
    return {
        path.relative_to(workspace.root).as_posix(): path.read_bytes()
        for root in roots
        if root.exists()
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


def test_provider_preview_and_apply_are_exact_replay_safe_and_never_probe(
    tmp_path: Path, monkeypatch
) -> None:
    workspace, _, api = _shell(tmp_path)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("provider configuration attempted hidden execution")

    monkeypatch.setattr("urllib.request.urlopen", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("subprocess.run", forbidden)
    monkeypatch.setattr("threading.Thread.start", forbidden)

    config_before = read_json(workspace.config_path)
    version_before = document_digest(config_before)
    preview_request = _request(
        "settings.provider.preview",
        {"mode": "retrieval-only", "model": None},
        expected_version=version_before,
        key="provider-preview",
    )
    preview_result = _dispatch(
        api, "/api/v1/settings/provider/preview", preview_request
    )
    assert preview_result.status == 200, _document(preview_result)
    preview_response = _document(preview_result)
    preview = preview_response["data"]["preview"]
    assert preview_response["changed"] is True
    assert preview["before_sha256"] == version_before
    assert preview["proposed_provider"] == {
        "mode": "retrieval-only",
        "model": None,
    }
    assert preview["availability_state"] == "RETRIEVAL_ONLY"
    assert preview["provider_attempted"] is False
    assert preview["execution_started"] is False
    assert read_json(workspace.config_path) == config_before

    apply_request = _request(
        "settings.provider.apply",
        {"preview": preview},
        expected_version=document_digest(preview),
        key="provider-apply-exact",
    )
    applied_result = _dispatch(
        api, "/api/v1/settings/provider/apply", apply_request
    )
    assert applied_result.status == 200, _document(applied_result)
    applied = _document(applied_result)
    assert applied["changed"] is True
    assert applied["data"]["provider"] == {
        "mode": "retrieval-only",
        "model": None,
        "availability_state": "RETRIEVAL_ONLY",
        "provider_attempted": False,
    }
    assert applied["data"]["execution_started"] is False
    assert read_json(workspace.config_path)["provider"] == {
        "mode": "retrieval-only",
        "model": None,
    }

    replay = _dispatch(api, "/api/v1/settings/provider/apply", apply_request)
    assert replay.status == 200
    assert _document(replay)["changed"] is False


def test_settings_projection_reports_provider_as_not_probed_without_network(
    tmp_path: Path, monkeypatch
) -> None:
    _, service, _ = _shell(tmp_path)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("settings projection attempted provider discovery")

    monkeypatch.setattr("urllib.request.urlopen", forbidden)
    response = service.read(
        route_for("GET", "/api/v1/settings"),
        tenant_id="local-user",
        project_id="HiveMind",
        query={},
    )
    provider = response["data"]["provider"]
    assert provider["configured_mode"] == "auto"
    assert provider["availability_state"] == "UNAVAILABLE_NOT_PROBED"
    assert provider["provider_attempted"] is False
    assert provider["states"] == {
        "authorized": False,
        "configured": True,
        "installed": False,
        "running": False,
        "verified": False,
        "working": False,
    }


def test_adapter_plan_and_invoke_use_exact_signed_runtime_documents(
    tmp_path: Path,
) -> None:
    workspace, _, api = _shell(tmp_path)
    text = "Signed adapter execution stays inside the existing authority boundary."
    plan_request = _request(
        "settings.adapters.plan",
        {
            "adapter_id": "nukotech.hive.local-capture",
            "capability_id": "capture.text",
            "payload": {"kind": "text", "text": text, "title": "Exact plan"},
            "evidence_sha256": [hashlib.sha256(text.encode("utf-8")).hexdigest()],
        },
        expected_version="ABSENT",
        key="adapter-plan-exact",
    )
    planned_result = _dispatch(
        api, "/api/v1/settings/adapters/plan", plan_request
    )
    assert planned_result.status == 200, _document(planned_result)
    planned = _document(planned_result)
    request_document = planned["data"]["request"]
    plan_document = planned["data"]["plan"]
    assert planned["data"]["execution_started"] is False
    assert request_document["schema_version"] == "hive.adapter-request.v1"
    assert plan_document["schema_version"] == "hive.adapter-plan.v1"
    assert plan_document["request_digest"] == document_digest(request_document)
    assert plan_document["network_destinations"] == []
    assert planned["object_version"] == document_digest(plan_document)

    invoke_request = _request(
        "settings.adapters.invoke",
        {
            "request": request_document,
            "plan": plan_document,
            "approval": None,
        },
        expected_version=document_digest(plan_document),
        key="adapter-invoke-exact",
    )
    invoked_result = _dispatch(
        api, "/api/v1/settings/adapters/invoke", invoke_request
    )
    assert invoked_result.status == 200, _document(invoked_result)
    invoked = _document(invoked_result)
    adapter_result = invoked["data"]["result"]
    assert invoked["changed"] is True
    assert invoked["data"]["execution_started"] is True
    assert adapter_result["schema_version"] == "hive.adapter-result.v1"
    assert adapter_result["request_digest"] == document_digest(request_document)
    assert adapter_result["plan_digest"] == document_digest(plan_document)
    assert adapter_result["outcome"] == "APPLIED"
    assert len(list(workspace.sources.rglob("*.md"))) == 1

    replay = _dispatch(api, "/api/v1/settings/adapters/invoke", invoke_request)
    assert replay.status == 200
    assert _document(replay)["changed"] is False
    assert len(list(workspace.sources.rglob("*.md"))) == 1


def test_adapter_uninstall_requires_exact_preview_and_approval_and_preserves_hive(
    tmp_path: Path,
) -> None:
    workspace, _, api = _shell(tmp_path)
    for root, name in (
        (workspace.sources, "source-sentinel.md"),
        (workspace.assets, "asset-sentinel.bin"),
        (workspace.staging, "staging-sentinel.txt"),
        (workspace.research, "research-sentinel.txt"),
        (workspace.prime, "prime-sentinel.txt"),
        (workspace.workflows, "workflow-sentinel.txt"),
        (workspace.provenance, "provenance-sentinel.txt"),
    ):
        root.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(f"preserve:{name}".encode("utf-8"))

    install_root = tmp_path / "adapter-install"
    install_root.mkdir()
    owned = install_root / "owned-marker.txt"
    owned.write_text("adapter-owned", encoding="utf-8")
    sentinel = install_root / "keep.txt"
    sentinel.write_text("unrelated", encoding="utf-8")
    ownership = {
        "schema_version": "hive.adapter-ownership-manifest.v1",
        "installation_id": "shell-uninstall-001",
        "adapter_id": "nukotech.hive.bounded-research",
        "adapter_version": "1.0.0",
        "root": str(install_root.resolve()),
        "created_at": NOW.isoformat().replace("+00:00", "Z"),
        "paths": [
            {
                "path": owned.name,
                "kind": "file",
                "sha256": hashlib.sha256(owned.read_bytes()).hexdigest(),
            }
        ],
    }
    preview_request = _request(
        "settings.lifecycle.preview",
        {
            "adapter_id": "nukotech.hive.bounded-research",
            "operation": "uninstall",
            "payload": ownership,
        },
        expected_version="ABSENT",
        key="lifecycle-preview-uninstall",
    )
    preview_result = _dispatch(
        api, "/api/v1/settings/lifecycle/preview", preview_request
    )
    assert preview_result.status == 200, _document(preview_result)
    previewed = _document(preview_result)
    plan = previewed["data"]["plan"]
    assert plan["requires_approval"] is True
    assert previewed["data"]["execution_started"] is False

    approval_request = _request(
        "settings.lifecycle.approve",
        {"plan": plan},
        expected_version=document_digest(plan),
        key="lifecycle-approve-uninstall",
    )
    approval_result = _dispatch(
        api, "/api/v1/settings/lifecycle/approve", approval_request
    )
    assert approval_result.status == 200, _document(approval_result)
    approved = _document(approval_result)
    approval = approved["data"]["approval"]
    assert approval["plan_digest"] == document_digest(plan)
    assert approved["data"]["execution_started"] is False

    forged = copy.deepcopy(approval)
    forged["approver"]["surface_id"] = "forged-surface"
    forged_request = _request(
        "settings.lifecycle.apply",
        {
            "adapter_id": "nukotech.hive.bounded-research",
            "operation": "uninstall",
            "input": ownership,
            "plan": plan,
            "approval": forged,
        },
        expected_version=document_digest(forged),
        key="lifecycle-forged-approval",
    )
    forged_result = _dispatch(
        api, "/api/v1/settings/lifecycle/apply", forged_request
    )
    assert forged_result.status != 200
    assert owned.read_text(encoding="utf-8") == "adapter-owned"
    assert sentinel.read_text(encoding="utf-8") == "unrelated"

    unsafe_ownership = copy.deepcopy(ownership)
    unsafe_ownership["paths"][0]["path"] = "../keep.txt"
    unsafe_request = _request(
        "settings.lifecycle.apply",
        {
            "adapter_id": "nukotech.hive.bounded-research",
            "operation": "uninstall",
            "input": unsafe_ownership,
            "plan": plan,
            "approval": approval,
        },
        expected_version=document_digest(approval),
        key="lifecycle-unsafe-ownership",
    )
    unsafe_result = _dispatch(
        api, "/api/v1/settings/lifecycle/apply", unsafe_request
    )
    assert unsafe_result.status != 200
    assert owned.read_text(encoding="utf-8") == "adapter-owned"
    assert sentinel.read_text(encoding="utf-8") == "unrelated"

    before = _portable_bytes(workspace)
    apply_request = _request(
        "settings.lifecycle.apply",
        {
            "adapter_id": "nukotech.hive.bounded-research",
            "operation": "uninstall",
            "input": ownership,
            "plan": plan,
            "approval": approval,
        },
        expected_version=document_digest(approval),
        key="lifecycle-apply-uninstall",
    )
    applied_result = _dispatch(
        api, "/api/v1/settings/lifecycle/apply", apply_request
    )
    assert applied_result.status == 200, _document(applied_result)
    applied = _document(applied_result)
    assert applied["changed"] is True
    assert applied["data"]["execution_started"] is True
    assert applied["data"]["result"]["outcome"] == "APPLIED"
    assert not owned.exists()
    assert sentinel.read_text(encoding="utf-8") == "unrelated"
    assert _portable_bytes(workspace) == before

    replay = _dispatch(api, "/api/v1/settings/lifecycle/apply", apply_request)
    assert replay.status == 200
    assert _document(replay)["changed"] is False
    assert sentinel.read_text(encoding="utf-8") == "unrelated"
    assert _portable_bytes(workspace) == before


def test_hive_snapshot_and_exact_approved_rollback_restore_checkpoint_once(
    tmp_path: Path,
) -> None:
    workspace, service, api = _shell(tmp_path)
    source = workspace.sources / "checkpoint.md"
    source.write_text("verified checkpoint\n", encoding="utf-8")
    unrelated = workspace.root / "unrelated-tracked.txt"
    unrelated.write_text("unrelated checkpoint bytes\n", encoding="utf-8")
    workspace.ensure_git()
    workspace._git("add", "unrelated-tracked.txt")
    workspace._git("commit", "-m", "track unrelated fixture")

    snapshot_probe = _request(
        "settings.snapshot",
        {"message": "operator exact checkpoint"},
        expected_version="ABSENT",
        key="snapshot-version-probe",
    )
    snapshot_version = _current_version(
        service, "/api/v1/settings/snapshot", snapshot_probe
    )
    snapshot_request = _request(
        "settings.snapshot",
        {"message": "operator exact checkpoint"},
        expected_version=snapshot_version,
        key="snapshot-create-exact",
    )
    snapshot_result = _dispatch(
        api, "/api/v1/settings/snapshot", snapshot_request
    )
    assert snapshot_result.status == 200, _document(snapshot_result)
    snapshotted = _document(snapshot_result)
    checkpoint = snapshotted["data"]["checkpoint"]
    snapshot_receipt = workspace.root / checkpoint["receipt_ref"]
    assert checkpoint["schema_version"] == "hive.operator-hive-checkpoint.v1"
    assert len(checkpoint["commit"]) == 40
    assert checkpoint["portable_manifest_sha256"] == document_digest(
        {
            "schema_version": "hive.operator-portable-manifest.v1",
            "files": checkpoint["portable_manifest"],
        }
    )
    assert snapshotted["data"]["execution_started"] is True

    source.write_text("unsafe drift\n", encoding="utf-8")
    unrelated.write_text("unrelated live bytes must remain\n", encoding="utf-8")
    extra = workspace.sources / "remove-after-checkpoint.md"
    extra.write_text("remove me\n", encoding="utf-8")
    rollback_probe = _request(
        "settings.rollback",
        {
            "checkpoint": checkpoint,
            "approval": {
                "checkpoint_sha256": document_digest(checkpoint),
                "expected_current_version": "0" * 64,
                "confirmation": f"ROLLBACK {checkpoint['commit']}",
            },
        },
        expected_version="ABSENT",
        key="rollback-version-probe",
    )
    current_state = _current_version(
        service, "/api/v1/settings/snapshot", snapshot_probe
    )
    rollback_probe["input"]["approval"]["expected_current_version"] = current_state
    rollback_request = _request(
        "settings.rollback",
        rollback_probe["input"],
        expected_version=current_state,
        key="rollback-apply-exact",
    )
    rollback_result = _dispatch(
        api, "/api/v1/settings/rollback", rollback_request
    )
    assert rollback_result.status == 200, _document(rollback_result)
    rolled_back = _document(rollback_result)
    assert rolled_back["changed"] is True
    assert rolled_back["data"]["target"] == checkpoint["commit"]
    assert rolled_back["data"]["execution_started"] is True
    assert source.read_text(encoding="utf-8") == "verified checkpoint\n"
    assert unrelated.read_text(encoding="utf-8") == "unrelated live bytes must remain\n"
    assert not extra.exists()
    assert snapshot_receipt.is_file() and not snapshot_receipt.is_symlink()
    assert hashlib.sha256(snapshot_receipt.read_bytes()).hexdigest() == checkpoint[
        "receipt_sha256"
    ]

    replay = _dispatch(api, "/api/v1/settings/rollback", rollback_request)
    assert replay.status == 200
    assert _document(replay)["changed"] is False
    assert source.read_text(encoding="utf-8") == "verified checkpoint\n"


def test_hive_rollback_refuses_checkpoint_with_changed_snapshot_receipt(
    tmp_path: Path,
) -> None:
    workspace, service, api = _shell(tmp_path)
    source = workspace.sources / "receipt-bound-checkpoint.md"
    source.write_text("receipt-bound bytes\n", encoding="utf-8")
    probe = _request(
        "settings.snapshot",
        {"message": "receipt-bound checkpoint"},
        expected_version="ABSENT",
        key="receipt-checkpoint-version-probe",
    )
    before = _current_version(service, "/api/v1/settings/snapshot", probe)
    snapshot_request = _request(
        "settings.snapshot",
        {"message": "receipt-bound checkpoint"},
        expected_version=before,
        key="receipt-checkpoint-create",
    )
    checkpoint = _document(
        _dispatch(api, "/api/v1/settings/snapshot", snapshot_request)
    )["data"]["checkpoint"]
    receipt_path = workspace.root / checkpoint["receipt_ref"]
    changed_receipt = read_json(receipt_path)
    changed_receipt["detail"]["message"] = "changed after checkpoint"
    atomic_write_json(receipt_path, changed_receipt)
    source.write_text("must remain after refusal\n", encoding="utf-8")

    current = _current_version(service, "/api/v1/settings/snapshot", probe)
    rollback_request = _request(
        "settings.rollback",
        {
            "checkpoint": checkpoint,
            "approval": {
                "checkpoint_sha256": document_digest(checkpoint),
                "expected_current_version": current,
                "confirmation": f"ROLLBACK {checkpoint['commit']}",
            },
        },
        expected_version=current,
        key="receipt-checkpoint-refusal",
    )
    refused = _dispatch(
        api, "/api/v1/settings/rollback", rollback_request
    )
    assert refused.status != 200
    assert _document(refused)["reason_code"] == "ROLLBACK_CHECKPOINT_INVALID"
    assert source.read_text(encoding="utf-8") == "must remain after refusal\n"


def test_hive_export_and_verified_reopen_bind_bundle_and_manifest_hashes(
    tmp_path: Path,
) -> None:
    workspace, service, api = _shell(tmp_path)
    source = workspace.sources / "portable.md"
    source.write_text("portable verified bytes\n", encoding="utf-8")
    state_probe = _request(
        "settings.snapshot",
        {"message": "state version probe"},
        expected_version="ABSENT",
        key="export-state-version-probe",
    )
    state_version = _current_version(
        service, "/api/v1/settings/snapshot", state_probe
    )
    bundle = tmp_path / "exports" / "hive-portable.tar.gz"
    export_request = _request(
        "settings.export",
        {
            "destination": str(bundle.resolve()),
            "expected_state_version": state_version,
        },
        expected_version=state_version,
        key="hive-export-exact",
    )
    exported_result = _dispatch(api, "/api/v1/settings/export", export_request)
    assert exported_result.status == 200, _document(exported_result)
    exported_response = _document(exported_result)
    exported = exported_response["data"]["export"]
    assert bundle.is_file() and not bundle.is_symlink()
    assert hashlib.sha256(bundle.read_bytes()).hexdigest() == exported["sha256"]
    assert exported["manifest_sha256"] == document_digest(exported["manifest"])
    assert exported["state_version"] == state_version
    assert exported_response["data"]["execution_started"] is True

    target = tmp_path / "reopened-hive"
    reopen_request = _request(
        "settings.reopen",
        {
            "bundle": str(bundle.resolve()),
            "bundle_sha256": exported["sha256"],
            "manifest_sha256": exported["manifest_sha256"],
            "target": str(target.resolve()),
        },
        expected_version="ABSENT",
        key="hive-reopen-verified",
    )
    reopened_result = _dispatch(api, "/api/v1/settings/reopen", reopen_request)
    assert reopened_result.status == 200, _document(reopened_result)
    reopened_response = _document(reopened_result)
    assert reopened_response["changed"] is True
    assert reopened_response["data"]["bundle_sha256"] == exported["sha256"]
    assert reopened_response["data"]["manifest_sha256"] == exported[
        "manifest_sha256"
    ]
    assert reopened_response["data"]["execution_started"] is True
    reopened = HiveWorkspace.open(target)
    assert (reopened.sources / source.name).read_bytes() == source.read_bytes()

    replay = _dispatch(api, "/api/v1/settings/reopen", reopen_request)
    assert replay.status == 200
    assert _document(replay)["changed"] is False
    assert (reopened.sources / source.name).read_bytes() == source.read_bytes()


def test_reopen_recovery_refuses_target_drift_after_verified_extraction(
    tmp_path: Path,
) -> None:
    crashed = False

    def crash(stage: str) -> None:
        nonlocal crashed
        if stage == "settings.reopen:after_workspace_reopen" and not crashed:
            crashed = True
            raise SystemExit("crash after verified reopen")

    workspace, service, api = _shell(tmp_path, fault_hook=crash)
    source = workspace.sources / "reopen-recovery.md"
    source.write_text("verified reopened bytes\n", encoding="utf-8")
    probe = _request(
        "settings.snapshot",
        {"message": "reopen recovery state probe"},
        expected_version="ABSENT",
        key="reopen-recovery-version-probe",
    )
    state_version = _current_version(
        service, "/api/v1/settings/snapshot", probe
    )
    bundle = tmp_path / "reopen-recovery.tar.gz"
    workspace.export(bundle)
    inspected = HiveWorkspace.inspect_export(bundle)
    target = tmp_path / "reopen-recovery-target"
    request = _request(
        "settings.reopen",
        {
            "bundle": str(bundle.resolve()),
            "bundle_sha256": inspected["sha256"],
            "manifest_sha256": inspected["manifest_sha256"],
            "target": str(target.resolve()),
        },
        expected_version="ABSENT",
        key="reopen-target-drift-recovery",
    )
    with pytest.raises(SystemExit, match="crash after verified reopen"):
        _dispatch(api, "/api/v1/settings/reopen", request)
    drifted = target / "sources" / source.name
    drifted.write_text("changed after extraction\n", encoding="utf-8")

    recovered_service = ShellService(
        workspace,
        tenant_id="local-user",
        project_ids={"HiveMind"},
        now=NOW,
    )
    recovered_api = OperatorAPI(
        workspace.root,
        recovered_service,
        tenant_id="local-user",
        project_ids={"HiveMind"},
    )
    refused = _dispatch(recovered_api, "/api/v1/settings/reopen", request)
    assert refused.status != 200
    assert _document(refused)["reason_code"] == "REOPEN_TARGET_MISMATCH"
    assert drifted.read_text(encoding="utf-8") == "changed after extraction\n"


def test_snapshot_recovers_after_commit_before_shell_checkpoint_without_duplicate(
    tmp_path: Path,
) -> None:
    crashed = False

    def crash(stage: str) -> None:
        nonlocal crashed
        if stage == "settings.snapshot:after_workspace_snapshot" and not crashed:
            crashed = True
            raise SystemExit("crash after Git snapshot")

    workspace, service, api = _shell(tmp_path, fault_hook=crash)
    (workspace.sources / "recover.md").write_text(
        "recover exact snapshot\n", encoding="utf-8"
    )
    probe = _request(
        "settings.snapshot",
        {"message": "crash recovery checkpoint"},
        expected_version="ABSENT",
        key="snapshot-crash-version-probe",
    )
    version = _current_version(service, "/api/v1/settings/snapshot", probe)
    request = _request(
        "settings.snapshot",
        {"message": "crash recovery checkpoint"},
        expected_version=version,
        key="snapshot-crash-recovery",
    )
    with pytest.raises(SystemExit, match="crash after Git snapshot"):
        _dispatch(api, "/api/v1/settings/snapshot", request)
    first_commit = workspace._git("rev-parse", "HEAD").stdout.strip()
    first_count = int(workspace._git("rev-list", "--count", "HEAD").stdout)

    recovered_service = ShellService(
        workspace,
        tenant_id="local-user",
        project_ids={"HiveMind"},
        now=NOW,
    )
    recovered_api = OperatorAPI(
        workspace.root,
        recovered_service,
        tenant_id="local-user",
        project_ids={"HiveMind"},
    )
    recovered = _dispatch(
        recovered_api, "/api/v1/settings/snapshot", request
    )
    assert recovered.status == 200, _document(recovered)
    assert _document(recovered)["changed"] is False
    assert _document(recovered)["data"]["checkpoint"]["commit"] == first_commit
    assert int(workspace._git("rev-list", "--count", "HEAD").stdout) == first_count
    assert (
        len(
            list(
                workspace.receipts.glob(
                    "operation-*-*-git-snapshot.json"
                )
            )
        )
        == 1
    )


def test_settings_lifecycle_refuses_stale_secret_and_unsafe_path_inputs(
    tmp_path: Path,
) -> None:
    workspace, service, api = _shell(tmp_path)
    config_before = read_json(workspace.config_path)
    preview_request = _request(
        "settings.provider.preview",
        {"mode": "retrieval-only", "model": None},
        expected_version=document_digest(config_before),
        key="provider-preview-stale-test",
    )
    preview_result = _dispatch(
        api, "/api/v1/settings/provider/preview", preview_request
    )
    preview = _document(preview_result)["data"]["preview"]
    drifted = read_json(workspace.config_path)
    drifted["provider"] = {"mode": "ollama", "model": "local-model:1"}
    drifted["updated_at"] = "2026-09-01T18:01:00Z"
    atomic_write_json(workspace.config_path, drifted)
    stale_request = _request(
        "settings.provider.apply",
        {"preview": preview},
        expected_version=document_digest(preview),
        key="provider-apply-stale-test",
    )
    stale = _dispatch(api, "/api/v1/settings/provider/apply", stale_request)
    assert stale.status != 200
    assert _document(stale)["reason_code"] == "PROVIDER_PREVIEW_STALE"
    assert read_json(workspace.config_path) == drifted

    secret_request = _request(
        "settings.adapters.plan",
        {
            "adapter_id": "nukotech.hive.local-capture",
            "capability_id": "capture.text",
            "payload": {
                "kind": "text",
                "text": "do not persist secrets",
                "title": "Secret refusal",
                "api_key": "example-secret-value-12345",
            },
            "evidence_sha256": ["a" * 64],
        },
        expected_version="ABSENT",
        key="adapter-secret-refusal",
    )
    secret = _dispatch(api, "/api/v1/settings/adapters/plan", secret_request)
    assert secret.status != 200
    assert "CREDENTIAL" in str(_document(secret)["reason_code"])

    state_probe = _request(
        "settings.snapshot",
        {"message": "unsafe export state probe"},
        expected_version="ABSENT",
        key="unsafe-export-version-probe",
    )
    state_version = _current_version(
        service, "/api/v1/settings/snapshot", state_probe
    )
    inside = workspace.root / "forbidden-export.tar.gz"
    inside_request = _request(
        "settings.export",
        {
            "destination": str(inside),
            "expected_state_version": state_version,
        },
        expected_version=state_version,
        key="unsafe-export-inside-hive",
    )
    refused_inside = _dispatch(api, "/api/v1/settings/export", inside_request)
    assert refused_inside.status != 200
    assert not inside.exists()

    existing = tmp_path / "existing-export.tar.gz"
    existing.write_bytes(b"preserve-existing-output")
    existing_request = _request(
        "settings.export",
        {
            "destination": str(existing.resolve()),
            "expected_state_version": state_version,
        },
        expected_version=state_version,
        key="unsafe-export-existing-output",
    )
    refused_existing = _dispatch(
        api, "/api/v1/settings/export", existing_request
    )
    assert refused_existing.status != 200
    assert existing.read_bytes() == b"preserve-existing-output"

    valid_bundle = tmp_path / "valid-for-digest-test.tar.gz"
    workspace.export(valid_bundle)
    inspected = HiveWorkspace.inspect_export(valid_bundle)
    target = tmp_path / "must-remain-absent"
    digest_request = _request(
        "settings.reopen",
        {
            "bundle": str(valid_bundle.resolve()),
            "bundle_sha256": "0" * 64,
            "manifest_sha256": inspected["manifest_sha256"],
            "target": str(target.resolve()),
        },
        expected_version="ABSENT",
        key="reopen-digest-refusal",
    )
    refused_digest = _dispatch(api, "/api/v1/settings/reopen", digest_request)
    assert refused_digest.status != 200
    assert _document(refused_digest)["reason_code"] == "REOPEN_BUNDLE_MISMATCH"
    assert not target.exists()


def test_adapter_plan_recovers_signed_runtime_plan_after_process_crash(
    tmp_path: Path,
) -> None:
    crashed = False

    def crash(stage: str) -> None:
        nonlocal crashed
        if stage == "settings.adapters.plan:after_runtime_plan" and not crashed:
            crashed = True
            raise SystemExit("crash after signed adapter plan")

    workspace, _, api = _shell(tmp_path, fault_hook=crash)
    text = "Recover the exact signed plan without replanning."
    request = _request(
        "settings.adapters.plan",
        {
            "adapter_id": "nukotech.hive.local-capture",
            "capability_id": "capture.text",
            "payload": {"kind": "text", "text": text, "title": "Recover plan"},
            "evidence_sha256": [hashlib.sha256(text.encode("utf-8")).hexdigest()],
        },
        expected_version="ABSENT",
        key="adapter-plan-crash-recovery",
    )
    with pytest.raises(SystemExit, match="crash after signed adapter plan"):
        _dispatch(api, "/api/v1/settings/adapters/plan", request)
    plan_root = workspace.root / ".hive" / "application-adapters" / "plans"
    original_plans = list(plan_root.glob("*.json"))
    assert len(original_plans) == 1
    original_plan = read_json(original_plans[0])

    recovered_service = ShellService(
        workspace,
        tenant_id="local-user",
        project_ids={"HiveMind"},
        now=NOW,
    )
    recovered_api = OperatorAPI(
        workspace.root,
        recovered_service,
        tenant_id="local-user",
        project_ids={"HiveMind"},
    )
    recovered = _dispatch(
        recovered_api, "/api/v1/settings/adapters/plan", request
    )
    assert recovered.status == 200, _document(recovered)
    assert _document(recovered)["changed"] is False
    assert _document(recovered)["data"]["plan"] == original_plan
    assert len(list(plan_root.glob("*.json"))) == 1


def test_adapter_plan_recovery_refuses_multiple_authentic_candidates(
    tmp_path: Path,
) -> None:
    crashed = False

    def crash(stage: str) -> None:
        nonlocal crashed
        if stage == "settings.adapters.plan:after_runtime_plan" and not crashed:
            crashed = True
            raise SystemExit("crash before operator plan bridge")

    workspace, _, api = _shell(tmp_path, fault_hook=crash)
    text = "Never guess which signed plan owns a recovery."
    request = _request(
        "settings.adapters.plan",
        {
            "adapter_id": "nukotech.hive.local-capture",
            "capability_id": "capture.text",
            "payload": {"kind": "text", "text": text, "title": "Ambiguity"},
            "evidence_sha256": [hashlib.sha256(text.encode("utf-8")).hexdigest()],
        },
        expected_version="ABSENT",
        key="adapter-plan-ambiguous-recovery",
    )
    with pytest.raises(SystemExit, match="crash before operator plan bridge"):
        _dispatch(api, "/api/v1/settings/adapters/plan", request)

    services = product_adapter_services(workspace.root)
    request_paths = list((services.runtime.root / "requests").glob("*.json"))
    assert len(request_paths) == 1
    signed_request = read_json(request_paths[0])
    services.runtime.plan(
        signed_request, adapter_invocation_context(services, signed_request)
    )
    assert len(list(services.runtime.plans.glob("*.json"))) == 2

    recovered_service = ShellService(
        workspace,
        tenant_id="local-user",
        project_ids={"HiveMind"},
        now=NOW,
    )
    recovered_api = OperatorAPI(
        workspace.root,
        recovered_service,
        tenant_id="local-user",
        project_ids={"HiveMind"},
    )
    refused = _dispatch(
        recovered_api, "/api/v1/settings/adapters/plan", request
    )
    assert refused.status != 200
    assert _document(refused)["reason_code"] == "ADAPTER_PLAN_RECOVERY_INVALID"


def test_adapter_plan_recovery_rejects_rehashed_but_unauthentic_bridge(
    tmp_path: Path,
) -> None:
    crashed = False

    def crash(stage: str) -> None:
        nonlocal crashed
        if (
            stage == "settings.adapters.plan:after_operator_plan_bridge"
            and not crashed
        ):
            crashed = True
            raise SystemExit("crash after operator plan bridge")

    workspace, _, api = _shell(tmp_path, fault_hook=crash)
    text = "A recomputed digest is not a replacement for a signature."
    request = _request(
        "settings.adapters.plan",
        {
            "adapter_id": "nukotech.hive.local-capture",
            "capability_id": "capture.text",
            "payload": {"kind": "text", "text": text, "title": "Authenticity"},
            "evidence_sha256": [hashlib.sha256(text.encode("utf-8")).hexdigest()],
        },
        expected_version="ABSENT",
        key="adapter-plan-bridge-authenticity",
    )
    with pytest.raises(SystemExit, match="crash after operator plan bridge"):
        _dispatch(api, "/api/v1/settings/adapters/plan", request)

    bridge_root = (
        workspace.root / ".hive" / "runtime" / "operator-shell" / "adapter-plans"
    )
    bridge_paths = list(bridge_root.glob("*.json"))
    assert len(bridge_paths) == 1
    forged = read_json(bridge_paths[0])
    forged["plan"]["expires_at"] = "2099-09-01T00:00:00Z"
    forged["plan_digest"] = document_digest(forged["plan"])
    atomic_write_json(bridge_paths[0], forged)

    recovered_service = ShellService(
        workspace,
        tenant_id="local-user",
        project_ids={"HiveMind"},
        now=NOW,
    )
    recovered_api = OperatorAPI(
        workspace.root,
        recovered_service,
        tenant_id="local-user",
        project_ids={"HiveMind"},
    )
    refused = _dispatch(
        recovered_api, "/api/v1/settings/adapters/plan", request
    )
    assert refused.status != 200
    assert _document(refused)["reason_code"] == "ADAPTER_PLAN_INVALID"


def test_lifecycle_preview_recovers_signed_plan_after_process_crash(
    tmp_path: Path,
) -> None:
    crashed = False

    def crash(stage: str) -> None:
        nonlocal crashed
        if stage == "settings.lifecycle.preview:after_domain_plan" and not crashed:
            crashed = True
            raise SystemExit("crash after signed lifecycle plan")

    workspace, _, api = _shell(tmp_path, fault_hook=crash)
    export_root = tmp_path / "adapter-export"
    export_root.mkdir()
    request = _request(
        "settings.lifecycle.preview",
        {
            "adapter_id": "nukotech.hive.bounded-research",
            "operation": "export",
            "payload": {"root": str(export_root.resolve())},
        },
        expected_version="ABSENT",
        key="lifecycle-plan-crash-recovery",
    )
    with pytest.raises(SystemExit, match="crash after signed lifecycle plan"):
        _dispatch(api, "/api/v1/settings/lifecycle/preview", request)
    plan_root = workspace.root / ".hive" / "application-adapters" / "plans"
    original_plans = list(plan_root.glob("*.json"))
    assert len(original_plans) == 1
    original_plan = read_json(original_plans[0])

    recovered_service = ShellService(
        workspace,
        tenant_id="local-user",
        project_ids={"HiveMind"},
        now=NOW,
    )
    recovered_api = OperatorAPI(
        workspace.root,
        recovered_service,
        tenant_id="local-user",
        project_ids={"HiveMind"},
    )
    recovered = _dispatch(
        recovered_api, "/api/v1/settings/lifecycle/preview", request
    )
    assert recovered.status == 200, _document(recovered)
    assert _document(recovered)["changed"] is False
    assert _document(recovered)["data"]["plan"] == original_plan
    assert len(list(plan_root.glob("*.json"))) == 1


def test_lifecycle_plan_recovery_rejects_unauthentic_operator_bridge(
    tmp_path: Path,
) -> None:
    crashed = False

    def crash(stage: str) -> None:
        nonlocal crashed
        if (
            stage == "settings.lifecycle.preview:after_operator_plan_bridge"
            and not crashed
        ):
            crashed = True
            raise SystemExit("crash after lifecycle plan bridge")

    workspace, _, api = _shell(tmp_path, fault_hook=crash)
    export_root = tmp_path / "adapter-export-authenticity"
    export_root.mkdir()
    request = _request(
        "settings.lifecycle.preview",
        {
            "adapter_id": "nukotech.hive.bounded-research",
            "operation": "export",
            "payload": {"root": str(export_root.resolve())},
        },
        expected_version="ABSENT",
        key="lifecycle-plan-bridge-authenticity",
    )
    with pytest.raises(SystemExit, match="crash after lifecycle plan bridge"):
        _dispatch(api, "/api/v1/settings/lifecycle/preview", request)

    bridge_root = (
        workspace.root
        / ".hive"
        / "runtime"
        / "operator-shell"
        / "lifecycle-plans"
    )
    bridge_paths = list(bridge_root.glob("*.json"))
    assert len(bridge_paths) == 1
    forged = read_json(bridge_paths[0])
    forged["plan"]["expires_at"] = "2099-09-01T00:00:00Z"
    forged["plan_digest"] = document_digest(forged["plan"])
    atomic_write_json(bridge_paths[0], forged)

    recovered_service = ShellService(
        workspace,
        tenant_id="local-user",
        project_ids={"HiveMind"},
        now=NOW,
    )
    recovered_api = OperatorAPI(
        workspace.root,
        recovered_service,
        tenant_id="local-user",
        project_ids={"HiveMind"},
    )
    refused = _dispatch(
        recovered_api, "/api/v1/settings/lifecycle/preview", request
    )
    assert refused.status != 200
    assert (
        _document(refused)["reason_code"]
        == "ADAPTER_LIFECYCLE_PLAN_MISMATCH"
    )


def test_lifecycle_approval_recovers_signed_approval_after_process_crash(
    tmp_path: Path,
) -> None:
    workspace, _, planning_api = _shell(tmp_path)
    install_root = tmp_path / "approval-owned"
    install_root.mkdir()
    owned = install_root / "owned.txt"
    owned.write_text("owned", encoding="utf-8")
    ownership = {
        "schema_version": "hive.adapter-ownership-manifest.v1",
        "installation_id": "approval-recovery-001",
        "adapter_id": "nukotech.hive.bounded-research",
        "adapter_version": "1.0.0",
        "root": str(install_root.resolve()),
        "created_at": NOW.isoformat().replace("+00:00", "Z"),
        "paths": [
            {
                "path": owned.name,
                "kind": "file",
                "sha256": hashlib.sha256(owned.read_bytes()).hexdigest(),
            }
        ],
    }
    preview_request = _request(
        "settings.lifecycle.preview",
        {
            "adapter_id": "nukotech.hive.bounded-research",
            "operation": "uninstall",
            "payload": ownership,
        },
        expected_version="ABSENT",
        key="lifecycle-approval-plan",
    )
    preview = _dispatch(
        planning_api, "/api/v1/settings/lifecycle/preview", preview_request
    )
    plan = _document(preview)["data"]["plan"]
    crashed = False

    def crash(stage: str) -> None:
        nonlocal crashed
        if stage == "settings.lifecycle.approve:after_domain_approval" and not crashed:
            crashed = True
            raise SystemExit("crash after signed lifecycle approval")

    crashing_service = ShellService(
        workspace,
        tenant_id="local-user",
        project_ids={"HiveMind"},
        now=NOW,
        settings_lifecycle_fault_hook=crash,
    )
    crashing_api = OperatorAPI(
        workspace.root,
        crashing_service,
        tenant_id="local-user",
        project_ids={"HiveMind"},
    )
    request = _request(
        "settings.lifecycle.approve",
        {"plan": plan},
        expected_version=document_digest(plan),
        key="lifecycle-approval-crash-recovery",
    )
    with pytest.raises(SystemExit, match="crash after signed lifecycle approval"):
        _dispatch(crashing_api, "/api/v1/settings/lifecycle/approve", request)
    approval_root = (
        workspace.root
        / ".hive"
        / "application-adapters"
        / "lifecycle"
        / "approvals"
    )
    original_approvals = list(approval_root.glob("*.json"))
    assert len(original_approvals) == 1
    original_approval = read_json(original_approvals[0])

    recovered_service = ShellService(
        workspace,
        tenant_id="local-user",
        project_ids={"HiveMind"},
        now=NOW,
    )
    recovered_api = OperatorAPI(
        workspace.root,
        recovered_service,
        tenant_id="local-user",
        project_ids={"HiveMind"},
    )
    recovered = _dispatch(
        recovered_api, "/api/v1/settings/lifecycle/approve", request
    )
    assert recovered.status == 200, _document(recovered)
    assert _document(recovered)["changed"] is False
    assert _document(recovered)["data"]["approval"] == original_approval
    assert len(list(approval_root.glob("*.json"))) == 1


def test_lifecycle_approval_recovery_rejects_unauthentic_operator_bridge(
    tmp_path: Path,
) -> None:
    workspace, _, planning_api = _shell(tmp_path)
    install_root = tmp_path / "approval-bridge-owned"
    install_root.mkdir()
    owned = install_root / "owned.txt"
    owned.write_text("owned", encoding="utf-8")
    ownership = {
        "schema_version": "hive.adapter-ownership-manifest.v1",
        "installation_id": "approval-bridge-authenticity-001",
        "adapter_id": "nukotech.hive.bounded-research",
        "adapter_version": "1.0.0",
        "root": str(install_root.resolve()),
        "created_at": NOW.isoformat().replace("+00:00", "Z"),
        "paths": [
            {
                "path": owned.name,
                "kind": "file",
                "sha256": hashlib.sha256(owned.read_bytes()).hexdigest(),
            }
        ],
    }
    preview_request = _request(
        "settings.lifecycle.preview",
        {
            "adapter_id": "nukotech.hive.bounded-research",
            "operation": "uninstall",
            "payload": ownership,
        },
        expected_version="ABSENT",
        key="lifecycle-approval-bridge-plan",
    )
    preview = _dispatch(
        planning_api, "/api/v1/settings/lifecycle/preview", preview_request
    )
    plan = _document(preview)["data"]["plan"]
    crashed = False

    def crash(stage: str) -> None:
        nonlocal crashed
        if (
            stage == "settings.lifecycle.approve:after_operator_approval_bridge"
            and not crashed
        ):
            crashed = True
            raise SystemExit("crash after lifecycle approval bridge")

    crashing_service = ShellService(
        workspace,
        tenant_id="local-user",
        project_ids={"HiveMind"},
        now=NOW,
        settings_lifecycle_fault_hook=crash,
    )
    crashing_api = OperatorAPI(
        workspace.root,
        crashing_service,
        tenant_id="local-user",
        project_ids={"HiveMind"},
    )
    request = _request(
        "settings.lifecycle.approve",
        {"plan": plan},
        expected_version=document_digest(plan),
        key="lifecycle-approval-bridge-authenticity",
    )
    with pytest.raises(SystemExit, match="crash after lifecycle approval bridge"):
        _dispatch(crashing_api, "/api/v1/settings/lifecycle/approve", request)

    bridge_root = (
        workspace.root
        / ".hive"
        / "runtime"
        / "operator-shell"
        / "lifecycle-approvals"
    )
    bridge_paths = list(bridge_root.glob("*.json"))
    assert len(bridge_paths) == 1
    forged = read_json(bridge_paths[0])
    forged["approval"]["expires_at"] = "2099-09-01T00:00:00Z"
    forged["approval_digest"] = document_digest(forged["approval"])
    atomic_write_json(bridge_paths[0], forged)

    recovered_service = ShellService(
        workspace,
        tenant_id="local-user",
        project_ids={"HiveMind"},
        now=NOW,
    )
    recovered_api = OperatorAPI(
        workspace.root,
        recovered_service,
        tenant_id="local-user",
        project_ids={"HiveMind"},
    )
    refused = _dispatch(
        recovered_api, "/api/v1/settings/lifecycle/approve", request
    )
    assert refused.status != 200
    assert _document(refused)["reason_code"] == "ADAPTER_APPROVAL_INVALID"
