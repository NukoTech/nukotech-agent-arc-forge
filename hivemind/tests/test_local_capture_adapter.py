from __future__ import annotations

import ast
import copy
import hashlib
import json
import stat
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import hive_protocol.adapters.capture.local as capture_module
from hive_protocol.adapters.capture import LocalCaptureAdapter
from hive_protocol.adapters.models import AdapterRequest
from hive_protocol.adapters.policy import InvocationContext
from hive_protocol.adapters.registry import AdapterRegistry
from hive_protocol.adapters.runtime import AdapterRuntime
from hive_protocol.core import ProtocolError, public_key_id, sign_document
from hive_protocol.product.workspace import HiveWorkspace
from hive_protocol.storage import atomic_write_json, read_json


IDENTITY = {
    "persona_id": "Director",
    "surface_id": "LeadA",
    "machine_id": "hive-lab-host",
    "project_id": "HiveMind",
    "app_actor": "hive-builda-app",
}


def test_capture_adapter_has_no_optimization_sensitive_assertions() -> None:
    source_path = (
        Path(__file__).parents[1]
        / "src/hive_protocol/adapters/capture/local.py"
    )
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    assert not [node for node in ast.walk(tree) if isinstance(node, ast.Assert)]


def _signed_request(
    request_key: Ed25519PrivateKey,
    *,
    request_id: str,
    nonce: str,
    capability_id: str,
    payload: dict,
    evidence_sha256: list[str] | None = None,
) -> dict:
    if evidence_sha256 is None:
        if payload.get("kind") == "text":
            evidence_sha256 = [
                hashlib.sha256(payload["text"].encode("utf-8")).hexdigest()
            ]
        elif payload.get("kind") == "file" and Path(payload["path"]).is_file():
            evidence_sha256 = [
                hashlib.sha256(Path(payload["path"]).read_bytes()).hexdigest()
            ]
        else:
            evidence_sha256 = ["0" * 64]
    return sign_document(
        AdapterRequest(
            request_id=request_id,
            adapter_id="nukotech.hive.local-capture",
            adapter_version="1.0.0",
            sender=dict(IDENTITY),
            project_id="HiveMind",
            capability_id=capability_id,
            data_classification="PROJECT_PRIVATE",
            authorization_ref="grant:hivemind:capture",
            evidence_sha256=evidence_sha256,
            payload=payload,
            nonce=nonce,
            expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5))
            .isoformat()
            .replace("+00:00", "Z"),
        ).as_dict(),
        request_key,
    )


@pytest.fixture
def registered_capture(tmp_path: Path):
    workspace = HiveWorkspace.create(tmp_path / "hive")
    adapter = LocalCaptureAdapter(
        workspace,
        tmp_path / "adapter-staging",
        state_signing_key=Ed25519PrivateKey.generate(),
    )
    manifest_path = (
        Path(__file__).parents[1]
        / "src/hive_protocol/adapters/capture/local-capture.manifest.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    registry = AdapterRegistry(
        tmp_path / "runtime",
        tmp_path / "runtime/policy",
        os_name="linux",
        architecture="aarch64",
        runtime="python>=3.11",
    )
    registry.register(adapter, manifest)
    request_key = Ed25519PrivateKey.generate()
    runtime_key = Ed25519PrivateKey.generate()
    runtime = AdapterRuntime(
        tmp_path / "runtime",
        registry,
        {public_key_id(request_key.public_key()): request_key.public_key()},
        {},
        runtime_key,
        trusted_approver_identities={},
    )
    context = InvocationContext(
        project_id="HiveMind",
        authorization_ref="grant:hivemind:capture",
        identity=dict(IDENTITY),
        granted_capabilities=frozenset({"capture.text", "capture.file"}),
        granted_permissions=frozenset(
            {
                "filesystem.read.project-source",
                "filesystem.write.adapter-state",
                "filesystem.write.workspace",
            }
        ),
        allowed_data_classifications=frozenset({"PROJECT_PRIVATE"}),
        allowed_network_destinations=frozenset(),
        available_credential_references=frozenset(),
    )
    return runtime, workspace, adapter, request_key, context


@pytest.fixture
def signed_request(registered_capture) -> dict:
    _, _, _, request_key, _ = registered_capture
    return _signed_request(
        request_key,
        request_id="capture-text-001",
        nonce="capture-text-nonce-001",
        capability_id="capture.text",
        payload={
            "kind": "text",
            "text": "bounded evidence",
            "title": "Bounded Evidence",
        },
    )


@pytest.fixture
def two_requests(registered_capture) -> list[dict]:
    _, _, _, request_key, _ = registered_capture
    payload = {
        "kind": "text",
        "text": "bounded evidence",
        "title": "Bounded Evidence",
    }
    return [
        _signed_request(
            request_key,
            request_id=f"capture-duplicate-{index}",
            nonce=f"capture-duplicate-nonce-{index}",
            capability_id="capture.text",
            payload=dict(payload),
        )
        for index in (1, 2)
    ]


def test_capture_adapter_plans_then_preserves_bytes(
    registered_capture, signed_request
) -> None:
    runtime, workspace, adapter, _, context = registered_capture
    assert not adapter.staging_root.exists()
    plan = runtime.plan(signed_request, context)
    assert plan["side_effects"] == [
        "workspace:sources",
        "workspace:provenance",
        "workspace:receipt",
    ]
    assert not adapter.staging_root.exists()
    assert workspace.search_exact("bounded evidence") == []
    result = runtime.invoke(signed_request, plan, context, approval_document=None)
    assert result["outcome"] == "APPLIED"
    hits = workspace.search_exact("bounded evidence")
    assert len(hits) == 1
    assert result["evidence_refs"][0]["sha256"] == hits[0]["source_sha256"]


def test_capture_apply_is_idempotent_for_one_operation_key(
    registered_capture,
) -> None:
    _, workspace, adapter, _, _ = registered_capture
    planned = adapter.plan(
        {"kind": "text", "text": "idempotent bytes", "title": "Idempotent"}
    )
    key = "a" * 64

    first = adapter.apply(planned["payload"], operation_key=key)
    second = adapter.apply(planned["payload"], operation_key=key)

    assert second == first
    assert adapter.recover(key) == first
    assert workspace.status()["documents"] == 1

    operation_path = adapter._operation_path(key)
    durable = read_json(operation_path)
    assert durable["signature"]["key_id"] == adapter.state_key_id
    tampered = copy.deepcopy(durable)
    tampered["result"]["side_effects"] = []
    atomic_write_json(operation_path, tampered, mode=0o600)
    with pytest.raises(ProtocolError, match="ADAPTER_OPERATION_KEY_MISMATCH"):
        adapter.recover(key)


def test_capture_recovers_after_process_crash_between_import_and_result(
    registered_capture, signed_request, monkeypatch
) -> None:
    runtime, workspace, adapter, _, context = registered_capture
    plan = runtime.plan(signed_request, context)
    finish_rollback_record = adapter._finish_rollback_record

    def crash_after_import(*args, **kwargs) -> None:
        raise SystemExit("process crash after portable import")

    monkeypatch.setattr(adapter, "_finish_rollback_record", crash_after_import)
    with pytest.raises(SystemExit, match="process crash after portable import"):
        runtime.invoke(signed_request, plan, context, approval_document=None)

    assert workspace.status()["documents"] == 1
    monkeypatch.setattr(adapter, "_finish_rollback_record", finish_rollback_record)
    recovered = runtime.recover_pending()

    assert [result["outcome"] for result in recovered] == ["APPLIED"]
    assert workspace.status()["documents"] == 1
    operation_key = recovered[0]["rollback_ref"].removeprefix("capture-delta:")
    assert len(
        list(
            workspace.receipts.glob(
                f"operation-{operation_key}-*-content-imported.json"
            )
        )
    ) == 1
    assert runtime.recover_pending() == []


def test_capture_request_evidence_must_match_exact_text_bytes(
    registered_capture,
) -> None:
    runtime, _, _, request_key, context = registered_capture
    request = _signed_request(
        request_key,
        request_id="capture-evidence-mismatch",
        nonce="capture-evidence-mismatch-nonce",
        capability_id="capture.text",
        payload={"kind": "text", "text": "exact bytes", "title": "Evidence"},
        evidence_sha256=["0" * 64],
    )

    with pytest.raises(ProtocolError, match="ADAPTER_EVIDENCE_MISMATCH"):
        runtime.plan(request, context)


def test_same_text_with_different_titles_is_one_document(
    registered_capture,
) -> None:
    runtime, workspace, _, request_key, context = registered_capture
    results = []
    for index, title in enumerate(("First Title", "Second Title"), start=1):
        request = _signed_request(
            request_key,
            request_id=f"capture-title-{index}",
            nonce=f"capture-title-nonce-{index}",
            capability_id="capture.text",
            payload={"kind": "text", "text": "same exact bytes", "title": title},
        )
        plan = runtime.plan(request, context)
        results.append(runtime.invoke(request, plan, context, approval_document=None))

    assert results[0]["evidence_refs"][0]["stable_id"] == results[1][
        "evidence_refs"
    ][0]["stable_id"]
    assert workspace.status()["documents"] == 1


def test_duplicate_capture_preserves_new_provenance_without_duplicate_source(
    registered_capture, two_requests
) -> None:
    runtime, workspace, _, _, context = registered_capture
    results = []
    for request in two_requests:
        plan = runtime.plan(request, context)
        results.append(
            runtime.invoke(request, plan, context, approval_document=None)
        )
    assert (
        results[0]["evidence_refs"][0]["sha256"]
        == results[1]["evidence_refs"][0]["sha256"]
    )
    assert workspace.status()["documents"] == 1
    assert results[1]["detail"]["deduplicated"] is True
    assert results[0]["detail"]["receipt_paths"] != results[1]["detail"][
        "receipt_paths"
    ]


def test_concurrent_duplicate_captures_serialize_exact_delta_ownership(
    registered_capture, two_requests, monkeypatch
) -> None:
    _, workspace, adapter, _, _ = registered_capture
    prepare = adapter._prepare_rollback

    def keep_snapshot_window_open(operation_key, payload, source):
        document = prepare(operation_key, payload, source)
        time.sleep(0.2)
        return document

    monkeypatch.setattr(adapter, "_prepare_rollback", keep_snapshot_window_open)
    payloads = [adapter.plan(request["payload"])["payload"] for request in two_requests]
    operation_keys = ["1" * 64, "2" * 64]

    def invoke(index: int) -> dict:
        return adapter.apply(
            payloads[index], operation_key=operation_keys[index]
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(invoke, range(2)))

    assert all(result["outcome"] == "APPLIED" for result in results), json.dumps(
        results, indent=2, sort_keys=True
    )
    older = next(result for result in results if not result["detail"]["deduplicated"])
    newer = next(result for result in results if result["detail"]["deduplicated"])
    assert workspace.status()["documents"] == 1

    adapter.rollback(newer["rollback_ref"], operation_key="d" * 64)
    assert workspace.status()["documents"] == 1
    adapter.rollback(older["rollback_ref"], operation_key="e" * 64)
    assert workspace.status()["documents"] == 0


def test_file_capture_preserves_exact_source_and_imported_bytes(
    tmp_path: Path, registered_capture
) -> None:
    runtime, workspace, _, request_key, context = registered_capture
    source = tmp_path / "external-evidence.md"
    payload = b"# External Evidence\n\nbounded bytes: \xe2\x98\x83\n"
    source.write_bytes(payload)
    request = _signed_request(
        request_key,
        request_id="capture-file-001",
        nonce="capture-file-nonce-001",
        capability_id="capture.file",
        payload={"kind": "file", "path": str(source.resolve())},
    )
    plan = runtime.plan(request, context)
    result = runtime.invoke(request, plan, context, approval_document=None)
    imported = workspace.root / result["evidence_refs"][0]["imported_relative_path"]
    assert source.read_bytes() == payload
    assert imported.read_bytes() == payload
    assert result["evidence_refs"][0]["sha256"] == hashlib.sha256(payload).hexdigest()
    assert result["detail"]["byte_preserving"] is True


def test_capture_refuses_symlink_inside_hive_and_extra_payload_fields(
    tmp_path: Path, registered_capture
) -> None:
    runtime, workspace, _, request_key, context = registered_capture
    source = tmp_path / "source.md"
    source.write_text("bounded", encoding="utf-8")
    link = tmp_path / "source-link.md"
    link.symlink_to(source)
    unsafe_payloads = [
        {"kind": "file", "path": str(link)},
        {
            "kind": "file",
            "path": str((workspace.sources / "inside.md").resolve()),
        },
        {"kind": "text", "text": "bounded", "title": "Title", "extra": True},
    ]
    (workspace.sources / "inside.md").write_text("inside", encoding="utf-8")
    for index, payload in enumerate(unsafe_payloads, start=1):
        request = _signed_request(
            request_key,
            request_id=f"capture-refused-{index}",
            nonce=f"capture-refused-nonce-{index}",
            capability_id="capture.file" if payload["kind"] == "file" else "capture.text",
            payload=payload,
        )
        with pytest.raises(
            ProtocolError,
            match="CAPTURE_SOURCE_BOUNDARY|CAPTURE_PAYLOAD_INVALID",
        ):
            runtime.plan(request, context)


def test_text_capability_cannot_authorize_file_capture(
    tmp_path: Path, registered_capture
) -> None:
    runtime, _, _, request_key, context = registered_capture
    source = tmp_path / "file-authority.md"
    source.write_text("file-only evidence", encoding="utf-8")
    request = _signed_request(
        request_key,
        request_id="capture-capability-confusion",
        nonce="capture-capability-confusion-nonce",
        capability_id="capture.text",
        payload={"kind": "file", "path": str(source.resolve())},
    )
    with pytest.raises(ProtocolError, match="ADAPTER_CAPABILITY_PAYLOAD_MISMATCH"):
        runtime.plan(request, context)


def test_capture_uses_preapply_snapshot_for_exact_rollback(
    registered_capture, signed_request
) -> None:
    runtime, workspace, adapter, _, context = registered_capture
    workspace.snapshot("baseline")
    plan = runtime.plan(signed_request, context)
    result = runtime.invoke(signed_request, plan, context, approval_document=None)
    rollback_root = adapter.staging_root / "rollback"
    assert stat.S_IMODE(rollback_root.stat().st_mode) == 0o700
    assert result["rollback_ref"] is not None
    assert workspace.status()["documents"] == 1
    rolled_back = adapter.rollback(result["rollback_ref"], operation_key="b" * 64)
    assert rolled_back["outcome"] == "APPLIED"
    assert workspace.status()["documents"] == 0
    assert workspace.status()["receipts"] >= 3


def test_capture_rollback_preserves_later_unrelated_source(
    tmp_path: Path, registered_capture, signed_request
) -> None:
    runtime, workspace, adapter, _, context = registered_capture
    workspace.snapshot("baseline")
    plan = runtime.plan(signed_request, context)
    result = runtime.invoke(signed_request, plan, context, approval_document=None)
    later_source = tmp_path / "later.md"
    later_source.write_text("# Later\n\nunrelated later work", encoding="utf-8")
    later = workspace.import_content(later_source)[0]
    receipts_before = workspace.status()["receipts"]

    rolled_back = adapter.rollback(result["rollback_ref"], operation_key="b" * 64)

    assert rolled_back["outcome"] == "APPLIED"
    assert workspace.status()["documents"] == 1
    assert workspace.status()["receipts"] >= receipts_before
    assert (workspace.root / later.imported_relative_path).is_file()
    assert workspace.search_exact("unrelated later work")[0]["stable_id"] == later.stable_id


def test_capture_rollback_refuses_drift_before_mutation(
    registered_capture, signed_request
) -> None:
    runtime, workspace, adapter, _, context = registered_capture
    workspace.snapshot("baseline")
    plan = runtime.plan(signed_request, context)
    result = runtime.invoke(signed_request, plan, context, approval_document=None)
    imported = workspace.root / result["evidence_refs"][0]["imported_relative_path"]
    imported.write_text("tampered after capture", encoding="utf-8")

    with pytest.raises(ProtocolError, match="CAPTURE_ROLLBACK_DRIFT"):
        adapter.rollback(result["rollback_ref"], operation_key="b" * 64)

    assert imported.read_text(encoding="utf-8") == "tampered after capture"


def test_capture_rollback_refuses_tampered_delta_path(
    registered_capture, signed_request
) -> None:
    runtime, _, adapter, _, context = registered_capture
    plan = runtime.plan(signed_request, context)
    result = runtime.invoke(signed_request, plan, context, approval_document=None)
    operation_key = result["rollback_ref"].removeprefix("capture-delta:")
    record_path = adapter.staging_root / "rollback" / f"{operation_key}.json"
    document = json.loads(record_path.read_text(encoding="utf-8"))
    document["entries"][0]["path"] = "../../outside"
    record_path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ProtocolError, match="CAPTURE_ROLLBACK_MISMATCH"):
        adapter.rollback(result["rollback_ref"], operation_key="b" * 64)


def test_capture_rollback_validates_all_saved_bytes_before_mutation(
    registered_capture, two_requests
) -> None:
    runtime, workspace, adapter, _, context = registered_capture
    first_plan = runtime.plan(two_requests[0], context)
    first = runtime.invoke(
        two_requests[0], first_plan, context, approval_document=None
    )
    second_plan = runtime.plan(two_requests[1], context)
    second = runtime.invoke(
        two_requests[1], second_plan, context, approval_document=None
    )
    source = workspace.root / first["evidence_refs"][0]["imported_relative_path"]
    source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
    operation_key = second["rollback_ref"].removeprefix("capture-delta:")
    record_path = adapter.staging_root / "rollback" / f"{operation_key}.json"
    document = json.loads(record_path.read_text(encoding="utf-8"))
    document["entries"][1]["before_bytes_b64"] = "dGFtcGVyZWQ="
    record_path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ProtocolError, match="CAPTURE_ROLLBACK_MISMATCH"):
        adapter.rollback(second["rollback_ref"], operation_key="b" * 64)

    assert hashlib.sha256(source.read_bytes()).hexdigest() == source_digest


def test_capture_rollback_resumes_after_process_crash_during_restore(
    tmp_path: Path, registered_capture, signed_request, monkeypatch
) -> None:
    runtime, workspace, adapter, _, context = registered_capture
    plan = runtime.plan(signed_request, context)
    result = runtime.invoke(signed_request, plan, context, approval_document=None)
    later_source = tmp_path / "later-crash-safe.md"
    later_source.write_text("later crash-safe work", encoding="utf-8")
    later = workspace.import_content(later_source)[0]
    atomic_write_json = capture_module.atomic_write_json
    crashed = False

    def crash_after_first_restore(path, document, mode=0o644) -> None:
        nonlocal crashed
        entries = document.get("entries", []) if isinstance(document, dict) else []
        first_restored = bool(
            entries and entries[0].get("restore_state") == "RESTORED"
        )
        if document.get("state") == "ROLLING_BACK" and first_restored and not crashed:
            crashed = True
            raise SystemExit("process crash during exact rollback")
        atomic_write_json(path, document, mode=mode)

    monkeypatch.setattr(capture_module, "atomic_write_json", crash_after_first_restore)
    with pytest.raises(SystemExit, match="process crash during exact rollback"):
        adapter.rollback(result["rollback_ref"], operation_key="b" * 64)

    monkeypatch.setattr(capture_module, "atomic_write_json", atomic_write_json)
    recovered = adapter.rollback(result["rollback_ref"], operation_key="b" * 64)

    assert recovered["outcome"] == "APPLIED"
    assert workspace.status()["documents"] == 1
    assert (workspace.root / later.imported_relative_path).is_file()


def test_capture_health_export_and_owned_uninstall_preserve_workspace(
    tmp_path: Path, registered_capture, signed_request
) -> None:
    runtime, workspace, adapter, _, context = registered_capture
    assert adapter.health()["status"] == "HEALTHY"
    plan = runtime.plan(signed_request, context)
    runtime.invoke(signed_request, plan, context, approval_document=None)
    receipt_count = workspace.status()["receipts"]

    export_root = tmp_path / "exports"
    export_root.mkdir()
    exported = adapter.export(
        {"root": str(export_root.resolve()), "filename": "capture.tar.gz"},
        operation_key="e" * 64,
    )
    bundle = export_root / "capture.tar.gz"
    assert exported["outcome"] == "APPLIED"
    assert exported["detail"]["workspace_export"]["sha256"] == hashlib.sha256(
        bundle.read_bytes()
    ).hexdigest()

    assert not callable(getattr(adapter, "uninstall", None))
    assert workspace.status()["documents"] == 1
    assert workspace.status()["receipts"] == receipt_count
    assert workspace.search_exact("bounded evidence")
