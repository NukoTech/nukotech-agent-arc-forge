from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.adapters.capture import LocalCaptureAdapter
from hive_protocol.adapters.models import AdapterRequest
from hive_protocol.adapters.policy import InvocationContext
from hive_protocol.adapters.registry import AdapterRegistry
from hive_protocol.adapters.runtime import AdapterRuntime
from hive_protocol.core import ProtocolError, public_key_id, sign_document
from hive_protocol.product.workspace import HiveWorkspace


def _adapter(tmp_path: Path):
    workspace = HiveWorkspace.create(tmp_path / "hive")
    adapter = LocalCaptureAdapter(
        workspace,
        tmp_path / "adapter-state",
        state_signing_key=Ed25519PrivateKey.generate(),
    )
    return workspace, adapter


def _path_payload(tmp_path: Path, kind: str, media_type: str) -> dict:
    suffix = {
        "webpage_snapshot": ".html",
        "browser_handoff": ".html",
        "pdf": ".pdf",
        "image": ".png",
        "audio": ".wav",
        "video": ".mp4",
        "meeting_recording": ".mp4",
        "transcript": ".vtt",
        "file": ".bin",
    }[kind]
    path = tmp_path / f"{kind}{suffix}"
    path.write_bytes(f"synthetic {kind}".encode())
    payload = {"kind": kind, "path": str(path.resolve()), "media_type": media_type}
    if kind == "file":
        payload["channel"] = "FILE"
    return payload


def test_m31_plans_every_local_channel_with_exact_bounds(tmp_path: Path) -> None:
    _, adapter = _adapter(tmp_path)
    payloads = [
        {"kind": "markdown", "text": "# Local\n", "title": "Local"},
        {"kind": "clipboard", "text": "clipboard", "title": "Clipboard"},
        _path_payload(tmp_path, "webpage_snapshot", "text/html"),
        _path_payload(tmp_path, "browser_handoff", "text/html"),
        _path_payload(tmp_path, "pdf", "application/pdf"),
        _path_payload(tmp_path, "image", "image/png"),
        _path_payload(tmp_path, "audio", "audio/wav"),
        _path_payload(tmp_path, "video", "video/mp4"),
        _path_payload(tmp_path, "meeting_recording", "video/mp4"),
        _path_payload(tmp_path, "transcript", "text/vtt"),
        _path_payload(tmp_path, "file", "application/octet-stream"),
    ]

    for payload in payloads:
        plan = adapter.plan(payload)
        assert plan["network_destinations"] == []
        assert plan["payload"]["kind"] == "m31_capture"
        assert len(plan["payload"]["admission_plans"]) == 1
        admission = plan["payload"]["admission_plans"][0]
        assert admission["original_sha256"]
        assert admission["original_size_bytes"] > 0
        assert admission["normalization"]["max_output_bytes"] == 10 * 1024 * 1024
        assert admission["normalization"]["provider_state"] in {
            "AVAILABLE",
            "UNAVAILABLE",
        }


def test_folder_handoff_is_exact_ordered_batch_and_replay_safe(tmp_path: Path) -> None:
    workspace, adapter = _adapter(tmp_path)
    first = tmp_path / "first.md"
    second = tmp_path / "second.txt"
    first.write_text("first evidence", encoding="utf-8")
    second.write_text("second evidence", encoding="utf-8")
    payload = {
        "kind": "folder_handoff",
        "items": [
            {"path": str(first.resolve()), "channel": "MARKDOWN", "media_type": "text/markdown"},
            {"path": str(second.resolve()), "channel": "FILE", "media_type": "text/plain"},
        ],
    }
    planned = adapter.plan(payload)["payload"]
    assert [item["filename"] for item in planned["admission_plans"]] == [
        "first.md",
        "second.txt",
    ]

    first_result = adapter.apply(planned, operation_key="1" * 64)
    replay = adapter.apply(planned, operation_key="1" * 64)
    assert replay == first_result
    assert first_result["outcome"] == "APPLIED"
    assert len(first_result["evidence_refs"]) == 2
    assert len(list(workspace.provenance.glob("source-*.json"))) == 2


def test_missing_provider_is_bounded_degraded_and_group_rollback_is_exact(tmp_path: Path) -> None:
    workspace, adapter = _adapter(tmp_path)
    pdf = tmp_path / "paper.pdf"
    pdf.write_bytes(b"%PDF-1.7 synthetic")
    planned = adapter.plan(
        {"kind": "pdf", "path": str(pdf.resolve()), "media_type": "application/pdf"}
    )["payload"]
    result = adapter.apply(planned, operation_key="2" * 64)

    assert result["outcome"] == "DEGRADED"
    assert result["detail"]["admissions"][0]["outcome"] == "QUEUED_PROVIDER"
    assert result["rollback_ref"] == "capture-admission-group:" + "2" * 64
    assert list(workspace.capture_queue.glob("*.json"))

    rolled_back = adapter.rollback(result["rollback_ref"], operation_key="3" * 64)
    assert rolled_back["outcome"] == "APPLIED"
    assert not list(workspace.capture_queue.glob("*.json"))
    assert not list(workspace.provenance.glob("source-*.json"))


def test_m31_capability_cannot_authorize_another_payload_kind(tmp_path: Path) -> None:
    _, adapter = _adapter(tmp_path)
    request = AdapterRequest(
        request_id="capture-m31-mismatch",
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
        capability_id="capture.image",
        data_classification="PROJECT_PRIVATE",
        authorization_ref="grant:hivemind:capture",
        evidence_sha256=[hashlib.sha256(b"# local\n").hexdigest()],
        payload={"kind": "markdown", "text": "# local\n", "title": "Local"},
        nonce="capture-m31-mismatch-nonce",
        expires_at="2026-09-01T05:00:00Z",
    )
    with pytest.raises(ProtocolError, match="ADAPTER_CAPABILITY_PAYLOAD_MISMATCH"):
        adapter.validate_request(request)

    disguised = _path_payload(tmp_path, "file", "image/png")
    disguised["channel"] = "IMAGE"
    with pytest.raises(ProtocolError, match="ADAPTER_CAPABILITY_PAYLOAD_MISMATCH"):
        adapter.plan(disguised)


def test_capture_manifest_exposes_exact_local_capabilities_without_egress() -> None:
    manifest_path = (
        Path(__file__).parents[1]
        / "src/hive_protocol/adapters/capture/local-capture.manifest.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert set(manifest["capability_ids"]) >= {
        "capture.markdown",
        "capture.clipboard",
        "capture.webpage-snapshot",
        "capture.browser-handoff",
        "capture.pdf",
        "capture.image",
        "capture.audio",
        "capture.video",
        "capture.meeting-recording",
        "capture.transcript",
        "capture.folder-handoff",
    }
    assert manifest["network_destinations"] == []
    assert manifest["credential_references"] == []


def test_signed_runtime_routes_markdown_through_m31_admission(tmp_path: Path) -> None:
    workspace, adapter = _adapter(tmp_path)
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
    runtime = AdapterRuntime(
        tmp_path / "runtime",
        registry,
        {public_key_id(request_key.public_key()): request_key.public_key()},
        {},
        Ed25519PrivateKey.generate(),
        trusted_approver_identities={},
    )
    identity = {
        "persona_id": "Director",
        "surface_id": "LeadA",
        "machine_id": "hive-lab-host",
        "project_id": "HiveMind",
        "app_actor": "hive-builda-app",
    }
    payload = {"kind": "markdown", "text": "# signed local\n", "title": "Signed"}
    request = sign_document(
        AdapterRequest(
            request_id="capture-m31-signed",
            adapter_id="nukotech.hive.local-capture",
            adapter_version="1.0.0",
            sender=identity,
            project_id="HiveMind",
            capability_id="capture.markdown",
            data_classification="PROJECT_PRIVATE",
            authorization_ref="grant:hivemind:capture",
            evidence_sha256=[hashlib.sha256(payload["text"].encode()).hexdigest()],
            payload=payload,
            nonce="capture-m31-signed-nonce",
            expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5))
            .isoformat()
            .replace("+00:00", "Z"),
        ).as_dict(),
        request_key,
    )
    context = InvocationContext(
        project_id="HiveMind",
        authorization_ref="grant:hivemind:capture",
        identity=identity,
        granted_capabilities=frozenset({"capture.markdown"}),
        granted_permissions=frozenset(manifest["required_permissions"]),
        allowed_data_classifications=frozenset({"PROJECT_PRIVATE"}),
        allowed_network_destinations=frozenset(),
        available_credential_references=frozenset(),
    )

    plan = runtime.plan(request, context)
    result = runtime.invoke(request, plan, context, approval_document=None)
    assert result["outcome"] == "APPLIED"
    assert result["detail"]["local_only"] is True
    assert len(list(workspace.provenance.glob("source-*.json"))) == 1


def test_m31_parent_recovers_after_child_admission_before_parent_result(
    tmp_path: Path, monkeypatch
) -> None:
    workspace, adapter = _adapter(tmp_path)
    planned = adapter.plan(
        {"kind": "markdown", "text": "# recover\n", "title": "Recover"}
    )["payload"]
    finish = adapter._finish_operation

    def crash(*args, **kwargs) -> None:
        raise SystemExit("crash after child admission")

    monkeypatch.setattr(adapter, "_finish_operation", crash)
    with pytest.raises(SystemExit, match="crash after child admission"):
        adapter.apply(planned, operation_key="4" * 64)
    assert len(list(workspace.provenance.glob("source-*.json"))) == 1

    monkeypatch.setattr(adapter, "_finish_operation", finish)
    recovered = adapter.apply(planned, operation_key="4" * 64)
    assert recovered["outcome"] == "APPLIED"
    assert len(list(workspace.provenance.glob("source-*.json"))) == 1
