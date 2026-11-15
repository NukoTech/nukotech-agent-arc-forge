from __future__ import annotations

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.capture.admission import CaptureAdmissionService
from hive_protocol.capture.models import CitationAnchor, SourceRecord
from hive_protocol.capture.normalizers import NormalizerRegistry
from hive_protocol.core import ProtocolError
from hive_protocol.product.workspace import HiveWorkspace
from hive_protocol.storage import atomic_write_bytes, atomic_write_json, read_json


def _service(tmp_path: Path, *, registry: NormalizerRegistry | None = None):
    workspace = HiveWorkspace.create(tmp_path / "hive")
    service = CaptureAdmissionService(
        workspace,
        tmp_path / "private-state",
        registry=registry or NormalizerRegistry(),
        signing_key=Ed25519PrivateKey.generate(),
    )
    return workspace, service


def _plan(service: CaptureAdmissionService, payload: bytes = b"alpha\r\nbeta\r\n"):
    return service.plan_bytes(
        payload,
        tenant_id="tenant:local",
        project_id="HiveMind",
        privacy_class="PROJECT_PRIVATE",
        channel="MARKDOWN",
        source_owner="Owner",
        rights_assertion="USER_PROVIDED",
        media_type="text/markdown",
        filename="evidence.md",
        destination="STAGING",
    )


def test_plan_validates_scope_before_reading_source(tmp_path: Path, monkeypatch) -> None:
    _, service = _service(tmp_path)
    source = tmp_path / "evidence.md"
    source.write_text("bounded evidence", encoding="utf-8")
    calls: list[str] = []
    original = Path.read_bytes

    def observed(path: Path) -> bytes:
        calls.append(str(path))
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", observed)
    with pytest.raises(ProtocolError, match="CAPTURE_SCOPE_INVALID"):
        service.plan_path(
            source,
            tenant_id="tenant:local",
            project_id="",
            privacy_class="PROJECT_PRIVATE",
            channel="MARKDOWN",
            source_owner="Owner",
            rights_assertion="USER_PROVIDED",
            media_type="text/markdown",
            destination="STAGING",
        )
    assert calls == []


def test_admission_preserves_original_and_verifiable_normalized_anchors(tmp_path: Path) -> None:
    workspace, service = _service(tmp_path)
    payload = b"alpha\r\nbeta\r\n"
    result = service.apply(_plan(service, payload), operation_key="1" * 64)

    assert result["outcome"] == "ADMITTED_STAGING"
    record = SourceRecord.from_dict(read_json(workspace.root / result["source_record_path"]))
    assert (workspace.root / record.original_asset_path).read_bytes() == payload
    normalized = (workspace.root / str(record.normalized_text_path)).read_text(encoding="utf-8")
    assert normalized == "alpha\nbeta\n"
    assert hashlib.sha256(normalized.encode()).hexdigest() == record.normalized_sha256
    for document in record.anchors:
        CitationAnchor.from_dict(document).verify(normalized)
    assert not (workspace.root / "prime").exists()


def test_duplicate_capture_reuses_content_and_appends_distinct_provenance(tmp_path: Path) -> None:
    workspace, service = _service(tmp_path)
    first = service.apply(_plan(service), operation_key="2" * 64)
    second = service.apply(_plan(service), operation_key="3" * 64)

    assert first["source_id"] == second["source_id"]
    assert first["asset_path"] == second["asset_path"]
    assert first["normalized_text_path"] == second["normalized_text_path"]
    assert first["capture_id"] != second["capture_id"]
    record = SourceRecord.from_dict(read_json(workspace.root / first["source_record_path"]))
    assert record.capture_ids == sorted([first["capture_id"], second["capture_id"]])
    assert len(list((workspace.root / "assets").rglob("*.*"))) == 1
    assert len(list((workspace.root / "sources").rglob("normalized.md"))) == 1


def test_missing_provider_queues_original_without_inventing_text(tmp_path: Path) -> None:
    workspace, service = _service(tmp_path)
    plan = service.plan_bytes(
        b"%PDF-1.7 synthetic",
        tenant_id="tenant:local",
        project_id="HiveMind",
        privacy_class="PROJECT_PRIVATE",
        channel="PDF",
        source_owner="Owner",
        rights_assertion="USER_PROVIDED",
        media_type="application/pdf",
        filename="paper.pdf",
        destination="RESEARCH",
    )
    result = service.apply(plan, operation_key="4" * 64)
    record = SourceRecord.from_dict(read_json(workspace.root / result["source_record_path"]))

    assert result["outcome"] == "QUEUED_PROVIDER"
    assert record.normalized_text_path is None
    assert record.normalized_sha256 is None
    assert record.anchors == []
    assert (workspace.root / result["queue_path"]).is_file()
    assert not (workspace.root / "prime").exists()


def test_concurrent_duplicate_admission_serializes_to_one_source(tmp_path: Path) -> None:
    workspace, service = _service(tmp_path)
    plans = [_plan(service) for _ in range(4)]
    keys = [f"{index:x}" * 64 for index in range(5, 9)]
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda item: service.apply(*item), zip(plans, keys)))

    assert len({result["source_id"] for result in results}) == 1
    record = SourceRecord.from_dict(read_json(workspace.root / results[0]["source_record_path"]))
    assert len(record.capture_ids) == 4


@pytest.mark.parametrize("crash_stage", ["ORIGINAL_WRITTEN", "NORMALIZED_WRITTEN"])
def test_crash_recovery_resumes_from_signed_staged_bytes(
    tmp_path: Path, monkeypatch, crash_stage: str
) -> None:
    workspace, service = _service(tmp_path)
    operation_key = ("a" if crash_stage == "ORIGINAL_WRITTEN" else "b") * 64
    original_hook = service._after_stage

    def crash(stage: str) -> None:
        if stage == crash_stage:
            raise SystemExit(f"crash at {stage}")

    monkeypatch.setattr(service, "_after_stage", crash)
    with pytest.raises(SystemExit, match=crash_stage):
        service.apply(_plan(service), operation_key=operation_key)

    monkeypatch.setattr(service, "_after_stage", original_hook)
    recovered = service.recover(operation_key)
    replayed = service.apply(_plan(service), operation_key=operation_key)
    assert recovered == replayed
    assert recovered["outcome"] == "ADMITTED_STAGING"
    assert len(list((workspace.root / "sources").rglob("normalized.md"))) == 1


def test_changed_source_tampering_symlinks_and_credentials_fail_closed(tmp_path: Path) -> None:
    workspace, service = _service(tmp_path)
    source = tmp_path / "source.md"
    source.write_text("first", encoding="utf-8")
    plan = service.plan_path(
        source,
        tenant_id="tenant:local",
        project_id="HiveMind",
        privacy_class="PROJECT_PRIVATE",
        channel="MARKDOWN",
        source_owner="Owner",
        rights_assertion="USER_PROVIDED",
        media_type="text/markdown",
        destination="STAGING",
    )
    source.write_text("changed", encoding="utf-8")
    with pytest.raises(ProtocolError, match="CAPTURE_SOURCE_CHANGED"):
        service.apply(plan, operation_key="c" * 64)

    with pytest.raises(ProtocolError, match="ADAPTER_CREDENTIAL_VALUE_DENIED"):
        service.apply(
            _plan(service, b"api_key=not-a-real-secret-value"),
            operation_key="d" * 64,
        )
    assert not list((workspace.root / "staging").glob("captures/*.json"))

    target = workspace.assets / ("asset-" + "0" * 64)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.symlink_to(tmp_path)
    with pytest.raises(ProtocolError, match="CAPTURE_PORTABLE_BOUNDARY"):
        service._ensure_portable_root(target)


def test_exact_delta_rollback_restores_shared_source_and_refuses_drift(tmp_path: Path) -> None:
    workspace, service = _service(tmp_path)
    first = service.apply(_plan(service), operation_key="e" * 64)
    second = service.apply(_plan(service), operation_key="f" * 64)
    service.rollback("f" * 64)

    record = SourceRecord.from_dict(read_json(workspace.root / first["source_record_path"]))
    assert record.capture_ids == [first["capture_id"]]
    assert (workspace.root / first["asset_path"]).is_file()
    assert (workspace.root / first["normalized_text_path"]).is_file()
    assert not (workspace.root / second["capture_envelope_path"]).exists()

    third = service.apply(_plan(service, b"independent\n"), operation_key="9" * 64)
    envelope = workspace.root / third["capture_envelope_path"]
    atomic_write_bytes(envelope, envelope.read_bytes() + b" ")
    with pytest.raises(ProtocolError, match="CAPTURE_ROLLBACK_MISMATCH"):
        service.rollback("9" * 64)
    assert envelope.is_file()
    assert (workspace.root / first["asset_path"]).is_file()


def test_private_state_is_owned_and_mode_0700(tmp_path: Path) -> None:
    _, service = _service(tmp_path)
    service.apply(_plan(service), operation_key="8" * 64)
    assert service.state_root.stat().st_uid == os.geteuid()
    assert service.state_root.stat().st_mode & 0o777 == 0o700


def test_recovery_refuses_tampered_signed_state_and_new_target_collision(tmp_path: Path) -> None:
    workspace, service = _service(tmp_path)
    operation_key = "7" * 64
    result = service.apply(_plan(service), operation_key=operation_key)
    journal = service.operations.path(operation_key)
    tampered = read_json(journal)
    tampered["stage"] = "PREPARED"
    atomic_write_json(journal, tampered, mode=0o600)
    with pytest.raises(ProtocolError, match="CAPTURE_OPERATION_MISMATCH"):
        service.recover(operation_key)

    other_key = "6" * 64
    envelope = workspace.root / f"staging/captures/capture-{other_key}.json"
    envelope.parent.mkdir(parents=True, exist_ok=True)
    envelope.write_text("foreign bytes", encoding="utf-8")
    with pytest.raises(ProtocolError, match="CAPTURE_CONTENT_COLLISION"):
        service.apply(_plan(service, b"other\n"), operation_key=other_key)
    assert (workspace.root / result["asset_path"]).is_file()


def test_rollback_resumes_after_crash_between_signed_stage_and_restore(
    tmp_path: Path, monkeypatch
) -> None:
    workspace, service = _service(tmp_path)
    operation_key = "5" * 64
    result = service.apply(_plan(service), operation_key=operation_key)
    original_write = service.operations.write
    crashed = False

    def crash_after_restoring_stage(document) -> None:
        nonlocal crashed
        original_write(document)
        if (
            not crashed
            and document.get("stage") == "ROLLING_BACK"
            and any(
                entry.get("restore_state") == "RESTORING"
                for entry in document.get("rollback", [])
            )
        ):
            crashed = True
            raise SystemExit("rollback crash")

    monkeypatch.setattr(service.operations, "write", crash_after_restoring_stage)
    with pytest.raises(SystemExit, match="rollback crash"):
        service.rollback(operation_key)

    monkeypatch.setattr(service.operations, "write", original_write)
    recovered = service.rollback(operation_key)
    replayed = service.rollback(operation_key)
    assert recovered == replayed
    assert recovered["outcome"] == "ROLLED_BACK"
    assert not (workspace.root / result["capture_envelope_path"]).exists()
