from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.capture.admission import CaptureAdmissionService
from hive_protocol.capture.models import SourceRecord
from hive_protocol.capture.normalizers import NormalizerRegistry
from hive_protocol.cognition.authority import CognitionAuthority
from hive_protocol.cognition.extraction import DeterministicCognitionExtractor
from hive_protocol.cognition.models import CognitionEvent
from hive_protocol.cognition.store import CognitionStore
from hive_protocol.core import ProtocolError, canonical_bytes
from hive_protocol.product.shell_contracts import route_for
from hive_protocol.product.agent_adapter import (
    authorize_agent_capabilities,
    register_agent,
    submit_task,
)
from hive_protocol.product.shell_service import ShellService
from hive_protocol.product.workspace import HiveWorkspace
from hive_protocol.research.workspace import BoundedResearchWorkspaceStore
from hive_protocol.tasks.engine import TaskEngine, TaskIdentity


NOW = datetime(2026, 9, 1, 11, 0, tzinfo=timezone.utc)


def _identity(label: str) -> TaskIdentity:
    return TaskIdentity(
        persona_id=f"persona:{label}",
        surface_id=f"surface:{label}",
        machine_id=f"machine:{label}",
        project_id="HiveMind",
        app_actor=f"app:{label}",
    )


def _capture(
    service: CaptureAdmissionService,
    payload: bytes,
    *,
    media_type: str,
    filename: str,
    channel: str,
    operation_key: str,
) -> dict:
    plan = service.plan_bytes(
        payload,
        tenant_id="local-user",
        project_id="HiveMind",
        privacy_class="PROJECT_PRIVATE",
        channel=channel,
        source_owner="Owner",
        rights_assertion="USER_PROVIDED",
        media_type=media_type,
        filename=filename,
        destination="RESEARCH",
    )
    return service.apply(plan, operation_key=operation_key)


def _event(record: SourceRecord) -> CognitionEvent:
    anchor = record.anchors[0]
    return CognitionEvent.from_dict(
        {
            "schema_version": "hive.cognition-event.v1",
            "event_id": str(uuid4()),
            "tenant_id": "local-user",
            "project_id": "HiveMind",
            "event_type": "PROJECT_EVENT",
            "privacy_class": "PROJECT_PRIVATE",
            "experience_scope": {"kind": "DOMAIN", "owner_id": "HiveMind"},
            "title": "Projection decision",
            "text": "Decision: shell projections remain canonical and local.",
            "structured_claims": [],
            "evidence": [
                {
                    "source_id": record.source_id,
                    "anchor_id": anchor["anchor_id"],
                    "source_sha256": record.original_sha256,
                    "normalized_sha256": record.normalized_sha256,
                }
            ],
            "source_ref": "project-event:shell-projection",
            "source_sha256": record.original_sha256,
            "occurred_at": NOW.isoformat().replace("+00:00", "Z"),
            "recorded_at": NOW.isoformat().replace("+00:00", "Z"),
        }
    )


def _fixture(tmp_path: Path) -> tuple[HiveWorkspace, ShellService, str]:
    workspace = HiveWorkspace.create(tmp_path / "hive")
    workspace.configure_provider("retrieval-only")
    capture = CaptureAdmissionService(
        workspace,
        tmp_path / "capture-state",
        registry=NormalizerRegistry(),
        signing_key=Ed25519PrivateKey.generate(),
    )
    admitted = _capture(
        capture,
        b"Projection evidence remains anchored.\n",
        media_type="text/markdown",
        filename="projection.md",
        channel="MARKDOWN",
        operation_key="a" * 64,
    )
    queued = _capture(
        capture,
        b"%PDF-1.7 projection fixture",
        media_type="application/pdf",
        filename="queued.pdf",
        channel="PDF",
        operation_key="b" * 64,
    )
    record = SourceRecord.from_dict(
        json.loads(
            (workspace.root / admitted["source_record_path"]).read_text(
                encoding="utf-8"
            )
        )
    )

    BoundedResearchWorkspaceStore(workspace).create_workspace(
        workspace_id="research:projection",
        tenant_id="local-user",
        project_id="HiveMind",
        name="Projection research",
        privacy_class="PROJECT_PRIVATE",
        created_at=NOW.isoformat().replace("+00:00", "Z"),
    )
    authority = CognitionAuthority(
        workspace.root, trusted_reviewer_actors={"Owner"}
    )
    event = _event(record)
    candidate = DeterministicCognitionExtractor().extract(event, now=NOW).candidates[0]
    CognitionStore(workspace.root, authority).stage(event, candidate)

    creator_key = Ed25519PrivateKey.generate()
    engine = TaskEngine(workspace.root)
    creator = _identity("creator")
    worker = _identity("worker")
    engine.create(
        identity=creator,
        assignee=worker,
        operation="research.review",
        payload={"record": "projection"},
        capability="vault:search",
        source_refs=[{"uri": "source:projection", "sha256": "c" * 64}],
        private_key=creator_key,
        task_id="task-projection",
    )
    engine.transition(
        "task-projection",
        target="ASSIGNED",
        actor=creator,
        private_key=creator_key,
        expected_version=1,
        event_id="event-projection-assigned",
        nonce="n" * 32,
    )
    return (
        workspace,
        ShellService(workspace, tenant_id="local-user", project_ids={"HiveMind"}),
        str(queued["capture_id"]),
    )


def _read(service: ShellService, action: str, query: dict[str, str] | None = None):
    route = next(route for route in (route_for("GET", path) for path in (
        "/api/v1/home",
        "/api/v1/projects",
        "/api/v1/inbox",
        "/api/v1/capture",
        "/api/v1/research",
        "/api/v1/memory",
        "/api/v1/knowledge",
        "/api/v1/receipts",
        "/api/v1/settings",
    )) if route.action == action)
    return service.read(
        route,
        tenant_id="local-user",
        project_id="HiveMind",
        query=query or {},
    )


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
        and not path.is_symlink()
        and not path.name.startswith("index.sqlite3")
        and not path.name.startswith("intelligence.sqlite3")
    }


def test_home_projects_inbox_and_settings_project_canonical_state(tmp_path: Path) -> None:
    _, service, queued_capture_id = _fixture(tmp_path)

    home = _read(service, "home.read")["data"]
    projects = _read(service, "projects.read")["data"]
    inbox = _read(service, "inbox.read")["data"]
    settings = _read(service, "settings.read")["data"]

    assert [item["project_id"] for item in projects["projects"]] == ["HiveMind"]
    assert home["project_id"] == "HiveMind"
    assert home["counts"] == {
        "agents": 0,
        "captures": 2,
        "inbox": 3,
        "knowledge_nodes": 0,
        "memory_candidates": 1,
        "receipts": 7,
        "research_workspaces": 1,
        "sources": 2,
        "tasks": 1,
        "workflow_runs": 0,
    }
    assert [item["kind"] for item in inbox["items"]] == [
        "CAPTURE_DEGRADED",
        "GOVERNED_TASK",
        "MEMORY_REVIEW",
    ]
    assert inbox["items"][0]["item_id"] == queued_capture_id
    assert settings["privacy_mode"] == "local-only"
    assert settings["provider"]["states"] == {
        "authorized": False,
        "configured": True,
        "installed": False,
        "running": False,
        "verified": False,
        "working": False,
    }
    for adapter in settings["adapters"]:
        assert set(adapter["states"]) == {
            "authorized",
            "configured",
            "installed",
            "running",
            "verified",
            "working",
        }


def test_receipts_filter_and_preserve_verification_labels(tmp_path: Path) -> None:
    _, service, _ = _fixture(tmp_path)

    capture = _read(
        service,
        "receipts.read",
        {"project_id": "HiveMind", "lane": "capture", "outcome": "QUEUED_PROVIDER"},
    )["data"]
    task = _read(
        service,
        "receipts.read",
        {"project_id": "HiveMind", "actor": "app:creator", "limit": "10"},
    )["data"]

    assert len(capture["receipts"]) == 1
    assert capture["receipts"][0]["verification_state"] == "DIGEST_VERIFIED"
    assert len(task["receipts"]) == 1
    assert task["receipts"][0]["verification_state"] == "SIGNATURE_UNVERIFIED"
    assert task["receipts"][0]["key_id"].startswith("ed25519:")


def test_capture_receipt_digest_claims_must_bind_canonical_capture(
    tmp_path: Path,
) -> None:
    workspace, service, _ = _fixture(tmp_path)
    capture_receipt = next(
        path
        for path in workspace.receipts.glob("*.json")
        if "capture-operation" in path.name
    )
    document = json.loads(capture_receipt.read_text(encoding="utf-8"))
    document["original_sha256"] = "d" * 64
    capture_receipt.write_bytes(canonical_bytes(document) + b"\n")

    with pytest.raises(ProtocolError, match="OPERATOR_CANONICAL_RECORD_INVALID"):
        _read(service, "receipts.read")


def test_historical_receipt_missing_project_uses_default_but_foreign_fails_closed(
    tmp_path: Path,
) -> None:
    workspace, service, _ = _fixture(tmp_path)
    historical = {
        "schema_version": "legacy.receipt.v0",
        "recorded_at": NOW.isoformat().replace("+00:00", "Z"),
    }
    (workspace.receipts / "legacy-unscoped.json").write_bytes(
        canonical_bytes(historical) + b"\n"
    )
    projected = _read(service, "receipts.read")["data"]["receipts"]
    assert any(item["action"] == "historical-record" for item in projected)

    foreign = {**historical, "project_id": "OtherProject"}
    (workspace.receipts / "legacy-foreign.json").write_bytes(
        canonical_bytes(foreign) + b"\n"
    )
    with pytest.raises(ProtocolError, match="OPERATOR_CANONICAL_SCOPE_MISMATCH"):
        _read(service, "receipts.read")


def test_agent_receipt_projection_verifies_acknowledgment_before_path_use(
    tmp_path: Path,
) -> None:
    workspace, service, _ = _fixture(tmp_path)
    authorize_agent_capabilities(
        workspace.root, "Planner", "planner", ["vault:search"]
    )
    register_agent(workspace.root, "Planner", "planner", ["vault:search"])
    authorize_agent_capabilities(
        workspace.root, "Researcher", "researcher", ["vault:search"]
    )
    register_agent(workspace.root, "Researcher", "researcher", ["vault:search"])
    submitted = submit_task(
        workspace.root,
        agent_id="planner",
        recipient="researcher",
        capability="vault:search",
        task={"kind": "unsupported"},
    )
    receipt_path = (
        workspace.meta / "agent-operations" / "receipts" / f"{submitted['task_id']}.json"
    )
    acknowledgment = json.loads(receipt_path.read_text(encoding="utf-8"))
    acknowledgment["recipient_agent"] = "researcher/../researcher"
    receipt_path.write_bytes(canonical_bytes(acknowledgment) + b"\n")

    with pytest.raises(ProtocolError, match="OPERATOR_CANONICAL_RECORD_INVALID"):
        _read(service, "home.read")


def test_receipt_time_and_limit_filters_are_bounded(tmp_path: Path) -> None:
    _, service, _ = _fixture(tmp_path)

    data = _read(
        service,
        "receipts.read",
        {
            "project_id": "HiveMind",
            "from": "2026-09-01T00:00:00Z",
            "to": "2026-09-02T00:00:00Z",
            "limit": "2",
        },
    )["data"]
    assert len(data["receipts"]) <= 2
    with pytest.raises(ProtocolError, match="OPERATOR_RECEIPT_FILTER_INVALID"):
        _read(service, "receipts.read", {"limit": "0"})


def test_wrong_project_and_malformed_supported_records_fail_closed(
    tmp_path: Path,
) -> None:
    workspace, service, _ = _fixture(tmp_path)
    provenance = next(workspace.provenance.glob("source-*.json"))
    document = json.loads(provenance.read_text(encoding="utf-8"))
    document["project_id"] = "OtherProject"
    provenance.write_bytes(canonical_bytes(document) + b"\n")

    with pytest.raises(ProtocolError, match="OPERATOR_CANONICAL_SCOPE_MISMATCH"):
        _read(service, "home.read")

    workspace, service, _ = _fixture(tmp_path / "malformed")
    capture_receipt = next(
        path
        for path in workspace.receipts.glob("*.json")
        if "capture-operation" in path.name
    )
    capture_receipt.write_text('{"schema_version":"hive.capture-receipt.v1"}\n')
    with pytest.raises(ProtocolError, match="OPERATOR_CANONICAL_RECORD_INVALID"):
        _read(service, "receipts.read")


def test_projection_is_byte_stable_and_read_only_in_a_fresh_process(
    tmp_path: Path,
) -> None:
    workspace, service, _ = _fixture(tmp_path)
    before = _tree_bytes(workspace.root)
    first = _read(service, "home.read")
    code = (
        "import json,sys; from pathlib import Path; "
        "from hive_protocol.product.shell_contracts import route_for; "
        "from hive_protocol.product.shell_service import ShellService; "
        "from hive_protocol.product.workspace import HiveWorkspace; "
        "w=HiveWorkspace.open(Path(sys.argv[1])); "
        "s=ShellService(w,tenant_id='local-user',project_ids={'HiveMind'}); "
        "r=s.read(route_for('GET','/api/v1/home'),tenant_id='local-user',"
        "project_id='HiveMind',query={}); "
        "print(json.dumps(r,sort_keys=True,separators=(',',':')))"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code, str(workspace.root)],
        check=True,
        capture_output=True,
        text=True,
    )
    second = json.loads(completed.stdout)

    assert first == second
    assert _tree_bytes(workspace.root) == before


def test_corrupt_disposable_index_is_rebuilt_without_canonical_changes(
    tmp_path: Path,
) -> None:
    workspace, service, _ = _fixture(tmp_path)
    before = _tree_bytes(workspace.root)
    workspace.index_path.write_bytes(b"not-a-sqlite-database")

    result = _read(service, "home.read")

    assert result["outcome"] == "OK"
    assert _tree_bytes(workspace.root) == before
    assert workspace.index_path.read_bytes() != b"not-a-sqlite-database"


def test_capability_lane_projections_are_installed_and_project_scoped(
    tmp_path: Path,
) -> None:
    _, service, _ = _fixture(tmp_path)

    capture = _read(service, "capture.read")["data"]
    research = _read(service, "research.read")["data"]
    memory = _read(service, "memory.read")["data"]
    knowledge = _read(service, "knowledge.read")["data"]

    assert len(capture["sources"]) == 2
    assert len(capture["captures"]) == 2
    assert [item["workspace_id"] for item in research["workspaces"]] == [
        "research:projection"
    ]
    assert research["artifacts"] == []
    assert len(memory["candidates"]) == 1
    assert memory["reviews"] == []
    assert knowledge["nodes"] == []
