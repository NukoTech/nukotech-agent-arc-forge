from __future__ import annotations

import copy
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from hive_protocol.product.api import OperatorAPI
from hive_protocol.product.agent_adapter import authorize_agent_capabilities
from hive_protocol.product.shell_service import ShellService
from hive_protocol.product.workspace import HiveWorkspace
from hive_protocol.core import document_digest
from hive_protocol.storage import atomic_write_json, read_json

from test_workflow_product import SHA_A, SHA_B, _definition


NOW = datetime(2026, 9, 1, 15, 0, tzinfo=timezone.utc)
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


def _shell(tmp_path: Path, *, fault_hook=None):
    workspace = HiveWorkspace.create(tmp_path / "hive")
    service = ShellService(
        workspace,
        tenant_id="local-user",
        project_ids={"HiveMind"},
        now=NOW,
        workflow_agents_fault_hook=fault_hook,
    )
    api = OperatorAPI(
        workspace.root,
        service,
        tenant_id="local-user",
        project_ids={"HiveMind"},
    )
    return workspace, service, api


def _registration(
    agent_id: str,
    *,
    capabilities: list[str],
    project_ids: list[str] | None = None,
) -> dict:
    return {
        "persona": f"Director-{agent_id}",
        "agent_id": agent_id,
        "capabilities": sorted(capabilities),
        "machine_id": f"machine:{agent_id}",
        "surface_id": f"surface:{agent_id}",
        "project_ids": project_ids or ["HiveMind"],
        "app_actor": f"app:{agent_id}",
    }


def _register(api: OperatorAPI, agent_id: str, capabilities: list[str]) -> dict:
    scope = _registration(agent_id, capabilities=capabilities)
    authorization = _request(
        "agents.capabilities.authorize",
        {
            **scope,
            "expires_at": (NOW + timedelta(hours=8)).isoformat(),
            "attended_confirmation": True,
        },
        expected_version="ABSENT",
        key=f"authorize-{agent_id}",
    )
    authorized = _dispatch(
        api, "/api/v1/agents/capabilities/authorize", authorization
    )
    assert authorized.status == 200, _document(authorized)
    assert _document(authorized)["data"]["execution_started"] is False
    request = _request(
        "agents.register",
        scope,
        expected_version="ABSENT",
        key=f"register-{agent_id}",
    )
    result = _dispatch(api, "/api/v1/agents/register", request)
    assert result.status == 200, _document(result)
    return _document(result)


def test_agent_capability_authorization_requires_attended_confirmation(
    tmp_path: Path,
) -> None:
    workspace, _, api = _shell(tmp_path)
    scope = _registration("unconfirmed", capabilities=["vault:search"])
    result = _dispatch(
        api,
        "/api/v1/agents/capabilities/authorize",
        _request(
            "agents.capabilities.authorize",
            {
                **scope,
                "expires_at": (NOW + timedelta(hours=8)).isoformat(),
                "attended_confirmation": False,
            },
            expected_version="ABSENT",
            key="authorize-without-confirmation",
        ),
    )

    assert (
        _document(result)["reason_code"]
        == "AGENT_CAPABILITY_AUTHORIZATION_INVALID"
    )
    assert not (
        workspace.root
        / ".hive"
        / "agent-operations"
        / "grants"
        / "unconfirmed.json"
    ).exists()


def test_agent_registration_without_authoritative_grant_fails_before_writes(
    tmp_path: Path,
) -> None:
    workspace, _, api = _shell(tmp_path)
    result = _dispatch(
        api,
        "/api/v1/agents/register",
        _request(
            "agents.register",
            _registration("ungranted", capabilities=["vault:search"]),
            expected_version="ABSENT",
            key="register-without-grant",
        ),
    )

    assert _document(result)["reason_code"] == "AGENT_CAPABILITY_GRANT_MISSING"
    assert not (
        workspace.root / ".hive" / "agent-operations" / "registry.json"
    ).exists()
    assert not (
        workspace.root
        / ".hive"
        / "keys"
        / "agents"
        / "ungranted.private.pem"
    ).exists()


def test_agent_registration_rejects_capability_grant_scope_expansion_before_writes(
    tmp_path: Path,
) -> None:
    workspace, _, api = _shell(tmp_path)
    scope = _registration("scope-mismatch", capabilities=["vault:search"])
    authorize_agent_capabilities(
        workspace.root,
        scope["persona"],
        scope["agent_id"],
        scope["capabilities"],
        machine_id=scope["machine_id"],
        surface_id=scope["surface_id"],
        project_ids=scope["project_ids"],
        app_actor=scope["app_actor"],
        issued_at=NOW,
    )
    expanded = _registration(
        "scope-mismatch", capabilities=["task:acknowledge", "vault:search"]
    )
    result = _dispatch(
        api,
        "/api/v1/agents/register",
        _request(
            "agents.register",
            expanded,
            expected_version="ABSENT",
            key="register-expanded-grant",
        ),
    )

    assert _document(result)["reason_code"] == "AGENT_CAPABILITY_GRANT_SCOPE_MISMATCH"
    assert not (
        workspace.root / ".hive" / "agent-operations" / "registry.json"
    ).exists()
    assert not (
        workspace.root / ".hive" / "keys" / "agents" / "scope-mismatch.private.pem"
    ).exists()


def test_agent_registration_rejects_expired_or_tampered_capability_grant(
    tmp_path: Path,
) -> None:
    workspace, _, api = _shell(tmp_path)
    for agent_id, mutate, reason_code in (
        ("expired", False, "CAPABILITY_GRANT_EXPIRED"),
        ("tampered", True, "SIGNATURE_INVALID"),
    ):
        scope = _registration(agent_id, capabilities=["vault:search"])
        authorize_agent_capabilities(
            workspace.root,
            scope["persona"],
            scope["agent_id"],
            scope["capabilities"],
            machine_id=scope["machine_id"],
            surface_id=scope["surface_id"],
            project_ids=scope["project_ids"],
            app_actor=scope["app_actor"],
            issued_at=NOW - timedelta(hours=2) if not mutate else NOW,
            expires_at=NOW - timedelta(hours=1) if not mutate else None,
        )
        grant_path = (
            workspace.root
            / ".hive"
            / "agent-operations"
            / "grants"
            / f"{agent_id}.json"
        )
        if mutate:
            grant = read_json(grant_path)
            grant["machine_id"] = "machine:substituted"
            atomic_write_json(grant_path, grant, mode=0o600)
        result = _dispatch(
            api,
            "/api/v1/agents/register",
            _request(
                "agents.register",
                scope,
                expected_version="ABSENT",
                key=f"register-{agent_id}-invalid-grant",
            ),
        )
        assert _document(result)["reason_code"] == reason_code
        assert not (
            workspace.root / ".hive" / "keys" / "agents" / f"{agent_id}.private.pem"
        ).exists()


def test_agent_registration_and_governed_task_submission_are_inert_and_capability_bound(
    tmp_path: Path,
) -> None:
    workspace, _, api = _shell(tmp_path)
    sender = _register(api, "planner", ["vault:search"])
    worker = _register(api, "researcher", ["vault:search", "task:acknowledge"])
    assert sender["data"]["execution_started"] is False
    assert worker["data"]["execution_started"] is False

    task_request = _request(
        "agents.tasks.submit",
        {
            "creator_agent_id": "planner",
            "assignee_agent_id": "researcher",
            "task_id": str(uuid4()),
            "operation": "research.request",
            "capability": "vault:search",
            "payload": {
                "request_kind": "SEARCH",
                "summary": "Find the exact local evidence without executing it.",
            },
            "source_refs": [],
            "expires_at": (NOW + timedelta(minutes=10))
            .isoformat()
            .replace("+00:00", "Z"),
        },
        expected_version="ABSENT",
        key="submit-governed-task",
    )
    submitted = _dispatch(api, "/api/v1/agents/tasks/submit", task_request)
    assert submitted.status == 200, _document(submitted)
    task = _document(submitted)
    assert task["outcome"] == "APPLIED"
    assert task["changed"] is True
    assert task["data"]["execution_started"] is False
    assert task["data"]["task"]["state"] == "CREATED"
    assert task["data"]["task"]["capability"] == "vault:search"
    assert task["data"]["task"]["created_at"] == NOW.isoformat().replace(
        "+00:00", "Z"
    )
    assert not (workspace.root / ".hive" / "agent-task-state").exists()

    replay = _dispatch(api, "/api/v1/agents/tasks/submit", task_request)
    assert replay.status == 200
    assert _document(replay)["changed"] is False
    assert len(list((workspace.root / "tasks").glob("*.json"))) == 1

    broadened = _dispatch(
        api,
        "/api/v1/agents/tasks/submit",
        _request(
            "agents.tasks.submit",
            {
                **task_request["input"],
                "task_id": str(uuid4()),
                "capability": "workflow:report",
            },
            expected_version="ABSENT",
            key="submit-broadened-task",
        ),
    )
    assert _document(broadened)["reason_code"] == "AGENT_CAPABILITY_DENIED"

    executable = _dispatch(
        api,
        "/api/v1/agents/tasks/submit",
        _request(
            "agents.tasks.submit",
            {
                **task_request["input"],
                "task_id": str(uuid4()),
                "payload": {"command": "python -c pass"},
            },
            expected_version="ABSENT",
            key="submit-executable-task",
        ),
    )
    assert _document(executable)["reason_code"] == "OPERATOR_EXECUTABLE_INPUT_DENIED"
    assert len(list((workspace.root / "tasks").glob("*.json"))) == 1


def test_agent_registration_refuses_wrong_project_and_identity_collapse(
    tmp_path: Path,
) -> None:
    workspace, _, api = _shell(tmp_path)
    wrong_project = _dispatch(
        api,
        "/api/v1/agents/register",
        _request(
            "agents.register",
            _registration(
                "outsider",
                capabilities=["vault:search"],
                project_ids=["OtherProject"],
            ),
            expected_version="ABSENT",
            key="register-wrong-project",
        ),
    )
    assert _document(wrong_project)["reason_code"] == "AGENT_SCOPE_INVALID"

    collapsed_input = _registration("collapsed", capabilities=["vault:search"])
    collapsed_input["surface_id"] = collapsed_input["machine_id"]
    collapsed = _dispatch(
        api,
        "/api/v1/agents/register",
        _request(
            "agents.register",
            collapsed_input,
            expected_version="ABSENT",
            key="register-collapsed-identity",
        ),
    )
    assert _document(collapsed)["reason_code"] == "AGENT_IDENTITY_COLLAPSE"
    assert not (
        workspace.root / ".hive" / "agent-operations" / "registry.json"
    ).exists()

    registered = _register(api, "stable-agent", ["vault:search"])
    changed_registration = _dispatch(
        api,
        "/api/v1/agents/register",
        _request(
            "agents.register",
            _registration(
                "stable-agent",
                capabilities=["vault:search", "workflow:report"],
            ),
            expected_version=registered["object_version"],
            key="register-existing-capability-change",
        ),
    )
    assert (
        _document(changed_registration)["reason_code"]
        == "AGENT_REGISTRATION_CONFLICT"
    )


def test_attended_workflow_control_room_completes_without_starting_execution(
    tmp_path: Path, monkeypatch
) -> None:
    workspace, _, api = _shell(tmp_path)
    _register(api, "researcher", ["vault:search"])

    def forbidden(*_args, **_kwargs):
        raise AssertionError("operator control room attempted hidden execution")

    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("subprocess.run", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("threading.Thread.start", forbidden)
    monkeypatch.setattr(
        "hive_protocol.adapters.runtime.AdapterRuntime.invoke",
        forbidden,
    )

    definition = _definition("machine:researcher")
    preview_request = _request(
        "workflows.definitions.preview",
        {"definition": definition},
        expected_version="ABSENT",
        key="workflow-definition-preview",
    )
    preview = _dispatch(
        api, "/api/v1/workflows/definitions/preview", preview_request
    )
    assert preview.status == 200, _document(preview)
    assert _document(preview)["changed"] is False
    assert _document(preview)["data"]["execution_started"] is False

    published = _dispatch(
        api,
        "/api/v1/workflows/definitions/publish",
        _request(
            "workflows.definitions.publish",
            {"definition": definition},
            expected_version="ABSENT",
            key="workflow-definition-publish",
        ),
    )
    assert published.status == 200, _document(published)
    published_document = _document(published)
    assert published_document["data"]["execution_started"] is False

    run_id = str(uuid4())
    launched = _dispatch(
        api,
        "/api/v1/workflows/runs/launch",
        _request(
            "workflows.runs.launch",
            {
                "workflow_id": "workflow:product",
                "version": 1,
                "run_id": run_id,
                "source_commit": SHA_A,
                "input_manifest_sha256": SHA_B,
                "event_id": str(uuid4()),
                "stale_after_seconds": 600,
                "max_concurrent_claims": 2,
            },
            expected_version="ABSENT",
            key="workflow-run-launch",
        ),
    )
    assert launched.status == 200, _document(launched)
    launched_document = _document(launched)
    assert launched_document["data"]["execution_started"] is False

    readiness_input = {
        "run_id": run_id,
        "step_id": "research",
        "attempt": 1,
        "current_source_commit": SHA_A,
        "current_machine_id": "machine:researcher",
        "task_sha256": "c" * 64,
        "existing_task_sha256s": [],
        "required_evidence_refs": [],
        "available_evidence_refs": [],
        "approvals": [],
        "explicit_agent_id": None,
    }
    readiness = _dispatch(
        api,
        "/api/v1/workflows/readiness",
        _request(
            "workflows.readiness",
            readiness_input,
            expected_version=launched_document["object_version"],
            key="workflow-readiness",
        ),
    )
    assert readiness.status == 200, _document(readiness)
    readiness_document = _document(readiness)
    readiness_view = readiness_document["data"]["readiness"]
    assert readiness_view["ready"] is True
    assert readiness_view["execution_started"] is False

    claim = _dispatch(
        api,
        "/api/v1/workflows/claims/create",
        _request(
            "workflows.claims.create",
            {
                "run_id": run_id,
                "readiness": readiness_view,
                "agent_id": "researcher",
                "expires_at": (NOW + timedelta(minutes=5))
                .isoformat()
                .replace("+00:00", "Z"),
                "event_id": str(uuid4()),
                "approvals": [],
            },
            expected_version=readiness_document["object_version"],
            key="workflow-claim-create",
        ),
    )
    assert claim.status == 200, _document(claim)
    claim_document = _document(claim)
    assert claim_document["data"]["execution_started"] is False
    claim_result = claim_document["data"]["claim"]

    task_id = str(uuid4())
    delivered = _dispatch(
        api,
        "/api/v1/workflows/tasks/deliver",
        _request(
            "workflows.tasks.deliver",
            {
                "run_id": run_id,
                "claim_event_id": claim_result["event"]["event_id"],
                "task_id": task_id,
                "nonce": "workflow-delivery-nonce",
                "issued_at": NOW.isoformat().replace("+00:00", "Z"),
                "expires_at": (NOW + timedelta(minutes=5))
                .isoformat()
                .replace("+00:00", "Z"),
            },
            expected_version=claim_document["object_version"],
            key="workflow-deliver",
        ),
    )
    assert delivered.status == 200, _document(delivered)
    delivered_document = _document(delivered)
    assert delivered_document["data"]["execution_started"] is False
    assert not (workspace.root / ".hive" / "agent-task-state" / f"{task_id}.json").exists()

    session_id = str(uuid4())
    started = _dispatch(
        api,
        "/api/v1/workflows/sessions/start",
        _request(
            "workflows.sessions.start",
            {
                "run_id": run_id,
                "claim_event_id": claim_result["event"]["event_id"],
                "session_id": session_id,
                "total_units": 1,
                "current_source_commit": SHA_A,
                "current_input_sha256": claim_result["claim"]["input_sha256"],
                "event_id": str(uuid4()),
            },
            expected_version=delivered_document["object_version"],
            key="workflow-session-start",
        ),
    )
    assert started.status == 200, _document(started)
    started_document = _document(started)
    assert started_document["data"]["execution_started"] is False

    completed_step = _dispatch(
        api,
        "/api/v1/workflows/sessions/record",
        _request(
            "workflows.sessions.record",
            {
                "run_id": run_id,
                "session_id": session_id,
                "event_type": "STEP_COMPLETED",
                "state": "COMPLETED",
                "progress": {"completed_units": 1, "total_units": 1},
                "resources": {
                    "tokens_used": 25,
                    "cost_microunits": 50,
                    "peak_memory_mb": 32,
                },
                "outputs": [
                    {
                        "name": "result",
                        "type": "application/json",
                        "sha256": SHA_B,
                        "evidence_refs": ["evidence:shell-workflow"],
                    }
                ],
                "current_source_commit": SHA_A,
                "current_input_sha256": claim_result["claim"]["input_sha256"],
                "event_id": str(uuid4()),
            },
            expected_version=started_document["object_version"],
            key="workflow-session-complete",
        ),
    )
    assert completed_step.status == 200, _document(completed_step)
    completed_step_document = _document(completed_step)
    assert completed_step_document["data"]["execution_started"] is False

    completed_run = _dispatch(
        api,
        "/api/v1/workflows/runs/complete",
        _request(
            "workflows.runs.complete",
            {
                "run_id": run_id,
                "event_id": str(uuid4()),
                "attended_confirmation": True,
            },
            expected_version=completed_step_document["object_version"],
            key="workflow-run-complete",
        ),
    )
    assert completed_run.status == 200, _document(completed_run)
    completed_run_document = _document(completed_run)
    assert completed_run_document["data"]["execution_started"] is False

    projection = api.dispatch_read(
        "GET",
        "/api/v1/workflows",
        tenant_id="local-user",
        project_id="HiveMind",
        query={"project_id": "HiveMind"},
    )
    assert projection.status == 200
    workflows = projection.response.as_dict()["data"]["workflows"]
    selected = next(item for item in workflows if item["run"]["run_id"] == run_id)
    assert selected["projection"]["state"] == "COMPLETED"

    agents_projection = api.dispatch_read(
        "GET",
        "/api/v1/agents",
        tenant_id="local-user",
        project_id="HiveMind",
        query={"project_id": "HiveMind"},
    )
    assert agents_projection.status == 200, _document(agents_projection)
    agents_data = _document(agents_projection)["data"]
    registered = next(
        item for item in agents_data["agents"] if item["agent_id"] == "researcher"
    )
    assert registered["capabilities"] == ["vault:search"]
    assert any(item["session_id"] == session_id for item in agents_data["sessions"])
    resources = next(
        item for item in agents_data["resource_summaries"] if item["run_id"] == run_id
    )
    assert resources["resources"]["tokens_used"] == 25
    health = next(
        item for item in agents_data["agent_health"] if item["agent_id"] == "researcher"
    )
    assert health == {
        "agent_id": "researcher",
        "active": True,
        "status": "REGISTERED_ATTENDED",
    }


def test_workflow_definition_refuses_executable_fields_before_publication(
    tmp_path: Path,
) -> None:
    workspace, _, api = _shell(tmp_path)
    definition = _definition("machine:researcher")
    definition["steps"][0]["command"] = "python -c pass"
    refused = _dispatch(
        api,
        "/api/v1/workflows/definitions/publish",
        _request(
            "workflows.definitions.publish",
            {"definition": definition},
            expected_version="ABSENT",
            key="workflow-executable-definition",
        ),
    )
    assert _document(refused)["reason_code"] == "OPERATOR_EXECUTABLE_INPUT_DENIED"
    assert not (workspace.root / "workflows" / "definitions").exists()


def _publish_and_launch(
    api: OperatorAPI,
    definition: dict,
    *,
    label: str,
) -> tuple[str, dict]:
    published = _dispatch(
        api,
        "/api/v1/workflows/definitions/publish",
        _request(
            "workflows.definitions.publish",
            {"definition": definition},
            expected_version="ABSENT",
            key=f"{label}-definition-publish",
        ),
    )
    assert published.status == 200, _document(published)
    run_id = str(uuid4())
    launched = _dispatch(
        api,
        "/api/v1/workflows/runs/launch",
        _request(
            "workflows.runs.launch",
            {
                "workflow_id": definition["workflow_id"],
                "version": definition["version"],
                "run_id": run_id,
                "source_commit": SHA_A,
                "input_manifest_sha256": SHA_B,
                "event_id": str(uuid4()),
                "stale_after_seconds": 30,
                "max_concurrent_claims": 2,
            },
            expected_version="ABSENT",
            key=f"{label}-workflow-launch",
        ),
    )
    assert launched.status == 200, _document(launched)
    return run_id, _document(launched)


def _workflow_readiness(
    api: OperatorAPI,
    run_id: str,
    expected_version: str,
    *,
    key: str,
    source_commit: str = SHA_A,
    approvals: list | None = None,
) -> dict:
    result = _dispatch(
        api,
        "/api/v1/workflows/readiness",
        _request(
            "workflows.readiness",
            {
                "run_id": run_id,
                "step_id": "research",
                "attempt": 1,
                "current_source_commit": source_commit,
                "current_machine_id": "machine:researcher",
                "task_sha256": "c" * 64,
                "existing_task_sha256s": [],
                "required_evidence_refs": [],
                "available_evidence_refs": [],
                "approvals": approvals or [],
                "explicit_agent_id": None,
            },
            expected_version=expected_version,
            key=key,
        ),
    )
    assert result.status == 200, _document(result)
    return _document(result)


def test_protected_approval_conflict_record_and_cancellation_are_exact(
    tmp_path: Path,
) -> None:
    workspace, _, api = _shell(tmp_path)
    _register(api, "researcher", ["vault:search"])
    run_id, launched = _publish_and_launch(
        api,
        _definition("machine:researcher", approval=True),
        label="protected",
    )
    blocked = _workflow_readiness(
        api,
        run_id,
        launched["object_version"],
        key="protected-readiness-blocked",
    )
    readiness = blocked["data"]["readiness"]
    assert "APPROVAL_REQUIRED" in {item["code"] for item in readiness["blockers"]}

    preview_result = _dispatch(
        api,
        "/api/v1/workflows/approvals/preview",
        _request(
            "workflows.approvals.preview",
            {
                "run_id": run_id,
                "readiness": readiness,
                "action": "run attended project research",
                "destination": "research/product.json",
                "expires_at": (NOW + timedelta(minutes=10))
                .isoformat()
                .replace("+00:00", "Z"),
            },
            expected_version=blocked["object_version"],
            key="protected-approval-preview",
        ),
    )
    assert preview_result.status == 200, _document(preview_result)
    preview_document = _document(preview_result)
    preview = preview_document["data"]["approval_preview"]

    changed_preview = {**preview, "destination": "another/path.json"}
    laundered = _dispatch(
        api,
        "/api/v1/workflows/approvals/approve",
        _request(
            "workflows.approvals.approve",
            {
                "run_id": run_id,
                "preview": changed_preview,
                "preview_operation_key": preview_document["data"][
                    "preview_operation_key"
                ],
                "binding": {
                    "kind": "STEP_APPROVAL",
                    "readiness": readiness,
                },
                "authorization_ref": "attended:changed-preview",
                "approval_id": str(uuid4()),
            },
            expected_version=preview_document["object_version"],
            key="protected-laundered-approval",
        ),
    )
    assert _document(laundered)["reason_code"] == "WORKFLOW_APPROVAL_BINDING_MISMATCH"

    approved_result = _dispatch(
        api,
        "/api/v1/workflows/approvals/approve",
        _request(
            "workflows.approvals.approve",
            {
                "run_id": run_id,
                "preview": preview,
                "preview_operation_key": preview_document["data"][
                    "preview_operation_key"
                ],
                "binding": {
                    "kind": "STEP_APPROVAL",
                    "readiness": readiness,
                },
                "authorization_ref": "attended:exact-preview",
                "approval_id": str(uuid4()),
            },
            expected_version=preview_document["object_version"],
            key="protected-exact-approval",
        ),
    )
    assert approved_result.status == 200, _document(approved_result)
    approved_document = _document(approved_result)
    approval = approved_document["data"]["approval"]["approval"]

    ready = _workflow_readiness(
        api,
        run_id,
        approved_document["object_version"],
        key="protected-readiness-approved",
        approvals=[{"preview": preview, "approval": approval}],
    )
    assert ready["data"]["readiness"]["ready"] is True

    conflict_view = _workflow_readiness(
        api,
        run_id,
        ready["object_version"],
        key="protected-conflict-view",
        source_commit=SHA_B,
    )
    conflict_readiness = conflict_view["data"]["readiness"]
    assert "STALE_SOURCE_COMMIT" in {
        item["code"] for item in conflict_readiness["blockers"]
    }
    recorded = _dispatch(
        api,
        "/api/v1/workflows/conflicts/record",
        _request(
            "workflows.conflicts.record",
            {
                "run_id": run_id,
                "readiness": conflict_readiness,
                "event_id": str(uuid4()),
                "attended_confirmation": True,
                "approvals": [],
            },
            expected_version=conflict_view["object_version"],
            key="protected-conflict-record",
        ),
    )
    assert recorded.status == 200, _document(recorded)
    recorded_document = _document(recorded)

    cancelled = _dispatch(
        api,
        "/api/v1/workflows/runs/cancel",
        _request(
            "workflows.runs.cancel",
            {
                "run_id": run_id,
                "event_id": str(uuid4()),
                "attended_confirmation": True,
            },
            expected_version=recorded_document["object_version"],
            key="protected-run-cancel",
        ),
    )
    assert cancelled.status == 200, _document(cancelled)
    assert _document(cancelled)["data"]["execution_started"] is False
    execution_state = workspace.root / ".hive" / "agent-task-state"
    assert not execution_state.exists() or not list(execution_state.glob("*.json"))


def test_stale_takeover_requires_exact_approval_and_retry_is_single_use(
    tmp_path: Path,
) -> None:
    workspace, service, api = _shell(tmp_path)
    _register(api, "researcher", ["vault:search"])
    run_id, launched = _publish_and_launch(
        api,
        _definition("machine:researcher"),
        label="stale",
    )
    readiness = _workflow_readiness(
        api,
        run_id,
        launched["object_version"],
        key="stale-readiness-view",
    )
    claim_result = _dispatch(
        api,
        "/api/v1/workflows/claims/create",
        _request(
            "workflows.claims.create",
            {
                "run_id": run_id,
                "readiness": readiness["data"]["readiness"],
                "agent_id": "researcher",
                "expires_at": (NOW + timedelta(minutes=5))
                .isoformat()
                .replace("+00:00", "Z"),
                "event_id": str(uuid4()),
                "approvals": [],
            },
            expected_version=readiness["object_version"],
            key="stale-workflow-claim",
        ),
    )
    assert claim_result.status == 200, _document(claim_result)
    claim_document = _document(claim_result)
    claim = claim_document["data"]["claim"]
    session_id = str(uuid4())
    started = _dispatch(
        api,
        "/api/v1/workflows/sessions/start",
        _request(
            "workflows.sessions.start",
            {
                "run_id": run_id,
                "claim_event_id": claim["event"]["event_id"],
                "session_id": session_id,
                "total_units": 1,
                "current_source_commit": SHA_A,
                "current_input_sha256": claim["claim"]["input_sha256"],
                "event_id": str(uuid4()),
            },
            expected_version=claim_document["object_version"],
            key="stale-session-start",
        ),
    )
    assert started.status == 200, _document(started)
    later = NOW + timedelta(seconds=31)
    service._clock = lambda: later

    preview_result = _dispatch(
        api,
        "/api/v1/workflows/stale/preview",
        _request(
            "workflows.stale.preview",
            {
                "run_id": run_id,
                "session_id": session_id,
                "expires_at": (later + timedelta(minutes=10))
                .isoformat()
                .replace("+00:00", "Z"),
            },
            expected_version=_document(started)["object_version"],
            key="stale-release-preview",
        ),
    )
    assert preview_result.status == 200, _document(preview_result)
    preview_document = _document(preview_result)
    preview = preview_document["data"]["stale_preview"]
    approved_result = _dispatch(
        api,
        "/api/v1/workflows/approvals/approve",
        _request(
            "workflows.approvals.approve",
            {
                "run_id": run_id,
                "preview": preview,
                "preview_operation_key": preview_document["data"][
                    "preview_operation_key"
                ],
                "binding": {
                    "kind": "STALE_RELEASE",
                    "session_id": session_id,
                },
                "authorization_ref": "attended:stale-release",
                "approval_id": str(uuid4()),
            },
            expected_version=preview_document["object_version"],
            key="stale-release-approval",
        ),
    )
    assert approved_result.status == 200, _document(approved_result)
    approved_document = _document(approved_result)
    approval = approved_document["data"]["approval"]["approval"]
    released = _dispatch(
        api,
        "/api/v1/workflows/stale/apply",
        _request(
            "workflows.stale.apply",
            {
                "run_id": run_id,
                "session_id": session_id,
                "preview": preview,
                "approval": approval,
                "abandonment_event_id": str(uuid4()),
                "release_event_id": str(uuid4()),
            },
            expected_version=approved_document["object_version"],
            key="stale-release-apply",
        ),
    )
    assert released.status == 200, _document(released)
    released_document = _document(released)
    assert released_document["data"]["execution_started"] is False

    retry_event_id = str(uuid4())
    retry = _dispatch(
        api,
        "/api/v1/workflows/retries/create",
        _request(
            "workflows.retries.create",
            {
                "run_id": run_id,
                "step_id": "research",
                "failed_attempt": 1,
                "event_id": retry_event_id,
            },
            expected_version=released_document["object_version"],
            key="stale-retry-create",
        ),
    )
    assert retry.status == 200, _document(retry)
    retry_document = _document(retry)
    assert retry_document["data"]["retry"]["new_attempt"] == 2
    duplicate = _dispatch(
        api,
        "/api/v1/workflows/retries/create",
        _request(
            "workflows.retries.create",
            {
                "run_id": run_id,
                "step_id": "research",
                "failed_attempt": 1,
                "event_id": str(uuid4()),
            },
            expected_version=retry_document["object_version"],
            key="stale-retry-duplicate",
        ),
    )
    assert _document(duplicate)["reason_code"] == "WORKFLOW_RETRY_ALREADY_AUTHORIZED"
    execution_state = workspace.root / ".hive" / "agent-task-state"
    assert not execution_state.exists() or not list(execution_state.glob("*.json"))


def test_portable_rollback_restores_only_an_exact_approved_git_checkpoint(
    tmp_path: Path,
) -> None:
    workspace, service, api = _shell(tmp_path)
    _register(api, "researcher", ["vault:search"])
    run_id, launched = _publish_and_launch(
        api,
        _definition("machine:researcher"),
        label="rollback",
    )
    portable = workspace.sources / "portable.md"
    portable.write_text("checkpoint\n", encoding="utf-8")
    checkpoint = workspace.snapshot("shell rollback checkpoint")["commit"]
    portable.write_text("mutated\n", encoding="utf-8")
    workspace.snapshot("shell rollback mutation")
    service._clock = lambda: NOW + timedelta(minutes=1)

    preview_result = _dispatch(
        api,
        "/api/v1/workflows/rollback/preview",
        _request(
            "workflows.rollback.preview",
            {
                "run_id": run_id,
                "step_id": "research",
                "attempt": 1,
                "checkpoint": checkpoint,
                "expires_at": (NOW + timedelta(minutes=10))
                .isoformat()
                .replace("+00:00", "Z"),
            },
            expected_version=launched["object_version"],
            key="rollback-checkpoint-preview",
        ),
    )
    assert preview_result.status == 200, _document(preview_result)
    preview_document = _document(preview_result)
    preview = preview_document["data"]["rollback_preview"]
    approval_result = _dispatch(
        api,
        "/api/v1/workflows/approvals/approve",
        _request(
            "workflows.approvals.approve",
            {
                "run_id": run_id,
                "preview": preview,
                "preview_operation_key": preview_document["data"][
                    "preview_operation_key"
                ],
                "binding": {
                    "kind": "ROLLBACK",
                    "step_id": "research",
                    "attempt": 1,
                    "checkpoint": checkpoint,
                },
                "authorization_ref": "attended:portable-rollback",
                "approval_id": str(uuid4()),
            },
            expected_version=preview_document["object_version"],
            key="rollback-checkpoint-approval",
        ),
    )
    assert approval_result.status == 200, _document(approval_result)
    approval_document = _document(approval_result)
    approval = approval_document["data"]["approval"]["approval"]
    applied = _dispatch(
        api,
        "/api/v1/workflows/rollback/apply",
        _request(
            "workflows.rollback.apply",
            {
                "run_id": run_id,
                "preview": preview,
                "approval": approval,
                "start_event_id": str(uuid4()),
                "complete_event_id": str(uuid4()),
            },
            expected_version=approval_document["object_version"],
            key="rollback-checkpoint-apply",
        ),
    )
    assert applied.status == 200, _document(applied)
    assert _document(applied)["data"]["execution_started"] is False
    assert portable.read_text(encoding="utf-8") == "checkpoint\n"


def test_declared_compensation_requires_separate_exact_approval(
    tmp_path: Path,
) -> None:
    workspace, service, api = _shell(tmp_path)
    _register(api, "researcher", ["vault:search"])
    definition = _definition("machine:researcher")
    definition["workflow_id"] = "workflow:compensation"
    definition["steps"][0]["rollback"] = {
        "mode": "COMPENSATION",
        "compensation_step_id": "recover",
    }
    recovery = copy.deepcopy(definition["steps"][0])
    recovery.update(
        {
            "step_id": "recover",
            "kind": "COMPENSATION",
            "dependencies": [],
            "inputs": [],
            "outputs": [{"name": "recovery", "type": "application/json"}],
            "approval": {"required": True, "risk_class": "HIGH"},
            "ownership": {
                "branches": ["workflows/recovery"],
                "files": ["research/recovery.json"],
            },
            "rollback": {
                "mode": "GIT_CHECKPOINT",
                "compensation_step_id": None,
            },
        }
    )
    definition["steps"].append(recovery)
    run_id, launched = _publish_and_launch(api, definition, label="compensation")
    readiness = _workflow_readiness(
        api,
        run_id,
        launched["object_version"],
        key="compensation-readiness",
    )
    claimed = _dispatch(
        api,
        "/api/v1/workflows/claims/create",
        _request(
            "workflows.claims.create",
            {
                "run_id": run_id,
                "readiness": readiness["data"]["readiness"],
                "agent_id": "researcher",
                "expires_at": (NOW + timedelta(minutes=5))
                .isoformat()
                .replace("+00:00", "Z"),
                "event_id": str(uuid4()),
                "approvals": [],
            },
            expected_version=readiness["object_version"],
            key="compensation-workflow-claim",
        ),
    )
    assert claimed.status == 200, _document(claimed)
    claim_document = _document(claimed)
    claim = claim_document["data"]["claim"]
    session_id = str(uuid4())
    started = _dispatch(
        api,
        "/api/v1/workflows/sessions/start",
        _request(
            "workflows.sessions.start",
            {
                "run_id": run_id,
                "claim_event_id": claim["event"]["event_id"],
                "session_id": session_id,
                "total_units": 1,
                "current_source_commit": SHA_A,
                "current_input_sha256": claim["claim"]["input_sha256"],
                "event_id": str(uuid4()),
            },
            expected_version=claim_document["object_version"],
            key="compensation-session-start",
        ),
    )
    assert started.status == 200, _document(started)
    failed_at = NOW + timedelta(minutes=1)
    service._clock = lambda: failed_at
    failed = _dispatch(
        api,
        "/api/v1/workflows/sessions/record",
        _request(
            "workflows.sessions.record",
            {
                "run_id": run_id,
                "session_id": session_id,
                "event_type": "STEP_FAILED",
                "state": "FAILED",
                "progress": {"completed_units": 0, "total_units": 1},
                "resources": {
                    "tokens_used": 0,
                    "cost_microunits": 0,
                    "peak_memory_mb": 0,
                },
                "outputs": [],
                "current_source_commit": SHA_A,
                "current_input_sha256": claim["claim"]["input_sha256"],
                "event_id": str(uuid4()),
            },
            expected_version=_document(started)["object_version"],
            key="compensation-session-failed",
        ),
    )
    assert failed.status == 200, _document(failed)
    failed_document = _document(failed)
    preview_result = _dispatch(
        api,
        "/api/v1/workflows/compensation/preview",
        _request(
            "workflows.compensation.preview",
            {
                "run_id": run_id,
                "failed_step_id": "research",
                "failed_attempt": 1,
                "expires_at": (failed_at + timedelta(minutes=10))
                .isoformat()
                .replace("+00:00", "Z"),
            },
            expected_version=failed_document["object_version"],
            key="compensation-exact-preview",
        ),
    )
    assert preview_result.status == 200, _document(preview_result)
    preview_document = _document(preview_result)
    preview = preview_document["data"]["compensation_preview"]
    approved = _dispatch(
        api,
        "/api/v1/workflows/approvals/approve",
        _request(
            "workflows.approvals.approve",
            {
                "run_id": run_id,
                "preview": preview,
                "preview_operation_key": preview_document["data"][
                    "preview_operation_key"
                ],
                "binding": {
                    "kind": "COMPENSATION",
                    "failed_step_id": "research",
                    "failed_attempt": 1,
                },
                "authorization_ref": "attended:declared-compensation",
                "approval_id": str(uuid4()),
            },
            expected_version=preview_document["object_version"],
            key="compensation-exact-approval",
        ),
    )
    assert approved.status == 200, _document(approved)
    approved_document = _document(approved)
    authorized = _dispatch(
        api,
        "/api/v1/workflows/compensation/authorize",
        _request(
            "workflows.compensation.authorize",
            {
                "run_id": run_id,
                "failed_step_id": "research",
                "failed_attempt": 1,
                "preview": preview,
                "approval": approved_document["data"]["approval"]["approval"],
                "event_id": str(uuid4()),
            },
            expected_version=approved_document["object_version"],
            key="compensation-exact-authorize",
        ),
    )
    assert authorized.status == 200, _document(authorized)
    assert _document(authorized)["data"]["execution_started"] is False
    execution_state = workspace.root / ".hive" / "agent-task-state"
    assert not execution_state.exists() or not list(execution_state.glob("*.json"))


def test_definition_diff_is_read_only_scoped_and_requires_two_exact_versions(
    tmp_path: Path,
) -> None:
    workspace, _, api = _shell(tmp_path)
    _register(api, "researcher", ["vault:search"])
    first_definition = _definition("machine:researcher")
    first = _dispatch(
        api,
        "/api/v1/workflows/definitions/publish",
        _request(
            "workflows.definitions.publish",
            {"definition": first_definition},
            expected_version="ABSENT",
            key="definition-diff-publish-one",
        ),
    )
    assert first.status == 200, _document(first)
    signed_first = _document(first)["data"]["publication"]["definition"]
    second_definition = copy.deepcopy(first_definition)
    second_definition.update(
        {
            "version": 2,
            "parent_digest": document_digest(signed_first),
            "title": "Product workflow improved",
        }
    )
    second = _dispatch(
        api,
        "/api/v1/workflows/definitions/publish",
        _request(
            "workflows.definitions.publish",
            {"definition": second_definition},
            expected_version="ABSENT",
            key="definition-diff-publish-two",
        ),
    )
    assert second.status == 200, _document(second)

    private_workflow_keys = workspace.root / ".hive" / "keys" / "workflows"
    shutil.rmtree(private_workflow_keys)
    before = sorted(path.relative_to(workspace.root) for path in workspace.root.rglob("*"))
    result = api.dispatch_read(
        "GET",
        "/api/v1/workflows",
        tenant_id="local-user",
        project_id="HiveMind",
        query={
            "project_id": "HiveMind",
            "workflow_id": "workflow:product",
            "from_version": "1",
            "to_version": "2",
        },
    )
    after = sorted(path.relative_to(workspace.root) for path in workspace.root.rglob("*"))
    assert result.status == 200, _document(result)
    diff = _document(result)["data"]["definition_diff"]
    assert diff["from_version"] == 1
    assert diff["to_version"] == 2
    assert any(change["path"].endswith("title") for change in diff["changes"])
    assert before == after
    assert not private_workflow_keys.exists()

    partial = api.dispatch_read(
        "GET",
        "/api/v1/workflows",
        tenant_id="local-user",
        project_id="HiveMind",
        query={"project_id": "HiveMind", "workflow_id": "workflow:product"},
    )
    assert _document(partial)["reason_code"] == "WORKFLOW_DEFINITION_DIFF_INVALID"


def test_lost_results_recover_each_workflow_boundary_with_one_history(
    tmp_path: Path,
) -> None:
    armed: dict[str, str | None] = {"stage": None}

    def crash_once(stage: str) -> None:
        if armed["stage"] == stage:
            armed["stage"] = None
            raise RuntimeError("simulated lost workflow result")

    workspace, service, api = _shell(tmp_path, fault_hook=crash_once)

    def crash_replay(path: str, request: dict, stage: str) -> dict:
        armed["stage"] = stage
        lost = _dispatch(api, path, request)
        assert lost.status == 500, _document(lost)
        replayed = _dispatch(api, path, request)
        assert replayed.status == 200, _document(replayed)
        document = _document(replayed)
        assert document["changed"] is False
        assert document["data"]["execution_started"] is False
        return document

    registration = _request(
        "agents.register",
        _registration("researcher", capabilities=["vault:search"]),
        expected_version="ABSENT",
        key="recovery-register-researcher",
    )
    registration_scope = registration["input"]
    authorize_agent_capabilities(
        workspace.root,
        registration_scope["persona"],
        registration_scope["agent_id"],
        registration_scope["capabilities"],
        machine_id=registration_scope["machine_id"],
        surface_id=registration_scope["surface_id"],
        project_ids=registration_scope["project_ids"],
        app_actor=registration_scope["app_actor"],
        issued_at=NOW,
    )
    crash_replay(
        "/api/v1/agents/register",
        registration,
        "agents.register:after_domain_result",
    )
    definition = _definition("machine:researcher")
    published = _dispatch(
        api,
        "/api/v1/workflows/definitions/publish",
        _request(
            "workflows.definitions.publish",
            {"definition": definition},
            expected_version="ABSENT",
            key="recovery-definition-publish",
        ),
    )
    assert published.status == 200, _document(published)
    run_id = str(uuid4())
    launched = crash_replay(
        "/api/v1/workflows/runs/launch",
        _request(
            "workflows.runs.launch",
            {
                "workflow_id": definition["workflow_id"],
                "version": 1,
                "run_id": run_id,
                "source_commit": SHA_A,
                "input_manifest_sha256": SHA_B,
                "event_id": str(uuid4()),
                "stale_after_seconds": 30,
                "max_concurrent_claims": 2,
            },
            expected_version="ABSENT",
            key="recovery-workflow-launch",
        ),
        "workflows.runs.launch:after_domain_effect",
    )
    readiness = _workflow_readiness(
        api,
        run_id,
        launched["object_version"],
        key="recovery-readiness-view",
    )
    claim_event_id = str(uuid4())
    claim = crash_replay(
        "/api/v1/workflows/claims/create",
        _request(
            "workflows.claims.create",
            {
                "run_id": run_id,
                "readiness": readiness["data"]["readiness"],
                "agent_id": "researcher",
                "expires_at": (NOW + timedelta(minutes=5))
                .isoformat()
                .replace("+00:00", "Z"),
                "event_id": claim_event_id,
                "approvals": [],
            },
            expected_version=readiness["object_version"],
            key="recovery-workflow-claim",
        ),
        "workflows.claims.create:after_domain_effect",
    )
    claim_result = claim["data"]["claim"]
    task_id = str(uuid4())
    delivered = crash_replay(
        "/api/v1/workflows/tasks/deliver",
        _request(
            "workflows.tasks.deliver",
            {
                "run_id": run_id,
                "claim_event_id": claim_event_id,
                "task_id": task_id,
                "nonce": "recovery-workflow-delivery-nonce",
                "issued_at": NOW.isoformat().replace("+00:00", "Z"),
                "expires_at": (NOW + timedelta(minutes=5))
                .isoformat()
                .replace("+00:00", "Z"),
            },
            expected_version=claim["object_version"],
            key="recovery-workflow-delivery",
        ),
        "workflows.tasks.deliver:after_domain_effect",
    )
    session_id = str(uuid4())
    started = crash_replay(
        "/api/v1/workflows/sessions/start",
        _request(
            "workflows.sessions.start",
            {
                "run_id": run_id,
                "claim_event_id": claim_event_id,
                "session_id": session_id,
                "total_units": 1,
                "current_source_commit": SHA_A,
                "current_input_sha256": claim_result["claim"]["input_sha256"],
                "event_id": str(uuid4()),
            },
            expected_version=delivered["object_version"],
            key="recovery-session-start",
        ),
        "workflows.sessions.start:after_domain_effect",
    )
    failed_at = NOW + timedelta(minutes=1)
    service._clock = lambda: failed_at
    failed = crash_replay(
        "/api/v1/workflows/sessions/record",
        _request(
            "workflows.sessions.record",
            {
                "run_id": run_id,
                "session_id": session_id,
                "event_type": "STEP_FAILED",
                "state": "FAILED",
                "progress": {"completed_units": 0, "total_units": 1},
                "resources": {
                    "tokens_used": 0,
                    "cost_microunits": 0,
                    "peak_memory_mb": 0,
                },
                "outputs": [],
                "current_source_commit": SHA_A,
                "current_input_sha256": claim_result["claim"]["input_sha256"],
                "event_id": str(uuid4()),
            },
            expected_version=started["object_version"],
            key="recovery-session-failure",
        ),
        "workflows.sessions.record:after_domain_effect",
    )
    retried = crash_replay(
        "/api/v1/workflows/retries/create",
        _request(
            "workflows.retries.create",
            {
                "run_id": run_id,
                "step_id": "research",
                "failed_attempt": 1,
                "event_id": str(uuid4()),
            },
            expected_version=failed["object_version"],
            key="recovery-retry-create",
        ),
        "workflows.retries.create:after_domain_effect",
    )

    portable = workspace.sources / "recovery.md"
    portable.write_text("checkpoint\n", encoding="utf-8")
    checkpoint = workspace.snapshot("workflow recovery checkpoint")["commit"]
    portable.write_text("mutated\n", encoding="utf-8")
    workspace.snapshot("workflow recovery mutation")
    preview_result = _dispatch(
        api,
        "/api/v1/workflows/rollback/preview",
        _request(
            "workflows.rollback.preview",
            {
                "run_id": run_id,
                "step_id": "research",
                "attempt": 1,
                "checkpoint": checkpoint,
                "expires_at": (failed_at + timedelta(minutes=10))
                .isoformat()
                .replace("+00:00", "Z"),
            },
            expected_version=retried["object_version"],
            key="recovery-rollback-preview",
        ),
    )
    assert preview_result.status == 200, _document(preview_result)
    preview_document = _document(preview_result)
    preview = preview_document["data"]["rollback_preview"]
    approval_id = str(uuid4())
    approval = crash_replay(
        "/api/v1/workflows/approvals/approve",
        _request(
            "workflows.approvals.approve",
            {
                "run_id": run_id,
                "preview": preview,
                "preview_operation_key": preview_document["data"][
                    "preview_operation_key"
                ],
                "binding": {
                    "kind": "ROLLBACK",
                    "step_id": "research",
                    "attempt": 1,
                    "checkpoint": checkpoint,
                },
                "authorization_ref": "attended:recovery-rollback",
                "approval_id": approval_id,
            },
            expected_version=preview_document["object_version"],
            key="recovery-rollback-approval",
        ),
        "workflows.approvals.approve:after_domain_effect",
    )
    event_root = workspace.receipts / "workflows" / run_id / "events"
    event_types = [read_json(path)["event_type"] for path in event_root.glob("*.json")]
    assert event_types.count("APPROVAL_RECORDED") == 1
    applied = crash_replay(
        "/api/v1/workflows/rollback/apply",
        _request(
            "workflows.rollback.apply",
            {
                "run_id": run_id,
                "preview": preview,
                "approval": approval["data"]["approval"]["approval"],
                "start_event_id": str(uuid4()),
                "complete_event_id": str(uuid4()),
            },
            expected_version=approval["object_version"],
            key="recovery-rollback-apply",
        ),
        "workflows.rollback.apply:after_domain_effect",
    )
    assert applied["data"]["rollback"]["outcome"] == "ROLLBACK_COMPLETED"
    assert portable.read_text(encoding="utf-8") == "checkpoint\n"
    event_types = [read_json(path)["event_type"] for path in event_root.glob("*.json")]
    assert event_types.count("RUN_STARTED") == 1
    assert event_types.count("STEP_CLAIMED") == 1
    assert event_types.count("SESSION_STARTED") == 1
    assert event_types.count("STEP_FAILED") == 1
    assert event_types.count("STEP_RETRY_CREATED") == 1
    assert event_types.count("ROLLBACK_STARTED") == 1
    assert event_types.count("ROLLBACK_COMPLETED") == 1
    inbox = workspace.root / ".hive" / "agent-operations" / "inbox" / "researcher"
    assert len(list(inbox.glob(f"{task_id}.json"))) == 1
