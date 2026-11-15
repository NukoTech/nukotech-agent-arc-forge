"""Inert, capability-bound agent and governed-task operator lane."""

from __future__ import annotations

import copy
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from hive_protocol.agents import validate_agent_registry
from hive_protocol.core import (
    ProtocolError,
    document_digest,
    public_key_id,
    verify_document,
)
from hive_protocol.product.agent_adapter import (
    _agent_registration_scope,
    _capability_grant_path,
    _private_key,
    authorize_agent_capabilities,
    register_agent,
)
from hive_protocol.product.workflow_adapter import WorkflowProductService
from hive_protocol.storage import (
    atomic_write_json,
    ensure_owned_directory,
    read_json,
    require_no_symlink_components,
)
from hive_protocol.tasks.engine import (
    TaskEngine,
    TaskIdentity,
    _validate as validate_cycle2_task,
)

from ..shell_contracts import OperatorRequest, RouteContract
from ..workspace import HiveWorkspace


_SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_WORKFLOW_ACTIONS = frozenset(
    {
        "workflows.definitions.preview",
        "workflows.definitions.publish",
        "workflows.runs.launch",
        "workflows.readiness",
        "workflows.conflicts.record",
        "workflows.approvals.preview",
        "workflows.approvals.approve",
        "workflows.claims.create",
        "workflows.tasks.deliver",
        "workflows.sessions.start",
        "workflows.sessions.record",
        "workflows.stale.preview",
        "workflows.stale.apply",
        "workflows.retries.create",
        "workflows.compensation.preview",
        "workflows.compensation.authorize",
        "workflows.rollback.preview",
        "workflows.rollback.apply",
        "workflows.runs.complete",
        "workflows.runs.cancel",
    }
)
_ACTIONS = frozenset(
    {"agents.capabilities.authorize", "agents.register", "agents.tasks.submit"}
) | _WORKFLOW_ACTIONS
_OPERATION_SCHEMA = "hive.operator-workflow-agent-operation.v1"
_EXECUTABLE_FIELDS = frozenset(
    {
        "argv",
        "cmd",
        "code",
        "command",
        "commands",
        "entrypoint",
        "executable",
        "program",
        "script",
        "shell",
    }
)


def _public_key(pem: str) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(pem.encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise ProtocolError("AGENT_PUBLIC_KEY_INVALID", "agent public key is invalid") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ProtocolError("AGENT_PUBLIC_KEY_INVALID", "agent key must be Ed25519")
    return key


def _time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ProtocolError("TASK_TIME_INVALID", "task expiry must be ISO-8601 text")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError("TASK_TIME_INVALID", "task expiry is invalid") from exc
    if parsed.tzinfo is None:
        raise ProtocolError("TASK_TIME_INVALID", "task expiry requires timezone")
    return parsed


class WorkflowAgentsLane:
    """Expose signed registry/task mutations without running submitted work."""

    def __init__(
        self,
        workspace: HiveWorkspace,
        *,
        tenant_id: str,
        project_ids: frozenset[str],
        now: datetime,
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        self.workspace = workspace
        self.root = workspace.root
        self.tenant_id = tenant_id
        self.project_ids = project_ids
        self.now = now
        self.fault_hook = fault_hook
        self.runtime = (
            workspace.runtime / "operator-shell" / "lanes" / "workflow-agents"
        )
        self.operations = self.runtime / "operations"

    @staticmethod
    def supports(action: str) -> bool:
        return action in _ACTIONS

    def _fault(self, stage: str) -> None:
        if self.fault_hook is not None:
            self.fault_hook(stage)

    def _ensure_runtime(self) -> None:
        ensure_owned_directory(
            self.root,
            self.operations,
            code="OPERATOR_RUNTIME_BOUNDARY",
            detail="workflow/agent runtime path is unsafe",
        )

    def _operation_path(self, operation_key: str) -> Path:
        self._ensure_runtime()
        if _SHA256.fullmatch(operation_key) is None:
            raise ProtocolError(
                "OPERATOR_RUNTIME_BOUNDARY", "workflow/agent operation key is invalid"
            )
        path = self.operations / f"{operation_key}.json"
        require_no_symlink_components(
            self.root,
            path,
            code="OPERATOR_RUNTIME_BOUNDARY",
            detail="workflow/agent operation path contains a symlink",
        )
        if path.is_symlink():
            raise ProtocolError(
                "OPERATOR_RUNTIME_BOUNDARY", "workflow/agent operation path is a symlink"
            )
        return path

    def _write_operation(
        self,
        operation_key: str,
        request: OperatorRequest,
        result: Mapping[str, Any] | None,
    ) -> None:
        atomic_write_json(
            self._operation_path(operation_key),
            {
                "schema_version": _OPERATION_SCHEMA,
                "operation_key": operation_key,
                "action": request.action,
                "request_digest": request.digest,
                "state": "TERMINAL" if result is not None else "PREPARED",
                "result": copy.deepcopy(dict(result)) if result is not None else None,
                "result_digest": document_digest(result) if result is not None else None,
            },
            mode=0o600,
        )

    def _read_operation(
        self, operation_key: str, request: OperatorRequest
    ) -> dict[str, Any] | None:
        path = self._operation_path(operation_key)
        if not path.exists():
            return None
        document = read_json(path)
        if (
            set(document)
            != {
                "schema_version",
                "operation_key",
                "action",
                "request_digest",
                "state",
                "result",
                "result_digest",
            }
            or document.get("schema_version") != _OPERATION_SCHEMA
            or document.get("operation_key") != operation_key
            or document.get("action") != request.action
            or document.get("request_digest") != request.digest
            or document.get("state") not in {"PREPARED", "TERMINAL"}
        ):
            raise ProtocolError(
                "OPERATOR_DOMAIN_RECOVERY_INVALID",
                "workflow/agent recovery record changed",
            )
        if document["state"] == "PREPARED":
            return None
        result = document.get("result")
        if not isinstance(result, dict) or document.get("result_digest") != document_digest(
            result
        ):
            raise ProtocolError(
                "OPERATOR_DOMAIN_RECOVERY_INVALID",
                "workflow/agent recovery result changed",
            )
        return copy.deepcopy(result)

    @staticmethod
    def _result(
        request: OperatorRequest,
        operation_key: str,
        *,
        object_version: str,
        changed: bool,
        data: Mapping[str, Any],
        evidence: list[dict[str, Any]],
    ) -> dict[str, Any]:
        return {
            "operation_key": operation_key,
            "request_digest": request.digest,
            "outcome": "APPLIED",
            "reason_code": None,
            "object_version": object_version,
            "changed": changed,
            "data": copy.deepcopy(dict(data)),
            "technical_evidence": copy.deepcopy(evidence),
        }

    @staticmethod
    def _exact(document: Mapping[str, Any], fields: set[str], *, code: str) -> None:
        if set(document) != fields:
            raise ProtocolError(code, "workflow/agent request is not exact")

    @classmethod
    def _deny_executable_fields(cls, value: Any) -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                if str(key).strip().lower().replace("-", "_") in _EXECUTABLE_FIELDS:
                    raise ProtocolError(
                        "OPERATOR_EXECUTABLE_INPUT_DENIED",
                        "operator task payload may not contain executable fields",
                    )
                cls._deny_executable_fields(child)
        elif isinstance(value, list):
            for child in value:
                cls._deny_executable_fields(child)

    @property
    def _registry_path(self) -> Path:
        return self.workspace.meta / "agent-operations" / "registry.json"

    def _registry(self) -> dict[str, Any]:
        if not self._registry_path.is_file() or self._registry_path.is_symlink():
            raise ProtocolError("AGENT_REGISTRY_MISSING", "agent registry is absent")
        registry = read_json(self._registry_path)
        validate_agent_registry(registry)
        return registry

    def _registration_intent(self, request: OperatorRequest) -> dict[str, Any] | None:
        self._exact(
            request.input,
            {
                "persona",
                "agent_id",
                "capabilities",
                "machine_id",
                "surface_id",
                "project_ids",
                "app_actor",
            },
            code="AGENT_REGISTRATION_INVALID",
        )
        persona = request.input.get("persona")
        agent_id = request.input.get("agent_id")
        capabilities = request.input.get("capabilities")
        machine_id = request.input.get("machine_id")
        surface_id = request.input.get("surface_id")
        project_ids = request.input.get("project_ids")
        app_actor = request.input.get("app_actor")
        if (
            not isinstance(persona, str)
            or not persona.strip()
            or not isinstance(agent_id, str)
            or _SAFE_ID.fullmatch(agent_id) is None
            or not isinstance(capabilities, list)
            or not capabilities
            or capabilities != sorted(set(capabilities))
            or any(not isinstance(item, str) or _SAFE_ID.fullmatch(item) is None for item in capabilities)
            or not isinstance(machine_id, str)
            or _SAFE_ID.fullmatch(machine_id) is None
            or not isinstance(surface_id, str)
            or _SAFE_ID.fullmatch(surface_id) is None
            or not isinstance(app_actor, str)
            or _SAFE_ID.fullmatch(app_actor) is None
            or project_ids != [request.project_id]
            or request.project_id not in self.project_ids
        ):
            code = "AGENT_SCOPE_INVALID" if project_ids != [request.project_id] else "AGENT_REGISTRATION_INVALID"
            raise ProtocolError(code, "agent registration is invalid or outside scope")
        persona_id = f"persona:{persona.strip()}"
        dimensions = [agent_id, persona_id, surface_id, machine_id, app_actor]
        if len(set(dimensions)) != len(dimensions):
            raise ProtocolError(
                "AGENT_IDENTITY_COLLAPSE",
                "agent, persona, surface, machine, and App actor must differ",
            )
        if not self._registry_path.exists():
            return None
        registry = self._registry()
        existing = registry["agents"].get(agent_id)
        if existing is not None and (
            existing.get("tenant_id") != self.tenant_id
            or existing.get("project_ids") != [request.project_id]
        ):
            raise ProtocolError("AGENT_SCOPE_INVALID", "agent is outside scope")
        if existing is not None:
            if not existing.get("active"):
                raise ProtocolError("AGENT_INACTIVE", "agent registration is inactive")
            expected = {
                "agent_id": agent_id,
                "persona_id": persona_id,
                "capabilities": capabilities,
                "machine_id": machine_id,
                "surface_id": surface_id,
                "project_ids": project_ids,
                "app_actor": app_actor,
            }
            if any(existing.get(field) != value for field, value in expected.items()):
                raise ProtocolError(
                    "AGENT_REGISTRATION_CONFLICT",
                    "agent ID is already bound to different identity or capabilities",
                )
        return existing

    def _authorization_intent(
        self, request: OperatorRequest
    ) -> tuple[dict[str, Any], datetime, Path, dict[str, Any] | None]:
        registration_fields = {
            "persona",
            "agent_id",
            "capabilities",
            "machine_id",
            "surface_id",
            "project_ids",
            "app_actor",
        }
        self._exact(
            request.input,
            registration_fields | {"expires_at", "attended_confirmation"},
            code="AGENT_CAPABILITY_AUTHORIZATION_INVALID",
        )
        if (
            request.input.get("project_ids") != [request.project_id]
            or request.project_id not in self.project_ids
            or request.input.get("attended_confirmation") is not True
        ):
            raise ProtocolError(
                "AGENT_CAPABILITY_AUTHORIZATION_INVALID",
                "capability authorization requires exact project scope and attended confirmation",
            )
        scope = _agent_registration_scope(
            request.input["persona"],
            request.input["agent_id"],
            request.input["capabilities"],
            machine_id=request.input["machine_id"],
            surface_id=request.input["surface_id"],
            project_ids=request.input["project_ids"],
            app_actor=request.input["app_actor"],
        )
        if request.input["capabilities"] != scope["capabilities"]:
            raise ProtocolError(
                "AGENT_CAPABILITY_AUTHORIZATION_INVALID",
                "authorized capabilities must be unique and sorted",
            )
        try:
            expiry = _time(request.input["expires_at"])
        except ProtocolError as exc:
            raise ProtocolError(
                "AGENT_CAPABILITY_AUTHORIZATION_INVALID",
                "capability authorization expiry is invalid",
            ) from exc
        if expiry <= self.now or expiry > self.now + timedelta(hours=24):
            raise ProtocolError(
                "AGENT_CAPABILITY_AUTHORIZATION_INVALID",
                "capability authorization must expire within 24 hours",
            )
        path = _capability_grant_path(self.root, scope["agent_id"])
        require_no_symlink_components(
            self.root,
            path,
            code="AGENT_CAPABILITY_GRANT_BOUNDARY",
            detail="capability grant path may not contain symlinks",
        )
        if path.exists() and (path.is_symlink() or not path.is_file()):
            raise ProtocolError(
                "AGENT_CAPABILITY_GRANT_BOUNDARY",
                "capability grant path is not a regular file",
            )
        existing = read_json(path) if path.exists() else None
        return scope, expiry, path, existing

    def _trusted_task_keys(self, registry: Mapping[str, Any]) -> dict[str, Ed25519PublicKey]:
        trusted: dict[str, Ed25519PublicKey] = {}
        for record in registry["agents"].values():
            key = _public_key(record["public_key_pem"])
            if public_key_id(key) != record["key_id"]:
                raise ProtocolError("AGENT_PUBLIC_KEY_INVALID", "agent key binding changed")
            trusted[record["key_id"]] = key
        return trusted

    def _task_intent(self, request: OperatorRequest):
        self._exact(
            request.input,
            {
                "creator_agent_id",
                "assignee_agent_id",
                "task_id",
                "operation",
                "capability",
                "payload",
                "source_refs",
                "expires_at",
            },
            code="AGENT_TASK_INVALID",
        )
        self._deny_executable_fields(request.input.get("payload"))
        registry = self._registry()
        creator = registry["agents"].get(request.input.get("creator_agent_id"))
        assignee = registry["agents"].get(request.input.get("assignee_agent_id"))
        if not isinstance(creator, Mapping) or not isinstance(assignee, Mapping):
            raise ProtocolError("AGENT_SCOPE_INVALID", "task agent is unregistered")
        for record in (creator, assignee):
            if (
                not record.get("active")
                or record.get("tenant_id") != self.tenant_id
                or request.project_id not in record.get("project_ids", [])
            ):
                raise ProtocolError("AGENT_SCOPE_INVALID", "task agent is inactive or outside scope")
        capability = request.input.get("capability")
        if capability not in creator["capabilities"] or capability not in assignee["capabilities"]:
            raise ProtocolError(
                "AGENT_CAPABILITY_DENIED",
                "task capability is not held by both creator and assignee",
            )
        if _time(request.input.get("expires_at")) <= self.now:
            raise ProtocolError("TASK_TIME_INVALID", "task expiry must be in the future")
        task_id = request.input.get("task_id")
        if not isinstance(task_id, str) or _SAFE_ID.fullmatch(task_id) is None:
            raise ProtocolError("TASK_ID_INVALID", "task identifier is unsafe")
        task_path = self.root / "tasks" / f"{task_id}.json"
        existing = None
        if task_path.exists() or task_path.is_symlink():
            if task_path.is_symlink() or not task_path.is_file():
                raise ProtocolError("TASK_ROOT_BOUNDARY", "task path is unsafe")
            existing = read_json(task_path)
            validate_cycle2_task(existing)
            verify_document(existing, self._trusted_task_keys(registry))
        return registry, creator, assignee, existing

    def _definition_intent(self, request: OperatorRequest) -> tuple[dict[str, Any], Path]:
        self._exact(
            request.input,
            {"definition"},
            code="WORKFLOW_DEFINITION_INVALID",
        )
        definition = request.input.get("definition")
        if not isinstance(definition, dict):
            raise ProtocolError(
                "WORKFLOW_DEFINITION_INVALID", "workflow definition must be an object"
            )
        self._deny_executable_fields(definition)
        if (
            definition.get("tenant_id") != self.tenant_id
            or definition.get("project_id") != request.project_id
            or request.project_id not in self.project_ids
        ):
            raise ProtocolError(
                "WORKFLOW_SCOPE_INVALID", "workflow definition is outside shell scope"
            )
        workflow_id = definition.get("workflow_id")
        version = definition.get("version")
        if (
            not isinstance(workflow_id, str)
            or _SAFE_ID.fullmatch(workflow_id) is None
            or not isinstance(version, int)
            or isinstance(version, bool)
            or version < 1
        ):
            raise ProtocolError(
                "WORKFLOW_DEFINITION_INVALID", "workflow identity or version is invalid"
            )
        path = self.root / "workflows" / "definitions" / workflow_id / f"{version:06d}.json"
        require_no_symlink_components(
            self.root,
            path,
            code="WORKFLOW_DEFINITION_BOUNDARY",
            detail="workflow definition path contains a symlink",
        )
        return definition, path

    def _run_id(self, request: OperatorRequest) -> str:
        run_id = request.input.get("run_id")
        if not isinstance(run_id, str) or _SAFE_ID.fullmatch(run_id) is None:
            raise ProtocolError("WORKFLOW_RUN_ID_INVALID", "workflow run ID is invalid")
        return run_id

    def _run_path(self, run_id: str) -> Path:
        path = self.root / "workflows" / "runs" / run_id / "run.json"
        require_no_symlink_components(
            self.root,
            path,
            code="WORKFLOW_RUN_BOUNDARY",
            detail="workflow run path contains a symlink",
        )
        return path

    def _run_head(self, run_id: str) -> str:
        path = self._run_path(run_id)
        if not path.exists():
            return "ABSENT"
        if path.is_symlink() or not path.is_file():
            raise ProtocolError("WORKFLOW_RUN_BOUNDARY", "workflow run path is unsafe")
        run = read_json(path)
        if (
            run.get("tenant_id") != self.tenant_id
            or run.get("project_id") not in self.project_ids
        ):
            raise ProtocolError("WORKFLOW_SCOPE_INVALID", "workflow run is outside scope")
        status = WorkflowProductService(self.root).run_status(run_id)
        return document_digest(status)

    def _workflow_service(self) -> WorkflowProductService:
        return WorkflowProductService(self.root)

    def _workflow_input(self, action: str, request: OperatorRequest) -> None:
        fields = {
            "workflows.runs.launch": {
                "workflow_id",
                "version",
                "run_id",
                "source_commit",
                "input_manifest_sha256",
                "event_id",
                "stale_after_seconds",
                "max_concurrent_claims",
            },
            "workflows.readiness": {
                "run_id",
                "step_id",
                "attempt",
                "current_source_commit",
                "current_machine_id",
                "task_sha256",
                "existing_task_sha256s",
                "required_evidence_refs",
                "available_evidence_refs",
                "approvals",
                "explicit_agent_id",
            },
            "workflows.conflicts.record": {
                "run_id",
                "readiness",
                "event_id",
                "attended_confirmation",
                "approvals",
            },
            "workflows.approvals.preview": {
                "run_id",
                "readiness",
                "action",
                "destination",
                "expires_at",
            },
            "workflows.approvals.approve": {
                "run_id",
                "preview",
                "preview_operation_key",
                "binding",
                "authorization_ref",
                "approval_id",
            },
            "workflows.claims.create": {
                "run_id",
                "readiness",
                "agent_id",
                "expires_at",
                "event_id",
                "approvals",
            },
            "workflows.tasks.deliver": {
                "run_id",
                "claim_event_id",
                "task_id",
                "nonce",
                "issued_at",
                "expires_at",
            },
            "workflows.sessions.start": {
                "run_id",
                "claim_event_id",
                "session_id",
                "total_units",
                "current_source_commit",
                "current_input_sha256",
                "event_id",
            },
            "workflows.sessions.record": {
                "run_id",
                "session_id",
                "event_type",
                "state",
                "progress",
                "resources",
                "outputs",
                "current_source_commit",
                "current_input_sha256",
                "event_id",
            },
            "workflows.stale.preview": {
                "run_id",
                "session_id",
                "expires_at",
            },
            "workflows.stale.apply": {
                "run_id",
                "session_id",
                "preview",
                "approval",
                "abandonment_event_id",
                "release_event_id",
            },
            "workflows.retries.create": {
                "run_id",
                "step_id",
                "failed_attempt",
                "event_id",
            },
            "workflows.compensation.preview": {
                "run_id",
                "failed_step_id",
                "failed_attempt",
                "expires_at",
            },
            "workflows.compensation.authorize": {
                "run_id",
                "failed_step_id",
                "failed_attempt",
                "preview",
                "approval",
                "event_id",
            },
            "workflows.rollback.preview": {
                "run_id",
                "step_id",
                "attempt",
                "checkpoint",
                "expires_at",
            },
            "workflows.rollback.apply": {
                "run_id",
                "preview",
                "approval",
                "start_event_id",
                "complete_event_id",
            },
            "workflows.runs.complete": {
                "run_id",
                "event_id",
                "attended_confirmation",
            },
            "workflows.runs.cancel": {
                "run_id",
                "event_id",
                "attended_confirmation",
            },
        }.get(action)
        if fields is None:
            raise ProtocolError("OPERATOR_DOMAIN_UNAVAILABLE", "workflow action is unavailable")
        self._exact(request.input, fields, code="WORKFLOW_OPERATOR_INPUT_INVALID")
        operator_authored = {
            key: value
            for key, value in request.input.items()
            if key not in {"approval", "approvals", "binding", "preview", "readiness"}
        }
        self._deny_executable_fields(operator_authored)
        self._run_id(request)

    def _workflow_result(
        self,
        request: OperatorRequest,
        operation_key: str,
        result: Mapping[str, Any],
        *,
        changed: bool,
        object_version: str,
        evidence_ref: str,
        evidence_sha256: str | None = None,
        field: str,
    ) -> dict[str, Any]:
        data = {field: copy.deepcopy(dict(result)), "execution_started": False}
        evidence = []
        if changed:
            evidence = [
                {
                    "kind": "workflow-control",
                    "ref": evidence_ref,
                    "sha256": evidence_sha256 or object_version,
                }
            ]
        return self._result(
            request,
            operation_key,
            object_version=object_version,
            changed=changed,
            data=data,
            evidence=evidence,
        )

    @staticmethod
    def _identity(record: Mapping[str, Any], project_id: str) -> TaskIdentity:
        return TaskIdentity(
            persona_id=record["persona_id"],
            surface_id=record["surface_id"],
            machine_id=record["machine_id"],
            project_id=project_id,
            app_actor=record["app_actor"],
        )

    def object_key(self, route: RouteContract, request: OperatorRequest) -> str:
        if route.action in {"agents.capabilities.authorize", "agents.register"}:
            value = request.input.get("agent_id", "invalid")
        elif route.action == "agents.tasks.submit":
            value = request.input.get("task_id", "invalid")
        elif route.action in {
            "workflows.definitions.preview",
            "workflows.definitions.publish",
        }:
            definition = request.input.get("definition", {})
            value = f"{definition.get('workflow_id', 'invalid')}:{definition.get('version', 'invalid')}"
        else:
            value = request.input.get("run_id", "invalid")
        return f"{request.project_id}:{route.action}:{value}"

    def current_version(self, route: RouteContract, request: OperatorRequest) -> str:
        if route.action == "agents.capabilities.authorize":
            _, _, _, existing = self._authorization_intent(request)
            return document_digest(existing) if existing is not None else "ABSENT"
        if route.action == "agents.register":
            existing = self._registration_intent(request)
            return document_digest(existing) if existing is not None else "ABSENT"
        if route.action == "agents.tasks.submit":
            _, _, _, existing = self._task_intent(request)
            return document_digest(existing) if existing is not None else "ABSENT"
        if route.action in {
            "workflows.definitions.preview",
            "workflows.definitions.publish",
        }:
            _, path = self._definition_intent(request)
            if not path.exists():
                return "ABSENT"
            if path.is_symlink() or not path.is_file():
                raise ProtocolError(
                    "WORKFLOW_DEFINITION_BOUNDARY", "workflow definition path is unsafe"
                )
            return document_digest(read_json(path))
        if route.action in _WORKFLOW_ACTIONS:
            self._workflow_input(route.action, request)
            return self._run_head(self._run_id(request))
        raise ProtocolError("OPERATOR_DOMAIN_UNAVAILABLE", "workflow/agent action is unavailable")

    def mutate(
        self,
        route: RouteContract,
        request: OperatorRequest,
        *,
        operation_key: str,
    ) -> Mapping[str, Any]:
        existing = self._read_operation(operation_key, request)
        if existing is not None:
            return existing
        self._write_operation(operation_key, request, None)
        result = self._apply(route.action, request, operation_key)
        self._fault(f"{route.action}:after_domain_effect")
        self._write_operation(operation_key, request, result)
        self._fault(f"{route.action}:after_domain_result")
        return result

    def recover(
        self,
        route: RouteContract,
        request: OperatorRequest,
        *,
        operation_key: str,
    ) -> Mapping[str, Any] | None:
        existing = self._read_operation(operation_key, request)
        if existing is not None:
            return existing
        result = self._apply(route.action, request, operation_key)
        self._write_operation(operation_key, request, result)
        return result

    def _apply(self, action: str, request: OperatorRequest, operation_key: str):
        if action == "agents.capabilities.authorize":
            return self._authorize_capabilities(request, operation_key)
        if action == "agents.register":
            return self._register(request, operation_key)
        if action == "agents.tasks.submit":
            return self._submit_task(request, operation_key)
        if action == "workflows.definitions.preview":
            return self._definition_preview(request, operation_key)
        if action == "workflows.definitions.publish":
            return self._definition_publish(request, operation_key)
        if action == "workflows.runs.launch":
            return self._run_launch(request, operation_key)
        if action == "workflows.readiness":
            return self._readiness(request, operation_key)
        if action == "workflows.conflicts.record":
            return self._conflict_record(request, operation_key)
        if action == "workflows.approvals.preview":
            return self._approval_preview(request, operation_key)
        if action == "workflows.approvals.approve":
            return self._approval_approve(request, operation_key)
        if action == "workflows.claims.create":
            return self._claim(request, operation_key)
        if action == "workflows.tasks.deliver":
            return self._deliver(request, operation_key)
        if action == "workflows.sessions.start":
            return self._session_start(request, operation_key)
        if action == "workflows.sessions.record":
            return self._session_record(request, operation_key)
        if action == "workflows.stale.preview":
            return self._stale_preview(request, operation_key)
        if action == "workflows.stale.apply":
            return self._stale_apply(request, operation_key)
        if action == "workflows.retries.create":
            return self._retry_create(request, operation_key)
        if action == "workflows.compensation.preview":
            return self._compensation_preview(request, operation_key)
        if action == "workflows.compensation.authorize":
            return self._compensation_authorize(request, operation_key)
        if action == "workflows.rollback.preview":
            return self._rollback_preview(request, operation_key)
        if action == "workflows.rollback.apply":
            return self._rollback_apply(request, operation_key)
        if action == "workflows.runs.complete":
            return self._run_complete(request, operation_key)
        if action == "workflows.runs.cancel":
            return self._run_cancel(request, operation_key)
        raise ProtocolError("OPERATOR_DOMAIN_UNAVAILABLE", "workflow/agent action is unavailable")

    def _authorize_capabilities(
        self, request: OperatorRequest, operation_key: str
    ) -> dict[str, Any]:
        scope, expiry, path, _ = self._authorization_intent(request)
        authorization = authorize_agent_capabilities(
            self.root,
            request.input["persona"],
            scope["agent_id"],
            scope["capabilities"],
            machine_id=scope["machine_id"],
            surface_id=scope["surface_id"],
            project_ids=scope["project_ids"],
            app_actor=scope["app_actor"],
            issued_at=self.now,
            expires_at=expiry,
        )
        version = str(authorization["grant_sha256"])
        return self._result(
            request,
            operation_key,
            object_version=version,
            changed=bool(authorization["changed"]),
            data={
                "capability_grant": {
                    key: value
                    for key, value in authorization.items()
                    if key != "changed"
                },
                "execution_started": False,
            },
            evidence=[
                {
                    "kind": "agent-capability-grant",
                    "ref": path.relative_to(self.root).as_posix(),
                    "sha256": version,
                }
            ] if authorization["changed"] else [],
        )

    def _register(self, request: OperatorRequest, operation_key: str):
        existing = self._registration_intent(request)
        changed = existing is None
        if existing is None:
            register_agent(
                self.root,
                request.input["persona"],
                request.input["agent_id"],
                request.input["capabilities"],
                machine_id=request.input["machine_id"],
                surface_id=request.input["surface_id"],
                project_ids=request.input["project_ids"],
                app_actor=request.input["app_actor"],
                now=self.now,
            )
        record = self._registry()["agents"][request.input["agent_id"]]
        version = document_digest(record)
        public = {key: value for key, value in record.items() if key != "public_key_pem"}
        return self._result(
            request,
            operation_key,
            object_version=version,
            changed=changed,
            data={"agent": public, "execution_started": False},
            evidence=[
                {
                    "kind": "agent-registry",
                    "ref": self._registry_path.relative_to(self.root).as_posix(),
                    "sha256": version,
                }
            ] if changed else [],
        )

    def _submit_task(self, request: OperatorRequest, operation_key: str):
        registry, creator, assignee, existing = self._task_intent(request)
        changed = existing is None
        if existing is None:
            engine = TaskEngine(
                self.root,
                trusted_keys=self._trusted_task_keys(registry),
            )
            task = engine.create(
                identity=self._identity(creator, str(request.project_id)),
                assignee=self._identity(assignee, str(request.project_id)),
                operation=request.input["operation"],
                payload=request.input["payload"],
                capability=request.input["capability"],
                source_refs=request.input["source_refs"],
                private_key=_private_key(self.root, creator["agent_id"]),
                task_id=request.input["task_id"],
                expires_at=request.input["expires_at"],
                now=self.now,
            )
        else:
            task = existing
            expected = {
                "task_id": request.input["task_id"],
                "creator": dict(self._identity(creator, str(request.project_id))),
                "assignee": dict(self._identity(assignee, str(request.project_id))),
                "operation": request.input["operation"],
                "capability": request.input["capability"],
                "payload": request.input["payload"],
                "source_refs": request.input["source_refs"],
                "expires_at": request.input["expires_at"],
            }
            if any(task.get(field) != value for field, value in expected.items()):
                raise ProtocolError("TASK_REPLAY", "task ID is bound to different work")
            TaskEngine(
                self.root,
                trusted_keys=self._trusted_task_keys(registry),
            ).recover()
        version = document_digest(task)
        return self._result(
            request,
            operation_key,
            object_version=version,
            changed=changed,
            data={"task": task, "execution_started": False},
            evidence=[
                {
                    "kind": "governed-task",
                    "ref": f"tasks/{task['task_id']}.json",
                    "sha256": version,
                }
            ] if changed else [],
        )

    def _definition_preview(self, request: OperatorRequest, operation_key: str):
        definition, _ = self._definition_intent(request)
        preview = self._workflow_service().definition_preview(definition, now=self.now)
        result = self._workflow_result(
            request,
            operation_key,
            preview,
            changed=False,
            object_version=self.current_version(
                RouteContract("POST", "", request.action, True, "NONE"), request
            ),
            evidence_ref=preview["target_path"],
            field="preview",
        )
        return result

    def _definition_publish(self, request: OperatorRequest, operation_key: str):
        definition, _ = self._definition_intent(request)
        result = self._workflow_service().publish_definition(
            definition,
            idempotency_key=operation_key,
            now=self.now,
        )
        version = document_digest(result["definition"])
        return self._workflow_result(
            request,
            operation_key,
            result,
            changed=bool(result["changed"]),
            object_version=version,
            evidence_ref=result["receipt"]["definition_path"],
            evidence_sha256=version,
            field="publication",
        )

    def _run_launch(self, request: OperatorRequest, operation_key: str):
        self._workflow_input(request.action, request)
        result = self._workflow_service().launch_run(
            request.input["workflow_id"],
            request.input["version"],
            run_id=request.input["run_id"],
            source_commit=request.input["source_commit"],
            input_manifest_sha256=request.input["input_manifest_sha256"],
            event_id=request.input["event_id"],
            idempotency_key=operation_key,
            now=self.now,
            stale_after_seconds=request.input["stale_after_seconds"],
            max_concurrent_claims=request.input["max_concurrent_claims"],
        )
        version = self._run_head(request.input["run_id"])
        return self._workflow_result(
            request,
            operation_key,
            result,
            changed=bool(result["changed"]),
            object_version=version,
            evidence_ref=f"workflows/runs/{request.input['run_id']}/run.json",
            field="launch",
        )

    def _readiness(self, request: OperatorRequest, operation_key: str):
        self._workflow_input(request.action, request)
        arguments = {key: copy.deepcopy(value) for key, value in request.input.items()}
        run_id = arguments.pop("run_id")
        step_id = arguments.pop("step_id")
        arguments["now"] = self.now
        result = self._workflow_service().readiness(run_id, step_id, **arguments)
        return self._workflow_result(
            request,
            operation_key,
            result,
            changed=False,
            object_version=self._run_head(run_id),
            evidence_ref=f"workflows/runs/{run_id}/run.json",
            field="readiness",
        )

    def _conflict_record(self, request: OperatorRequest, operation_key: str):
        self._workflow_input(request.action, request)
        run_id = request.input["run_id"]
        result = self._workflow_service().record_conflicts(
            run_id,
            request.input["readiness"],
            event_id=request.input["event_id"],
            idempotency_key=operation_key,
            now=self.now,
            attended_confirmation=request.input["attended_confirmation"],
            approvals=request.input["approvals"],
        )
        return self._workflow_result(
            request,
            operation_key,
            result,
            changed=bool(result["changed"]),
            object_version=self._run_head(run_id),
            evidence_ref=f".hive/receipts/workflows/{run_id}/events/{request.input['event_id']}.json",
            field="conflict",
        )

    def _approval_preview(self, request: OperatorRequest, operation_key: str):
        self._workflow_input(request.action, request)
        run_id = request.input["run_id"]
        preview = self._workflow_service().step_approval_preview(
            run_id,
            request.input["readiness"],
            action=request.input["action"],
            destination=request.input["destination"],
            expires_at=_time(request.input["expires_at"]),
            now=self.now,
        )
        result = self._workflow_result(
            request,
            operation_key,
            preview,
            changed=False,
            object_version=self._run_head(run_id),
            evidence_ref=f"workflows/runs/{run_id}/run.json",
            field="approval_preview",
        )
        result["data"]["preview_operation_key"] = operation_key
        return result

    def _generated_preview(
        self,
        operation_key: str,
        preview: Mapping[str, Any],
        *,
        action: str,
        field: str,
    ) -> None:
        path = self._operation_path(operation_key)
        if not path.is_file() or path.is_symlink():
            raise ProtocolError(
                "WORKFLOW_APPROVAL_BINDING_MISMATCH",
                "approval preview has no exact shell provenance",
            )
        record = read_json(path)
        result = record.get("result")
        if (
            set(record)
            != {
                "schema_version",
                "operation_key",
                "action",
                "request_digest",
                "state",
                "result",
                "result_digest",
            }
            or record.get("schema_version") != _OPERATION_SCHEMA
            or record.get("operation_key") != operation_key
            or record.get("action") != action
            or _SHA256.fullmatch(str(record.get("request_digest", ""))) is None
            or record.get("state") != "TERMINAL"
            or not isinstance(result, Mapping)
            or record.get("result_digest") != document_digest(result)
            or result.get("data", {}).get("preview_operation_key") != operation_key
            or result.get("data", {}).get(field) != dict(preview)
        ):
            raise ProtocolError(
                "WORKFLOW_APPROVAL_BINDING_MISMATCH",
                "approval preview differs from the exact shell-generated preview",
            )

    def _approval_approve(self, request: OperatorRequest, operation_key: str):
        self._workflow_input(request.action, request)
        run_id = request.input["run_id"]
        preview = request.input["preview"]
        binding = request.input["binding"]
        if not isinstance(preview, Mapping) or not isinstance(binding, Mapping):
            raise ProtocolError(
                "WORKFLOW_APPROVAL_BINDING_MISMATCH",
                "approval requires an exact preview and binding",
            )
        approval_kind = preview.get("approval_kind")
        if binding.get("kind") != approval_kind:
            raise ProtocolError(
                "WORKFLOW_APPROVAL_BINDING_MISMATCH",
                "approval kind differs from its exact binding",
            )
        generated = {
            "STEP_APPROVAL": ("workflows.approvals.preview", "approval_preview"),
            "STALE_RELEASE": ("workflows.stale.preview", "stale_preview"),
            "COMPENSATION": (
                "workflows.compensation.preview",
                "compensation_preview",
            ),
            "ROLLBACK": ("workflows.rollback.preview", "rollback_preview"),
        }.get(str(approval_kind))
        if generated is None:
            raise ProtocolError(
                "WORKFLOW_APPROVAL_BINDING_MISMATCH",
                "approval kind is not supported by the operator shell",
            )
        self._generated_preview(
            request.input["preview_operation_key"],
            preview,
            action=generated[0],
            field=generated[1],
        )
        service = self._workflow_service()
        if approval_kind == "STEP_APPROVAL":
            self._exact(
                binding,
                {"kind", "readiness"},
                code="WORKFLOW_APPROVAL_BINDING_MISMATCH",
            )
            readiness = binding.get("readiness")
            if not isinstance(readiness, Mapping):
                raise ProtocolError(
                    "WORKFLOW_APPROVAL_BINDING_MISMATCH",
                    "step approval requires one exact readiness view",
                )
            expected = service.step_approval_preview(
                run_id,
                readiness,
                action=str(preview.get("action", "")),
                destination=str(preview.get("destination", "")),
                expires_at=_time(preview.get("expires_at")),
                now=_time(preview.get("created_at")),
            )
        elif approval_kind == "STALE_RELEASE":
            self._exact(
                binding,
                {"kind", "session_id"},
                code="WORKFLOW_APPROVAL_BINDING_MISMATCH",
            )
            expected = service.stale_preview(
                run_id,
                str(binding.get("session_id", "")),
                now=_time(preview.get("created_at")),
                expires_at=_time(preview.get("expires_at")),
            )
        elif approval_kind == "COMPENSATION":
            self._exact(
                binding,
                {"kind", "failed_step_id", "failed_attempt"},
                code="WORKFLOW_APPROVAL_BINDING_MISMATCH",
            )
            expected = service.compensation_preview(
                run_id,
                str(binding.get("failed_step_id", "")),
                failed_attempt=binding.get("failed_attempt"),
                now=_time(preview.get("created_at")),
                expires_at=_time(preview.get("expires_at")),
            )
        else:
            self._exact(
                binding,
                {"kind", "step_id", "attempt", "checkpoint"},
                code="WORKFLOW_APPROVAL_BINDING_MISMATCH",
            )
            expected = service.rollback_preview(
                run_id,
                str(binding.get("step_id", "")),
                attempt=binding.get("attempt"),
                checkpoint=str(binding.get("checkpoint", "")),
                now=_time(preview.get("created_at")),
                expires_at=_time(preview.get("expires_at")),
            )
        if dict(preview) != expected:
            raise ProtocolError(
                "WORKFLOW_APPROVAL_BINDING_MISMATCH",
                "approval does not bind the exact workflow preview",
            )
        result = self._workflow_service().approve(
            preview,
            authorization_ref=request.input["authorization_ref"],
            approval_id=request.input["approval_id"],
            idempotency_key=operation_key,
            now=self.now,
        )
        return self._workflow_result(
            request,
            operation_key,
            result,
            changed=bool(result["changed"]),
            object_version=self._run_head(run_id),
            evidence_ref=f".hive/receipts/workflows/{run_id}/events/{request.input['approval_id']}.json",
            field="approval",
        )

    def _claim(self, request: OperatorRequest, operation_key: str):
        self._workflow_input(request.action, request)
        result = self._workflow_service().claim(
            request.input["run_id"],
            request.input["readiness"],
            agent_id=request.input["agent_id"],
            expires_at=_time(request.input["expires_at"]),
            event_id=request.input["event_id"],
            idempotency_key=operation_key,
            now=self.now,
            approvals=request.input["approvals"],
        )
        run_id = request.input["run_id"]
        return self._workflow_result(
            request,
            operation_key,
            result,
            changed=bool(result["changed"]),
            object_version=self._run_head(run_id),
            evidence_ref=f".hive/receipts/workflows/{run_id}/events/{request.input['event_id']}.json",
            field="claim",
        )

    def _deliver(self, request: OperatorRequest, operation_key: str):
        self._workflow_input(request.action, request)
        result = self._workflow_service().deliver_claim(
            request.input["run_id"],
            request.input["claim_event_id"],
            task_id=request.input["task_id"],
            nonce=request.input["nonce"],
            issued_at=_time(request.input["issued_at"]),
            expires_at=_time(request.input["expires_at"]),
            now=self.now,
        )
        run_id = request.input["run_id"]
        return self._workflow_result(
            request,
            operation_key,
            result,
            changed=bool(result["changed"]),
            object_version=self._run_head(run_id),
            evidence_ref=f".hive/agent-operations/inbox/{result['recipient_agent']}/{result['task_id']}.json",
            evidence_sha256=result["task_sha256"],
            field="delivery",
        )

    def _session_start(self, request: OperatorRequest, operation_key: str):
        self._workflow_input(request.action, request)
        result = self._workflow_service().start_session(
            request.input["run_id"],
            claim_event_id=request.input["claim_event_id"],
            session_id=request.input["session_id"],
            total_units=request.input["total_units"],
            current_source_commit=request.input["current_source_commit"],
            current_input_sha256=request.input["current_input_sha256"],
            event_id=request.input["event_id"],
            idempotency_key=operation_key,
            recorded_at=self.now,
        )
        run_id = request.input["run_id"]
        return self._workflow_result(
            request,
            operation_key,
            result,
            changed=bool(result["changed"]),
            object_version=self._run_head(run_id),
            evidence_ref=f".hive/receipts/workflows/{run_id}/sessions/{request.input['session_id']}",
            field="session",
        )

    def _session_record(self, request: OperatorRequest, operation_key: str):
        self._workflow_input(request.action, request)
        result = self._workflow_service().record_session(
            request.input["run_id"],
            request.input["session_id"],
            event_type=request.input["event_type"],
            state=request.input["state"],
            progress=request.input["progress"],
            resources=request.input["resources"],
            outputs=request.input["outputs"],
            current_source_commit=request.input["current_source_commit"],
            current_input_sha256=request.input["current_input_sha256"],
            event_id=request.input["event_id"],
            idempotency_key=operation_key,
            recorded_at=self.now,
        )
        run_id = request.input["run_id"]
        return self._workflow_result(
            request,
            operation_key,
            result,
            changed=bool(result["changed"]),
            object_version=self._run_head(run_id),
            evidence_ref=f".hive/receipts/workflows/{run_id}/sessions/{request.input['session_id']}",
            field="session",
        )

    def _stale_preview(self, request: OperatorRequest, operation_key: str):
        self._workflow_input(request.action, request)
        run_id = request.input["run_id"]
        preview = self._workflow_service().stale_preview(
            run_id,
            request.input["session_id"],
            now=self.now,
            expires_at=_time(request.input["expires_at"]),
        )
        result = self._workflow_result(
            request,
            operation_key,
            preview,
            changed=False,
            object_version=self._run_head(run_id),
            evidence_ref=f".hive/receipts/workflows/{run_id}/sessions/{request.input['session_id']}",
            field="stale_preview",
        )
        result["data"]["preview_operation_key"] = operation_key
        return result

    def _stale_apply(self, request: OperatorRequest, operation_key: str):
        self._workflow_input(request.action, request)
        run_id = request.input["run_id"]
        result = self._workflow_service().release_stale(
            run_id,
            request.input["session_id"],
            preview=request.input["preview"],
            approval=request.input["approval"],
            now=self.now,
            abandonment_event_id=request.input["abandonment_event_id"],
            release_event_id=request.input["release_event_id"],
            idempotency_key=operation_key,
        )
        return self._workflow_result(
            request,
            operation_key,
            result,
            changed=bool(result["changed"]),
            object_version=self._run_head(run_id),
            evidence_ref=f".hive/receipts/workflows/{run_id}/events/{request.input['release_event_id']}.json",
            field="stale_release",
        )

    def _retry_create(self, request: OperatorRequest, operation_key: str):
        self._workflow_input(request.action, request)
        run_id = request.input["run_id"]
        result = self._workflow_service().create_retry(
            run_id,
            request.input["step_id"],
            failed_attempt=request.input["failed_attempt"],
            event_id=request.input["event_id"],
            idempotency_key=operation_key,
            recorded_at=self.now,
        )
        return self._workflow_result(
            request,
            operation_key,
            result,
            changed=bool(result["changed"]),
            object_version=self._run_head(run_id),
            evidence_ref=f".hive/receipts/workflows/{run_id}/events/{request.input['event_id']}.json",
            field="retry",
        )

    def _compensation_preview(self, request: OperatorRequest, operation_key: str):
        self._workflow_input(request.action, request)
        run_id = request.input["run_id"]
        preview = self._workflow_service().compensation_preview(
            run_id,
            request.input["failed_step_id"],
            failed_attempt=request.input["failed_attempt"],
            now=self.now,
            expires_at=_time(request.input["expires_at"]),
        )
        result = self._workflow_result(
            request,
            operation_key,
            preview,
            changed=False,
            object_version=self._run_head(run_id),
            evidence_ref=f"workflows/runs/{run_id}/run.json",
            field="compensation_preview",
        )
        result["data"]["preview_operation_key"] = operation_key
        return result

    def _compensation_authorize(
        self, request: OperatorRequest, operation_key: str
    ):
        self._workflow_input(request.action, request)
        run_id = request.input["run_id"]
        result = self._workflow_service().authorize_compensation(
            run_id,
            request.input["failed_step_id"],
            failed_attempt=request.input["failed_attempt"],
            preview=request.input["preview"],
            approval=request.input["approval"],
            event_id=request.input["event_id"],
            idempotency_key=operation_key,
            recorded_at=self.now,
        )
        return self._workflow_result(
            request,
            operation_key,
            result,
            changed=bool(result["changed"]),
            object_version=self._run_head(run_id),
            evidence_ref=f".hive/receipts/workflows/{run_id}/events/{request.input['event_id']}.json",
            field="compensation",
        )

    def _rollback_preview(self, request: OperatorRequest, operation_key: str):
        self._workflow_input(request.action, request)
        run_id = request.input["run_id"]
        preview = self._workflow_service().rollback_preview(
            run_id,
            request.input["step_id"],
            attempt=request.input["attempt"],
            checkpoint=request.input["checkpoint"],
            now=self.now,
            expires_at=_time(request.input["expires_at"]),
        )
        result = self._workflow_result(
            request,
            operation_key,
            preview,
            changed=False,
            object_version=self._run_head(run_id),
            evidence_ref=f"git:{request.input['checkpoint']}",
            field="rollback_preview",
        )
        result["data"]["preview_operation_key"] = operation_key
        return result

    def _rollback_apply(self, request: OperatorRequest, operation_key: str):
        self._workflow_input(request.action, request)
        run_id = request.input["run_id"]
        result = self._workflow_service().apply_rollback(
            run_id,
            request.input["preview"],
            approval=request.input["approval"],
            start_event_id=request.input["start_event_id"],
            complete_event_id=request.input["complete_event_id"],
            idempotency_key=operation_key,
            now=self.now,
        )
        return self._workflow_result(
            request,
            operation_key,
            result,
            changed=bool(result["changed"]),
            object_version=self._run_head(run_id),
            evidence_ref=f"git:{result['target']}",
            field="rollback",
        )

    def _run_complete(self, request: OperatorRequest, operation_key: str):
        self._workflow_input(request.action, request)
        result = self._workflow_service().complete_run(
            request.input["run_id"],
            event_id=request.input["event_id"],
            idempotency_key=operation_key,
            now=self.now,
            attended_confirmation=request.input["attended_confirmation"],
        )
        run_id = request.input["run_id"]
        return self._workflow_result(
            request,
            operation_key,
            result,
            changed=bool(result["changed"]),
            object_version=self._run_head(run_id),
            evidence_ref=f".hive/receipts/workflows/{run_id}/events/{request.input['event_id']}.json",
            field="completion",
        )

    def _run_cancel(self, request: OperatorRequest, operation_key: str):
        self._workflow_input(request.action, request)
        run_id = request.input["run_id"]
        result = self._workflow_service().cancel_run(
            run_id,
            event_id=request.input["event_id"],
            idempotency_key=operation_key,
            now=self.now,
            attended_confirmation=request.input["attended_confirmation"],
        )
        return self._workflow_result(
            request,
            operation_key,
            result,
            changed=bool(result["changed"]),
            object_version=self._run_head(run_id),
            evidence_ref=f".hive/receipts/workflows/{run_id}/events/{request.input['event_id']}.json",
            field="cancellation",
        )
