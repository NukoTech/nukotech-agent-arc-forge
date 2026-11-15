"""Product bridge over the provider-neutral agent-operation contracts."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from importlib.resources import files
from pathlib import Path
from typing import Any
from uuid import uuid4

from hive_protocol.agents import (
    AgentOperations,
    build_signed_ack,
    build_signed_capability_grant,
    build_signed_task,
    public_pem,
    verify_capability_grant,
)
from hive_protocol.adapters.capture import LocalCaptureAdapter
from hive_protocol.adapters.authority import AdapterAuthorityStore
from hive_protocol.adapters.lifecycle import AdapterLifecycle
from hive_protocol.adapters.manifest import load_manifest, manifest_digest
from hive_protocol.adapters.models import AdapterRequest, validate_adapter_document
from hive_protocol.adapters.registry import AdapterRegistry
from hive_protocol.adapters.research import BoundedResearchAdapter
from hive_protocol.adapters.runtime import AdapterRuntime
from hive_protocol.ask import AskHive
from hive_protocol.research.artifacts import ResearchArtifactStore
from hive_protocol.research.portable import ResearchPortableService
from hive_protocol.research.query import ResearchQueryService
from hive_protocol.research.workspace import BoundedResearchWorkspaceStore
from hive_protocol.core import (
    ProtocolError,
    document_digest,
    generate_keypair,
    load_private_key,
    public_key_id,
    verify_document,
)
from hive_protocol.product.scope import ADAPTER_PROJECT_ID, TENANT_ID
from hive_protocol.retrieval import LocalRetriever
from hive_protocol.storage import (
    atomic_write_json,
    ensure_owned_directory,
    exclusive_lock,
    read_json,
    require_no_symlink_components,
)


SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
WORKSPACE_ID = "local-hive"
ADAPTER_OPERATOR_IDENTITY = {
    "persona_id": "local-operator",
    "surface_id": "hive-local-attended",
    "machine_id": re.sub(r"[^A-Za-z0-9._:-]", "-", platform.node())
    or "local-machine",
    "project_id": ADAPTER_PROJECT_ID,
    "app_actor": "hive-local-attended-cli",
}


@dataclass(frozen=True)
class ProductAdapterServices:
    registry: AdapterRegistry
    runtime: AdapterRuntime
    lifecycle: AdapterLifecycle
    request_key: Any
    approver_key: Any
    runtime_key: Any
    manifests: dict[str, dict[str, Any]]
    authority: AdapterAuthorityStore
    research_store: BoundedResearchWorkspaceStore
    research_query: ResearchQueryService
    research_artifacts: ResearchArtifactStore
    research_portable: ResearchPortableService


def _require_private_key_root(key_root: Path) -> Path:
    raw_root = key_root.expanduser()
    for candidate in [raw_root, *raw_root.parents]:
        if candidate.is_symlink():
            raise ProtocolError(
                "PRIVATE_KEY_BOUNDARY", "private key path may not contain symlinks"
            )
    resolved = raw_root.resolve(strict=False)
    resolved.mkdir(parents=True, exist_ok=True, mode=0o700)
    if (
        resolved.is_symlink()
        or not resolved.is_dir()
        or resolved.resolve() != resolved
        or resolved.stat().st_uid != os.geteuid()
    ):
        raise ProtocolError(
            "PRIVATE_KEY_BOUNDARY",
            "private key root is not an owned canonical directory",
        )
    os.chmod(resolved, 0o700)
    return resolved


def _adapter_private_key(key_root: Path, label: str):
    key_root = _require_private_key_root(key_root)
    with exclusive_lock(key_root / ".bootstrap.lock"):
        key_root = _require_private_key_root(key_root)
        private_path = key_root / f"{label}.private.pem"
        if private_path.is_symlink() or (
            private_path.exists() and not private_path.is_file()
        ):
            raise ProtocolError(
                "PRIVATE_KEY_BOUNDARY", "private key path is not a regular file"
            )
        if not private_path.exists():
            generate_keypair(key_root, label)
        return load_private_key(private_path)


def _adapter_manifest(package: str, filename: str) -> dict[str, Any]:
    document = json.loads(
        files(package).joinpath(filename).read_text(encoding="utf-8")
    )
    if not isinstance(document, dict):
        raise ProtocolError("ADAPTER_MANIFEST_INVALID", "adapter manifest is not an object")
    return document


def _platform_identity() -> tuple[str, str]:
    system = platform.system().lower()
    os_name = {"darwin": "macos"}.get(system, system)
    architecture = platform.machine().lower()
    architecture = {"amd64": "x86_64"}.get(architecture, architecture)
    return os_name, architecture


def _product_adapter_manifests() -> dict[str, dict[str, Any]]:
    return {
        "nukotech.hive.local-capture": _adapter_manifest(
            "hive_protocol.adapters.capture", "local-capture.manifest.json"
        ),
        "nukotech.hive.bounded-research": _adapter_manifest(
            "hive_protocol.adapters.research", "bounded-research.manifest.json"
        ),
    }


def product_adapter_services(
    root: Path, *, research_workspace_id: str = WORKSPACE_ID
) -> ProductAdapterServices:
    from .workspace import HiveWorkspace

    raw_vault = root.expanduser()
    for candidate in [raw_vault, *raw_vault.parents]:
        if candidate.is_symlink():
            raise ProtocolError(
                "ADAPTER_RUNTIME_ROOT_BOUNDARY",
                "adapter vault path may not contain symlinks",
            )
    vault = raw_vault.resolve(strict=False)
    hive_root = vault / ".hive"
    if hive_root.is_symlink():
        raise ProtocolError(
            "ADAPTER_RUNTIME_ROOT_BOUNDARY",
            "adapter vault metadata root may not be a symlink",
        )
    document_root = vault / ".hive" / "application-adapters"
    derived_root = vault / ".hive" / "runtime" / "application-adapters"
    key_root = vault / ".hive" / "keys" / "application-adapters"
    request_key = _adapter_private_key(key_root, "attended-request")
    approver_key = _adapter_private_key(key_root, "attended-approver")
    runtime_key = _adapter_private_key(key_root, "runtime-result")
    os_name, architecture = _platform_identity()
    registry = AdapterRegistry(
        derived_root,
        document_root / "policy",
        os_name=os_name,
        architecture=architecture,
        runtime="python>=3.11",
    )
    workspace = HiveWorkspace(vault)
    vault_key = hashlib.sha256(str(vault).encode("utf-8")).hexdigest()[:16]
    capture = LocalCaptureAdapter(
        workspace,
        vault.parent / f".nukotech-hive-capture-{vault_key}",
        state_signing_key=runtime_key,
    )
    retriever = LocalRetriever(vault / ".hive" / "intelligence.sqlite3")
    research_store = BoundedResearchWorkspaceStore(workspace)
    research_query = ResearchQueryService(research_store, retriever)
    research_artifacts = ResearchArtifactStore(
        research_store,
        derived_root / "state" / "research-artifacts",
        signing_key=runtime_key,
    )
    research_portable = ResearchPortableService(research_store)
    research_exists = research_store.workspace_path(research_workspace_id).is_file()
    research = BoundedResearchAdapter(
        retriever,
        AskHive(retriever),
        tenant_id=TENANT_ID,
        workspace_id=research_workspace_id,
        project_id=ADAPTER_PROJECT_ID,
        state_root=derived_root / "state" / "research",
        state_signing_key=runtime_key,
        research_query_service=research_query,
        artifact_store=research_artifacts if research_exists else None,
        portable_service=research_portable if research_exists else None,
    )
    manifests = _product_adapter_manifests()
    registry.register(capture, manifests["nukotech.hive.local-capture"])
    registry.register(research, manifests["nukotech.hive.bounded-research"])
    runtime = AdapterRuntime(
        document_root,
        registry,
        {public_key_id(request_key.public_key()): request_key.public_key()},
        {public_key_id(approver_key.public_key()): approver_key.public_key()},
        runtime_key,
        trusted_approver_identities={
            public_key_id(approver_key.public_key()): ADAPTER_OPERATOR_IDENTITY
        },
    )
    authority = AdapterAuthorityStore(
        document_root / "policy" / "grants",
        {public_key_id(approver_key.public_key()): approver_key.public_key()},
    )
    authority.ensure_attended_grant(
        signer_key_id=public_key_id(request_key.public_key()),
        identity=ADAPTER_OPERATOR_IDENTITY,
        project_id=ADAPTER_PROJECT_ID,
        authorization_ref="attended-cli:hivemind",
        manifests=manifests,
        policy_signing_key=approver_key,
    )
    return ProductAdapterServices(
        registry=registry,
        runtime=runtime,
        lifecycle=AdapterLifecycle(runtime),
        request_key=request_key,
        approver_key=approver_key,
        runtime_key=runtime_key,
        manifests=manifests,
        authority=authority,
        research_store=research_store,
        research_query=research_query,
        research_artifacts=research_artifacts,
        research_portable=research_portable,
    )


def adapter_invocation_context(
    services: ProductAdapterServices, request_document: dict[str, Any]
) -> InvocationContext:
    validate_adapter_document("adapter-request.v1.schema.json", request_document)
    verify_document(request_document, services.runtime.trusted_request_keys)
    request = AdapterRequest.from_dict(request_document)
    signature = request_document["signature"]
    signer_key_id = signature["key_id"]
    return services.authority.resolve(
        signer_key_id, request.adapter_id
    ).invocation_context()


def adapter_status(root: Path) -> list[dict[str, Any]]:
    vault = root.expanduser().resolve()
    config = vault / ".hive" / "config.json"
    initialized = config.is_file() and not config.is_symlink()
    revocation_path = (
        vault
        / ".hive"
        / "application-adapters"
        / "policy"
        / "adapter-revocations.json"
    )
    revocations: dict[str, Any] = {}
    if revocation_path.exists():
        document = read_json(revocation_path)
        if (
            document.get("schema_version") != "hive.adapter-revocations.v1"
            or not isinstance(document.get("revocations"), dict)
        ):
            raise ProtocolError(
                "ADAPTER_REVOCATIONS_INVALID", "adapter revocation state is malformed"
            )
        revocations = document["revocations"]
    os_name, architecture = _platform_identity()
    status: list[dict[str, Any]] = []
    for adapter_id, document in sorted(_product_adapter_manifests().items()):
        manifest = load_manifest(document)
        compatible = any(
            platform_item
            == {
                "os": os_name,
                "architecture": architecture,
                "runtime": "python>=3.11",
            }
            for platform_item in manifest.platforms
        )
        references = manifest.credential_references
        status.append(
            {
                "adapter_id": adapter_id,
                "version": manifest.version,
                "manifest_digest": manifest_digest(document),
                "compatible": compatible,
                "revoked": adapter_id in revocations,
                "health": {
                    "status": "NOT_PROBED" if initialized else "NOT_INITIALIZED",
                    "evidence": [],
                },
                "credential_state": "NOT_REQUIRED" if not references else "MISSING",
            }
        )
    return status


def _paths(root: Path) -> tuple[Path, Path]:
    root = root.expanduser().resolve()
    config = root / ".hive" / "config.json"
    if not config.is_file() or config.is_symlink():
        raise ProtocolError("VAULT_CONFIG_INVALID", "agent operations require an initialized Hive")
    return root / ".hive" / "agent-operations", root / ".hive" / "keys" / "agents"


def _private_key(root: Path, agent_id: str):
    _, key_root = _paths(root)
    return _adapter_private_key(key_root, agent_id)


def _agent_registration_scope(
    persona: str,
    agent_id: str,
    capabilities: list[str],
    *,
    machine_id: str | None = None,
    surface_id: str | None = None,
    project_ids: list[str] | None = None,
    app_actor: str = "app:hive-local-attended",
) -> dict[str, Any]:
    if not isinstance(persona, str) or not persona.strip():
        raise ProtocolError("AGENT_PERSONA_INVALID", "agent persona is required")
    if not isinstance(agent_id, str) or not SAFE_ID.fullmatch(agent_id):
        raise ProtocolError("AGENT_ID_INVALID", "agent ID must be a path-safe identifier")
    if not isinstance(capabilities, list) or any(
        not isinstance(capability, str) for capability in capabilities
    ):
        raise ProtocolError("CAPABILITY_INVALID", "capabilities must be a list of strings")
    normalized_capabilities = sorted(set(capabilities))
    if (
        not normalized_capabilities
        or any(
            not isinstance(capability, str)
            or not SAFE_ID.fullmatch(capability)
            or capability.lower() != capability
            for capability in normalized_capabilities
        )
    ):
        raise ProtocolError(
            "CAPABILITY_INVALID",
            "at least one lowercase path-safe capability is required",
        )
    if project_ids is not None and (
        not isinstance(project_ids, list)
        or any(not isinstance(project, str) for project in project_ids)
    ):
        raise ProtocolError("AGENT_SCOPE_INVALID", "agent project scope is invalid")
    normalized_projects = sorted(set(project_ids or [ADAPTER_PROJECT_ID]))
    if len(normalized_projects) != 1 or not SAFE_ID.fullmatch(normalized_projects[0]):
        raise ProtocolError(
            "AGENT_SCOPE_INVALID", "agent registration requires exactly one safe project"
        )
    persona_id = f"persona:{persona.strip()}"
    normalized_surface = surface_id or f"surface:{agent_id}"
    normalized_machine = machine_id or (
        f"machine:{re.sub(r'[^A-Za-z0-9._:-]', '-', platform.node()) or 'local-machine'}"
    )
    dimensions = {
        "agent_id": agent_id,
        "persona_id": persona_id,
        "surface_id": normalized_surface,
        "machine_id": normalized_machine,
        "app_actor": app_actor,
    }
    if len(persona_id) > 128 or any(
        not isinstance(value, str) or not SAFE_ID.fullmatch(value)
        for key, value in dimensions.items()
        if key != "persona_id"
    ):
        raise ProtocolError(
            "AGENT_IDENTITY_INVALID", "agent identity fields are not path-safe"
        )
    if len(set(dimensions.values())) != len(dimensions):
        raise ProtocolError(
            "AGENT_IDENTITY_COLLAPSE",
            "agent, persona, surface, machine, and App actor must differ",
        )
    return {
        **dimensions,
        "project_id": normalized_projects[0],
        "project_ids": normalized_projects,
        "capabilities": normalized_capabilities,
        "trust_level": "ATTENDED",
    }


def _agent_policy_private_path(root: Path) -> Path:
    _, key_root = _paths(root)
    return key_root / "policy" / "attended-approver.private.pem"


def _capability_grant_path(root: Path, agent_id: str) -> Path:
    ops_root, _ = _paths(root)
    return ops_root / "grants" / f"{agent_id}.json"


def authorize_agent_capabilities(
    root: Path,
    persona: str,
    agent_id: str,
    capabilities: list[str],
    *,
    machine_id: str | None = None,
    surface_id: str | None = None,
    project_ids: list[str] | None = None,
    app_actor: str = "app:hive-local-attended",
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> dict[str, Any]:
    """Create an attended, expiring policy grant separate from registration."""

    scope = _agent_registration_scope(
        persona,
        agent_id,
        capabilities,
        machine_id=machine_id,
        surface_id=surface_id,
        project_ids=project_ids,
        app_actor=app_actor,
    )
    now = issued_at or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ProtocolError(
            "CAPABILITY_GRANT_TIME_INVALID", "grant issue time requires timezone"
        )
    expiry = expires_at or (now + timedelta(hours=8))
    if expiry.tzinfo is None or expiry <= now:
        raise ProtocolError(
            "CAPABILITY_GRANT_TIME_INVALID", "grant expiry must follow issue time"
        )
    grant_path = _capability_grant_path(root, agent_id)
    grants_root = ensure_owned_directory(
        root.expanduser().resolve(),
        grant_path.parent,
        code="AGENT_CAPABILITY_GRANT_BOUNDARY",
        detail="capability grant directory is not an owned contained directory",
    )
    with exclusive_lock(grants_root / ".authorization.lock"):
        _, key_root = _paths(root)
        policy_root = key_root / "policy"
        private_path = policy_root / "attended-approver.private.pem"
        policy_preexisting = private_path.is_file() and not private_path.is_symlink()
        key = _adapter_private_key(policy_root, "attended-approver")
        key_id = public_key_id(key.public_key())
        grant_fields = {
            "schema_version": "hive.capability-grant.v1",
            "tenant_id": TENANT_ID,
            "workspace_id": WORKSPACE_ID,
            "project_id": scope["project_id"],
            "agent_id": scope["agent_id"],
            "persona_id": scope["persona_id"],
            "surface_id": scope["surface_id"],
            "machine_id": scope["machine_id"],
            "app_actor": scope["app_actor"],
            "capabilities": scope["capabilities"],
            "trust_level": scope["trust_level"],
            "issued_at": now.astimezone(timezone.utc).isoformat(),
            "expires_at": expiry.astimezone(timezone.utc).isoformat(),
            "issuer": key_id,
        }
        existing = None
        if grant_path.exists() and policy_preexisting:
            try:
                existing = verify_capability_grant(
                    read_json(grant_path), {key_id: key.public_key()}, now=now
                )
            except ProtocolError as exc:
                if exc.code != "CAPABILITY_GRANT_EXPIRED":
                    raise
        if existing is not None and all(
            existing.get(field) == value for field, value in grant_fields.items()
        ):
            grant = existing
            changed = False
        else:
            grant = build_signed_capability_grant(
                {**grant_fields, "grant_id": str(uuid4())}, key
            )
            atomic_write_json(grant_path, grant, mode=0o600)
            changed = True
    return {
        "outcome": "AGENT_CAPABILITIES_AUTHORIZED",
        "changed": changed,
        "agent_id": agent_id,
        "project_id": scope["project_id"],
        "capabilities": scope["capabilities"],
        "trust_level": scope["trust_level"],
        "expires_at": grant["expires_at"],
        "grant_sha256": document_digest(grant),
    }


def _require_agent_capability_grant(
    root: Path, scope: dict[str, Any], *, now: datetime | None = None
) -> dict[str, Any]:
    grant_path = _capability_grant_path(root, scope["agent_id"])
    private_path = _agent_policy_private_path(root)
    if (
        not grant_path.is_file()
        or grant_path.is_symlink()
        or not private_path.is_file()
        or private_path.is_symlink()
    ):
        raise ProtocolError(
            "AGENT_CAPABILITY_GRANT_MISSING",
            "registration requires a separate attended capability grant",
        )
    require_no_symlink_components(
        root.expanduser().resolve(),
        grant_path,
        code="AGENT_CAPABILITY_GRANT_BOUNDARY",
        detail="capability grant path may not contain symlinks",
    )
    require_no_symlink_components(
        root.expanduser().resolve(),
        private_path,
        code="AGENT_CAPABILITY_GRANT_BOUNDARY",
        detail="capability policy key path may not contain symlinks",
    )
    key = load_private_key(private_path)
    key_id = public_key_id(key.public_key())
    grant = verify_capability_grant(
        read_json(grant_path), {key_id: key.public_key()}, now=now
    )
    expected = {
        "tenant_id": TENANT_ID,
        "workspace_id": WORKSPACE_ID,
        "project_id": scope["project_id"],
        "agent_id": scope["agent_id"],
        "persona_id": scope["persona_id"],
        "surface_id": scope["surface_id"],
        "machine_id": scope["machine_id"],
        "app_actor": scope["app_actor"],
        "capabilities": scope["capabilities"],
        "trust_level": scope["trust_level"],
        "issuer": key_id,
    }
    if any(grant.get(field) != value for field, value in expected.items()):
        raise ProtocolError(
            "AGENT_CAPABILITY_GRANT_SCOPE_MISMATCH",
            "capability grant does not exactly bind the registration scope",
        )
    return grant


def register_agent(
    root: Path,
    persona: str,
    agent_id: str,
    capabilities: list[str],
    *,
    machine_id: str | None = None,
    surface_id: str | None = None,
    project_ids: list[str] | None = None,
    app_actor: str = "app:hive-local-attended",
    now: datetime | None = None,
) -> dict[str, Any]:
    scope = _agent_registration_scope(
        persona,
        agent_id,
        capabilities,
        machine_id=machine_id,
        surface_id=surface_id,
        project_ids=project_ids,
        app_actor=app_actor,
    )
    _require_agent_capability_grant(root, scope, now=now)
    ops_root, _ = _paths(root)
    key = _private_key(root, agent_id)
    record = {
        "agent_id": agent_id,
        "tenant_id": TENANT_ID,
        "workspace_id": WORKSPACE_ID,
        "persona_id": scope["persona_id"],
        "surface_id": scope["surface_id"],
        "machine_id": scope["machine_id"],
        "project_ids": scope["project_ids"],
        "app_actor": scope["app_actor"],
        "capabilities": scope["capabilities"],
        "trust_level": scope["trust_level"],
        "recipient_aliases": [],
        "key_id": public_key_id(key.public_key()),
        "public_key_pem": public_pem(key),
        "active": True,
    }
    AgentOperations(ops_root).register(record)
    return {
        "outcome": "AGENT_REGISTERED",
        "agent_id": agent_id,
        "persona_id": record["persona_id"],
        "capabilities": scope["capabilities"],
        "trust_level": record["trust_level"],
        "key_id": record["key_id"],
    }


def submit_task(
    root: Path,
    *,
    agent_id: str,
    recipient: str,
    capability: str,
    task: dict[str, Any],
) -> dict[str, Any]:
    from .workspace import HiveWorkspace

    ops_root, _ = _paths(root)
    operations = AgentOperations(ops_root)
    recipient_record = operations.resolve_recipient(TENANT_ID, WORKSPACE_ID, recipient)
    sender_key = _private_key(root, agent_id)
    now = datetime.now(timezone.utc)
    envelope = build_signed_task(
        {
            "schema_version": "hive.task-envelope.v1",
            "task_id": str(uuid4()),
            "tenant_id": TENANT_ID,
            "workspace_id": WORKSPACE_ID,
            "sender_agent": agent_id,
            "recipient_agent": recipient_record["agent_id"],
            "required_capabilities": [capability],
            "required_trust": "OBSERVE",
            "operation": str(task.get("kind", "task.local")),
            "payload": task,
            "provenance": ["nukotech-hive-local-alpha-v0.1.0"],
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(minutes=10)).isoformat(),
            "nonce": uuid4().hex,
        },
        sender_key,
    )
    delivery = operations.deliver(envelope)
    outcome = "REFUSED"
    changed = False
    state_sha256 = None
    result: dict[str, Any] = {"reason": "unsupported local task"}
    if task.get("kind") == "search" and capability == "vault:search":
        query = task.get("query")
        if not isinstance(query, str) or not query.strip():
            raise ProtocolError("TASK_PAYLOAD_INVALID", "search task requires a query")
        hits = HiveWorkspace.open(root).search_exact(query)
        state = {
            "schema_version": "nukotech.hive-local.task-state.v1",
            "task_id": envelope["task_id"],
            "query": query,
            "result_ids": [hit["stable_id"] for hit in hits],
        }
        state_path = root / ".hive" / "agent-task-state" / f"{envelope['task_id']}.json"
        atomic_write_json(state_path, state)
        outcome, changed, state_sha256 = "APPLIED", True, document_digest(state)
        result = {"matches": len(hits), "result_ids": state["result_ids"]}
    recipient_key = _private_key(root, recipient_record["agent_id"])
    acknowledgment = build_signed_ack(
        {
            "schema_version": "hive.task-acknowledgment.v1",
            "ack_id": str(uuid4()),
            "task_id": envelope["task_id"],
            "tenant_id": TENANT_ID,
            "workspace_id": WORKSPACE_ID,
            "recipient_agent": recipient_record["agent_id"],
            "outcome": outcome,
            "changed": changed,
            "state_sha256": state_sha256,
            "acknowledged_at": datetime.now(timezone.utc).isoformat(),
            "nonce": uuid4().hex,
        },
        recipient_key,
    )
    acknowledged = operations.acknowledge(acknowledgment)
    persisted = operations.retrieve_next_turn(
        envelope["task_id"],
        tenant_id=TENANT_ID,
        workspace_id=WORKSPACE_ID,
        recipient_agent=recipient_record["agent_id"],
    )
    return {
        "outcome": outcome,
        "task_id": envelope["task_id"],
        "receipt_id": envelope["task_id"],
        "recipient": recipient_record["agent_id"],
        "capability": capability,
        "delivery": delivery["status"],
        "acknowledgment": acknowledged["status"],
        "changed": changed,
        "result": result,
        "next_turn": persisted["status"],
        "task_sha256": document_digest(envelope),
        "ack_sha256": document_digest(acknowledgment),
    }


def deliver_workflow_step(
    root: Path,
    *,
    agent_id: str,
    required_capabilities: list[str],
    task_id: str,
    nonce: str,
    issued_at: datetime,
    expires_at: datetime,
    now: datetime,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Deliver one claim-bound step envelope without executing its payload."""

    if (
        issued_at.tzinfo is None
        or expires_at.tzinfo is None
        or now.tzinfo is None
        or expires_at <= issued_at
    ):
        raise ProtocolError(
            "WORKFLOW_DELIVERY_TIME_INVALID", "workflow delivery expiry is invalid"
        )
    ops_root, _ = _paths(root)
    operations = AgentOperations(ops_root)
    recipient = operations.resolve_recipient(TENANT_ID, WORKSPACE_ID, agent_id)
    required = sorted(set(required_capabilities))
    if (
        not required
        or required != required_capabilities
        or not set(required).issubset(set(recipient["capabilities"]))
    ):
        raise ProtocolError(
            "WORKFLOW_DELIVERY_CAPABILITY_INVALID",
            "workflow delivery cannot expand the claimed capabilities",
        )
    key = _private_key(root, agent_id)
    envelope = build_signed_task(
        {
            "schema_version": "hive.task-envelope.v1",
            "task_id": task_id,
            "tenant_id": TENANT_ID,
            "workspace_id": WORKSPACE_ID,
            "sender_agent": agent_id,
            "recipient_agent": agent_id,
            "required_capabilities": required,
            "required_trust": "ATTENDED",
            "operation": "workflow.step",
            "payload": payload,
            "provenance": ["hivemind-m3.3-signed-claim"],
            "issued_at": issued_at.astimezone(timezone.utc).isoformat(),
            "expires_at": expires_at.astimezone(timezone.utc).isoformat(),
            "nonce": nonce,
        },
        key,
    )
    task_path = ops_root / "inbox" / agent_id / f"{task_id}.json"
    ledger_path = operations.task_replay.ledger_path
    vault_root = ops_root.parent.parent
    require_no_symlink_components(
        vault_root,
        task_path,
        code="WORKFLOW_DELIVERY_REPLAY_CONFLICT",
        detail="workflow delivery path contains a symlink",
    )
    require_no_symlink_components(
        vault_root,
        ledger_path,
        code="WORKFLOW_DELIVERY_REPLAY_CONFLICT",
        detail="workflow delivery replay path contains a symlink",
    )
    if ledger_path.is_symlink():
        raise ProtocolError(
            "WORKFLOW_DELIVERY_REPLAY_CONFLICT",
            "workflow delivery replay path is unsafe",
        )
    recovered = False
    if task_path.exists() or task_path.is_symlink():
        if task_path.is_symlink() or not task_path.is_file():
            raise ProtocolError(
                "WORKFLOW_DELIVERY_REPLAY_CONFLICT",
                "workflow delivery path is unsafe",
            )
        existing = read_json(task_path)
        if not ledger_path.is_file():
            raise ProtocolError(
                "WORKFLOW_DELIVERY_REPLAY_CONFLICT",
                "workflow delivery has no exact replay record",
            )
        ledger = read_json(ledger_path)
        record = ledger.get("messages", {}).get(task_id)
        if (
            not isinstance(record, dict)
            or record.get("nonce") != nonce
            or record.get("state") not in {"PENDING", "COMPLETE"}
            or document_digest(existing) != document_digest(envelope)
        ):
            raise ProtocolError(
                "WORKFLOW_DELIVERY_REPLAY_CONFLICT",
                "workflow task ID is bound to different delivery bytes",
            )
        operations._verify_task(existing, now=now, enforce_expiry=False)
        if record["state"] == "COMPLETE":
            delivered = {
                "status": "DELIVERED",
                "task_id": task_id,
                "recipient_agent": agent_id,
                "task_sha256": document_digest(envelope),
            }
            recovered = True
        else:
            delivered = operations.deliver(envelope, now=now)
    else:
        delivered = operations.deliver(envelope, now=now)
    return {
        "outcome": "DELIVERED",
        "changed": not recovered,
        "task_id": task_id,
        "recipient_agent": agent_id,
        "task_sha256": document_digest(envelope),
        "delivery": delivered["status"],
        "execution_started": False,
    }


def verify_task_receipt(root: Path, receipt_id: str) -> bool:
    ops_root, _ = _paths(root)
    task_receipt = read_json(ops_root / "receipts" / f"{receipt_id}.json")
    result = AgentOperations(ops_root).retrieve_next_turn(
        receipt_id,
        tenant_id=TENANT_ID,
        workspace_id=WORKSPACE_ID,
        recipient_agent=task_receipt["recipient_agent"],
    )
    return result["status"] == "PERSISTED_NEXT_TURN"


def list_agents(root: Path) -> list[dict[str, Any]]:
    ops_root, _ = _paths(root)
    registry = read_json(ops_root / "registry.json")
    return [
        {key: value for key, value in record.items() if key != "public_key_pem"}
        for record in sorted(registry["agents"].values(), key=lambda item: item["agent_id"])
    ]


def list_tasks(root: Path) -> list[dict[str, Any]]:
    ops_root, _ = _paths(root)
    receipt_paths = sorted((ops_root / "receipts").glob("*.json"))
    if not receipt_paths:
        return []
    operations = AgentOperations(ops_root, initialize=False)
    results = []
    for receipt_path in receipt_paths:
        acknowledgment = read_json(receipt_path)
        task_id = receipt_path.stem
        if (
            not SAFE_ID.fullmatch(task_id)
            or acknowledgment.get("task_id") != task_id
        ):
            raise ProtocolError(
                "AGENT_RECEIPT_BINDING_INVALID",
                "task acknowledgment is not bound to its receipt path",
            )
        persisted = operations.retrieve_next_turn(
            task_id,
            tenant_id=TENANT_ID,
            workspace_id=WORKSPACE_ID,
            recipient_agent=str(acknowledgment.get("recipient_agent", "")),
        )
        task = persisted["task"]
        acknowledgment = persisted["acknowledgment"]
        results.append(
            {
                "task_id": task["task_id"],
                "sender": task["sender_agent"],
                "recipient": task["recipient_agent"],
                "operation": task["operation"],
                "capabilities": task["required_capabilities"],
                "outcome": acknowledgment["outcome"],
                "changed": acknowledgment["changed"],
                "task_sha256": document_digest(task),
                "ack_sha256": document_digest(acknowledgment),
            }
        )
    return results


def product_status(root: Path) -> dict[str, Any]:
    ops_root = root / ".hive" / "agent-operations"
    if not (ops_root / "registry.json").exists():
        return {
            "adapter": "available",
            "agents": 0,
            "tasks": 0,
            "adapters": adapter_status(root),
        }
    return {
        "adapter": "available",
        "agents": len(list_agents(root)),
        "tasks": len(list_tasks(root)),
        "adapters": adapter_status(root),
    }
