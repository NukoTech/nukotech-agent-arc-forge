"""Escaped, semantic server-rendered views for the local M4 operator shell."""

from __future__ import annotations

import hashlib
import html
from dataclasses import dataclass
from importlib import resources
from typing import Any, Mapping, Sequence

from hive_protocol.core import ProtocolError

from .shell_contracts import MUTATION_ROUTES


@dataclass(frozen=True)
class PageDefinition:
    slug: str
    title: str
    description: str
    api_path: str


PAGE_DEFINITIONS: dict[str, PageDefinition] = {
    "home": PageDefinition(
        "home",
        "Home",
        "A plain-language view of recent work, approvals, health, and evidence.",
        "/api/v1/home",
    ),
    "projects": PageDefinition(
        "projects",
        "Projects",
        "Canonical project activity gathered from every installed Hive lane.",
        "/api/v1/projects",
    ),
    "inbox": PageDefinition(
        "inbox",
        "Inbox",
        "Items waiting for review, approval, recovery, or another attended action.",
        "/api/v1/inbox",
    ),
    "capture": PageDefinition(
        "capture",
        "Capture",
        "Preview local evidence before admitting the exact bytes into this Hive.",
        "/api/v1/capture",
    ),
    "research": PageDefinition(
        "research",
        "Research",
        "Search bounded source sets and produce answers that retain their citations.",
        "/api/v1/research",
    ),
    "memory": PageDefinition(
        "memory",
        "Memory",
        "Review proposed memory separately from promotion, correction, or deletion.",
        "/api/v1/memory",
    ),
    "knowledge": PageDefinition(
        "knowledge",
        "Knowledge",
        "Read versioned notes, backlinks, lifecycle state, and graph evidence.",
        "/api/v1/knowledge",
    ),
    "workflows": PageDefinition(
        "workflows",
        "Workflows",
        "Inspect attended workflow definitions, runs, approvals, and recovery state.",
        "/api/v1/workflows",
    ),
    "agents": PageDefinition(
        "agents",
        "Agents",
        "See registered identities, governed tasks, sessions, and adapter health.",
        "/api/v1/agents",
    ),
    "receipts": PageDefinition(
        "receipts",
        "Receipts",
        "Inspect durable evidence without treating unsupported records as verified.",
        "/api/v1/receipts",
    ),
    "settings": PageDefinition(
        "settings",
        "Settings",
        "Configure local-only behavior and use exact, approval-bound lifecycle tools.",
        "/api/v1/settings",
    ),
}

APP_PATHS: dict[str, str] = {
    "/": "home",
    "/app": "home",
    **{f"/app/{slug}": slug for slug in PAGE_DEFINITIONS if slug != "home"},
}

_STATIC_ASSETS = {
    "/static/app.css": ("app.css", "text/css; charset=utf-8"),
    "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/static/knowledge.js": ("knowledge.js", "text/javascript; charset=utf-8"),
    "/static/workflows.js": ("workflows.js", "text/javascript; charset=utf-8"),
}


@dataclass(frozen=True)
class StaticAsset:
    body: bytes
    content_type: str
    etag: str


@dataclass(frozen=True)
class FieldSpec:
    name: str
    label: str
    help_text: str
    kind: str = "text"
    required: bool = True
    options: tuple[str, ...] = ()
    value_type: str = "string"
    value: str = ""
    typed_confirmation: bool = False
    control_only: bool = False


@dataclass(frozen=True)
class ActionForm:
    action: str
    title: str
    description: str
    fields: tuple[FieldSpec, ...] = ()
    expected: str = "ABSENT"
    destructive: bool = False


def _field(
    name: str,
    label: str,
    help_text: str,
    *,
    kind: str = "text",
    required: bool = True,
    options: tuple[str, ...] = (),
    value_type: str = "string",
    value: str = "",
    typed_confirmation: bool = False,
    control_only: bool = False,
) -> FieldSpec:
    return FieldSpec(
        name,
        label,
        help_text,
        kind,
        required,
        options,
        value_type,
        value,
        typed_confirmation,
        control_only,
    )


_WORKSPACE = _field("workspace_id", "Research workspace", "Use its exact research: identifier.")
_SOURCE_SET = _field("source_set_digest", "Source-set version", "The exact version shown after adding or removing a source.")
_SOURCE_SET_EXPECTED = _field(
    "source_set_digest",
    "Current source-set version",
    "Leave blank only when adding the first source.",
    required=False,
    control_only=True,
)
_RUN = _field("run_id", "Workflow run", "The exact run identifier shown in the control room.")
_STEP = _field("step_id", "Workflow step", "The exact step identifier from the dependency table.")
_RUN_VERSION = _field(
    "run_version",
    "Current run version",
    "The exact run object version shown after its latest change.",
    control_only=True,
)
_ATTENDED = _field(
    "confirmation",
    "Typed confirmation",
    "Type the phrase shown in the confirmation dialog; it is never remembered.",
    typed_confirmation=True,
    control_only=True,
)

INTERACTION_FORMS: dict[str, tuple[ActionForm, ...]] = {
    "capture": (
        ActionForm(
            "capture.preview",
            "1. Preview evidence",
            "Choose a local file or paste text. Nothing canonical changes yet.",
            (
                _field("filename", "Portable filename", "A simple filename without folders."),
                _field("title", "Evidence title", "A clear human-readable title."),
                _field("channel", "Content type", "Choose the matching local parser.", kind="select", options=("MARKDOWN", "TEXT", "PDF", "IMAGE", "WEB_CLIP")),
                _field("media_type", "Media type", "For example text/markdown or application/pdf.", value="text/markdown"),
                _field("privacy_class", "Privacy", "The alpha accepts project-private evidence only.", kind="select", options=("PROJECT_PRIVATE",)),
                _field("text", "Paste text", "Leave blank when choosing a file.", kind="textarea", required=False),
                _field("file_payload", "Choose local file", "The browser sends bounded bytes, never a local path.", kind="file", required=False, control_only=True),
            ),
        ),
        ActionForm(
            "capture.admit",
            "2. Admit exact preview",
            "Admit only the byte-for-byte preview returned by step one.",
            (
                _field("preview_id", "Preview ID", "Filled automatically after preview."),
                _field("preview_digest", "Preview version", "Filled automatically after preview."),
            ),
            expected="BINDING:capture.preview",
        ),
    ),
    "research": (
        ActionForm("research.workspaces.create", "Create research workspace", "Create a project-private bounded workspace.", (_field("workspace_id", "Workspace ID", "Use a research: identifier."), _field("name", "Workspace name", "A plain-language name."), _field("privacy_class", "Privacy", "Project-private only.", kind="select", options=("PROJECT_PRIVATE",)))),
        ActionForm("research.sources.add", "Add source", "Create a new immutable source-set version.", (_WORKSPACE, _SOURCE_SET_EXPECTED, _field("source_id", "Source ID", "Choose an admitted source from Capture."), _field("max_results", "Maximum results", "Between 1 and 100.", kind="number", value_type="integer", value="10"), _field("max_quote_bytes", "Maximum quoted bytes", "Between 32 and 16384.", kind="number", value_type="integer", value="2048")), expected="BINDING:research.source-set.latest"),
        ActionForm("research.sources.remove", "Remove source", "Create a new source-set version without this source.", (_WORKSPACE, _SOURCE_SET_EXPECTED, _field("source_id", "Source ID", "The exact source to remove.")), expected="BINDING:research.source-set.latest"),
        ActionForm("research.search", "Search exact sources", "Search only the visible source-set version.", (_WORKSPACE, _SOURCE_SET, _field("query", "Search terms", "Exact local search terms."), _field("limit", "Result limit", "Between 1 and 100.", kind="number", value_type="integer", value="5")), expected="FIELD:source_set_digest"),
        ActionForm("research.ask", "Ask from sources", "Receive a cited answer or an explicit retrieval-only result.", (_WORKSPACE, _SOURCE_SET, _field("question", "Question", "Ask only about evidence in this source set."), _field("limit", "Citation limit", "Between 1 and 100.", kind="number", value_type="integer", value="5")), expected="FIELD:source_set_digest"),
        ActionForm("research.artifacts.create", "Save cited artifact", "Save the latest cited Ask result as a Markdown artifact.", (_WORKSPACE, _SOURCE_SET, _field("artifact_type", "Artifact type", "Cited answers retain evidence anchors.", kind="select", options=("CITED_ANSWER",)), _field("title", "Artifact title", "A clear title for the saved result.")), expected="FIELD:source_set_digest"),
        ActionForm("research.export", "Export research", "Create a portable archive for this exact source set.", (_WORKSPACE, _SOURCE_SET, _field("filename", "Archive filename", "Use a new .tar.gz filename.")), expected="FIELD:source_set_digest"),
    ),
    "memory": (
        ActionForm("memory.propose", "Propose memory", "Create evidence-bound candidates; this does not promote them.", (_field("title", "Event title", "A short description."), _field("narrative", "Proposed memory", "The exact claim to review.", kind="textarea"), _field("source_id", "Evidence source ID", "An admitted source."), _field("anchor_id", "Evidence anchor ID", "The exact source anchor."), _field("source_sha256", "Evidence SHA-256", "The admitted source digest."), _field("normalized_sha256", "Normalized SHA-256", "Use the normalized digest when present.", required=False), _field("occurred_at", "Occurred at", "An ISO 8601 timestamp with timezone.", kind="datetime-local"))),
        ActionForm("memory.review", "Review candidate", "Record a separate human review decision.", (_field("candidate_id", "Candidate ID", "The exact proposed candidate."), _field("candidate_sha256", "Candidate version", "The exact candidate digest."), _field("outcome", "Decision", "Approve or reject without promotion.", kind="select", options=("APPROVED", "REJECTED")), _field("actor_id", "Reviewer", "The authorized attended reviewer.", value="Owner"), _field("authorization_ref", "Authorization reference", "The attended decision reference.")), expected="FIELD:candidate_sha256"),
        ActionForm("memory.promote", "Promote reviewed memory", "Promote only an exact approved review.", (_field("candidate_id", "Candidate ID", "The reviewed candidate."), _field("candidate_sha256", "Candidate version", "The exact candidate digest."), _field("decision_id", "Decision ID", "The separate review decision."), _field("decision_sha256", "Decision version", "The exact review digest.")), expected="FIELD:decision_sha256"),
        ActionForm("memory.correct", "Propose correction", "Create a correction candidate; review and promotion remain separate.", (_field("target_node_id", "Node to correct", "The exact existing node."), _field("target_sha256", "Current node version", "The exact current node digest."), _field("title", "Correction title", "A short description."), _field("narrative", "Corrected statement", "The proposed corrected claim.", kind="textarea"), _field("source_id", "Evidence source ID", "An admitted source."), _field("anchor_id", "Evidence anchor ID", "The exact anchor."), _field("source_sha256", "Evidence SHA-256", "The source digest."), _field("occurred_at", "Occurred at", "An ISO 8601 timestamp with timezone.", kind="datetime-local")), expected="FIELD:target_sha256"),
        ActionForm("memory.revoke", "Propose revocation", "Create a revocation candidate; no deletion is inferred.", (_field("target_node_id", "Node to revoke", "The exact existing node."), _field("target_sha256", "Current node version", "The exact current node digest."), _field("title", "Revocation title", "A short description."), _field("narrative", "Reason", "Why this memory should be revoked.", kind="textarea"), _field("source_id", "Evidence source ID", "An admitted source."), _field("anchor_id", "Evidence anchor ID", "The exact anchor."), _field("source_sha256", "Evidence SHA-256", "The source digest."), _field("occurred_at", "Occurred at", "An ISO 8601 timestamp with timezone.", kind="datetime-local")), expected="FIELD:target_sha256"),
        ActionForm("memory.retention.scan", "Scan retention", "Create review work only; never delete automatically.", expected="PAGE"),
        ActionForm("memory.deletion.preview", "1. Preview deletion", "Show the exact node set and checkpoint before approval.", (_field("node_id", "Node ID", "The exact memory node."), _field("node_sha256", "Current node version", "The exact current node digest.")), expected="FIELD:node_sha256"),
        ActionForm("memory.deletion.approve", "2. Approve deletion plan", "Approve only the exact previewed plan after typed confirmation.", (_field("plan_id", "Plan ID", "Filled from the deletion preview."), _field("plan_sha256", "Plan version", "The exact preview digest."), _field("actor_id", "Approver", "The authorized attended approver.", value="Owner"), _field("authorization_ref", "Authorization reference", "The attended approval reference."), _ATTENDED), expected="BINDING:memory.deletion.preview", destructive=True),
        ActionForm("memory.deletion.apply", "3. Apply approved deletion", "Apply only the approved exact plan and preserve its checkpoint.", (_field("plan_id", "Plan ID", "The approved deletion plan."), _field("plan_sha256", "Plan version", "The exact plan digest."), _field("approval_id", "Approval ID", "The separate approval."), _field("approval_sha256", "Approval version", "The exact approval digest."), _ATTENDED), expected="BINDING:memory.deletion.approve", destructive=True),
    ),
    "knowledge": (
        ActionForm("knowledge.notes.preview", "1. Preview Markdown note", "Validate content and exact current version before writing.", (_field("relative_path", "Note path", "A portable Markdown path inside PRIME."), _field("content", "Markdown content", "Plain Markdown; embedded HTML remains text.", kind="textarea"), _field("expected_sha256", "Current note version", "Leave blank only for a new note.", required=False)), expected="FIELD:expected_sha256"),
        ActionForm("knowledge.notes.approve", "2. Approve protected note edit", "Required only when the exact preview says approval is needed.", (_field("preview_id", "Preview ID", "Filled from note preview."), _field("preview_sha256", "Preview version", "The exact preview digest."), _field("actor_id", "Approver", "The authorized attended approver.", value="Owner"), _field("authorization_ref", "Authorization reference", "The attended approval reference.")), expected="BINDING:knowledge.notes.preview"),
        ActionForm("knowledge.notes.apply", "3. Apply exact note", "Apply the previewed bytes with the separate approval when required.", (_field("preview_id", "Preview ID", "Filled from note preview."), _field("preview_sha256", "Preview version", "The exact preview digest."), _field("content", "Markdown content", "Must match the preview exactly.", kind="textarea"), _field("approval_id", "Approval ID", "Leave blank when the preview does not require approval.", required=False), _field("approval_sha256", "Approval version", "Leave blank when no approval is required.", required=False)), expected="BINDING:knowledge.notes.approve"),
        ActionForm("knowledge.graph.rebuild", "Rebuild graph view", "Rebuild only the disposable graph projection.", (_field("tag", "Tag filter", "Optional exact tag.", required=False), _field("trust_state", "Trust filter", "Optional trust state.", required=False), _field("lifecycle_state", "Lifecycle filter", "Optional lifecycle state.", required=False)), expected="PAGE"),
    ),
    "agents": (
        ActionForm("agents.capabilities.authorize", "1. Authorize agent capabilities", "Create a separate signed, expiring, attended grant for one exact identity and capability set.", (_field("persona", "Persona", "The declared persona label."), _field("agent_id", "Agent ID", "A stable distinct agent identifier."), _field("capabilities", "Capabilities", "Comma-separated existing capability IDs.", value_type="list"), _field("machine_id", "Machine ID", "The exact machine binding."), _field("surface_id", "Surface ID", "The exact surface binding."), _field("app_actor", "App actor", "A distinct app: actor identifier."), _field("expires_at", "Grant expires at", "An ISO 8601 timestamp within 24 hours.", kind="datetime-local"), _field("attended_confirmation", "Attended authorization", "Confirm this exact capability grant.", kind="select", options=("true",), value_type="boolean"))),
        ActionForm("agents.register", "2. Register authorized agent", "Consume the exact signed grant and bind persona, surface, machine, project, App actor, and capabilities without starting it.", (_field("persona", "Persona", "The authorized persona label."), _field("agent_id", "Agent ID", "The authorized stable agent identifier."), _field("capabilities", "Capabilities", "The authorized comma-separated capability IDs.", value_type="list"), _field("machine_id", "Machine ID", "The authorized machine binding."), _field("surface_id", "Surface ID", "The authorized surface binding."), _field("app_actor", "App actor", "The authorized app: actor identifier."))),
        ActionForm("agents.tasks.submit", "Submit governed task", "Create an attended task record; this does not start execution.", (_field("creator_agent_id", "Creator agent", "A registered agent."), _field("assignee_agent_id", "Assignee agent", "A registered capable agent."), _field("task_id", "Task ID", "A new UUID or stable task identifier."), _field("operation", "Operation", "A non-executable operation label."), _field("capability", "Required capability", "Must be held by creator and assignee."), _field("summary", "Task summary", "Plain-language non-executable work request.", kind="textarea", control_only=True), _field("source_refs", "Evidence references", "Comma-separated source references.", value_type="list", required=False), _field("expires_at", "Expires at", "A future ISO 8601 timestamp with timezone.", kind="datetime-local"))),
    ),
    "workflows": (
        ActionForm("workflows.definitions.preview", "1. Preview workflow definition", "Build one closed attended step without executable fields.", (_field("workflow_id", "Workflow ID", "Use a workflow: identifier."), _field("version", "Version", "A positive version number.", kind="number", value_type="integer", value="1"), _field("title", "Workflow title", "A clear title."), _field("description", "Description", "What this attended workflow records.", kind="textarea"), _field("step_id", "Step ID", "A stable step identifier."), _field("dependencies", "Dependencies", "Comma-separated earlier step IDs.", value_type="list", required=False), _field("capabilities", "Required capabilities", "Comma-separated capability IDs.", value_type="list"), _field("machine_id", "Target machine", "The exact machine binding."), _field("approval_required", "Approval required", "Whether this step is protected.", kind="select", options=("false", "true"), value_type="boolean"))),
        ActionForm("workflows.definitions.publish", "2. Publish exact definition", "Publish only the definition just previewed.", expected="BINDING:workflows.definitions.preview"),
        ActionForm("workflows.runs.launch", "Launch attended run record", "Create orchestration state without starting a worker.", (_field("workflow_id", "Workflow ID", "The published definition."), _field("version", "Version", "The exact published version.", kind="number", value_type="integer", value="1"), _field("run_id", "Run ID", "A new UUID."), _field("source_commit", "Source commit", "The exact 40-character Git commit."), _field("input_manifest_sha256", "Input manifest SHA-256", "The exact input digest."), _field("stale_after_seconds", "Stale after seconds", "A bounded heartbeat interval.", kind="number", value_type="integer", value="600"), _field("max_concurrent_claims", "Maximum claims", "A bounded attended claim count.", kind="number", value_type="integer", value="1"))),
        ActionForm("workflows.readiness", "Check step readiness", "Explain blockers before a claim is created.", (_RUN, _RUN_VERSION, _STEP, _field("attempt", "Attempt", "A positive attempt number.", kind="number", value_type="integer", value="1"), _field("current_source_commit", "Current source commit", "The exact current commit."), _field("current_machine_id", "Current machine", "The machine asking to claim."), _field("task_sha256", "Task SHA-256", "The exact governed task digest.")), expected="RUN"),
        ActionForm("workflows.approvals.preview", "1. Preview protected approval", "Bind the exact readiness view to an attended action and destination.", (_RUN, _RUN_VERSION, _field("action", "Attended action", "Describe the exact non-executable work being approved."), _field("destination", "Destination", "The exact owned output path."), _field("expires_at", "Approval expires at", "An ISO 8601 timestamp with timezone.", kind="datetime-local")), expected="BINDING:workflows.readiness"),
        ActionForm("workflows.approvals.approve", "2. Approve exact workflow preview", "Record a separate attended approval.", (_field("authorization_ref", "Authorization reference", "The attended approval reference."),), expected="BINDING:workflows.approval-preview.latest"),
        ActionForm("workflows.retries.create", "Create bounded retry", "Create the next allowed attempt after a recorded failure.", (_RUN, _RUN_VERSION, _STEP, _field("failed_attempt", "Failed attempt", "The exact prior attempt.", kind="number", value_type="integer", value="1"), _field("event_id", "Event ID", "A new UUID.")), expected="RUN"),
        ActionForm("workflows.rollback.preview", "1. Preview workflow rollback", "Show the exact checkpoint and affected run before approval.", (_RUN, _RUN_VERSION, _STEP, _field("attempt", "Attempt", "The exact attempt being rolled back.", kind="number", value_type="integer", value="1"), _field("checkpoint", "Target commit", "An exact ancestor checkpoint."), _field("expires_at", "Approval expires at", "An ISO 8601 timestamp with timezone.", kind="datetime-local")), expected="RUN"),
        ActionForm("workflows.rollback.apply", "3. Apply approved workflow rollback", "Rollback only the exact approved checkpoint.", (_ATTENDED,), expected="BINDING:workflows.approvals.approve", destructive=True),
        ActionForm("workflows.runs.complete", "Complete attended run", "Mark the run complete only after all required steps are recorded.", (_RUN, _RUN_VERSION, _field("event_id", "Event ID", "A new UUID."), _field("attended_confirmation", "Attended confirmation", "Explicitly confirm completion.", kind="select", options=("true",), value_type="boolean")), expected="RUN"),
    ),
    "settings": (
        ActionForm("settings.provider.preview", "1. Preview provider mode", "No discovery, download, login, or activation occurs.", (_field("mode", "Provider mode", "Choose local auto, Ollama, or retrieval-only.", kind="select", options=("auto", "ollama", "retrieval-only")), _field("model", "Model name", "Optional configured local model name.", required=False)), expected="PAGE"),
        ActionForm("settings.provider.apply", "2. Apply provider preview", "Apply only the exact configuration preview.", expected="BINDING:settings.provider.preview"),
        ActionForm("settings.adapters.plan", "Plan adapter request", "Create a signed plan without invoking it.", (_field("adapter_id", "Adapter", "An installed adapter ID."), _field("capability_id", "Capability", "A declared adapter capability."), _field("title", "Request title", "A plain-language title.", control_only=True), _field("text", "Local text", "Project-private local input.", kind="textarea", control_only=True))),
        ActionForm("settings.adapters.invoke", "Invoke exact adapter plan", "Invoke only the signed request and plan returned above.", expected="BINDING:settings.adapters.plan"),
        ActionForm("settings.lifecycle.preview", "1. Preview adapter uninstall", "Create an ownership-bound uninstall plan without removing anything.", (_field("adapter_id", "Adapter", "The exact installed adapter ID."), _field("operation", "Operation", "The alpha exposes only the ownership-bound uninstall path here.", kind="select", options=("uninstall",)), _field("installation_id", "Installation ID", "The exact ownership-manifest ID."), _field("root", "Install root", "An absolute manifest-owned root."), _field("owned_path", "Owned relative path", "One manifest-owned relative file."), _field("owned_sha256", "Owned file SHA-256", "The exact file digest."))),
        ActionForm("settings.lifecycle.approve", "2. Approve lifecycle plan", "Approve only the signed plan returned above.", expected="BINDING:settings.lifecycle.preview"),
        ActionForm("settings.lifecycle.apply", "3. Apply lifecycle plan", "Apply only the exact plan, approval, and ownership manifest.", (_ATTENDED,), expected="BINDING:settings.lifecycle.approve", destructive=True),
        ActionForm("settings.snapshot", "Create whole-Hive checkpoint", "Commit the exact portable Hive state for recovery.", (_field("message", "Checkpoint message", "A short one-line reason."),), expected="PAGE"),
        ActionForm("settings.export", "Export whole Hive", "Write a new verified portable archive outside the Hive.", (_field("destination", "Absolute export path", "The new archive must be outside this Hive."), _field("expected_state_version", "Current Hive version", "The exact portable-state version shown by the latest checkpoint.")), expected="FIELD:expected_state_version"),
        ActionForm("settings.reopen", "Reopen verified export", "Extract only a verified archive into a new empty target.", (_field("bundle", "Absolute bundle path", "The verified archive."), _field("bundle_sha256", "Bundle SHA-256", "The exact archive digest."), _field("manifest_sha256", "Manifest SHA-256", "The exact embedded manifest digest."), _field("target", "New absolute Hive path", "A new empty destination."))),
        ActionForm("settings.rollback", "Rollback whole Hive", "Restore one exact ancestor checkpoint after typed confirmation.", (_field("checkpoint_commit", "Checkpoint commit", "The exact checkpoint commit."), _field("checkpoint_sha256", "Checkpoint SHA-256", "The exact checkpoint document digest."), _field("expected_current_version", "Current Hive version", "The state being replaced."), _ATTENDED), expected="FIELD:expected_current_version", destructive=True),
    ),
}

INTERACTION_FORMS["settings"] += (
    ActionForm("loadouts.stage", "1. Select loadout package", "Stage the package and its four original evidence files for review. Together they may use up to 16 MiB.", (
        _field("package_file", "Arc package ZIP", "The composed declarative package.", kind="file", control_only=True),
        _field("checksum_manifest_file", "Checksum manifest", "The package's MANIFEST.sha256 file.", kind="file", control_only=True),
        _field("recipe_file", "Original recipe", "The exact recipe used to compose this package.", kind="file", control_only=True),
        _field("registry_file", "Original registry", "The exact component registry used for composition.", kind="file", control_only=True),
        _field("arc_authorization_file", "Arc authorization", "The original declarative authorization file; credentials are never accepted.", kind="file", control_only=True),
    )),
    ActionForm("loadouts.plan", "2. Review loadout change", "Plan admission or a change to an installed loadout. Review its target, component versions, and ownership before approval.", (
        _field("operation", "Change", "Choose admission, revocation, rollback, or uninstall.", kind="select", options=("admit", "revoke", "rollback", "uninstall")),
        _field("loadout_id", "Loadout name", "A stable name using letters, numbers, dots, colons, underscores, or hyphens."),
        _field("stage_id", "Selected package", "Filled from the exact staged files.", required=False),
        _field("stage_digest", "Selected package version", "The exact staged-file binding.", required=False),
        _field("version_digest", "Rollback version", "Choose a previously installed unrevoked version; blank selects the most recent eligible version.", required=False),
        _field("authorization_ref", "Authorization reference", "The user or work instruction authorizing this loadout change."),
        _field("reason", "Reason", "Describe why you want this change.", kind="textarea"),
    )),
    ActionForm("loadouts.approve", "3. Approve reviewed loadout", "Approve the exact reviewed plan for this local target.", (
        _field("plan_digest", "Reviewed plan version", "Filled from the reviewed plan."), _ATTENDED,
    ), expected="FIELD:plan_digest", destructive=True),
    ActionForm("loadouts.apply", "4. Apply approved loadout", "Apply the exact approved change to owned declarative loadout files.", (
        _field("plan_digest", "Reviewed plan version", "Filled from the reviewed plan."),
        _field("approval_digest", "Approval version", "Filled from the separate approval."), _ATTENDED,
    ), expected="FIELD:approval_digest", destructive=True),
)

_ACTION_PATHS = {route.action: route.path for route in MUTATION_ROUTES}


def resolve_app_page(path: str) -> str | None:
    return APP_PATHS.get(path)


def read_static_asset(path: str) -> StaticAsset:
    descriptor = _STATIC_ASSETS.get(path)
    if descriptor is None:
        raise ProtocolError(
            "OPERATOR_ROUTE_UNKNOWN", "operator application resource is not available"
        )
    filename, content_type = descriptor
    try:
        body = (
            resources.files("hive_protocol.product")
            .joinpath("static", filename)
            .read_bytes()
        )
    except (FileNotFoundError, OSError) as exc:
        raise ProtocolError(
            "OPERATOR_RESOURCE_UNAVAILABLE",
            "operator application resource is unavailable",
        ) from exc
    digest = hashlib.sha256(body).hexdigest()
    return StaticAsset(body, content_type, f'"sha256-{digest}"')


def _escape(value: Any) -> str:
    if value is None:
        text = "Not set"
    elif value is True:
        text = "Yes"
    elif value is False:
        text = "No"
    else:
        text = str(value)
    return html.escape(text, quote=True)


def _label(value: Any) -> str:
    return _escape(str(value).replace("_", " ").replace("-", " ").strip().title())


def _render_scalar(value: Any) -> str:
    return f"<span class=\"value\">{_escape(value)}</span>"


def _columns(rows: Sequence[Mapping[str, Any]]) -> list[str]:
    return sorted({str(key) for row in rows for key in row})


def _render_table(rows: Sequence[Mapping[str, Any]], caption: str) -> str:
    columns = _columns(rows)
    head = "".join(f"<th scope=\"col\">{_label(column)}</th>" for column in columns)
    body_rows = []
    for row in rows:
        cells = []
        for column in columns:
            value = row.get(column)
            if isinstance(value, (Mapping, list, tuple)):
                rendered = _render_value(value, f"{caption} {_label(column)}")
            else:
                rendered = _render_scalar(value)
            cells.append(f"<td>{rendered}</td>")
        body_rows.append(f"<tr>{''.join(cells)}</tr>")
    return (
        '<div class="table-scroll" tabindex="0">'
        '<table><caption>'
        + _escape(caption)
        + "</caption><thead><tr>"
        + head
        + "</tr></thead><tbody>"
        + "".join(body_rows)
        + "</tbody></table></div>"
    )


def _render_mapping(value: Mapping[str, Any]) -> str:
    terms = []
    for key in sorted(value, key=str):
        item = value[key]
        rendered = (
            _render_value(item, _label(key))
            if isinstance(item, (Mapping, list, tuple))
            else _render_scalar(item)
        )
        terms.append(f"<dt>{_label(key)}</dt><dd>{rendered}</dd>")
    if not terms:
        return '<p class="empty-state">No records yet.</p>'
    return '<dl class="record">' + "".join(terms) + "</dl>"


def _render_value(value: Any, caption: str) -> str:
    if isinstance(value, Mapping):
        return _render_mapping(value)
    if isinstance(value, (list, tuple)):
        if not value:
            return '<p class="empty-state">No records yet.</p>'
        if all(isinstance(item, Mapping) for item in value):
            return _render_table(value, str(caption))  # type: ignore[arg-type]
        return "<ul>" + "".join(f"<li>{_render_value(item, caption)}</li>" for item in value) + "</ul>"
    return _render_scalar(value)


def _navigation(active_slug: str) -> str:
    links = []
    for slug, page in PAGE_DEFINITIONS.items():
        href = "/app" if slug == "home" else f"/app/{slug}"
        current = ' aria-current="page"' if slug == active_slug else ""
        links.append(f'<li><a href="{href}"{current}>{_escape(page.title)}</a></li>')
    return '<nav aria-label="Primary"><ul>' + "".join(links) + "</ul></nav>"


def _render_field(form_id: str, field: FieldSpec) -> str:
    control_id = f"{form_id}-{field.name.replace('_', '-')}"
    help_id = f"{control_id}-help"
    required = " required" if field.required else ""
    typed = ' data-typed-confirmation="true"' if field.typed_confirmation else ""
    control_only = ' data-control-only="true"' if field.control_only else ""
    common = (
        f'id="{_escape(control_id)}" name="{_escape(field.name)}" '
        f'aria-describedby="{_escape(help_id)}" data-value-type="{_escape(field.value_type)}"'
        f"{required}{typed}{control_only}"
    )
    if field.kind == "textarea":
        control = f"<textarea {common}>{_escape(field.value)}</textarea>"
    elif field.kind == "select":
        options = "".join(
            f'<option value="{_escape(option)}">{_escape(option.replace("_", " ").title())}</option>'
            for option in field.options
        )
        control = f"<select {common}>{options}</select>"
    else:
        value = f' value="{_escape(field.value)}"' if field.value else ""
        control = f'<input type="{_escape(field.kind)}" {common}{value}>'
    return (
        '<div class="field">'
        f'<label for="{_escape(control_id)}">{_escape(field.label)}</label>'
        f'<p id="{_escape(help_id)}">{_escape(field.help_text)}</p>'
        f"{control}</div>"
    )


def _render_action_form(
    form: ActionForm, action_versions: Mapping[str, Any]
) -> str:
    form_id = "action-" + form.action.replace(".", "-")
    route = _ACTION_PATHS[form.action]
    destructive = ' data-confirm="true" data-confirm-phrase="CONFIRM ACTION"' if form.destructive else ""
    fields = "".join(_render_field(form_id, field) for field in form.fields)
    expected = form.expected
    if expected == "PAGE":
        candidate = action_versions.get(form.action)
        expected = candidate if isinstance(candidate, str) else "ABSENT"
    return (
        '<form class="action-card" data-operator-form="true" '
        f'data-action="{_escape(form.action)}" data-route="{_escape(route)}" '
        f'data-expected-version="{_escape(expected)}"{destructive}>'
        f'<fieldset><legend>{_escape(form.title)}</legend>'
        f'<p>{_escape(form.description)}</p>{fields}'
        f'<button type="submit">{_escape(form.title)}</button>'
        "</fieldset></form>"
    )


def _render_receipt_filters() -> str:
    form_id = "receipt-filters"
    fields = (
        _field("lane", "Lane", "Optional exact lane name.", required=False),
        _field("action", "Action", "Optional exact action name.", required=False),
        _field("actor", "Actor or key", "Optional exact actor or public-key ID.", required=False),
        _field("outcome", "Outcome", "Optional exact outcome label.", required=False),
        _field("limit", "Maximum receipts", "Between 1 and 200.", kind="number", value_type="integer", value="100"),
    )
    return (
        '<form class="action-card" data-read-form="true" data-read-route="/api/v1/receipts">'
        '<fieldset><legend>Filter and verify receipts</legend>'
        '<p>Verification state distinguishes supported signatures, digests, structure, and historical records.</p>'
        + "".join(_render_field(form_id, field) for field in fields)
        + '<button type="submit">Apply receipt filters</button></fieldset></form>'
    )


def _render_interactions(slug: str, projection: Mapping[str, Any]) -> str:
    forms = INTERACTION_FORMS.get(slug, ())
    raw_versions = projection.get("action_versions", {})
    action_versions = raw_versions if isinstance(raw_versions, Mapping) else {}
    receipt_form = _render_receipt_filters() if slug == "receipts" else ""
    if not forms and not receipt_form:
        return ""
    return (
        '<section class="operator-actions" aria-labelledby="operator-actions-heading">'
        '<h2 id="operator-actions-heading">Attended actions</h2>'
        '<p>Each button performs only the named step. Preview, approval, and apply are never combined.</p>'
        '<div class="action-grid">'
        + "".join(_render_action_form(form, action_versions) for form in forms)
        + receipt_form
        + "</div></section>"
    )


def _knowledge_alternative(projection: Mapping[str, Any]) -> str:
    raw_nodes = projection.get("nodes", [])
    nodes = [item for item in raw_nodes if isinstance(item, Mapping)] if isinstance(raw_nodes, list) else []
    rows = [
        {
            "node_id": node.get("node_id", node.get("id", "UNKNOWN")),
            "title": node.get("title", "Untitled"),
            "tags": node.get("tags", []),
        }
        for node in nodes
    ]
    edges = []
    for node in nodes:
        source = node.get("node_id", node.get("id", "UNKNOWN"))
        links = node.get("outgoing_links", node.get("links", []))
        if isinstance(links, list):
            edges.extend({"source": source, "target": target} for target in links)
    return (
        '<section class="visual-alternative" aria-labelledby="knowledge-relationships-heading">'
        '<h2 id="knowledge-relationships-heading">Node relationships</h2>'
        '<div data-knowledge-graph="true"><svg role="img" aria-labelledby="knowledge-graph-title knowledge-graph-description" tabindex="0"><title id="knowledge-graph-title">Knowledge graph</title><desc id="knowledge-graph-description">A visual enhancement of the complete node and relationship tables.</desc></svg></div>'
        '<div data-knowledge-table="true">'
        + _render_table(rows, "Knowledge nodes")
        + _render_table(edges, "Knowledge relationships")
        + "</div></section>"
    )


def _workflow_alternative(projection: Mapping[str, Any]) -> str:
    raw_workflows = projection.get("workflows", [])
    rows = []
    if isinstance(raw_workflows, list):
        for workflow in raw_workflows:
            if not isinstance(workflow, Mapping):
                continue
            definition = workflow.get("definition", {})
            if not isinstance(definition, Mapping):
                continue
            workflow_id = definition.get("workflow_id", "UNKNOWN")
            steps = definition.get("steps", [])
            if not isinstance(steps, list):
                continue
            for step in steps:
                if not isinstance(step, Mapping):
                    continue
                rows.append(
                    {
                        "workflow_id": workflow_id,
                        "step_id": step.get("step_id", "UNKNOWN"),
                        "dependencies": step.get(
                            "dependencies", step.get("depends_on", [])
                        ),
                    }
                )
    return (
        '<section class="visual-alternative" aria-labelledby="workflow-dependencies-heading">'
        '<h2 id="workflow-dependencies-heading">Step dependencies</h2>'
        '<div data-workflow-graph="true"><svg role="img" aria-labelledby="workflow-graph-title workflow-graph-description" tabindex="0"><title id="workflow-graph-title">Workflow dependency graph</title><desc id="workflow-graph-description">A visual enhancement of the complete step dependency table.</desc></svg></div>'
        '<div data-workflow-table="true">'
        + _render_table(rows, "Workflow step dependencies")
        + "</div></section>"
    )


def _enhancement_alternative(slug: str, projection: Mapping[str, Any]) -> str:
    if slug == "knowledge":
        return _knowledge_alternative(projection)
    if slug == "workflows":
        return _workflow_alternative(projection)
    return ""


def _confirmation_dialog() -> str:
    return """<dialog id="confirmation-dialog" aria-labelledby="confirmation-title">
<h2 id="confirmation-title">Confirm this exact protected action</h2>
<p>The preview and approval remain separate. Type <strong>CONFIRM ACTION</strong> in the action form before continuing.</p>
<div class="dialog-actions"><button type="button" data-dialog-cancel="true">Go back</button><button type="button" data-dialog-confirm="true">Continue exact action</button></div>
</dialog>"""


def _technical_evidence(projection: Mapping[str, Any], version: str) -> str:
    evidence = projection.get("technical_evidence", [])
    return (
        '<details class="technical-evidence"><summary>Technical evidence</summary>'
        '<dl class="record"><dt>Object version</dt><dd><code>'
        + _escape(version)
        + "</code></dd><dt>Evidence</dt><dd>"
        + _render_value(evidence, "Technical evidence")
        + "</dd></dl></details>"
    )


def render_shell_page(
    slug: str,
    projection: Mapping[str, Any],
    *,
    object_version: str,
) -> bytes:
    page = PAGE_DEFINITIONS.get(slug)
    if page is None:
        raise ProtocolError(
            "OPERATOR_ROUTE_UNKNOWN", "operator application page is not available"
        )
    project = projection.get("project_id", "HiveMind")
    status_value = projection.get("health", "Local-only · attended")
    provider = projection.get("provider")
    if isinstance(provider, Mapping) and isinstance(provider.get("label"), str):
        status_value = provider["label"]
    content = {key: value for key, value in projection.items() if key != "technical_evidence"}
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{_escape(page.title)} · NukoTech HiveMind</title>
<link rel="stylesheet" href="/static/app.css">
<script type="module" src="/static/app.js"></script>
</head>
<body data-page="{_escape(slug)}" data-object-version="{_escape(object_version)}">
<a class="skip-link" href="#main-content">Skip to main content</a>
<header class="site-header">
<a class="brand" href="/app">NukoTech HiveMind <span>Alpha</span></a>
{_navigation(slug)}
</header>
<section class="status-banner" id="project-status" role="status" aria-label="Project status">
<span class="status-marker" aria-hidden="true">●</span>
<span class="status-text">{_escape(project)} · {_escape(status_value)}</span>
</section>
<main id="main-content" tabindex="-1">
<nav aria-label="Breadcrumb"><ol><li><a href="/app">Home</a></li><li aria-current="page">{_escape(page.title)}</li></ol></nav>
<div id="error-summary" role="alert" tabindex="-1" hidden><h2>We could not complete that action</h2><p data-error-message></p><p><code data-error-code></code></p></div>
<div id="request-status" role="status" aria-live="polite"></div>
<section class="page-heading" aria-labelledby="page-title">
<p class="eyebrow">Current project · {_escape(project)}</p>
<h1 id="page-title">{_escape(page.title)}</h1>
<p>{_escape(page.description)}</p>
</section>
<section class="global-search" aria-labelledby="global-search-heading">
<h2 id="global-search-heading">Find local evidence</h2>
<label for="global-search">Search this Hive</label>
<p id="global-search-help">Search imported documents in this local Hive. Research source sets have their own search.</p>
<div class="control-row"><input id="global-search" name="query" type="search" aria-describedby="global-search-help" autocomplete="off"><button type="button" data-action="search">Search</button></div>
<div id="global-search-results" aria-live="polite"></div>
</section>
<section class="projection" aria-labelledby="projection-heading">
<h2 id="projection-heading">Current {_escape(page.title.lower())} state</h2>
{_render_mapping(content)}
</section>
{_enhancement_alternative(slug, projection)}
{_render_interactions(slug, projection)}
{_technical_evidence(projection, object_version)}
</main>
{_confirmation_dialog()}
<footer><p>Local-only · attended operation · no background runner</p></footer>
</body>
</html>""".encode("utf-8")
