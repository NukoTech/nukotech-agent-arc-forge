"use strict";

import { enhanceKnowledge } from "./knowledge.js";
import { buildWorkflowDefinition, enhanceWorkflows } from "./workflows.js";

const root = document.documentElement;
const page = document.body.dataset.page || "home";
const project = document.querySelector(".eyebrow")?.textContent.split("·").pop()?.trim() || "HiveMind";
const statusRegion = document.querySelector("#request-status");
const errorSummary = document.querySelector("#error-summary");
const errorMessage = errorSummary?.querySelector("[data-error-message]");
const errorCode = errorSummary?.querySelector("[data-error-code]");
const dialog = document.querySelector("#confirmation-dialog");
const pendingForms = new WeakSet();
const requestKeys = new WeakMap();
const bindings = new Map();
const settingsCheckpoints = new Map();
const installedLoadouts = new Map();
let csrfProof = null;
let pendingConfirmation = null;
let returnFocus = null;

root.dataset.enhanced = "true";

const remediation = {
  OPERATOR_VERSION_STALE: "Refresh the page and preview the current version again.",
  OPERATOR_REPLAY_CONFLICT: "This action key was already used for different inputs. Review before retrying.",
  WEB_CSRF_DENIED: "Refresh the page to create a new attended browser session.",
  CAPTURE_UPLOAD_HASH_MISMATCH: "Choose the file again; its bytes changed before preview.",
  RESEARCH_SOURCE_SET_STALE: "Reload the current source set before searching or exporting.",
  WORKFLOW_APPROVAL_REQUIRED: "Preview and approve this exact protected step first.",
};

function showStatus(message) {
  if (statusRegion) statusRegion.textContent = message;
}

function showError(code, message) {
  if (!errorSummary || !errorMessage || !errorCode) return;
  errorCode.textContent = code || "OPERATOR_REQUEST_REFUSED";
  errorMessage.textContent = remediation[code] || message || "Review the fields and technical evidence, then try again.";
  errorSummary.hidden = false;
  errorSummary.focus();
}

function clearError() {
  if (!errorSummary) return;
  errorSummary.hidden = true;
  if (errorMessage) errorMessage.textContent = "";
  if (errorCode) errorCode.textContent = "";
}

function textElement(tag, text, attributes = {}) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = String(text);
  Object.entries(attributes).forEach(([name, value]) => element.setAttribute(name, String(value)));
  return element;
}

async function sessionProof() {
  if (csrfProof) return csrfProof;
  const response = await fetch("/api/v1/session", {
    credentials: "same-origin",
    headers: { "Sec-Fetch-Site": "same-origin" },
  });
  const result = await response.json();
  if (!response.ok || result.outcome !== "OK") {
    throw new Error(result.reason_code || "WEB_SESSION_REQUIRED");
  }
  csrfProof = result.data.csrf_proof;
  return csrfProof;
}

function setPath(target, path, value) {
  const parts = path.split(".");
  let cursor = target;
  parts.slice(0, -1).forEach((part) => {
    if (!Object.hasOwn(cursor, part)) cursor[part] = {};
    cursor = cursor[part];
  });
  cursor[parts.at(-1)] = value;
}

function typedValue(control) {
  const raw = control.value.trim();
  const valueType = control.dataset.valueType || "string";
  if (!raw && !control.required) return null;
  if (valueType === "integer") return Number.parseInt(raw, 10);
  if (valueType === "boolean") return raw === "true";
  if (valueType === "list") {
    return raw.split(",").map((item) => item.trim()).filter(Boolean).sort();
  }
  if (control.type === "datetime-local" && raw) return new Date(raw).toISOString();
  return raw;
}

function flatInput(form) {
  const input = {};
  form.querySelectorAll("input, select, textarea").forEach((control) => {
    if (!control.name || control.dataset.controlOnly === "true") return;
    setPath(input, control.dataset.inputPath || control.name, typedValue(control));
  });
  return input;
}

async function sha256(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function base64(bytes) {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 32768) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 32768));
  }
  return btoa(binary);
}

const actionDependencies = {
  "capture.admit": ["capture.preview"],
  "memory.review": ["memory.candidate.latest"],
  "memory.promote": ["memory.review.latest"],
  "memory.deletion.approve": ["memory.deletion.preview"],
  "memory.deletion.apply": ["memory.deletion.approve"],
  "knowledge.notes.approve": ["knowledge.notes.preview"],
  "knowledge.notes.apply": ["knowledge.notes.preview", "knowledge.notes.approve"],
  "workflows.definitions.publish": ["workflows.definitions.preview"],
  "workflows.approvals.preview": ["workflows.readiness"],
  "workflows.approvals.approve": ["workflows.approval-preview.latest"],
  "workflows.rollback.apply": ["workflows.approvals.approve"],
  "settings.provider.apply": ["settings.provider.preview"],
  "settings.adapters.invoke": ["settings.adapters.plan"],
  "settings.lifecycle.approve": ["settings.lifecycle.preview"],
  "settings.lifecycle.apply": ["settings.lifecycle.approve"],
  "settings.rollback": ["settings.checkpoint.latest"],
  "agents.register": ["agents.capabilities.authorize"],
  "loadouts.plan": ["loadouts.stage"],
  "loadouts.approve": ["loadouts.plan"],
  "loadouts.apply": ["loadouts.plan", "loadouts.approve"],
};

function resolveBinding(records, action, visited = new Set()) {
  const direct = records.get(action);
  if (direct) return direct;
  for (const record of records.values()) {
    if (visited.has(record)) continue;
    visited.add(record);
    const nested = resolveBinding(record.dependencies || new Map(), action, visited);
    if (nested) return nested;
  }
  return null;
}

function binding(action) {
  return resolveBinding(bindings, action);
}

function boundResponse(action) {
  return binding(action)?.response || null;
}

function dependencySnapshot(action) {
  const snapshot = new Map();
  (actionDependencies[action] || []).forEach((dependency) => {
    const record = binding(dependency);
    if (record) snapshot.set(dependency, record);
  });
  if (action !== "settings.snapshot") {
    const checkpoint = binding("settings.checkpoint.latest");
    if (checkpoint) snapshot.set("settings.checkpoint.latest", checkpoint);
  }
  return snapshot;
}

function bindingAliases(action) {
  if (["research.sources.add", "research.sources.remove"].includes(action)) return ["research.source-set.latest"];
  if (["memory.propose", "memory.correct", "memory.revoke"].includes(action)) return ["memory.candidate.latest"];
  if (action === "memory.review") return ["memory.review.latest"];
  if (["workflows.approvals.preview", "workflows.rollback.preview"].includes(action)) return ["workflows.approval-preview.latest"];
  if (action.startsWith("workflows.") && !action.startsWith("workflows.definitions.")) return ["workflows.run.latest"];
  if (action === "settings.snapshot") return ["settings.checkpoint.latest"];
  return [];
}

function buildMemoryEvent(action, input) {
  const now = input.occurred_at || new Date().toISOString();
  const proposedAction = action === "memory.correct" ? "CORRECT" : action === "memory.revoke" ? "REVOKE" : "CREATE";
  const target = input.target_node_id || null;
  return {
    event: {
      schema_version: "hive.cognition-event.v1",
      event_id: crypto.randomUUID(),
      tenant_id: "local-user",
      project_id: project,
      event_type: "PROJECT_EVENT",
      privacy_class: "PROJECT_PRIVATE",
      experience_scope: { kind: "DOMAIN", owner_id: project },
      title: input.title,
      text: "",
      structured_claims: [{
        candidate_type: proposedAction === "CREATE" ? "DECISION" : "CORRECTION",
        subject_id: `project:${project}`,
        key: "operator.memory.proposal",
        value: input.narrative,
        narrative: input.narrative,
        proposed_action: proposedAction,
        supersedes: proposedAction === "CORRECT" ? target : null,
        revokes: proposedAction === "REVOKE" ? target : null,
      }],
      evidence: [{
        source_id: input.source_id,
        anchor_id: input.anchor_id,
        source_sha256: input.source_sha256,
        normalized_sha256: input.normalized_sha256 || null,
      }],
      source_ref: `operator-shell:${crypto.randomUUID()}`,
      source_sha256: input.source_sha256,
      occurred_at: now,
      recorded_at: new Date().toISOString(),
    },
  };
}

function applyBindings(action, input) {
  if (action === "loadouts.plan") {
    const staged = boundResponse("loadouts.stage")?.data;
    input.stage_id = input.operation === "admit" ? staged?.stage_id || input.stage_id : null;
    input.stage_digest = input.operation === "admit" ? staged?.stage_digest || input.stage_digest : null;
    if (input.operation !== "rollback") input.version_digest = null;
  }
  if (action === "capture.admit") {
    const preview = boundResponse("capture.preview");
    if (preview) return { preview_id: preview.data.preview_id, preview_digest: preview.object_version };
  }
  if (action === "research.artifacts.create") {
    const asked = boundResponse("research.ask");
    if (asked) input.research_result = asked.data;
  }
  if (["research.search", "research.ask", "research.artifacts.create", "research.export"].includes(action)) {
    const latest = boundResponse("research.source-set.latest");
    if (latest && latest.data.workspace_id === input.workspace_id) input.source_set_digest = latest.data.source_set_digest;
    if (action === "research.export") input.preview_digest = input.source_set_digest;
  }
  if (action === "memory.review") {
    const proposed = boundResponse("memory.candidate.latest");
    if (proposed?.data?.candidates?.length === 1) {
      input.candidate_id = proposed.data.candidates[0].candidate_id;
      input.candidate_sha256 = proposed.data.candidate_sha256[0];
    }
  }
  if (action === "memory.promote") {
    const reviewed = binding("memory.review.latest");
    const decision = reviewed?.response?.data?.decision;
    if (reviewed && decision) {
      input.candidate_id = reviewed.input.candidate_id;
      input.candidate_sha256 = reviewed.input.candidate_sha256;
      input.decision_id = decision.decision_id;
      input.decision_sha256 = reviewed.response.object_version;
    }
  }
  if (action === "memory.deletion.approve") {
    const preview = boundResponse("memory.deletion.preview");
    if (preview) {
      input.plan_id = preview.data.plan.plan_id;
      input.plan_sha256 = preview.object_version;
      input.confirmation = `DELETE ${preview.data.plan.node_id}`;
    }
  }
  if (action === "memory.deletion.apply") {
    const approved = binding("memory.deletion.approve");
    if (approved) {
      return {
        plan_id: approved.input.plan_id,
        plan_sha256: approved.input.plan_sha256,
        approval_id: approved.response.data.approval_id,
        approval_sha256: approved.response.object_version,
      };
    }
  }
  if (action === "settings.provider.apply") {
    const preview = boundResponse("settings.provider.preview");
    if (preview) return { preview: preview.data.preview };
  }
  if (action === "settings.adapters.invoke") {
    const planned = boundResponse("settings.adapters.plan");
    if (planned) return { request: planned.data.request, plan: planned.data.plan, approval: null };
  }
  if (action === "settings.lifecycle.approve") {
    const preview = boundResponse("settings.lifecycle.preview");
    if (preview) return { plan: preview.data.plan };
  }
  if (action === "settings.lifecycle.apply") {
    const preview = binding("settings.lifecycle.preview");
    const approval = boundResponse("settings.lifecycle.approve");
    if (preview && approval) {
      return {
        adapter_id: preview.input.adapter_id,
        operation: preview.input.operation,
        input: preview.input.payload,
        plan: preview.response.data.plan,
        approval: approval.data.approval,
      };
    }
  }
  if (action === "knowledge.notes.approve") {
    const preview = boundResponse("knowledge.notes.preview");
    if (preview) {
      input.preview_id = preview.data.preview_id;
      input.preview_sha256 = preview.object_version;
    }
  }
  if (action === "knowledge.notes.apply") {
    const preview = boundResponse("knowledge.notes.preview");
    const approval = boundResponse("knowledge.notes.approve");
    if (preview) {
      input.preview_id = preview.data.preview_id;
      input.preview_sha256 = preview.object_version;
      input.approval_id = approval?.data.approval_id || null;
      input.approval_sha256 = approval?.object_version || null;
    }
  }
  if (action === "workflows.definitions.publish") {
    const preview = binding("workflows.definitions.preview");
    if (preview) return { definition: preview.input.definition };
  }
  if (action === "workflows.approvals.preview") {
    const readiness = boundResponse("workflows.readiness");
    if (readiness) input.readiness = readiness.data.readiness;
  }
  if (action === "workflows.approvals.approve") {
    const previewBinding = binding("workflows.approval-preview.latest");
    if (previewBinding) {
      const preview = previewBinding.response.data.approval_preview || previewBinding.response.data.rollback_preview;
      const kind = preview.approval_kind;
      const exactBinding = kind === "ROLLBACK"
        ? {
            kind,
            step_id: previewBinding.input.step_id,
            attempt: previewBinding.input.attempt,
            checkpoint: previewBinding.input.checkpoint,
          }
        : { kind, readiness: previewBinding.input.readiness };
      return {
        run_id: previewBinding.input.run_id,
        preview,
        preview_operation_key: previewBinding.response.data.preview_operation_key,
        binding: exactBinding,
        authorization_ref: input.authorization_ref,
        approval_id: crypto.randomUUID(),
      };
    }
  }
  if (action === "workflows.rollback.apply") {
    const approved = binding("workflows.approvals.approve");
    if (approved) {
      return {
        run_id: approved.input.run_id,
        preview: approved.input.preview,
        approval: approved.response.data.approval.approval,
        start_event_id: crypto.randomUUID(),
        complete_event_id: crypto.randomUUID(),
      };
    }
  }
  if (action === "settings.rollback") {
    const entry = settingsCheckpoints.get(input.checkpoint_commit);
    if (entry) {
      if (input.checkpoint_sha256 !== entry.checkpoint_sha256) {
        throw new Error("ROLLBACK_CHECKPOINT_INVALID");
      }
      return {
        checkpoint: entry.checkpoint,
        approval: {
          checkpoint_sha256: input.checkpoint_sha256,
          expected_current_version: input.expected_current_version,
          confirmation: `ROLLBACK ${entry.checkpoint.commit}`,
        },
      };
    }
  }
  return input;
}

async function buildInput(form) {
  const action = form.dataset.action;
  let input = flatInput(form);
  if (action === "loadouts.stage") {
    const limits = { package: 16 * 1024 * 1024, checksum_manifest: 128 * 1024, recipe: 2 * 1024 * 1024, registry: 2 * 1024 * 1024, arc_authorization: 128 * 1024 };
    const files = Object.entries(limits).map(([role, limit]) => ({ role, limit, file: form.elements.namedItem(`${role}_file`)?.files?.[0] }));
    if (files.some((item) => !item.file)) throw new Error("LOADOUT_UPLOAD_INVALID");
    if (files.some((item) => item.file.size > item.limit) || files.reduce((sum, item) => sum + item.file.size, 0) > 16 * 1024 * 1024) throw new Error("LOADOUT_UPLOAD_LIMIT");
    input = { files: [] };
    for (const item of files) {
      const bytes = new Uint8Array(await item.file.arrayBuffer());
      input.files.push({ role: item.role, sha256: await sha256(bytes), data_b64: base64(bytes) });
    }
  } else if (["loadouts.approve", "loadouts.apply"].includes(action)) {
    input.confirmation = form.querySelector("[data-typed-confirmation]").value;
  } else if (action === "capture.preview") {
    const file = form.querySelector("input[type='file']")?.files?.[0];
    if (file) {
      const bytes = new Uint8Array(await file.arrayBuffer());
      delete input.text;
      input = { ...input, kind: "file", data_b64: base64(bytes), sha256: await sha256(bytes) };
    } else {
      const bytes = new TextEncoder().encode(input.text || "");
      input = { ...input, kind: "text", sha256: await sha256(bytes) };
    }
  } else if (action === "research.sources.add") {
    input.retrieval_policy = { exact_first: true, semantic_allowed: false, max_results: input.max_results, max_quote_bytes: input.max_quote_bytes };
    delete input.max_results;
    delete input.max_quote_bytes;
  } else if (["memory.propose", "memory.correct", "memory.revoke"].includes(action)) {
    const eventInput = input;
    input = buildMemoryEvent(action, eventInput);
    if (action !== "memory.propose") {
      input.target_id = eventInput.target_node_id;
      input.target_sha256 = eventInput.target_sha256;
    }
  } else if (action === "memory.review") {
    input.corrections = [];
  } else if (action === "memory.retention.scan") {
    input = { project_id: project };
  } else if (action === "knowledge.graph.rebuild") {
    input = { project_id: project, relation: null, tag: input.tag || null, trust_state: input.trust_state || null, lifecycle_state: input.lifecycle_state || null, node_id: null, direction: null };
  } else if (["agents.capabilities.authorize", "agents.register"].includes(action)) {
    input.project_ids = [project];
  } else if (action === "agents.tasks.submit") {
    const summary = form.querySelector("[name='summary']")?.value.trim() || "";
    input.payload = { request_kind: "ATTENDED", summary };
    input.source_refs = (input.source_refs || []).map((uri) => ({ uri }));
  } else if (action === "workflows.definitions.preview") {
    input = { definition: buildWorkflowDefinition(form, project) };
  } else if (action === "workflows.runs.launch") {
    input.event_id = crypto.randomUUID();
  } else if (action === "workflows.readiness") {
    input.existing_task_sha256s = [];
    input.required_evidence_refs = [];
    input.available_evidence_refs = [];
    input.approvals = [];
    input.explicit_agent_id = null;
  } else if (action === "settings.adapters.plan") {
    const title = form.querySelector("[name='title']")?.value.trim() || "Local adapter request";
    const text = form.querySelector("[name='text']")?.value || "";
    input.payload = { kind: "text", title, text };
    input.evidence_sha256 = [await sha256(new TextEncoder().encode(text))];
  } else if (action === "settings.lifecycle.preview") {
    input.payload = {
      schema_version: "hive.adapter-ownership-manifest.v1",
      installation_id: input.installation_id,
      adapter_id: input.adapter_id,
      adapter_version: "1.0.0",
      root: input.root,
      created_at: new Date().toISOString(),
      paths: [{ path: input.owned_path, kind: "file", sha256: input.owned_sha256 }],
    };
    delete input.installation_id;
    delete input.root;
    delete input.owned_path;
    delete input.owned_sha256;
  }
  return applyBindings(action, input);
}

function expectedVersion(form, input) {
  const rule = form.dataset.expectedVersion || "ABSENT";
  if (rule === "RUN") {
    return boundResponse("workflows.run.latest")?.object_version || form.elements.namedItem("run_version")?.value || "ABSENT";
  }
  if (rule.startsWith("BINDING:")) {
    const action = rule.slice(8);
    const response = boundResponse(action);
    if (response) return response.object_version;
    if (action === "research.source-set.latest") {
      return form.elements.namedItem("source_set_digest")?.value || "ABSENT";
    }
    if (form.dataset.action === "knowledge.notes.apply") {
      return boundResponse("knowledge.notes.preview")?.object_version || "ABSENT";
    }
    return "ABSENT";
  }
  if (rule.startsWith("FIELD:")) {
    const name = rule.slice(6);
    return input[name] || form.elements.namedItem(name)?.value || "ABSENT";
  }
  return rule;
}

function clearSensitive(form) {
  form.querySelectorAll("[data-typed-confirmation='true'], input[type='file']").forEach((control) => {
    control.value = "";
  });
}

function setActionValue(action, name, value) {
  document.querySelectorAll("form[data-action]").forEach((form) => {
    if (form.dataset.action !== action) return;
    const control = form.elements.namedItem(name);
    if (control && "value" in control && value !== null && value !== undefined) {
      control.value = String(value);
    }
  });
}

function setManyActionValues(actions, values) {
  actions.forEach((action) => {
    Object.entries(values).forEach(([name, value]) => setActionValue(action, name, value));
  });
}

function hydrateBoundControls(action, result, input) {
  if (action === "loadouts.stage") setManyActionValues(["loadouts.plan"], { stage_id: result.data.stage_id, stage_digest: result.data.stage_digest });
  if (action === "loadouts.plan") {
    setManyActionValues(["loadouts.approve", "loadouts.apply"], { plan_digest: result.data.plan_digest });
    const plan = result.data.plan;
    for (const [nextAction, verb] of [["loadouts.approve", "APPROVE"], ["loadouts.apply", "APPLY"]]) {
      const form = document.querySelector(`form[data-action='${nextAction}']`);
      if (!form) continue;
      form.dataset.confirmPhrase = `${verb} ${plan.operation.toUpperCase()} ${plan.loadout_id}`;
      const field = form.querySelector("[data-typed-confirmation]");
      field.value = "";
      document.getElementById(field.getAttribute("aria-describedby")).textContent = `Type ${form.dataset.confirmPhrase} to confirm this exact change.`;
    }
  }
  if (action === "loadouts.approve") setManyActionValues(["loadouts.apply"], { approval_digest: result.data.approval_digest });
  if (action === "capture.preview") {
    setManyActionValues(["capture.admit"], { preview_id: result.data.preview_id, preview_digest: result.object_version });
  }
  if (["research.sources.add", "research.sources.remove"].includes(action)) {
    setManyActionValues(
      ["research.sources.add", "research.sources.remove", "research.search", "research.ask", "research.artifacts.create", "research.export"],
      { workspace_id: result.data.workspace_id, source_set_digest: result.data.source_set_digest },
    );
  }
  if (["memory.propose", "memory.correct", "memory.revoke"].includes(action) && result.data.candidates?.length === 1) {
    setManyActionValues(["memory.review"], {
      candidate_id: result.data.candidates[0].candidate_id,
      candidate_sha256: result.data.candidate_sha256[0],
    });
  }
  if (action === "memory.review" && result.data.decision) {
    setManyActionValues(["memory.promote"], {
      candidate_id: input.candidate_id,
      candidate_sha256: input.candidate_sha256,
      decision_id: result.data.decision.decision_id,
      decision_sha256: result.object_version,
    });
  }
  if (action === "memory.deletion.preview") {
    setManyActionValues(["memory.deletion.approve", "memory.deletion.apply"], {
      plan_id: result.data.plan.plan_id,
      plan_sha256: result.object_version,
    });
  }
  if (action === "memory.deletion.approve") {
    setManyActionValues(["memory.deletion.apply"], {
      approval_id: result.data.approval_id,
      approval_sha256: result.object_version,
    });
  }
  if (action === "knowledge.notes.preview") {
    setManyActionValues(["knowledge.notes.approve", "knowledge.notes.apply"], {
      preview_id: result.data.preview_id,
      preview_sha256: result.object_version,
      content: input.content,
    });
  }
  if (action === "knowledge.notes.approve") {
    setManyActionValues(["knowledge.notes.apply"], {
      approval_id: result.data.approval_id,
      approval_sha256: result.object_version,
    });
  }
  if (action === "agents.capabilities.authorize") {
    setManyActionValues(["agents.register"], {
      persona: input.persona,
      agent_id: input.agent_id,
      capabilities: input.capabilities.join(", "),
      machine_id: input.machine_id,
      surface_id: input.surface_id,
      app_actor: input.app_actor,
    });
  }
  if (action.startsWith("workflows.") && input.run_id) {
    setManyActionValues(
      ["workflows.readiness", "workflows.approvals.preview", "workflows.retries.create", "workflows.rollback.preview", "workflows.runs.complete"],
      { run_id: input.run_id, run_version: result.object_version },
    );
  }
  if (action === "settings.snapshot") {
    const checkpoint = result.data.checkpoint;
    setManyActionValues(["settings.rollback"], {
      checkpoint_commit: checkpoint.commit,
      expected_current_version: result.object_version,
    });
    setActionValue("settings.export", "expected_state_version", result.object_version);
  }
}

async function refreshSettingsState() {
  if (page !== "settings") return;
  const query = new URLSearchParams({ project_id: project });
  const response = await fetch(`/api/v1/settings?${query}`, {
    credentials: "same-origin",
    headers: { "Sec-Fetch-Site": "same-origin" },
  });
  const result = await response.json();
  if (!response.ok || result.outcome === "REFUSED") return;
  const checkpoints = Array.isArray(result.data?.checkpoints) ? result.data.checkpoints : [];
  checkpoints.forEach((entry) => settingsCheckpoints.set(entry.checkpoint.commit, entry));
  const latest = checkpoints.at(-1);
  const current = result.data?.action_versions?.["settings.snapshot"];
  if (latest) {
    setManyActionValues(["settings.rollback"], {
      checkpoint_commit: latest.checkpoint.commit,
      checkpoint_sha256: latest.checkpoint_sha256,
      expected_current_version: current,
    });
  }
  if (current) setActionValue("settings.export", "expected_state_version", current);
  await refreshLoadoutChoices();
}

async function refreshLoadoutChoices() {
  const data = await readLane("loadouts");
  installedLoadouts.clear();
  (data.loadouts || []).forEach((item) => installedLoadouts.set(item.loadout_id, item));
  let section = document.querySelector("[data-installed-loadouts]");
  if (!section) { section = textElement("section", undefined, { class: "action-card", "data-installed-loadouts": "true" }); document.querySelector(".operator-actions")?.prepend(section); }
  section.replaceChildren(textElement("h3", "Installed loadouts"));
  if (!installedLoadouts.size) section.append(textElement("p", "No loadouts have been admitted."));
  installedLoadouts.forEach((item) => {
    const card = textElement("details");
    card.append(textElement("summary", `${item.loadout_id} · ${item.status.toLowerCase()}`));
    card.append(textElement("p", `Target: ${item.target.persona_id} / ${item.target.surface_id} / ${item.target.machine_id} · ${item.target.os} ${item.target.architecture}`));
    if (item.reason) card.append(textElement("p", item.reason.replaceAll("_", " ")));
    if (item.retained_recovery?.length) card.append(textElement("p", "Uninstalled content has recovery copies preserved in this Hive. Those copies have not been purged."));
    const components = textElement("ul");
    (item.manifest?.components || item.manifest?.arc?.components || []).forEach((component) => components.append(textElement("li", `${component.id} · ${component.version} · ${component.type}`)));
    card.append(components);
    const details = textElement("details"); details.append(textElement("summary", "Exact installed versions and ownership"), textElement("pre", JSON.stringify(item, null, 2))); card.append(details); section.append(card);
  });
  updateLoadoutSelection();
}

function updateLoadoutSelection() {
  const form = document.querySelector("form[data-action='loadouts.plan']");
  if (!form) return;
  const operation = form.elements.namedItem("operation").value;
  let choice = form.querySelector("[data-picker='loadout_id']");
  if (operation === "admit") { if (choice) choice.hidden = true; }
  else {
    picker(form, "loadout_id", "Choose installed loadout", Array.from(installedLoadouts.values()).map((item) => ({ value: item.loadout_id, label: `${item.loadout_id} · ${item.status.toLowerCase()}` })), form.elements.namedItem("loadout_id").value, updateLoadoutSelection);
    form.querySelector("[data-picker='loadout_id']").hidden = false;
  }
  const item = installedLoadouts.get(form.elements.namedItem("loadout_id").value);
  const versions = operation === "rollback" ? (item?.installed_versions || []).filter((pin) => pin !== item.active_version_digest && !item.revoked_versions.includes(pin)) : [];
  picker(form, "version_digest", "Choose rollback version", versions.map((pin, index) => ({ value: pin, label: `Installed version ${index + 1} · ${pin.slice(0, 12)}` })), form.elements.namedItem("version_digest").value, () => {});
  form.querySelector("[data-picker='version_digest']").hidden = operation !== "rollback";
}

async function readLane(lane) {
  const response = await fetch(`/api/v1/${lane}?${new URLSearchParams({ project_id: project })}`, { credentials: "same-origin", headers: { "Sec-Fetch-Site": "same-origin" } });
  const result = await response.json();
  if (!response.ok || result.outcome === "REFUSED") throw new Error(result.reason_code || "OPERATOR_VIEW_UNAVAILABLE");
  return result.data;
}

function picker(form, name, title, options, selected, onChange) {
  const original = form.elements.namedItem(name);
  if (!original) return;
  const id = `${form.dataset.action.replaceAll(".", "-")}-${name}-choice`;
  let group = form.querySelector(`[data-picker='${name}']`);
  if (!group) {
    group = textElement("div", undefined, { class: "field", "data-picker": name });
    (original.closest(".advanced-details") || original.closest(".field")).before(group);
  }
  group.replaceChildren();
  const select = textElement("select", undefined, { id, "aria-describedby": `${id}-help` });
  select.append(textElement("option", "Choose…", { value: "" }));
  options.forEach((option) => select.append(textElement("option", option.label, { value: option.value })));
  select.value = selected || "";
  original.value = select.value;
  group.append(textElement("label", title, { for: id }), textElement("p", "Select by name.", { id: `${id}-help` }), select);
  select.addEventListener("change", () => { original.value = select.value; onChange(select.value); });
}

function renderLoadoutResult(form, result) {
  if (!form.dataset.action.startsWith("loadouts.")) return;
  let container = form.querySelector("[data-action-result]");
  if (!container) { container = textElement("div", undefined, { class: "action-result", "data-action-result": "true", "aria-live": "polite" }); form.append(container); }
  container.replaceChildren();
  const data = result.data || {};
  if (data.plan && form.dataset.action === "loadouts.plan") {
    const plan = data.plan;
    container.append(textElement("p", `${plan.operation.toUpperCase()}: ${plan.loadout_id}`));
    container.append(textElement("p", `Target: ${plan.target.persona_id} / ${plan.target.surface_id} / ${plan.target.machine_id} · ${plan.target.os} ${plan.target.architecture}`));
    container.append(textElement("p", `Approval expires: ${plan.expires_at}`));
    const pins = plan.payload.manifest?.components || plan.payload.manifest?.arc?.components || [];
    const components = textElement("ul"); pins.forEach((component) => components.append(textElement("li", `${component.id} · ${component.version} · ${component.type}`))); container.append(components);
    if (plan.payload.owned_digests) container.append(textElement("p", `Owned installed versions affected: ${plan.payload.owned_digests.length}`));
    if (plan.operation === "uninstall") container.append(textElement("p", "Uninstall removes this loadout from active use and preserves a recovery copy. It does not purge its content."));
    container.append(textElement("p", `Next: type APPROVE ${plan.operation.toUpperCase()} ${plan.loadout_id} in the approval form.`));
  }
  if (data.receipt?.operation === "uninstall" && data.receipt.content_purged === false) container.append(textElement("p", "Loadout uninstalled. Recovery copies are preserved in this Hive; no content was purged."));
}

function hydrateWorkflowState(workflows) {
  const latest = workflows.at(-1);
  if (!latest?.run?.run_id || !latest.object_version) return;
  setManyActionValues(
    ["workflows.readiness", "workflows.approvals.preview", "workflows.retries.create", "workflows.rollback.preview", "workflows.runs.complete"],
    { run_id: latest.run.run_id, run_version: latest.object_version },
  );
}

async function executeForm(form, button) {
  if (pendingForms.has(form)) return;
  pendingForms.add(form);
  button.disabled = true;
  clearError();
  try {
    const input = await buildInput(form);
    const expected = expectedVersion(form, input);
    let key = requestKeys.get(form);
    if (!key) {
      key = `browser:${crypto.randomUUID()}`;
      requestKeys.set(form, key);
    }
    const action = form.dataset.action;
    const request = {
      schema_version: "hive.operator-request.v1",
      request_id: crypto.randomUUID(),
      tenant_id: "local-user",
      project_id: project,
      action,
      expected_version: expected,
      idempotency_key: key,
      input,
    };
    const response = await fetch(form.dataset.route, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "Sec-Fetch-Site": "same-origin",
        "X-Hive-CSRF": await sessionProof(),
        "X-Hive-Idempotency-Key": key,
        "If-Match": expected,
      },
      body: JSON.stringify(request),
    });
    const result = await response.json();
    if (!response.ok || result.outcome === "REFUSED") {
      showError(result.reason_code, "The governed service refused this exact action.");
      return;
    }
    requestKeys.delete(form);
    const dependencies = dependencySnapshot(action);
    const previousVersion = document.body.getAttribute("data-object-version");
    if (result.changed && previousVersion !== result.object_version) {
      bindings.clear();
      document.body.setAttribute("data-object-version", result.object_version);
    }
    const record = { response: result, input, dependencies };
    bindings.set(action, record);
    bindingAliases(action).forEach((alias) => bindings.set(alias, record));
    hydrateBoundControls(action, result, input);
    renderLoadoutResult(form, result);
    if (page === "settings" && result.changed) await refreshSettingsState();
    showStatus(`${action.replaceAll(".", " ")} · ${result.outcome}. No approval was inferred.`);
    clearSensitive(form);
  } catch (error) {
    const code = error instanceof Error ? error.message : "WEB_REQUEST_FAILED";
    showError(code, "The request did not complete. Its action key is retained for a safe retry.");
  } finally {
    pendingForms.delete(form);
    button.disabled = false;
  }
}

async function executeReadForm(form, button) {
  if (pendingForms.has(form)) return;
  pendingForms.add(form);
  button.disabled = true;
  clearError();
  try {
    const query = new URLSearchParams({ project_id: project });
    Object.entries(flatInput(form)).forEach(([name, value]) => {
      if (value !== null && value !== "") query.set(name, String(value));
    });
    const response = await fetch(`${form.dataset.readRoute}?${query}`, { credentials: "same-origin", headers: { "Sec-Fetch-Site": "same-origin" } });
    const result = await response.json();
    if (!response.ok) return showError(result.reason_code, "Receipt filtering was refused.");
    showStatus(`Receipt filter complete · ${result.data.receipts.length} verified or labeled records.`);
  } finally {
    pendingForms.delete(form);
    button.disabled = false;
  }
}

document.addEventListener("submit", (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) return;
  event.preventDefault();
  const button = event.submitter instanceof HTMLButtonElement ? event.submitter : form.querySelector("button[type='submit']");
  if (!button) return;
  if (form.dataset.readForm === "true") {
    executeReadForm(form, button);
    return;
  }
  if (form.dataset.confirm === "true") {
    const typed = form.querySelector("[data-typed-confirmation='true']")?.value;
    if (typed !== form.dataset.confirmPhrase) {
      showError("TYPED_CONFIRMATION_REQUIRED", `Type ${form.dataset.confirmPhrase} exactly before continuing.`);
      return;
    }
    pendingConfirmation = { form, button };
    returnFocus = button;
    dialog.showModal();
    return;
  }
  executeForm(form, button);
});

dialog?.querySelector("[data-dialog-cancel]")?.addEventListener("click", () => dialog.close("cancel"));
dialog?.querySelector("[data-dialog-confirm]")?.addEventListener("click", () => {
  const pending = pendingConfirmation;
  pendingConfirmation = null;
  dialog.close("confirmed");
  if (pending) executeForm(pending.form, pending.button);
});
dialog?.addEventListener("close", () => {
  if (returnFocus) returnFocus.focus();
  returnFocus = null;
});
dialog?.addEventListener("cancel", () => {
  pendingConfirmation = null;
});

document.addEventListener("click", async (event) => {
  const trigger = event.target.closest("[data-action='search']");
  if (!trigger || trigger.disabled || !statusRegion) return;
  const field = document.querySelector("#global-search");
  const results = document.querySelector("#global-search-results");
  if (!results) return;
  const query = field instanceof HTMLInputElement ? field.value.trim() : "";
  results.replaceChildren();
  clearError();
  if (!query) { showStatus("Enter a local search term first."); return; }
  trigger.disabled = true;
  showStatus("Searching imported local documents…");
  try {
    const response = await fetch(`/api/search?${new URLSearchParams({ q: query })}`, { credentials: "same-origin" });
    const result = await response.json();
    if (!response.ok || !Array.isArray(result.results)) throw new Error(result.reason_code || "SEARCH_UNAVAILABLE");
    if (field.value.trim() !== query) { showStatus("Search terms changed. Search again for the current text."); return; }
    results.append(textElement("h3", `Results for “${query}”`));
    for (const item of result.results) {
      const entry = textElement("article");
      entry.append(textElement("h4", item.title), textElement("p", item.snippet));
      const evidence = textElement("details");
      evidence.append(textElement("summary", "Source evidence"), textElement("pre", `${item.path}\nSHA-256: ${item.source_sha256}`));
      entry.append(evidence);
      results.append(entry);
    }
    showStatus(result.results.length ? `${result.results.length} local document(s) found.` : "No imported local documents matched.");
  } catch (error) {
    showStatus("Local search could not finish.");
    showError(error.message, "Local search could not finish. Reopen the app if its session has ended.");
  } finally {
    trigger.disabled = false;
  }
});

document.querySelector("#global-search")?.addEventListener("keydown", (event) => {
  if (event.key === "Enter") { event.preventDefault(); document.querySelector("[data-action='search']")?.click(); }
});

if (page === "knowledge") enhanceKnowledge(project, showError);
if (page === "workflows") enhanceWorkflows(project, showError).then(hydrateWorkflowState);
if (page === "settings") {
  document.querySelector("form[data-action='loadouts.plan'] [name='operation']")?.addEventListener("change", updateLoadoutSelection);
  refreshSettingsState().catch((error) => showError(error.message, "Settings choices could not load."));
}
