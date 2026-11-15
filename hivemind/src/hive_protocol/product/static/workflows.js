"use strict";

const SVG_NS = "http://www.w3.org/2000/svg";

function svgElement(name, attributes = {}) {
  const element = document.createElementNS(SVG_NS, name);
  Object.entries(attributes).forEach(([key, value]) => element.setAttribute(key, String(value)));
  return element;
}

function control(form, name) {
  return form.elements.namedItem(name);
}

function value(form, name) {
  return String(control(form, name)?.value || "").trim();
}

function list(form, name) {
  return value(form, name).split(",").map((item) => item.trim()).filter(Boolean).sort();
}

export function buildWorkflowDefinition(form, project) {
  const workflowId = value(form, "workflow_id");
  const stepId = value(form, "step_id");
  const dependencies = list(form, "dependencies");
  if (dependencies.length > 0) {
    throw new Error("WORKFLOW_DEPENDENCY_UNKNOWN");
  }
  const approvalRequired = value(form, "approval_required") === "true";
  const portableName = workflowId.replace(/[^A-Za-z0-9._-]/g, "-");
  return {
    schema_version: "hive.workflow-definition.v1",
    workflow_id: workflowId,
    version: Number.parseInt(value(form, "version"), 10),
    tenant_id: "local-user",
    project_id: project,
    title: value(form, "title"),
    description: value(form, "description"),
    parent_digest: null,
    steps: [{
      step_id: stepId,
      kind: "TASK",
      dependencies,
      inputs: [],
      outputs: [{ name: "result", type: "application/json" }],
      required_capabilities: list(form, "capabilities"),
      required_trust: "ATTENDED",
      target: { project_id: project, machine_id: value(form, "machine_id"), surface_id: null },
      approval: { required: approvalRequired, risk_class: approvalRequired ? "HIGH" : "LOW" },
      retry: { max_attempts: 2, timeout_seconds: 300 },
      resources: { max_tokens: 2000, max_cost_microunits: 10000, max_memory_mb: 512 },
      ownership: { branches: [`workflows/${portableName}`], files: [`workflows/${portableName}/${stepId}.json`] },
      rollback: { mode: "GIT_CHECKPOINT", compensation_step_id: null },
    }],
    metadata: { tags: ["alpha"] },
  };
}

function selectStep(items, index) {
  items.forEach((item, itemIndex) => {
    const selected = itemIndex === index;
    item.setAttribute("aria-selected", String(selected));
    item.setAttribute("tabindex", selected ? "0" : "-1");
  });
  items[index]?.focus();
}

function keyboardNavigation(items, index, event) {
  if (!["ArrowRight", "ArrowDown", "ArrowLeft", "ArrowUp", "Home", "End", "Enter", " "].includes(event.key)) return;
  event.preventDefault();
  let target = index;
  if (["ArrowRight", "ArrowDown"].includes(event.key)) target = (index + 1) % items.length;
  if (["ArrowLeft", "ArrowUp"].includes(event.key)) target = (index - 1 + items.length) % items.length;
  if (event.key === "Home") target = 0;
  if (event.key === "End") target = items.length - 1;
  selectStep(items, target);
}

function renderWorkflowGraph(container, workflows) {
  const svg = container.querySelector("svg");
  if (!svg) return;
  const steps = [];
  workflows.forEach((workflow) => {
    const definition = workflow?.definition || {};
    if (!Array.isArray(definition.steps)) return;
    definition.steps.forEach((step) => steps.push({ ...step, workflow_id: definition.workflow_id || "UNKNOWN" }));
  });
  if (steps.length === 0) return;
  svg.querySelectorAll("g, line").forEach((element) => element.remove());
  svg.setAttribute("viewBox", `0 0 ${Math.max(720, steps.length * 230)} 220`);
  const positions = new Map();
  steps.forEach((step, index) => positions.set(String(step.step_id), { x: 85 + index * 220, y: 95 }));
  steps.forEach((step) => {
    const target = positions.get(String(step.step_id));
    const dependencies = Array.isArray(step.dependencies) ? step.dependencies : Array.isArray(step.depends_on) ? step.depends_on : [];
    dependencies.forEach((dependency) => {
      const source = positions.get(String(dependency));
      if (!source || !target) return;
      svg.append(svgElement("line", { x1: source.x, y1: source.y, x2: target.x, y2: target.y, class: "graph-edge" }));
    });
  });
  const items = steps.map((step, index) => {
    const position = positions.get(String(step.step_id));
    const group = svgElement("g", {
      role: "option",
      tabindex: index === 0 ? "0" : "-1",
      "aria-selected": index === 0 ? "true" : "false",
      "aria-label": `${step.workflow_id}; step ${step.step_id}`,
      transform: `translate(${position.x} ${position.y})`,
    });
    group.append(svgElement("rect", { x: -62, y: -28, width: 124, height: 56, rx: 10, class: "graph-node" }));
    const label = svgElement("text", { x: 0, y: 5, "text-anchor": "middle", class: "graph-label" });
    label.textContent = String(step.step_id).slice(0, 24);
    group.append(label);
    svg.append(group);
    return group;
  });
  svg.setAttribute("role", "listbox");
  items.forEach((item, index) => {
    item.addEventListener("keydown", (event) => keyboardNavigation(items, index, event));
    item.addEventListener("click", () => selectStep(items, index));
  });
}

export async function enhanceWorkflows(project, showError) {
  const container = document.querySelector("[data-workflow-graph='true']");
  if (!container) return [];
  try {
    const query = new URLSearchParams({ project_id: project });
    const response = await fetch(`/api/v1/workflows?${query}`, {
      credentials: "same-origin",
      headers: { "Sec-Fetch-Site": "same-origin" },
    });
    const result = await response.json();
    if (!response.ok || result.outcome === "REFUSED") {
      showError(result.reason_code, "The workflow enhancement could not load; the complete table remains available.");
      return [];
    }
    const workflows = Array.isArray(result.data?.workflows) ? result.data.workflows : [];
    renderWorkflowGraph(container, workflows);
    return workflows;
  } catch {
    showError("WORKFLOW_VIEW_UNAVAILABLE", "The workflow enhancement could not load; the complete table remains available.");
    return [];
  }
}
