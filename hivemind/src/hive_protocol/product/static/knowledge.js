"use strict";

const SVG_NS = "http://www.w3.org/2000/svg";

function svgElement(name, attributes = {}) {
  const element = document.createElementNS(SVG_NS, name);
  Object.entries(attributes).forEach(([key, value]) => element.setAttribute(key, String(value)));
  return element;
}

function nodeId(node) {
  return String(node.node_id || node.id || "UNKNOWN");
}

function selectNode(items, index) {
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
  selectNode(items, target);
}

function renderKnowledgeGraph(container, nodes) {
  const svg = container.querySelector("svg");
  if (!svg || nodes.length === 0) return;
  svg.querySelectorAll("g, line").forEach((element) => element.remove());
  svg.setAttribute("viewBox", `0 0 720 ${Math.max(220, nodes.length * 92)}`);

  const positions = new Map();
  nodes.forEach((node, index) => {
    positions.set(nodeId(node), { x: 80 + (index % 3) * 250, y: 70 + Math.floor(index / 3) * 130 });
  });
  nodes.forEach((node) => {
    const source = positions.get(nodeId(node));
    const links = Array.isArray(node.outgoing_links) ? node.outgoing_links : Array.isArray(node.links) ? node.links : [];
    links.forEach((targetId) => {
      const target = positions.get(String(targetId));
      if (!source || !target) return;
      const edge = svgElement("line", { x1: source.x, y1: source.y, x2: target.x, y2: target.y, class: "graph-edge" });
      svg.append(edge);
    });
  });

  const items = nodes.map((node, index) => {
    const id = nodeId(node);
    const position = positions.get(id);
    const group = svgElement("g", {
      role: "option",
      tabindex: index === 0 ? "0" : "-1",
      "aria-selected": index === 0 ? "true" : "false",
      "aria-label": `${node.title || id}; ${id}`,
      transform: `translate(${position.x} ${position.y})`,
    });
    group.append(svgElement("circle", { r: 32, class: "graph-node" }));
    const label = svgElement("text", { x: 42, y: 5, class: "graph-label" });
    label.textContent = String(node.title || id).slice(0, 52);
    group.append(label);
    svg.append(group);
    return group;
  });
  svg.setAttribute("role", "listbox");
  items.forEach((item, index) => {
    item.addEventListener("keydown", (event) => keyboardNavigation(items, index, event));
    item.addEventListener("click", () => selectNode(items, index));
  });
}

export async function enhanceKnowledge(project, showError) {
  const container = document.querySelector("[data-knowledge-graph='true']");
  if (!container) return;
  try {
    const query = new URLSearchParams({ project_id: project });
    const response = await fetch(`/api/v1/knowledge?${query}`, {
      credentials: "same-origin",
      headers: { "Sec-Fetch-Site": "same-origin" },
    });
    const result = await response.json();
    if (!response.ok || result.outcome === "REFUSED") {
      showError(result.reason_code, "The knowledge enhancement could not load; the complete table remains available.");
      return;
    }
    const nodes = Array.isArray(result.data?.nodes) ? result.data.nodes : [];
    renderKnowledgeGraph(container, nodes);
  } catch {
    showError("KNOWLEDGE_VIEW_UNAVAILABLE", "The knowledge enhancement could not load; the complete table remains available.");
  }
}
