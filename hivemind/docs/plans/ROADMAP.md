# NukoTech HiveMind roadmap (canonical plan)

Status: alpha. MIT License, Copyright (c) 2026 Nuko Technologies LLC.

HiveMind is a local-first agent workspace: a portable Markdown vault, retrieval and a
typed knowledge graph, capability-checked agent tasks and workflows, Git-backed
snapshot and rollback, signed receipts, and export. A loopback-only operator UI and an
optional local model provider (Ollama on loopback, or retrieval-only) are included.

## Milestones

1. **Local core (shipped in this tree):** vault init/import/search/ask, graph, agents,
   snapshot/rollback/export, receipts, loopback UI (`hive-local`).
2. **Adapter SDK (shipped):** v1 adapter manifest, policy, registry, lifecycle,
   attended runtime; reference capture and bounded-research adapters.
3. **Governed protocol slice (shipped as a sample):** signed identity context, work
   envelopes, memory proposals/promotion, governance release and node pin, and a
   receiver matrix with a configurable sample seat roster. The bundled identity is a
   sample that keeps the `QUEEN` role, with the persona for that slot unassigned for now; deployments supply their own.
4. **Arc integration (next):** `hive-local install-arc <package>` verifies an Agent Arc
   package manifest and maps components to Hive capabilities.
5. **Native packaging (later):** per-platform installers and attested release builds
   against the public repository identity, once it exists.

## Non-goals for the first public release

Hosted or commercial tiers, organization-specific device adapters, and any persona,
device, or account bound to a specific deployment.
