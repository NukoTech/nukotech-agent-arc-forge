# Context Manifest Graph and Memory Binding

Status: candidate component 0.1.0

Owner: example

Provenance: clean-room first-party design.

## Purpose

Bind modular organization context into a deterministic manifest without converting staged interview answers into durable memory. The manifest is a graph index: it points to immutable module candidates and records their relationships, provenance, status, and freshness.

## Required Modules

- `organization_identity`
- `products_and_services`
- `customers_and_users`
- `brand_voice`
- `current_priorities`
- `quality_standards`
- `prohibited_behavior`

Modules may be incomplete or withheld. Missing facts remain explicitly unknown; they are never inferred from a neighboring tenant, product, account, or prior conversation.

## Candidate Record

Every referenced candidate must declare:

- `candidate_id`
- `tenant_ref`
- `project_id`
- `module_id`
- `scope`
- `content_sha256`
- `source_type`
- `source_reference`
- `source_owner`
- `observed_at`
- `last_verified_at`
- `freshness_policy`
- `sensitivity`
- `status`
- `supersedes`
- `conflicts_with`
- `approval_reference`

The content hash is calculated from canonical candidate bytes. The record does not embed secrets; it may contain only an approved secret-manager or Keychain reference when a workflow genuinely needs one.

## Deterministic Graph

- Nodes are module candidates and approved context snapshots.
- Edges are limited to `supports`, `supersedes`, `conflicts_with`, `belongs_to`, and `derived_from`.
- Node and edge order is lexical by stable identifier.
- Backlinks are derived from edges and must produce the same order for the same inputs.
- A new candidate never overwrites prior bytes; it adds a node and may propose a `supersedes` edge.
- Only an approved candidate may become the active manifest pointer.

## State Rules

Allowed states are `staged_unreviewed`, `staged_reviewed`, `approved`, `rejected`, and `superseded`. Composition produces only staged records. Promotion to `approved` requires an external human approval reference and a separately authorized memory operation; this component performs neither.

## Output Boundary

The binding may emit a candidate manifest, deterministic graph, backlinks, hash list, conflict list, and rollback plan. It has no authority to read unrelated repositories, import whole drives or vaults, publish externally, connect accounts, or mutate canonical memory.

## Rollback

Remove the staged candidate manifest and its graph records. Because prior records are immutable and the active pointer is not changed during composition, rollback requires no canonical-memory rewrite.
