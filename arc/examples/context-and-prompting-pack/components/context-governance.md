# Context Governance Harness

Status: candidate component 0.1.0

Owner: example

Provenance: clean-room first-party governance design.

## Decision Boundary

Evaluate every context candidate before it may enter an Agent Arc package and again before any later memory promotion. Default to hold when identity, provenance, freshness, sensitivity, or approval is unresolved.

## Pre-Composition Checks

1. Tenant and project match the authorization subject.
2. Requested modules are explicitly allowed and minimum necessary.
3. Each fact has a source reference, source owner, observed date, and last-verified date.
4. Freshness is sufficient for the task; time-sensitive facts must be reverified.
5. Sensitivity is labeled and unnecessary sensitive content is excluded.
6. Credentials and secret values are absent; only approved secret references may remain.
7. Conflicts are preserved as conflicts, not silently reconciled.
8. Component hashes and declared bytes match.
9. No external action, public publishing, account connection, spending, deletion, deployment, or production mutation is requested.

## Promotion Gate

Composition and staging do not authorize durable memory. A later promotion requires all of:

- An explicit human approval reference tied to the exact content hash
- A named destination and tenant boundary
- A freshness check at promotion time
- A conflict decision
- A rollback pointer to the previous approved snapshot
- A separate authorization that permits the memory side effect

Without every item, return `HOLD_NO_MEMORY_PROMOTION`.

## Mandatory Refusals

Return a refusal receipt and create no package when the request includes:

- Bulk whole-company, repository, Drive, vault, mailbox, or transcript import
- Automatic durable-memory promotion
- Cross-tenant context reuse without explicit source and destination authorization
- Secret harvesting or raw credential storage
- Hidden inference presented as owner-approved fact
- Any side effect outside the authorization envelope

## Third-Party Prompt Library Intake

Prompt libraries may enter only as individually selected research candidates with source, author, license or rights basis, intended use, sensitivity, and content hash. Unknown-rights material may inform clean-room principles but may not be copied into a commercial component. No bulk account scrape or library import is allowed.

## Rollback and Evidence

On refusal or hold, preserve a deterministic receipt containing issue codes and evidence hashes without secret values. Rollback removes only staged candidate artifacts; it never deletes source material or rewrites an approved context snapshot.
