# HiveApplicationAdapter v0.1 — Draft

Status: `SUPERSEDED / HISTORICAL EVIDENCE / NOT OPERATIVE`

This draft is preserved for design provenance. It is superseded by
`hive-application-adapter-contract-v1.md` and the packaged v1 JSON schemas.
Implementations and compatibility decisions must use the v1 contract; this file
does not grant a legacy compatibility exception.

All capability lanes implement this neutral boundary. Vendor services,
open-source components, local implementations, and manual bridges are
replaceable adapters; none owns canonical project knowledge.

## Manifest

The machine-readable schema is
`hive-application-adapter-manifest.v0.1.schema.json`. A manifest binds adapter
identity/version, capabilities, execution mode, OS/architecture/runtime,
permissions, accepted project/data classifications, request/result schemas,
events, network destinations, credential references, dependency hashes and
licenses, health, rollback/uninstall, retention/deletion, degraded behavior,
and signer policy.

Credential references identify OS-protected entries; credential values are
forbidden. Empty network destinations mean local-only operation.

## Runtime requirements

Adapters must fail closed on wrong identity, project, source, version, digest,
signer, revocation, replay, or dependency. Durable mutation supports dry-run
and emits a signed receipt. Adapters cannot read unrelated projects or write
PRIME unless a distinct governed promoter authorizes that exact operation.

## Common request/result envelope

Requests bind request ID, adapter ID/version, sender surface, target project,
capability, input evidence hashes, authorization reference, nonce, expiry,
and signature. Results bind the request hash, outcome, evidence references,
data classification, side effects, resource use, and receipt signature.

Required outcomes distinguish `APPLIED`, `NO_OP`, `REFUSED`, `DEGRADED`, and
`FAILED`. A missing adapter or dependency never reports success.

## Shared acceptance suite

Every implementation must test correct and wrong identity/project/source,
digest and signer mismatch, replay, revocation, dependency mismatch,
offline/degraded behavior, prompt injection, malicious content, credential
patterns, egress limits, export/reopen, rollback/uninstall, unrelated-file
preservation, and fresh-session recovery. Two independently implemented
adapters must pass this suite before the contract is frozen.
