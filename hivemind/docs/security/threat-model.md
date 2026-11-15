# Hive protocol reference threat model

Status: LAB/STAGING only

Scope: provider-neutral protocol contracts and the disposable reference turn

Enforcement posture: fail-closed validation in the reference implementation

## Protected assets

- The nine independent identity dimensions: persona, surface, agent/worker, model/runtime, machine/node, project, seat, vault namespace, and capability/authority.
- Authorization references, environment constraints, and the exact capability set.
- Work-envelope, delivery, acknowledgment, proposal, review, promotion, distribution, rollback, and next-turn receipt integrity.
- Replay uniqueness for message identifiers and nonces.
- Filesystem boundaries for LAB runs, private signing keys, mailboxes, and vault notes.
- Durable proof that a consumer changed behavior and that the state remains retrievable on the next turn.

## Trust boundaries

The issuer, consumer/proposer, reviewer, promoter, and node use separate disposable Ed25519 keys. Public keys are copied into a run-local trust store; private keys must be regular mode-0600 files. A work envelope crosses the sender outbox, router, recipient inbox, consumer, persona/surface proposal lanes, reviewer, promoter, vault graph, Bases, and next-turn retriever. A separate signed governance manifest crosses the issuer, reviewer pin, and node staging boundary without activation. Each transition must validate the prior signed document or bind an unsigned operational receipt to signed content by digest and expected identity/machine/surface metadata.

The reference implementation writes only below a marked, non-symlinked LAB root. GitHub remains implementation authority. HiveVault promotion in this slice is disposable and local; it does not activate or schedule any external vault promoter. Heartbeat, mailbox, orchestration-persona, and production services are external contract peers and remain outside this implementation branch.

## Threats and controls

| Threat | Fail-closed control | Verification |
|---|---|---|
| Signature tampering | Ed25519 verification over canonical unsigned JSON | Unsigned envelope and acknowledgment tamper tests |
| Replay | Locked message-ID and nonce ledger with `PENDING`/`COMPLETE` transaction states | Consumer replay and concurrent router tests |
| Forged identity or recipient | Exact marker-to-envelope tuple comparison | Re-signed identity and recipient forgery tests |
| Capability escalation | Requested capabilities must equal the authorized set | Added-capability and missing-capability tests |
| Expired or future work | Bounded issued/expiry timestamps | Expired-envelope test |
| Cross-machine consumption | Exact recipient machine check | Process-separated flow and policy validation |
| Atomic-write interruption | Same-directory temporary, fsync, atomic replace, cleanup | Injected replace-failure test preserves prior target |
| Router crash after replay claim | Durable pending claim plus idempotent archive/inbox recovery | Injected archive-write crash and successful retry |
| Concurrent delivery | Whole-router filesystem transaction lock plus replay ledger | Two-process race produces one delivery and one replay refusal |
| Symlink or path traversal | Real-directory and safe-note-name boundaries | Symlinked LAB root and malicious note-name tests |
| Poisoned operational receipt | Message, digest, machine, and recipient binding before promotion | Forged delivery receipt test |
| Malicious Obsidian links | ASCII allowlist for note/entity names; generated typed links only | Brackets, traversal, alias, and newline rejection tests |
| False next-turn persistence | Signed receipt binds exact state, artifact, Base, and note digests; backlink presence checked | State drift and false Base persistence tests |
| Poisoned memory promotion | Only `APPLIED` signed acknowledgments with matching persisted state are eligible | Promotion eligibility and signature tests |
| Persona/surface lane forgery | Proposal lane owner and identity digest must match the signed envelope | Forged lane and persona-continuity tests |
| Uncontrolled PRIME write | Proposer writes only STAGING; promoter requires a separately keyed signed review decision over the exact proposal digest set | Direct-write, reviewer-tamper, and unreviewed-proposal tests |
| Silent contradiction overwrite | Precondition hash and competing fact keys are evaluated before approval; conflicts remain visible in STAGING | Existing-fact-without-precondition conflict test |
| Raw memory or credentials in GitHub | Release allowlist contains schemas and Bases only; manifest classifications and content flags must be non-private/false | Raw-memory release refusal and credential scan |
| Release or node-pin tampering | Issuer signs version/tree/artifact manifest; reviewer signs exact release digest and node/version pin | Artifact drift, release signature, and pin mismatch tests |
| Unauthorized node activation | LAB pin schema requires `activation: false`; staging refuses an activating pin | Signed staging test asserts `STAGED_NOT_ACTIVATED` |
| Incomplete pruning | Two-stage Base requires `FLAGGED`, then 30-day `QUARANTINED`, then a deletion receipt | Two-stage retention and receipt test; no deletion performed |
| Rollback substitution or residue | Node verifies its signed stage receipt and exact version; full rollback requires durable retrieval evidence and an exact marked path | Release rollback and full residue-free rollback tests |

## Residual risks and held seams

- The reference trust store is run-local and does not yet implement a multi-host key-distribution or revocation service.
- Delivery receipts are not independently signed; promotion instead binds their fields to a verified envelope and the expected run marker. A future protocol revision should define a router signature schema.
- Replay state is host-filesystem scoped. Distributed replay consensus is intentionally deferred to a contract-owned service.
- A power loss can require replaying a `PENDING` router transaction. Recovery is idempotent, but automated stale-pending adjudication is not implemented.
- Typed-link validation protects generated names, not arbitrary pre-existing vault content. Production promotion requires separate content policy and review.
- The reviewer in M003 is a separately keyed LAB fixture, not independent human or project-lead approval.
- Base syntax and content are validated deterministically, but interactive Obsidian rendering remains an acceptance hold.
- Node staging is local and single-host. Multi-host key distribution, remote release transport, pin revocation, and multi-node rollout consensus are not implemented.
- No claim is made that heartbeat, mailbox, vault scheduling, external security-provider blocking, or production integration is wired or running.

## Security disposition

This implementation is suitable only for the bounded, disposable LAB/STAGING milestone. Promotion to a shared or live service requires independent review, signed release provenance, external key management, distributed replay policy, and explicit authorization to cross the held service seams.
