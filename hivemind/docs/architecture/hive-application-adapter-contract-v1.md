# Hive Application Adapter Contract v1

Status: `FROZEN / IMPLEMENTED / CONFORMANCE-TESTED / ALPHA`

This contract is the application boundary for NukoTech HiveMind. An adapter is a
replaceable implementation beneath the runtime. It does not own canonical
project knowledge, mint authority, widen a signed request, or turn technical
access into authorization.

The original v1 conformance baseline implementations are:

- `nukotech.hive.local-capture` (`capture.text`, `capture.file`)
- `nukotech.hive.bounded-research` (`research.search`, `research.ask`)

Both run locally in the alpha. This contract does not authorize a production
deployment or an unattended runner.

## Capture and research consumers of the frozen v1 contract

The capture and bounded-research services do not revise this contract, its schemas, authority intersection, replay
claims, recovery ordering, lifecycle ownership, or outcome meanings. They add
capture and bounded-research domain services above the same signed runtime and
extend the two existing manifests through their existing v1 capability lists.

The local-capture consumer now routes `capture.markdown`, `capture.clipboard`,
`capture.webpage-snapshot`, `capture.browser-handoff`, `capture.pdf`,
`capture.image`, `capture.audio`, `capture.video`, `capture.meeting-recording`,
`capture.transcript`, and `capture.folder-handoff`, in addition to the original text
and file cases. Each remains a separately declared capability under the same
independent attended grant and no-egress manifest boundary. Its adapter apply hook
delegates byte preservation, normalization, citation anchors, admission, rollback,
and recovery to the governed capture service; the runtime still owns signed
request/plan/result validation and replay.

The bounded-research consumer adds `research.artifact` alongside search and Ask.
All three bind an immutable source-set digest and verify source records and citation
anchors after retrieval. Exact-source-set portable export continues through the v1
lifecycle `export` hook and returns only root-relative evidence paths to the frozen
lifecycle verifier. The portable research bundle is a domain artifact, not an
ownership or authority document.

The attended product commands are clients of these consumers. They cannot mint a
grant, reinterpret a plan, bypass approval or replay, broaden a source set, enable
egress, or start an unattended process. Any future incompatible weakening or new
authority model still requires a new adapter-contract version.

## Packaged schemas

The contract is defined by the following Draft 2020-12 JSON schemas and the
cross-document checks in the runtime:

| Schema | Version marker | Purpose |
| --- | --- | --- |
| `application-adapter-manifest.v1.schema.json` | `hive.application-adapter-manifest.v1` | Identity, platform, capability, permission, data, dependency, egress, credential, lifecycle, resource, retention, offline, and signer declarations |
| `adapter-request.v1.schema.json` | `hive.adapter-request.v1` | Signed caller identity, project, capability, evidence hashes, payload, nonce, and expiry |
| `adapter-plan.v1.schema.json` | `hive.adapter-plan.v1` | Runtime-signed binding of request, manifest, policy, effects, egress, approval requirement, expiry, and executable payload |
| `adapter-approval.v1.schema.json` | `hive.adapter-approval.v1` | Trusted-approver decision bound to the exact signed plan digest and expiry |
| `adapter-result.v1.schema.json` | `hive.adapter-result.v1` | Runtime-signed terminal outcome, evidence, effects, resource use, rollback reference, and bounded detail |
| `adapter-ownership-manifest.v1.schema.json` | `hive.adapter-ownership-manifest.v1` | Exact installation, adapter, version, resolved root, creation time, and owned-path hashes for lifecycle containment |

Unknown schemas, unknown fields, invalid formats, and unknown versions fail
closed. Every signed document uses Ed25519 over canonical JSON. A signature
contains only `algorithm`, `key_id`, and `value`; the key ID must resolve in the
operation's explicit trust set.

Before schema validation or adapter-specific recursive inspection, the runtime
iteratively bounds the complete signed request envelope: canonical byte size,
total object/array nodes, and nesting depth. The manifest `max_input_bytes`
limits the payload; a small fixed allowance covers the signed envelope. This
prevents a deeply nested or oversized non-payload field from bypassing the
adapter's declared resource boundary or exhausting the recursive validators.
Lifecycle planning and execution apply the same iterative byte, node, and depth
preflight to the complete lifecycle input before credential inspection,
canonical hashing, schema validation, or adapter-specific traversal.

## Adapter protocol

An adapter implements these methods:

```text
health() -> health object
plan(payload) -> closed plan contribution
apply(planned_payload, *, operation_key) -> closed terminal contribution
recover(operation_key) -> prior terminal contribution or None
export(scope, *, operation_key) -> closed export contribution
rollback(rollback_ref, *, operation_key) -> closed terminal contribution
recover_lifecycle(operation, operation_key) -> prior contribution or None
```

`plan()` returns exactly:

```text
side_effects: unique strings
network_destinations: unique URI strings
requires_approval: boolean
payload: object
```

Planning may read bounded local state but may not perform the planned mutation.
The runtime may call an optional `validate_request(request)` hook with a detached
request object before planning. This hook binds adapter-specific payload meaning
to the signed capability and configured project/scope; it cannot add authority.

Adapters receive a copy of the payload. Adapter-returned effects must be a subset
of the signed plan. Adapter output is subject to manifest byte limits before the
runtime signs it. Every mutation receives the deterministic operation key derived
from the exact request and plan digests. Native adapters write a `PREPARED` record
before their first effect and a `TERMINAL` record with the closed contribution
after the effect. Recovery asks for that exact operation before it may call the
mutation again. Uninstall is deliberately absent from the adapter protocol; only
the lifecycle orchestrator may delete ownership-manifest paths.

## Manifest and registry rules

The registry accepts one active version per adapter ID. Registration requires:

1. a valid closed v1 manifest;
2. the complete application-adapter protocol;
3. an exact OS, architecture, and runtime platform match;
4. every declared dependency to match the runtime's available-dependency
   inventory on name, version, SHA-256, and license;
5. a non-revoked adapter at lookup time.

A missing or mismatched dependency is
`ADAPTER_DEPENDENCY_UNAVAILABLE`. Registry status is sorted and omits credential
references and credential values. A health exception is reported as `DEGRADED`
with only the exception type, not hidden or reported as healthy.

## Authority intersection and policy order

The runtime validates request schema and signature before consulting the
registry. The invocation context comes from a separately signed attended grant
looked up by the already verified request-signing key and adapter ID. No project,
identity, capability, permission, classification, egress, credential reference,
or authorization field is copied from the request to construct that grant.
Effective authority is the intersection of signed request, independent grant,
manifest, dependency state, and revocation state. The policy checks, in
fail-closed order, are:

1. adapter revocation;
2. request project equals invocation project;
3. authorization reference equals the invocation grant;
4. complete sender identity equals the invocation identity;
5. capability is both manifest-declared and context-granted;
6. every manifest permission is granted;
7. data classification is both accepted and allowed;
8. every manifest network destination is allowed;
9. every credential reference is available by reference;
10. request adapter ID and version equal the manifest;
11. request expiry is valid and in the future;
12. adapter-specific request validation, when present.

Each stored attended grant is signed and bound to the exact request key,
adapter, manifest, project, identity, authorization reference, capabilities,
permissions, classifications, destinations, and credential references. An
existing grant that differs from the currently derived body is refused as
`ADAPTER_AUTHORITY_GRANT_MISMATCH`; it is never silently replaced. Grant
rotation is therefore an explicit attended action.

Credential references may use only `keychain:`, `secret-service:`,
`credential-manager:`, or `manual:` forms accepted by the schema. Raw credential
values and plaintext credential patterns are not manifest data. Empty network
destinations means no egress authority. A plan naming any destination outside the
effective set is `ADAPTER_EGRESS_DENIED`.

## Plan and approval binding

The runtime signs and durably writes a plan before invocation. A plan binds:

- exact signed request digest;
- exact registered manifest digest;
- exact policy-decision digest;
- adapter ID and version;
- capability and project;
- complete declared effects and network destinations;
- approval requirement and bounded expiry;
- the adapter's executable payload.

Invocation verifies all bindings, plan signature, expiry, and byte-identical
stored plan. A required approval must be signed by a trusted approver, have
decision `APPROVED`, bind the exact signed plan digest, remain unexpired, and
match the plan project identity. Every trusted approver key ID is separately
configured with one exact identity and project, and the signed approval must
match that key binding as well as the invocation context. Possession of a
trusted key cannot approve as another trusted identity. Approval of a similar
or modified plan has no effect.

The local capture adapter enriches a planned file payload with the observed
SHA-256 and byte size. Apply rechecks both. A file changed after planning produces
a signed `FAILED` result with error code `CAPTURE_SOURCE_DIGEST_MISMATCH`; the
changed bytes are not reported as approved evidence.

## Replay and recovery ordering

Before apply, the runtime writes a complete `PREPARED` recovery journal containing
the exact request, plan, approval, independent context, adapter ID, and operation
key. It then atomically claims both request ID and nonce and advances the journal
to `CLAIMED`. Ordering is:

```text
verify -> write PREPARED journal -> claim ID/nonce -> write CLAIMED journal
       -> adapter recover(operation_key) or apply(..., operation_key)
       -> sign/write result -> write RESULT_WRITTEN journal
       -> complete replay claim -> write TERMINAL journal
```

A repeated completed request ID is `REPLAY_MESSAGE_ID`; reuse of a nonce by a
different request is `REPLAY_NONCE`. Concurrent invocation produces exactly one
terminal application and one replay refusal. The operation key also derives one
deterministic durable result ID. If the result reached durable storage before a
crash but its ID did not reach the journal, recovery locates, verifies, and
adopts that same signed result instead of minting or overwriting another one.

If apply raises after the replay claim, the runtime first asks the adapter for an
authenticated terminal operation record. It adopts that exact contribution when
one exists. If the adapter cannot prove whether an effect occurred, the runtime
returns `ADAPTER_EFFECT_STATE_PENDING` and deliberately leaves the signed journal
and replay claim pending for attended recovery; it does not conceal a possible
partial effect behind an empty terminal `FAILED` result. A terminal `FAILED`
result is valid only when the adapter explicitly returns a validated terminal
failure contribution. Stable error codes are retained without sensitive
exception detail.

Recovery handles a crash before the claim, during the adapter effect, after the
adapter's terminal operation record, after the durable result, or after replay
completion. It accepts only byte-identical, correctly signed, stored
request/plan/result/context bindings, exact timestamps and operation identity,
and a matching replay claim. It adopts an existing terminal adapter contribution
or durable result instead of blindly applying again. Any discrepancy is
`ADAPTER_RECOVERY_MISMATCH`; an unproven effect remains
`ADAPTER_EFFECT_STATE_PENDING`.

Lifecycle recovery distinguishes a signed `PREPARED` journal from a `CLAIMED`
journal. A `PREPARED` journal with no replay claim or its exact matching pending
claim proves the signed journal never advanced to `CLAIMED`, so the effect could
not have started and may execute once after atomically acquiring or resuming the
claim. Once the signed journal is `CLAIMED`, recovery may adopt only an
authenticated terminal adapter record; `None` means unknown effect state and
never falls through to reissue the operation.

Runtime and lifecycle journals, native-adapter operation records, and terminal
adapter state are signed by the owning runtime or adapter key and verified before
recovery. Accepted state roots must be canonical directories owned by the current
user, and no root path may contain a symlink component. State directories are
mode `0700`; plans, approvals, grants, replay ledgers, journals, results,
operation records, and lock files are mode `0600`.

Private-key bootstrap applies the same no-symlink-component, canonical-owner
boundary to the nested key root. Bootstrap is serialized by a private
inter-process lock. A private PEM is opened exactly once with exclusive,
no-follow creation and mode `0600`, so no permissive-umask visibility window or
concurrent key replacement exists.

Both invocation and lifecycle execution run under the manifest timeout and reject
terminal output larger than `max_output_bytes`. Input is bounded by
`max_input_bytes`. Credential-like field names, provider-key patterns, private
keys, assignments, and authorization headers are refused before any request,
grant, plan, approval, journal, contribution, result, fixture, or log crosses a
persistence boundary. Singular `credential_reference` fields must match the
protected reference syntax, and `credential_state` is restricted to
`AVAILABLE`, `MISSING`, or `NOT_REQUIRED`; neither field is an unchecked
credential-value escape. This structural guard is deliberately heuristic for
credential-like text embedded under ordinary field names; arbitrary opaque
secrets in otherwise innocuous free text are outside this alpha classifier and
must not be supplied as adapter content.

## Outcomes

The only result outcomes are:

- `APPLIED`: the bounded operation ran and its declared effects occurred;
- `NO_OP`: the authorized operation required no state change;
- `REFUSED`: the adapter made a terminal, policy-respecting refusal;
- `DEGRADED`: bounded partial behavior occurred and is labeled as such;
- `FAILED`: the attempted operation failed and does not claim success.

Research status remains inside signed result detail. `NO_EVIDENCE`,
`RETRIEVAL_ONLY`, `MODEL_OUTPUT_REJECTED`, and `ANSWERED` are never collapsed into
an invented answer. A valid research request may have adapter outcome `APPLIED`
while truthfully reporting `NO_EVIDENCE` and an empty evidence list.

## Offline, injection, and model boundaries

Both alpha adapters declare `offline_behavior: SUPPORTED` and plan no
network destinations. Capture reads only exact local input and writes through the
portable local workspace. Research queries one configured tenant/workspace/project
scope. Absence of a local model is `RETRIEVAL_ONLY`, not failure and not a remote
fallback.

Source text is untrusted data. Prompt-like content is stored or cited inertly.
Ask sends an evidence-bound system instruction to an available local provider and
accepts an answer only when every citation names a retrieved source. Missing or
unknown citations produce `MODEL_OUTPUT_REJECTED` with no accepted answer.

## Export, rollback, and uninstall

`adapter-lifecycle-plan` creates and stores a runtime-signed, 15-minute, single-use
plan for one exact export scope, prior result, or ownership manifest.
`adapter-approve` signs one exact rollback or uninstall plan with the trusted local
attended approver key and independent grant identity. Export does not accept an
approval. Every lifecycle operation has its own replay claim, recovery journal,
deterministic operation key, adapter operation record where applicable, and
deterministic durable result ID.

Export validates its signed scope before calling an adapter. Every exported file
must be a regular, non-symlink file beneath the exact export root. The signed
lifecycle result binds path, SHA-256, and byte size. Capture exports a portable
Hive archive that can be reopened with verified bytes. Research exports only the
selected workspace's sources, provenance, citations, and a file-hash manifest.

Rollback requires an `APPLIED` signed result with a rollback reference, a signed
rollback plan bound to that exact result and reference, and an unexpired exact-plan
approval. Cross-adapter, cross-version, and cross-project rollback is refused.
Capture rollback validates its closed operation record and restores only the exact
source/provenance paths changed by that capture, with expected before/after bytes.
Capture snapshot/import/finalize and rollback validate/restore transactions share
one workspace-scoped inter-process lock. Concurrent same-content operations
therefore record an ordered ownership delta instead of two false absent-before
snapshots. Rollback preserves receipts and later unrelated work, and refuses
drift instead of rewinding the whole workspace.

Uninstall accepts only a valid ownership manifest whose root is an exact resolved
real directory. Paths must be unique canonical relative paths. Absolute paths,
`..`, symlinks, hash mismatches, duplicates, and resolved escapes are refused.
The orchestrator prevalidates every file and directory before mutation, records a
per-entry `PENDING`/`REMOVING`/`REMOVED` journal, and removes only exact files and
then empty owned directories. It never calls adapter-supplied uninstall code. A
crash resumes from the entry journal without widening deletion. Unrelated
sentinels, canonical sources, provenance, user files, and receipts are preserved.
Lifecycle journals and receipts are never deleted by lifecycle operations.

The native adapter manifests declare Linux `aarch64`/`x86_64` and macOS
`arm64`/`x86_64`. Linux `aarch64` was verified by an aarch64 alpha gate;
macOS remains declared but requires its native verification gate. Windows is not
declared because replay locking and execution deadlines currently rely on POSIX
`fcntl` and `signal.setitimer`; Windows support is not yet implemented.

## Frozen conformance matrix

`tests/adapter_conformance.py` is inherited unchanged by both v1 implementations.
The concrete files provide adapter fixtures and adapter-specific evidence only.
No conformance case is skipped. The matrix covers:

- valid plan/apply and signed result;
- wrong project, identity, capability, permission, and data class;
- source digest, signer, expiry, nonce, replay, revocation, and dependency;
- offline and degraded states;
- prompt injection and plaintext credential patterns;
- undeclared egress;
- scoped export and reopen;
- rollback and manifest-only uninstall;
- unrelated sentinel and symlink escape;
- concurrent invocation;
- signed-result verification in a fresh process.

The v1 contract is frozen only while both adapters pass this identical matrix and
the canonical repository verifier reports `VERIFIED`.

## Compatibility policy

The v1 schema names and required semantics are stable for this contract version. A change that
weakens validation, changes required fields, reinterprets an outcome, widens
authority, or breaks stored plan/result verification requires a new contract
version. Implementations may add new adapter IDs and capabilities only through a
valid manifest and the full conformance gate. Historical v0.1 material is not an
operative fallback.
