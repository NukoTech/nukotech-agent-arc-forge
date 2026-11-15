# Hive Local Alpha — Intelligence and Agent Operations

Status: alpha implementation for reversible LAB/STAGING review. This
document grants no seat, deployment, subscription, external action, or production
authority.

## Native implementation decision

The retained local baseline is Python standard-library SQLite plus the existing Hive
protocol signing and atomic-storage primitives. Exact phrase retrieval is guaranteed
by scoped SQLite substring matching. Deterministic token overlap makes questions
usable without a model. Optional semantic retrieval and answer synthesis are exposed
through a provider interface; the included Ollama adapter accepts only plain HTTP on
a loopback host and never installs or pulls a model.

This is the smallest native choice that remains installable, inspectable, and useful
offline. It introduces no external vector database, hosted account, mandatory
subscription, copied proprietary implementation, or raw customer-memory path.

## Attended capture and bounded research

This layer exposes the implemented domain services through process-bounded CLI commands.
It does not add a listener, watcher, scheduler, login item, or background worker.
The operator first creates a signed capture request and dry plan with
`capture-plan`, inspects those files, and applies that exact pair with
`capture-admit`. Reusing the request or nonce is refused by the frozen adapter
runtime.

Supported local handoffs are Markdown, clipboard material, a file, a locally saved
webpage/browser snapshot, PDF, image, audio, video, meeting recording, transcript,
and an explicit folder-handoff manifest. These commands do not fetch a webpage or
discover, install, or download a parser. The original is retained byte-for-byte.
Built-in text normalizers produce independently verifiable citation anchors;
unavailable optional PDF, OCR, transcription, or local-model providers yield an
explicit bounded status while preserving only the authorized local material.

`research-workspace-create` establishes one project-private workspace.
`research-source-add` and `research-source-remove` require the caller's expected
head digest, so a concurrent or stale update fails instead of silently changing the
selected evidence. Each successful update creates a new immutable source-set
version. Search, Ask, cited artifacts, and portable export must name one exact
source-set digest:

```text
research-search -> SEARCH_COMPLETE or NO_EVIDENCE
research-ask -> NO_EVIDENCE, RETRIEVAL_ONLY, MODEL_OUTPUT_REJECTED, DEGRADED, or ANSWERED
research-artifact -> verified Markdown plus signed, content-addressed metadata
research-export -> deterministic exact-source-set bundle
research-reopen -> verified retrieval-only workspace with rebuilt derived index
```

Factual synthesized output is accepted only when each claim uses an exact citation
anchor from the selected set. Unsupported, unknown, stale, or out-of-set citations
are rejected; contradiction and uncertainty records remain visible. Portable
bundles contain only the selected sources, immutable snapshots, provenance,
citations, artifacts, and their manifest. SQLite databases, runtime journals,
provider caches, credentials, and unrelated workspaces are excluded.

All capture and research routes remain local and attended. They write neither `prime/` nor protected
identity paths, perform no remote fallback, and activate no
persistent service. This remains an alpha: not released, no customer deployment, no unattended
runner, no persistent service, and native Windows and macOS support not verified
(status flags `NOT_RELEASED`, `NO_CUSTOMER_DEPLOYMENT`,
`NO_UNATTENDED_RUNNER`, `NO_PERSISTENT_SERVICE`, `WINDOWS_NATIVE_NOT_VERIFIED`,
and `MACOS_NATIVE_NOT_VERIFIED`).

## Continuous cognition and portable knowledge

This layer connects captured evidence to an explicit, signed memory lifecycle without
granting a model or extractor mutation authority. Typed local events are validated as
closed documents. The deterministic extractor stores evidence-bound candidates and
all seven explainable ranking features in `staging/memory/`; optional provider output
may add proposals only. Missing or rejected provider output never enables remote
fallback or a direct PRIME write.

Proposer, reviewer, and promoter are distinct Ed25519 roles. A reviewer decision is
bound to the candidate digest, tenant, project, experience scope, outcome, actor,
authorization reference, and expiry. Promotion verifies the proposal receipt and
approved decision again before writing the exact persona, surface, domain, or shared
lane. Correction creates a new node plus `SUPERSEDES`; revocation creates a new audit
node plus `REVOKES`. Default retrieval excludes revoked, superseded, and revocation
audit nodes while historical retrieval and graph views preserve them.

Retention is intentionally non-destructive: expiry produces a signed review request.
Deletion is a second high-risk flow with an exact node digest, owned regular-file
manifest, short-lived separately signed approval, typed `DELETE NODE_ID`
confirmation, and pre-mutation Git checkpoint. There is no automatic pruning route.

`KnowledgeEditor` makes one atomic Markdown create or update from an exact preview.
Updates require optimistic version equality and a separate attended approval. The
derived graph rebuilds deterministically from sources, research, candidates, reviewed
PRIME, and human notes. It provides typed links, MOC membership, tags, citations,
broken links, backlinks, trust labels, lifecycle states, and project/relation/tag/
trust/state filters. Editing or deleting a projection cannot mutate canonical
evidence.

The attended CLI surface is process-bounded:

```text
memory-propose-event | memory-correct | memory-revoke
memory-candidates | memory-review | memory-promote
memory-retention-scan
memory-deletion-plan | memory-deletion-approve | memory-deletion-apply
knowledge-note-preview | knowledge-note-approve | knowledge-note-apply
knowledge-graph
```

Whole-Hive snapshot/rollback now covers `prime/` alongside the existing portable
roots. Export includes portable cognition/knowledge records and public signature
keys, but excludes private keys, `.hive/runtime`, `.hive/derived`, SQLite, WAL, and
provider state. A reopened Hive creates fresh private role keys while retaining all
historical public role keys, allowing promotion/edit/deletion history to remain
verifiable before rebuilding retrieval and graph projections.

## Attended visual workflows

This layer adds immutable versioned DAGs and a one-shot local control-room facade. A
definition preview performs complete DAG, type, target, resource, retry, approval,
ownership, and rollback validation without mutation. Publication records one signed
version and lineage receipt. A run binds that exact definition digest, source commit,
input manifest, tenant, project, and attended policy.

The scheduler is a deterministic readiness calculator, not an executor. It exposes
typed missing inputs, failed dependencies, stale source state, capability mismatch,
active branch/file claims, concurrency limits, and expired or absent approvals. A
claim is signed by the chosen registered agent and binds the exact readiness digest,
attempt, capability set, target machine/surface, source/input state, owned paths, and
expiry. Delivery then crosses the existing signed task-envelope boundary with only
workflow identifiers and digests; it cannot carry a shell command or widen authority.

Agent sessions append signed start, heartbeat, acknowledgment, progress, resource,
output, failure, and completion snapshots. Counters cannot regress or exceed the
immutable step budget, outputs are append-only, and terminal attempts cannot be
rewritten. A stale preview is read-only. Applying stale abandonment and claim release
requires an exact attended approval. Retry creates a new attempt; declared protected
compensation and exact Git-checkpoint rollback each require their own approval.

The CLI commands are process-bounded `workflow-*` JSON operations. There is no timer,
daemon, background scheduler, automatic task execution, service activation, or remote
fallback. Replay reconstructs signed history without mutation or execution.

Portable roots now include `workflows/`, workflow receipts, provenance, agent public
records, and `.hive/workflow-keys/public-keys.json`. Private keys, runtime ledgers,
locks, derived projections, and SQLite/WAL files remain excluded. Reopened Hives rotate
private workflow keys and retain historical public verification keys.

## Public integration API

The shared CLI or product shell can render these provider-neutral calls without
changing their security semantics:

```python
from hive_protocol.retrieval import LocalRetriever, SourceDocument
from hive_protocol.ask import AskHive
from hive_protocol.awareness import awareness_candidates
from hive_protocol.agents import AgentOperations, build_signed_task, build_signed_ack
from hive_protocol.providers import OllamaLocalProvider
```

- `LocalRetriever.index(SourceDocument(...))` validates the supplied SHA-256 and
  nonempty provenance before a scoped upsert.
- `search_exact(query, tenant_id=..., workspace_id=...)` guarantees literal,
  case-sensitive phrase retrieval.
- `search(query, ...)` returns exact results first, followed by deterministic local
  token-overlap results.
- `search_semantic(query, ...)` exists only when a configured local provider reports
  an installed embedding model; otherwise it fails with `SEMANTIC_UNAVAILABLE`.
- `AskHive.ask(question, ...)` returns `NO_EVIDENCE`, `RETRIEVAL_ONLY`,
  `MODEL_OUTPUT_REJECTED`, or `ANSWERED`. It never calls a model without evidence.
- `awareness_candidates(events)` emits only `PROPOSED` candidates with
  `external_action=false` for unfinished work, contradictions, stale decisions,
  repeated topics, and declared related context.
- `AgentOperations` registers pinned Ed25519 identities, resolves scoped recipients,
  delivers signed replay-protected tasks, stores signed acknowledgments, and proves
  persistence from a fresh instance. It persists messages; it does not execute their
  requested operations.

Recommended shared-CLI command names are:

```text
hive retrieval capabilities
hive retrieval index --tenant TENANT --workspace WORKSPACE --source-id ID --path PATH --sha256 HASH
hive retrieval exact --tenant TENANT --workspace WORKSPACE --query TEXT
hive ask --tenant TENANT --workspace WORKSPACE --question TEXT
hive awareness candidates --events EVENTS_JSON
hive agents register --record AGENT_JSON
hive agents deliver --task SIGNED_TASK_JSON
hive agents acknowledge --ack SIGNED_ACK_JSON
hive agents next-turn --tenant TENANT --workspace WORKSPACE --recipient AGENT --task-id UUID
```

Those routes belong to the shared CLI. Wiring must pass tenant and workspace on every
call, preserve status codes and citations verbatim, and must not turn awareness
candidates or delivered task payloads into automatic actions.

## Unified attended operator application

The unified application exposes the capture, research, memory, knowledge, agent, workflow, receipt, and
settings lanes through one nontechnical application and the closed `/api/v1` contract.
Launch it as one attended foreground process:

```text
hive-local app --vault VAULT --host 127.0.0.1 --port 0 --open
```

The launcher prints a plain loopback URL without a credential. With `--open`, the
foreground process passes a private one-time launch URL directly to the browser; the
server consumes it once, sets an HttpOnly process-lifetime session, and redirects to
the clean printed URL. Navigating to the printed URL without that handoff fails
closed. Every mutation additionally requires same-origin Fetch Metadata, a CSRF
proof, an idempotency key, and the exact visible object version. Agent capability
authorization and registration are separate attended actions; registration consumes
an exact signed, expiring grant. Protected operations retain their separate preview
and approval boundaries. The application stores no canonical state in browser
storage and installs no daemon, service, login item, scheduler, or unattended worker.

The installed standard-library fixture proves the complete HTTP path, including
capture and cited research, separate memory review and promotion, knowledge rebuild,
agent registration, conflict/failure/retry/stale/completion workflow recovery,
receipt filtering, checkpoint/mutation/rollback, portable export/reopen, replay, and
second-process reconstruction. Browser sessions and API runtime state are excluded
from the portable Hive.

## Optional local Ollama

`OllamaLocalProvider(model=..., embedding_model=...)` probes `/api/tags` before use.
A missing endpoint, unconfigured model, or uninstalled model is an explicit
unavailable capability. The alpha does not select a default model, transmit API
credentials, use non-loopback URLs, or invoke model tools. Source text is delimited
as untrusted data; a model answer is rejected unless it contains only source IDs from
the retrieved evidence set.

Example application construction, with model names supplied by local configuration:

```python
provider = OllamaLocalProvider(
    model=configured_chat_model,
    embedding_model=configured_embedding_model,
)
retriever = LocalRetriever(state_dir / "retrieval.sqlite", provider)
ask = AskHive(retriever, provider)
```

## Security properties and limits

| Threat | Alpha behavior |
|---|---|
| Cross-tenant leakage | Every query and identity lookup requires tenant and workspace equality. |
| Missing/poisoned provenance | Empty provenance and mismatched source hashes are refused. |
| Prompt injection / malicious wiki links | Source text stays inert, quoted evidence; no tool interface is exposed. |
| Fabricated model citations | Missing or out-of-set source IDs reject the model output. |
| Forged identity or recipient | Registry key pins, exact scope, canonical recipient, and Ed25519 signatures are verified. |
| Capability escalation | Required capabilities must be held by both sender and recipient. |
| Replay / concurrent delivery | A locked two-phase ledger produces one durable result and refuses duplicates. |
| Atomic-write crash | Pending claims resume; a conflicting durable object fails closed. |
| Poisoned receipt | Next-turn readback revalidates schema, scope, and recipient signature. |
| False persistence | No next-turn success is returned until both task and signed acknowledgment exist. |
| Model/self approval | Extractors and optional providers can only create staged proposals; distinct reviewer and promoter signatures are required. |
| Silent memory rewrite | Corrections, supersession, and revocation append immutable nodes and typed edges; history stays queryable. |
| Retention-driven deletion | Expiry creates review work only; deletion needs a separate exact approval, typed confirmation, and Git checkpoint. |
| Portable-key loss | Exports retain role-scoped public keys only; reopened Hives rotate private keys while verifying historical signatures. |
| Workflow approval laundering | Every approval binds one preview digest, input digest, step, attempt, risk, destination, side effects, and expiry. |
| Workflow claim race | Readiness is recomputed under a local lock; event-head changes and overlapping active ownership refuse the claim. |
| Stale-session takeover | Stale detection is read-only; abandonment/release needs attended approval and append-only receipts. |
| Hidden workflow execution | Scheduling, replay, and session recording expose `execution_started=false`; delivery is a signed envelope, not an executor. |

Trust labels constrain acceptance; they are not operating-system sandboxes. Local
registration is an attended operator/configuration action. Task delivery is not task
execution. A future executor must independently enforce its own tool and OS policy.

## Deterministic demonstration

The fixture under `tests/fixtures/alpha-intelligence/` contains only synthetic,
non-private text, including an inert prompt-injection string and malicious-looking
Obsidian link. Run the complete intelligence seam with:

```bash
PYTHONPATH=src python -m pytest -q \
  tests/test_retrieval.py tests/test_ask.py tests/test_awareness.py \
  tests/test_agents.py tests/test_alpha_security.py
```

The suite covers exact/lexical/optional-semantic retrieval, absent evidence,
signature tampering, replay, forged recipients, capability escalation, atomic-write
failure, crash recovery, concurrency, symlinks/path traversal, poisoned receipts,
malicious links, prompt injection, missing provenance, and false next-turn
persistence.

## Integration notes

1. Add CLI or product adapters only through the public API above. Do not duplicate
   or fork the intelligence implementation.
2. Render capability status before presenting semantic or local-answer controls.
3. Use a disposable state directory and the deterministic fixture for the integrated
   demo. Prove fresh-process next-turn readback, then delete only that resolved
   disposable directory.
4. Preserve `NO_EVIDENCE` and replay/security errors exactly. Do not silently fall
   back to an ungrounded model response.

Rollback is removal of the disposable demo-state directory. No service, scheduler,
external mailbox, heartbeat, vault promoter, customer node, or production route is
activated.
