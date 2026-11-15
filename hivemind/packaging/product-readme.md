# NukoTech Hive Local Alpha v0.1.0

This alpha provides one local-first Hive over portable Markdown and
assets. It includes exact search, typed graph/backlinks, grounded retrieval, governed
agent/task receipts, Git snapshots and rollback, verified portable export, and a
loopback-only authenticated web surface.

Launch the unified attended application in the foreground with:

```text
hive-local app --vault VAULT --host 127.0.0.1 --port 0 --open
```

The printed URL contains no credential. With `--open`, the process passes a private
one-time launch URL directly to the browser; the server consumes it once, creates a
process-lifetime session, and redirects to the clean printed URL. Direct navigation
without that handoff is refused. Mutations remain same-origin, CSRF-protected,
idempotent, and bound to an exact visible object version. Agent capability
authorization and registration are separate attended actions backed by a signed,
expiring grant. Closing or interrupting the foreground process invalidates the
session and leaves no service, login item, PID file, or socket behind. The artifact's
`verify/m4-installed-shell-e2e.py` is a standard-library-only installed boundary
proof, not a background runner.

The packaged adapter SDK adds two governed local adapters: byte-preserving local
capture and bounded local research. Its operator commands are attended-only:

```text
hive-local adapter-list --vault VAULT
hive-local adapter-health --vault VAULT --adapter ADAPTER_ID
hive-local adapter-plan --vault VAULT --adapter nukotech.hive.local-capture \
  --capability capture.text --input INPUT.txt --request-output REQUEST.json \
  --output PLAN.json
hive-local adapter-invoke --vault VAULT --request REQUEST.json --plan PLAN.json \
  --output RESULT.json
hive-local adapter-lifecycle-plan --vault VAULT \
  --adapter nukotech.hive.local-capture --operation export --input SCOPE.json \
  --output EXPORT-PLAN.json
hive-local adapter-export --vault VAULT --adapter nukotech.hive.local-capture \
  --scope SCOPE.json --plan EXPORT-PLAN.json --output EXPORT-RESULT.json
hive-local adapter-lifecycle-plan --vault VAULT \
  --adapter nukotech.hive.local-capture --operation rollback --input RESULT.json \
  --output ROLLBACK-PLAN.json
hive-local adapter-approve --vault VAULT --plan ROLLBACK-PLAN.json \
  --output ROLLBACK-APPROVAL.json
hive-local adapter-rollback --vault VAULT --result RESULT.json \
  --plan ROLLBACK-PLAN.json --approval ROLLBACK-APPROVAL.json \
  --output ROLLBACK-RESULT.json
hive-local adapter-lifecycle-plan --vault VAULT --adapter ADAPTER_ID \
  --operation uninstall --input OWNERSHIP.json --output UNINSTALL-PLAN.json
hive-local adapter-approve --vault VAULT --plan UNINSTALL-PLAN.json \
  --output UNINSTALL-APPROVAL.json
hive-local adapter-uninstall --vault VAULT --adapter ADAPTER_ID \
  --ownership-manifest OWNERSHIP.json --plan UNINSTALL-PLAN.json \
  --approval UNINSTALL-APPROVAL.json --output UNINSTALL-RESULT.json
```

Adapter operations use explicit signed JSON envelopes. No command accepts raw
credential values, and default status output exposes only credential availability
state. Planning is side-effect free. Create a lifecycle plan before every export,
rollback, or uninstall. Rollback and uninstall also require an attended approval
of that exact stored lifecycle plan; export rejects an approval. Each plan is
single-use, and a replay returns a stable refusal instead of applying again.
Invocation and lifecycle operations remain bounded by the signed request, plan,
approval when required, manifest resource limits, and exact ownership evidence.

An attended capture-to-research workflow sits above that frozen SDK. Capture
is deliberately split into a signed dry plan and a separate admission command.
Research commands always name one immutable source-set digest; `NONE` is the
explicit expected digest only for the first source-set version.

```text
hive-local capture-plan --vault VAULT --channel markdown --source SOURCE.md \
  --title TITLE --request-output CAPTURE-REQUEST.json \
  --plan-output CAPTURE-PLAN.json
hive-local capture-admit --vault VAULT --request CAPTURE-REQUEST.json \
  --plan CAPTURE-PLAN.json --output CAPTURE-RESULT.json
hive-local research-workspace-create --vault VAULT \
  --workspace-id research:alpha --name "Alpha Research"
hive-local research-source-add --vault VAULT --workspace-id research:alpha \
  --source-id SOURCE_ID --expected-digest NONE
hive-local research-source-remove --vault VAULT --workspace-id research:alpha \
  --source-id SOURCE_ID --expected-digest SOURCE_SET_DIGEST
hive-local research-search --vault VAULT --workspace-id research:alpha \
  --source-set-digest SOURCE_SET_DIGEST --query TEXT --output SEARCH-RESULT.json
hive-local research-ask --vault VAULT --workspace-id research:alpha \
  --source-set-digest SOURCE_SET_DIGEST --question TEXT --output ASK-RESULT.json
hive-local research-artifact --vault VAULT --workspace-id research:alpha \
  --source-set-digest SOURCE_SET_DIGEST --artifact-type SOURCE_SUMMARY \
  --title TITLE --research-result ASK-RESULT.json --output ARTIFACT-RESULT.json
hive-local research-export --vault VAULT --workspace-id research:alpha \
  --source-set-digest SOURCE_SET_DIGEST --bundle RESEARCH.tar.gz \
  --plan-output EXPORT-PLAN.json --output EXPORT-RESULT.json
hive-local research-reopen --bundle RESEARCH.tar.gz --target REOPENED
```

Capture recognizes credential-shaped content before portable admission and refuses
it without echoing the value. Originals are byte-preserved, normalized citation
anchors re-verify against their exact source-set version, and export/reopen omits
derived indexes and provider caches. Missing optional parsers or local models are
reported as bounded `DEGRADED` or `RETRIEVAL_ONLY` states. They do not trigger a
download, remote fallback, or hidden network request.

Continuous cognition is provided as an attended review queue and a portable knowledge
workspace. A typed event may propose candidates, but it cannot approve or write
PRIME. The operator records a separately signed decision and explicitly promotes an
approved exact candidate. Corrections and revocations are new typed event records;
they preserve, link, and hide historical claims from default retrieval rather than
silently rewriting history.

```text
hive-local memory-propose-event --vault VAULT --event EVENT.json
hive-local memory-candidates --vault VAULT
hive-local memory-review --vault VAULT --candidate-id MEMORY_ID \
  --outcome APPROVED --actor-id Owner \
  --authorization-ref attended:local-review
hive-local memory-promote --vault VAULT --candidate-id MEMORY_ID

# CORRECTION.json must contain only CORRECT claims with exact supersedes targets.
hive-local memory-correct --vault VAULT --event CORRECTION.json
# REVOCATION.json must contain only REVOKE claims with exact revokes targets.
hive-local memory-revoke --vault VAULT --event REVOCATION.json

hive-local memory-retention-scan --vault VAULT --project-id PROJECT
hive-local memory-deletion-plan --vault VAULT --node-id NODE_ID
hive-local memory-deletion-approve --vault VAULT --plan-id PLAN_ID \
  --actor-id Owner --authorization-ref attended:local-delete \
  --confirmation "DELETE NODE_ID" --output DELETE-APPROVAL.json
hive-local memory-deletion-apply --vault VAULT --plan-id PLAN_ID \
  --approval DELETE-APPROVAL.json
```

Retention expiry creates review work only. Physical deletion additionally requires
an exact owned-file manifest, short-lived signed approval, exact typed confirmation,
and a Git checkpoint created before either owned file is removed.

Human-authored Markdown uses the same preview/approval boundary. Creating one new
note needs its exact preview and idempotency key. Replacing an existing note also
needs a separately signed approval for that preview.

```text
hive-local knowledge-note-preview --vault VAULT --project-id PROJECT \
  --relative-path "notes/Architecture.md" --content NOTE.md
hive-local knowledge-note-apply --vault VAULT --preview-id PREVIEW_ID \
  --content NOTE.md --idempotency-key SHA256
hive-local knowledge-note-approve --vault VAULT --preview-id UPDATE_PREVIEW_ID \
  --actor-id Owner --authorization-ref attended:local-edit \
  --output EDIT-APPROVAL.json
hive-local knowledge-graph --vault VAULT --project-id PROJECT \
  --tag architecture --trust-state REVIEWED --lifecycle-state CURRENT
```

Whole-Hive export now includes PRIME Markdown/sidecars, memory staging and decisions,
human notes, receipts, provenance, and public verification keys. It excludes private
keys, runtime journals, derived graph/search indexes, and SQLite/WAL state. Reopening
rotates private cognition keys, retains the portable historical public keys, and
rebuilds current, superseded, revoked, MOC, backlink, and trust views from canonical
files.

The alpha also includes an attended visual-workflow control room. Definitions and runs are signed,
versioned, and immutable. Readiness and conflict views are read-only; a claim is bound
to one source commit, input digest, agent identity, capability set, branch/file scope,
and expiry. Session commands append signed state without starting a process. Protected
steps, stale release, compensation, and Git rollback use separate exact approvals.
Every request command below consumes one closed JSON object and exits; none starts a
scheduler, runner, listener, or service.

```text
hive-local workflow-definition-preview --vault VAULT --definition DEFINITION.json
hive-local workflow-definition-publish --vault VAULT --definition DEFINITION.json \
  --idempotency-key PUBLISH_KEY
hive-local workflow-definition-list --vault VAULT --workflow-id WORKFLOW_ID
hive-local workflow-definition-diff --vault VAULT --workflow-id WORKFLOW_ID \
  --from-version 1 --to-version 2
hive-local workflow-run-launch --vault VAULT --request LAUNCH.json
hive-local workflow-run-status --vault VAULT --run-id RUN_ID
hive-local workflow-readiness --vault VAULT --request READINESS.json
hive-local workflow-conflicts --vault VAULT --request READINESS.json
hive-local workflow-approval-preview --vault VAULT --request APPROVAL-PREVIEW.json
hive-local workflow-approval-approve --vault VAULT --request APPROVAL-DECISION.json
hive-local workflow-claim --vault VAULT --request CLAIM.json
hive-local workflow-deliver --vault VAULT --request DELIVERY.json
hive-local workflow-session-start --vault VAULT --request SESSION-START.json
hive-local workflow-session-heartbeat --vault VAULT --request HEARTBEAT.json
hive-local workflow-session-progress --vault VAULT --request PROGRESS.json
hive-local workflow-session-fail --vault VAULT --request FAILURE.json
hive-local workflow-session-complete --vault VAULT --request COMPLETION.json
hive-local workflow-stale-preview --vault VAULT --request STALE-PREVIEW.json
hive-local workflow-stale-apply --vault VAULT --request STALE-APPLY.json
hive-local workflow-retry --vault VAULT --request RETRY.json
hive-local workflow-compensation-preview --vault VAULT --request COMPENSATION-PREVIEW.json
hive-local workflow-compensation-authorize --vault VAULT --request COMPENSATION-AUTH.json
hive-local workflow-rollback-preview --vault VAULT --request ROLLBACK-PREVIEW.json
hive-local workflow-rollback-apply --vault VAULT --request ROLLBACK-APPLY.json
hive-local workflow-run-cancel --vault VAULT --request CANCELLATION.json
hive-local workflow-replay --vault VAULT --run-id RUN_ID
```

Whole-Hive export includes workflow definitions, runs, approvals, events, signed
session receipts, provenance, agent public records, and role-scoped public verification
keys. It excludes `.hive/keys`, `.hive/runtime`, `.hive/derived`, locks, replay
ledgers, and private/transient state. Reopening rotates private workflow keys while
retaining historical public keys for signature verification.

It is not a customer-production release. It does not require a subscription, hosted
service, customer GitHub account, or proprietary application for its core workflow.
Local Ollama is optional; without it, Ask returns a labeled retrieval-only result with
source citations.

This artifact is not released: it has no customer deployment, no unattended runner
and no persistent service, and native Windows and macOS support are not verified
(status flags `NOT_RELEASED`, `NO_CUSTOMER_DEPLOYMENT`,
`NO_UNATTENDED_RUNNER`, `NO_PERSISTENT_SERVICE`, `WINDOWS_NATIVE_NOT_VERIFIED`,
and `MACOS_NATIVE_NOT_VERIFIED`). The native adapters declare Linux and macOS
only because replay locking and execution deadlines require POSIX facilities;
Windows support is not yet implemented. Installing the alpha does not create
or activate a persistent service or unattended worker.

See `INSTALL.md` for the one-command install, demo, rollback, and uninstall commands.
