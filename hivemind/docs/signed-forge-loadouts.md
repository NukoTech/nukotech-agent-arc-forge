# Signed Forge loadouts in HiveMind

HiveMind admits exact declarative packages composed by Agent Arc
`0.3.0-alpha.1`. Arc remains a separate local composer. Its ZIP, checksum manifest,
architecture manifest, and composition receipt are evidence inputs. Arc's current
receipt and authorization YAML are **not cryptographic signatures**. HiveMind adds
its own signed target-specific plan and a separate attended approval over that
exact plan. It uses the existing local operator request, approval, and result keys.
No new persona, fleet seat, or global authority is created.

## Keys: bring your own

Loadouts use no shipped, shared, or embedded key material. Every plan, approval,
state document, and receipt is signed with the operator's own local Ed25519
identities: `attended-request`, `attended-approver`, and `runtime-result`, kept
under `<Hive>/.hive/keys/application-adapters/` (owner-only permissions). The product creates them once,
locally, for a new Hive, or you can provision that directory with your own key
pairs before first use. After a loadout history exists, HiveMind refuses to
replace a missing or mismatched key, so a lost key cannot be silently swapped
for a new one. Arc packages never carry or grant keys. The test suite generates
throwaway Ed25519 keys per run and checks in none.

Context handoffs (`loadout-context`, `loadout-context-verify`) use the same
operator-held keys and never create, rotate, or export them. The envelope's
`admission_key_id` is only the public key ID of your own `runtime-result`
identity; no private key or signature material is included. Verification on a
Hive with a different key refuses the envelope. Tests use a synthetic
`admission_key_id` derived from throwaway keys.

## Platform support

Loadouts run on macOS and Linux. Native Windows loadout storage is deferred:
on Windows every loadout entry point refuses with
`LOADOUT_PLATFORM_UNSUPPORTED: Windows support arrives in v1.1` before it
reads artifacts or touches the Hive.

## What an admitted loadout can do

An admitted loadout makes its exact versioned skills, policies, loops, protocols,
and declarative configuration available for local reviewed use. Its optional adapter
references resolve exact already-registered HiveMind adapter IDs, versions, manifest
digests, and declared capabilities. Those adapters remain subject to their own
independent invocation grants and lifecycle checks.

Admission never imports Python modules, evaluates JavaScript, runs shell commands,
installs executables, changes an agent's identity, promotes memory, or broadens an
adapter grant. A `runtime_binding` component is stored as declarative text. Agent
Arc's current format does not supply a verified executable adapter installer, so
this bridge does not claim arbitrary third-party adapter deployment. Removing a
loadout removes its declarative artifacts from active use and retains recovery
copies; independently installed adapters
retain their separately governed lifecycle.

## Source contract

Admission requires five bounded local files:

| Role | File | Maximum |
| --- | --- | --- |
| `package` | Arc composition ZIP | 64 MiB |
| `checksum_manifest` | Adjacent `MANIFEST.sha256` | 128 KiB |
| `recipe` | Exact original recipe YAML | 2 MiB |
| `registry` | Exact original component registry YAML | 2 MiB |
| `authorization` | Exact original composition authorization YAML | 128 KiB |

The original inputs are necessary because Arc's current ZIP omits them and its
architecture manifest omits dependency/conflict lists. HiveMind checks their hashes,
exact component identities and bytes, full dependency closure, conflicts, provenance,
rights, declared capabilities and effects, and the composition/security evidence
bindings. It rejects unsupported composer versions, credential values, YAML aliases,
duplicate keys, explicit YAML tags, undeclared files, symlinks, traversal, case
collisions, encrypted entries, and excessive archive expansion. Archives have at
most 256 regular entries, 8 MiB per unpacked file, 64 MiB total, and ratio 200.
Component files must be UTF-8 Markdown, text, JSON, YAML, or TOML under `components/`.
The browser upload flow may impose a smaller aggregate limit.

## Exact targeting and approval

A signed plan binds the loadout ID, full manifest and hashes, current state digest,
authorization reference, expiry, and exact persona/surface/machine/project plus
OS/architecture/runtime. An approval binds the signed plan digest and the existing
attended operator identity. Plans expire after 15 minutes by default, at most one
hour. Apply repeats signature, target, expiry, state, artifact, dependency, and
adapter-revocation checks under a local lifecycle lock. It rechecks before making
staged bytes active if writing them took long enough for authorization to expire.

Completed replay returns the original signed receipt without performing new work,
including after the original approval expires. A changed state requires a fresh
plan. The product bridge refuses to regenerate missing signing identities when a
loadout history exists.

## CLI

Create a JSON source mapping with the five role names above and absolute local paths.
For an optional adapter reference, supply a JSON array of objects with exactly
`adapter_id`, `version`, `manifest_digest`, and `capability_ids`.

```sh
hive-local loadout-plan --vault /path/to/Hive --operation admit \
  --loadout-id drafting --authorization-ref attended-review-reference \
  --source /path/to/source.json --output /path/to/plan.json
hive-local loadout-approve --vault /path/to/Hive \
  --plan /path/to/plan.json --output /path/to/approval.json
hive-local loadout-apply --vault /path/to/Hive \
  --plan /path/to/plan.json --approval /path/to/approval.json \
  --source /path/to/source.json --output /path/to/receipt.json
hive-local loadout-status --vault /path/to/Hive
hive-local loadout-read --vault /path/to/Hive --loadout-id drafting
hive-local loadout-context --vault /path/to/Hive --loadout-id drafting \
  --output /path/to/context.json
hive-local loadout-context-verify --vault /path/to/Hive \
  --context /path/to/context.json
```

`loadout-context` returns an aggregate-bounded (8 MiB) declarative handoff with the
exact loadout ID, active version digest, target, existing admission key ID, adapter
references, component text and hashes, and a digest of the canonical envelope.
It checks signed state, current adapter pins/revocations, immutable objects, and
the actual returned component bytes under the existing lifecycle lock. Reading
or verifying does not create keys, grants, state or vault files.
An optional CLI output file must be outside the Hive and have no symlink path
components; it cannot overwrite the selected vault's state or signing files.

`loadout-context-verify` requires that entire envelope to match a fresh read of
this vault's currently admitted context. Changed bytes, another vault's admission
key, another target/version, revocation or uninstall refuse the handoff. Unrelated
loadout changes do not invalidate it. Its digest is an integrity binding, not a
portable signed attestation or an invocation grant. A successful verification is
an observation at `verified_at`; it does not authorize future execution. A
consumer must revalidate before use and output acceptance, and still enforce its
own scope, grants and output checks. These explicit entry points do not inject
instructions into a model, start a worker, or automatically bind a workflow run.

The same separate plan/approve/apply flow supports `revoke`, `rollback`, and
`uninstall`; these operations do not take source artifacts. Rollback accepts an
explicit `--version-digest`, or selects the latest previously admitted version that
is still installed and unrevoked. Revocation permanently blocks that exact version
from readmission and active context use. A newly reviewed different version can be
admitted separately.

## Storage, cleanup and recovery

Loadout state, immutable version objects, and signed recovery journals live only
inside the selected Hive's `.hive/loadouts`. Content paths are recorded with exact
hashes. Uninstall removes a loadout from active use and atomically moves each owned
version into `.hive/loadouts/recovery/<original-plan-digest>/<version-digest>`.
The signed preparation journal binds each root's device/inode and destination.
Descriptor-anchored, no-follow paths and native no-clobber rename preserve occupied
destinations. The full owned set is checked before and after the move. Changed
files, symlinks, extra files, and unowned empty directories stop completion; any
already captured content remains available for review. No automatic restoration
overwrites a newly occupied original path.

Recovery copies are retained, not purged. This is necessary because another process
may replace a checked filename or keep writing through an already-open file handle;
an advisory lifecycle lock cannot prevent either action. A final hash followed by
deletion would still risk losing those bytes. The signed receipt reports recovery
paths and `content_purged: false`. These paths are evidence locations, not a claim
that their bytes cannot subsequently change. No purge operation is provided or
scheduled. Signed state, receipts, revocation tombstones, unrelated user files and
product signing keys are preserved.

A signed prepared journal supports resuming an interrupted exact uninstall by
recognizing only the exact captured inode at its recorded destination. Legacy
partial removals tolerate missing files only with their signed preverification.
No changed or new file is accepted as owned. Inactive staging left by an interrupted
or expired admission can be reused only when a fresh approved request reproduces
the exact same bytes. An expired interrupted uninstall requires a fresh plan and
attended approval. That fresh operation may reuse prior signed preverification only
for the same unchanged state, loadout, and exact owned version set; the new signed
journal binds the earlier proof and its original recovery destinations. Expired
approval itself cannot perform a new move.
No background worker performs lifecycle work.

## Acceptance evidence

Golden test artifacts were generated by the unchanged Arc composer at Git revision
`45c46b16da46e2a59f107c6dbede3039d975c68f`, using its MIT first-party draft-only example.
The original recipe `1.0.0` produces ZIP SHA-256
`ddf4e9cfd68f04b4cf18cf3c0fcb9920076da6db29f0f09c92adebf2974948b0`.
An isolated recipe-only update to `1.0.1` produces
`4e5ee8adff84fcbb567d33028d0fc9b6fd2dbb76a03a423b82a121f3b134e0a0`.
The source repository was left unchanged. No ZIP is checked in here: the plain
package members are stored under `tests/fixtures/arc-loadout-0.3.0/package-src/`,
and `tests/arc_loadout_fixture.py` rebuilds byte-identical archives (fixed
timestamps and modes, sorted members) at test time. Tests use these real artifacts for
admission, persistence, upgrade, rollback, revocation, owned uninstall, tampering,
source substitution, target isolation, approval expiry, and interrupted cleanup.

## Configured scope boundary

The attended bridge signs plans, approvals and context for one configured
tenant/project authority. The defaults are `local-user` / `HiveMind`. To use
another scope, set both before starting `hive-local` (they are read once, in
`hive_protocol.product.scope`, at process start):

```sh
export HIVE_TENANT_ID=acme
export HIVE_PROJECT_ID=Research
```

Each value must be 1-128 characters of `A-Z a-z 0-9 . _ : -`, and the tenant and
project must differ; anything else fails closed with `VAULT_SCOPE_INVALID`. The
same values are used for a new Hive's `tenant_id` / `project_id` configuration,
the fallback for legacy Hives without explicit scope fields, the attended adapter
authority and grants, the local research index tenant, and the loadout target.
The web shell still serves only the default scope.

A Hive whose configured `tenant_id` / `project_id` differs from the process
setting is refused with `LOADOUT_SCOPE_UNSUPPORTED` before any key, grant or
loadout state is created. This also applies to reopening existing loadouts after
the configured scope or the setting changed. Restore the original configuration
or setting; this refusal does not migrate or relabel signed history, and
changing the setting does not authorize edits to another scope.
