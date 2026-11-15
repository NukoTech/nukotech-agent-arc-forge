# NukoTech Hive Local Alpha

> **Alpha.** MIT License, Copyright (c) 2026 Nuko Technologies LLC.

## Canonical plan

The controlling plan is [`docs/plans/ROADMAP.md`](docs/plans/ROADMAP.md), bound by
SHA-256 in [`CANONICAL_HIVEMIND.json`](CANONICAL_HIVEMIND.json). Verify it with:

```bash
python3 scripts/verify_canonical_repository.py --repository .
```

NukoTech Hive Local Alpha v0.1.0 is an installable, local-first alpha product slice.
It keeps ordinary Markdown/text files portable, derives a rebuildable local index and
typed graph, supports grounded local Ask behavior, records governed agent work,
checkpoints state with Git, rolls back exact disposable state, and exports a bundle
that can be reopened without a proprietary service.

It is ready for hands-on trial use only after the fresh-install proof below passes. It is not a customer
production release and contains no deployment identity or private memory. The
bundled identity context is a neutral sample.

## Build and fresh-install proof

```bash
./scripts/build-alpha.sh
./scripts/fresh-install-e2e.sh dist/nukotech-hive-local-alpha-v0.1.0-linux-$(uname -m).tar.gz
```

The first command builds a self-contained platform wheelhouse, checksum manifest,
CycloneDX SBOM, notices, installer, uninstaller, and versioned tarball. The second
extracts it into a clean temporary directory, installs without PyPI access, runs the
entire disposable-vault workflow through the installed executable, and emits a JSON
receipt.

## Source development

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e . pytest
.venv/bin/python -m pytest -q
.venv/bin/hive-local --help
```

The bundled lab identity keeps the `QUEEN` role and leaves the persona slot
unassigned. Before a governed lab turn, assign a local persona. This writes a
user context file and does not change the packaged sample:

```bash
.venv/bin/hive-local persona assign YourName
```

Create a local Hive and import a source vault without modifying it:

```bash
.venv/bin/hive-local init --vault /tmp/my-hive
.venv/bin/hive-local import --vault /tmp/my-hive --source /path/to/disposable-source
.venv/bin/hive-local configure --vault /tmp/my-hive --provider retrieval-only
.venv/bin/hive-local search --vault /tmp/my-hive --query "exact phrase"
.venv/bin/hive-local ask --vault /tmp/my-hive --question "What changed?"
.venv/bin/hive-local serve --vault /tmp/my-hive
```

If local Ollama is unavailable, Ask returns a clearly labeled retrieval-only result
with source IDs and paths. It never invents a grounded answer.

## Retained alpha capabilities

- Byte-for-byte Markdown/text import with stable IDs, hashes, and provenance sidecars.
- SQLite exact-text retrieval, optional FTS5, typed wikilinks, and backlinks.
- Optional loopback-only Ollama answers constrained to retrieved local passages.
- Provider-neutral agent/task adapter with signed receipts and replay protection.
- New-process retrieval and append-only local receipts.
- Git snapshots and exact ancestor rollback inside the selected Hive only.
- Portable export manifest with per-file hashes and verified reopen.
- Loopback-only web surface showing vault, search, graph, agents/tasks, receipts, Git,
  privacy mode, provider/model, and health.
- One end-to-end demo command with a machine-readable classification receipt.

## Architecture and authority boundaries

The canonical layer is portable Markdown, assets, provenance, configuration, and Git.
SQLite/FTS, graph projection, model context, and UI state are derived or ephemeral.
External services are optional adapters. The core does not require GitHub, a cloud
model, a subscription, or a proprietary application at runtime.

The source repository also carries the provider-neutral LAB protocol slice
(identity context, signed work envelopes, memory promotion, governance release, and a
receiver matrix with a configurable sample roster) under `src/hive_protocol/`. The
sample identity reference is excluded from the product wheel and is never copied
into user vaults. The product shell is under
`src/hive_protocol/product/`.

See [install and rollback instructions](docs/install/alpha-install.md), the
[adapter contract](docs/architecture/hive-application-adapter-contract-v1.md), the
[threat model](docs/security/threat-model.md), and the SBOM/third-party notices
inside each built artifact.

The current code is an early foundation, not a finished replacement for NotebookLM,
Mem.ai, Hynote, Orbit, or similar products. Those products are capability references;
equivalence must be implemented and verified feature by feature.
