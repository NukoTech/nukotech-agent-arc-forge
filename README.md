# NukoTech Agent Arc Forge

This repository holds two local-first alpha tools and a set of skill packs:

- **Arc Forge** ([`arc/`](arc/README.md)) is the Agent Arc composer, Python package
  `nukotech-agent-arc` 0.3.0a1 with the `agent-arc` command.
- **NukoTech HiveMind** ([`hivemind/`](hivemind/README.md)) is shipped as NukoTech Hive Local
  Alpha v0.1.0, Python package `nukotech-hive-local` with the `hive-local` command.
- **Packs** ([`packs/`](packs/README.md)) are `SKILL.md` skills that can be imported into
  an Agent Arc registry.
- **Capabilities** ([`capabilities/loop-gate`](capabilities/loop-gate/README.md)) holds a
  loop gate and file memory capability with its own tests.

Everything here is **alpha and not for production use**.

## What Arc Forge does

Agent Arc composes governed agent architectures from exact, versioned components:
skills, loops, governance or harness layers, graph or memory bindings, runtime
bindings, and protocols. It is a local, **non-runtime** composer. It validates
inputs, resolves exact component bytes, enforces authorization and compatibility
policy, calls a provider-neutral security gate, and emits deterministic packages
and receipts. Identical inputs produce byte-identical package and receipt
artifacts, and any failure stops closed.

It does not install or execute an agent, connect accounts, publish content,
spend money or deploy infrastructure. Optional detached Ed25519 signing is
available through the `signing` extra. See [`arc/README.md`](arc/README.md).

## What NukoTech HiveMind does

Hive Local is a local-first product slice over ordinary Markdown and text files.
It keeps those files portable and adds:

- a rebuildable local index and typed graph;
- grounded local Ask, with optional loopback-only Ollama;
- governed agent work with signed receipts;
- Git checkpoints and exact rollback inside the selected Hive;
- a portable export bundle that can be reopened without a proprietary service.

If Ollama is not available, Ask returns a clearly labeled retrieval-only result
with source IDs and paths. The core does not require GitHub, a cloud model, a
subscription or a proprietary application at runtime. It is not a customer
production release. See [`hivemind/README.md`](hivemind/README.md).

## Quickstart

Both tools need Python 3.11 or newer. Hive Local also needs Git and 64-bit Linux
for the packaged artifact.

### Arc Forge

These steps follow [`arc/docs/INSTALL_UNINSTALL.md`](arc/docs/INSTALL_UNINSTALL.md).
Install into an isolated virtual environment, never into the system Python:

```sh
git clone https://github.com/NukoTech/nukotech-agent-arc-forge.git
cd nukotech-agent-arc-forge/arc
python3 -m venv .agent-arc-venv
.agent-arc-venv/bin/python -m pip install .
.agent-arc-venv/bin/agent-arc --help
```

The install doc installs a release wheel, `nukotech_agent_arc-0.3.0a1-py3-none-any.whl`.
From a source checkout, `pip install .` builds and installs the same package.

Compose and verify the included safe example in a disposable output directory:

```sh
.agent-arc-venv/bin/agent-arc compose \
  --recipe examples/marketing-operator/recipe.yaml \
  --registry examples/marketing-operator/registry.yaml \
  --authorization examples/marketing-operator/authorization.yaml \
  --component-root examples/marketing-operator \
  --output /tmp/agent-arc-example-output

.agent-arc-venv/bin/agent-arc verify-package \
  --package /tmp/agent-arc-example-output/marketing-operator-1.0.0.zip \
  --manifest /tmp/agent-arc-example-output/marketing-operator-1.0.0.MANIFEST.sha256
```

`examples/marketing-operator/prohibited-recipe.yaml` shows a refusal: a refusal
receipt and no package. CI runs this example and the refusal as its `demo` job.
To uninstall, run `.agent-arc-venv/bin/python -m pip uninstall -y nukotech-agent-arc`
and remove the `.agent-arc-venv` directory.

### NukoTech HiveMind

From source, following [`hivemind/README.md`](hivemind/README.md):

```sh
cd nukotech-agent-arc-forge/hivemind
python3 -m venv .venv
.venv/bin/python -m pip install -e . pytest
.venv/bin/hive-local --help
.venv/bin/hive-local persona assign YourName
.venv/bin/hive-local init --vault /tmp/my-hive
```

`hive-local persona assign` writes a local persona into your user context file.
The packaged sample keeps the `QUEEN` role and leaves that slot unassigned.

To build the self-contained artifact, install it, and use snapshots, rollback and
uninstall, see [`hivemind/docs/install/alpha-install.md`](hivemind/docs/install/alpha-install.md).
The application binds only to `127.0.0.1`, runs only in its foreground process,
and does not install a service, login item, daemon or unattended worker.

## How the packs work

Each folder under [`packs/`](packs/README.md) is a `SKILL.md` skill with YAML
frontmatter (`name`, `description`), under MIT. With Agent Arc installed, import
one into an Agent Arc registry from the repository root:

```sh
python -m nukotech_agent_arc import-skill packs/<name> --registry-root . --type skill
```

`import-skill` reads the `SKILL.md`, hashes it, and prints a registry component
entry. Five public NukoTech packs are not vendored. They are pinned by exact
commit in [`packs/upstream/lock.json`](packs/upstream/lock.json) and fetched with
`python packs/upstream/fetch.py`. The [packs README](packs/README.md) lists every
in-tree pack and what it is for.

## Security, contributing, and legal

- Security: report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
  The threat model is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
- Contributing: see [CONTRIBUTING.md](CONTRIBUTING.md) and the
  [Code of Conduct](CODE_OF_CONDUCT.md). Changes land through pull requests only.
- Attributions for adapted methods and prompts: [NOTICE](NOTICE).
- Licenses: MIT, Copyright (c) 2026 Nuko Technologies LLC. See the root [LICENSE](LICENSE),
  [arc/LICENSE](arc/LICENSE), [hivemind/LICENSE](hivemind/LICENSE), and the
  `LICENSE` file in each pack and capability.
- Trademarks: the code license grants no trademark rights. See [TRADEMARKS.md](TRADEMARKS.md).
