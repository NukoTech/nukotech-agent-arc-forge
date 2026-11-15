# Agent Arc (core)

Agent Arc composes governed agent architectures from exact, versioned components. It combines skills, loops, governance or harness layers, graph or memory bindings, runtime bindings, and protocols without treating any one layer as the whole agent architecture.

Version `0.3.0-alpha.1` is a local, **non-runtime** composer. It validates inputs, resolves exact component bytes, enforces authorization and compatibility policy, calls a provider-neutral security gate, and emits deterministic packages and receipts. It does **not** install or execute an agent, connect accounts, publish content, spend money or deploy infrastructure.

## Boundary

- **Core:** transparent recipe, registry, policy, composition, verification and receipt formats.
- **Security provider:** Agent Arc consumes allow/deny decisions only through the provider-neutral contract in `docs/SECURITY_PROVIDER_CONTRACT.md`. A restrictive local provider is the default.
- **Runtime:** out of scope. The flagship repo's `hivemind/` workspace is one place a composed package can be installed.

## Run without installing

```sh
python -m nukotech_agent_arc --help        # works on Windows when the agent-arc.exe launcher is blocked
```

## Safe local example

```sh
agent-arc validate \
  --recipe examples/marketing-operator/recipe.yaml \
  --registry examples/marketing-operator/registry.yaml

agent-arc compose \
  --recipe examples/marketing-operator/recipe.yaml \
  --registry examples/marketing-operator/registry.yaml \
  --authorization examples/marketing-operator/authorization.yaml \
  --component-root examples/marketing-operator \
  --output /tmp/agent-arc-example-output

agent-arc verify-package \
  --package /tmp/agent-arc-example-output/marketing-operator-1.0.0.zip \
  --manifest /tmp/agent-arc-example-output/marketing-operator-1.0.0.MANIFEST.sha256
```

Identical inputs produce byte-identical package and receipt artifacts. Any validation, resolution, authorization, security, packaging or verification failure stops closed. `examples/*/prohibited-recipe.yaml` shows a refusal: a refusal receipt and no package.

Unsigned compose and verify stay on the standard library and remain
byte-reproducible. Optional detached signing uses the `signing` extra
(`pip install nukotech-agent-arc[signing]`):

```sh
agent-arc sign \
  --package /tmp/agent-arc-example-output/marketing-operator-1.0.0.zip \
  --manifest /tmp/agent-arc-example-output/marketing-operator-1.0.0.MANIFEST.sha256 \
  --key /path/to/ed25519-private.pem

agent-arc verify-package \
  --package /tmp/agent-arc-example-output/marketing-operator-1.0.0.zip \
  --manifest /tmp/agent-arc-example-output/marketing-operator-1.0.0.MANIFEST.sha256 \
  --pubkey /path/to/ed25519-public.pem \
  --require-signature
```

`verify-package` without `--pubkey`, `--trusted-keys`, or
`--require-signature` still checks hashes only, so existing unsigned
packages keep working. When a key or `--require-signature` is given,
a missing or invalid signature fails closed. The detached receipt
(`*.SIGNATURE.json`) binds the signer key id (full SHA-256 fingerprint
of the raw Ed25519 public key) and the digests of the manifest and
composition receipt.

## Importing skills

`agent-arc import-skill <skill-dir> --type skill` reads a `SKILL.md` (YAML frontmatter `name`, `description`, optional `metadata.version`), hashes it, and prints a registry component entry. See the flagship `demo/` for an end-to-end use.

## Context and prompting example pack

`examples/context-and-prompting-pack` composes a prompt-strategy selector, a one-question-at-a-time organization-context loop, a modular context-manifest binding and a tenant-scoped governance harness. It stages context only: bulk imports, automatic durable-memory promotion, credentials, external actions and cross-tenant reuse are outside its authorization. Third-party prompt libraries must be selected individually and carry provenance and a rights basis; they are never bulk imported.

## Status

Alpha. Not for production use.
