# Install, Verify, Uninstall, and Roll Back

Agent Arc `0.3.0-alpha.1` is a local, non-runtime composer. Install it only in an isolated Python virtual environment. Do not install it into the operating-system Python, another agent's runtime environment, or a production service.

## Install in an isolated environment

From the unpacked candidate source directory:

```sh
python3 -m venv .agent-arc-venv
.agent-arc-venv/bin/python -m pip install ./nukotech_agent_arc-0.3.0a1-py3-none-any.whl
```

If the candidate was supplied as source rather than a wheel, build the wheel first in a separate build environment, verify it against the release manifest, and then install the verified wheel into the isolated environment.

The installation must not edit shell profiles, global environment variables, Keychain entries, browser profiles, network services, schedulers, agents, vaults, or external accounts.

## Verify the CLI

```sh
.agent-arc-venv/bin/agent-arc --help
# equivalent, and the recommended form on Windows (no .exe launcher involved):
.agent-arc-venv/bin/python -m nukotech_agent_arc --help
```

Run the included safe example in a disposable output directory. It must create a deterministic package and composition receipt without installing or executing an agent:

```sh
.agent-arc-venv/bin/agent-arc compose \
  --recipe examples/marketing-operator/recipe.yaml \
  --registry examples/marketing-operator/registry.yaml \
  --authorization examples/marketing-operator/authorization.yaml \
  --component-root examples/marketing-operator \
  --output /tmp/agent-arc-example-output
```

Verify the package:

```sh
.agent-arc-venv/bin/agent-arc verify-package \
  --package /tmp/agent-arc-example-output/marketing-operator-1.0.0.zip \
  --manifest /tmp/agent-arc-example-output/marketing-operator-1.0.0.MANIFEST.sha256
```

The example authorization is draft-only. Any request for an undeclared or prohibited effect, including public publishing, must produce a refusal and no package.

## Uninstall

```sh
.agent-arc-venv/bin/python -m pip uninstall -y nukotech-agent-arc
```

Confirm that the package is gone:

```sh
.agent-arc-venv/bin/python -c 'import nukotech_agent_arc'
```

The final command must fail with `ModuleNotFoundError`.

## Rollback

Rollback is limited to candidate-owned local state:

1. Uninstall `nukotech-agent-arc` from its isolated environment.
2. Remove the isolated `.agent-arc-venv` directory.
3. Remove only disposable output directories created by the candidate.
4. Preserve signed receipts, manifests, and review evidence when they are part of an audit record.

Do not delete or modify the source registry, any knowledge workspace, security provider, vault, backup history, other agent runtimes, user credentials or unrelated virtual environments during rollback.
