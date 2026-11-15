# NukoTech Hive Local Alpha v0.1.0 install

This is an alpha, not a production release. It requires
64-bit Linux, Python 3.11 or newer with `venv`, and Git. Core vault, exact search,
graph, retrieval-only Ask, snapshots, rollback, export, and the local UI work offline.
Ollama is optional.

From the extracted artifact, install with one command:

```bash
./install.sh --prefix "$PWD/.nukotech-hive-local"
```

Create and launch a disposable Hive:

```bash
.nukotech-hive-local/bin/hive-local init --vault "$PWD/demo-hive"
.nukotech-hive-local/bin/hive-local app --vault "$PWD/demo-hive" \
  --host 127.0.0.1 --port 0 --open
```

The application runs only in that foreground process. It binds only to `127.0.0.1`
and prints a plain loopback URL with no token or credential. With `--open`, the process
passes a private one-time launch URL directly to the browser; the server consumes it
once and redirects to the clean printed URL. Direct navigation to the printed URL
without that handoff is refused. Restarting the application invalidates the prior
session. It does not install a service, login item, daemon, or unattended worker.

To verify the entire installed application boundary without optional browser tooling:

```bash
python3 verify/m4-installed-shell-e2e.py \
  --launcher .nukotech-hive-local/bin/hive-local \
  --vault "$PWD/demo-hive" --work-root "$PWD/m4-proof"
```

Run the complete machine-readable proof:

```bash
.nukotech-hive-local/bin/hive-local demo --work-root "$PWD/alpha-demo"
```

## Rollback

Create a checkpoint before changes and restore it by exact full SHA:

```bash
.nukotech-hive-local/bin/hive-local snapshot --vault "$PWD/demo-hive" --message "before change"
.nukotech-hive-local/bin/hive-local rollback --vault "$PWD/demo-hive" --commit FULL_40_CHARACTER_SHA
```

Rollback affects only the selected disposable Hive. It does not touch the source vault
used for import.

## Uninstall

From the extracted artifact:

```bash
./uninstall.sh --prefix "$PWD/.nukotech-hive-local"
```

The uninstaller requires the exact alpha install marker and never removes user-created
Hive vaults.
