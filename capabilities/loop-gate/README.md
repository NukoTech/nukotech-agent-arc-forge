# NukoTech Loop Gate

> Part of the NukoTech open skill set. MIT licensed. (c) 2026 Nuko Technologies LLC.

## What it is

Use when an agent needs to remember durable facts across sessions, or recall them, using dated markdown files with write, consolidate, recall, and apply steps.

## Install

From the flagship monorepo (this capability lives at `capabilities/loop-gate`):

```bash
git clone https://github.com/NukoTech/nukotech-agent-arc-forge.git
cd nukotech-agent-arc-forge/capabilities/loop-gate
```

Pure Python standard library, no dependencies (Python 3.10+).

```bash
python3 -m unittest discover -s tests
```

## Usage

See the main file(s) below.

## Files

- `docs/file-memory-design.md`
- `docs/loop-gate-design.md`
- `examples/example_packets.json`
- `file_memory/__init__.py`
- `file_memory/file_memory.py`
- `loop_gate/__init__.py`
- `loop_gate/loop_gate.py`
- `loop_gate/packets.py`
- `skills/nukotech-file-memory/SKILL.md`
- `skills/nukotech-loop-gate/SKILL.md`
- `tests/test_file_memory.py`
- `tests/test_loop_gate.py`

## License

MIT. Copyright (c) 2026 Nuko Technologies LLC. See `LICENSE`.
