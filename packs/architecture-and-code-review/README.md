# Architecture And Code Review

> Part of the NukoTech open skill set. MIT licensed. (c) 2026 Nuko Technologies LLC.

## What it is

Use to sketch an architecture (components, data flow, failure modes) or review code, a diff, config or plan with a red-team pass, and before presenting any code.

## Install

From the flagship monorepo (this skill lives at `packs/architecture-and-code-review`):

```bash
git clone https://github.com/NukoTech/nukotech-agent-arc-forge.git
cd nukotech-agent-arc-forge/packs/architecture-and-code-review
```

Copy the skill folder into your agent's skills directory (for example `~/.claude/skills/` for Claude Code, or your platform's equivalent). Each `SKILL.md` has YAML front matter (`name`, `description`) that agent runtimes use to decide when to load it.

## Usage

Ask your agent for the task described above; the runtime loads the skill when the request matches its description. You can also paste the main file into a system prompt or custom-instructions field.

## Files

- `SKILL.md`

## License

MIT. Copyright (c) 2026 Nuko Technologies LLC. See `LICENSE`.
