# Fleet-Build Integrity Governor

> Part of the NukoTech open skill set. MIT licensed. (c) 2026 Nuko Technologies LLC.

## What it is

* business agent mesh development (for example procurement, scheduling, document control or finance agents in a domain project) * Federal RFP work with autonomous-operation clauses * Any task whose stated purpose is to operate without continuous AI assistance * Any agentic coding session exceeding 4 continuous hours

## Install

From the flagship monorepo (this skill lives at `packs/fleet-build-integrity-governor`):

```bash
git clone https://github.com/NukoTech/nukotech-agent-arc-forge.git
cd nukotech-agent-arc-forge/packs/fleet-build-integrity-governor
```

Copy the skill folder into your agent's skills directory (for example `~/.claude/skills/` for Claude Code, or your platform's equivalent). Each `SKILL.md` has YAML front matter (`name`, `description`) that agent runtimes use to decide when to load it.

## Usage

Ask your agent for the task described above; the runtime loads the skill when the request matches its description. You can also paste the main file into a system prompt or custom-instructions field.

## Files

- `SKILL.md`

## License

MIT. Copyright (c) 2026 Nuko Technologies LLC. See `LICENSE`.
