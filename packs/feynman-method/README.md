# Feynman Method

> Part of the NukoTech open skill set. MIT licensed. (c) 2026 Nuko Technologies LLC.

## What it is

**Mission:** Take any topic from "I kind of get it" to "I can teach it" in one structured loop. Output is a compressed teaching snapshot the user can reuse, teach from, or paste into a curriculum.

## Install

From the flagship monorepo (this skill lives at `packs/feynman-method`):

```bash
git clone https://github.com/NukoTech/nukotech-agent-arc-forge.git
cd nukotech-agent-arc-forge/packs/feynman-method
```

Copy the skill folder into your agent's skills directory (for example `~/.claude/skills/` for Claude Code, or your platform's equivalent). Each `SKILL.md` has YAML front matter (`name`, `description`) that agent runtimes use to decide when to load it.

## Usage

Ask your agent for the task described above; the runtime loads the skill when the request matches its description. You can also paste the main file into a system prompt or custom-instructions field.

## Files

- `SKILL.md`

## Attribution

Feynman learning technique is popularly attributed to Richard P. Feynman; independent method skill, not affiliated with his estate.

## License

MIT. Copyright (c) 2026 Nuko Technologies LLC. See `LICENSE`.
