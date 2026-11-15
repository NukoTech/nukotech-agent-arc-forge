# Stair Toc Retrieval

> Part of the NukoTech open skill set. MIT licensed. (c) 2026 Nuko Technologies LLC.

## What it is

Use when searching a long document, book, manual, or corpus that has a table of contents or heading tree, instead of flat chunk RAG. Works with any general-purpose LLM.

## Install

From the flagship monorepo (this skill lives at `packs/stair-toc-retrieval`):

```bash
git clone https://github.com/NukoTech/nukotech-agent-arc-forge.git
cd nukotech-agent-arc-forge/packs/stair-toc-retrieval
```

Copy the skill folder into your agent's skills directory (for example `~/.claude/skills/` for Claude Code, or your platform's equivalent). Each `SKILL.md` has YAML front matter (`name`, `description`) that agent runtimes use to decide when to load it.

## Usage

Ask your agent for the task described above; the runtime loads the skill when the request matches its description. You can also paste the main file into a system prompt or custom-instructions field.

## Files

- `SKILL.md`

## Attribution

Method based on the public STAIR paper (IBM Research, arXiv:2609.03874). No code from the paper is bundled.

## License

MIT. Copyright (c) 2026 Nuko Technologies LLC. See `LICENSE`.
