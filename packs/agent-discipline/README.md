# Agent Discipline

> Part of the NukoTech open skill set. MIT licensed. (c) 2026 Nuko Technologies LLC.

## What it is

Coding governance framework that enforces disciplined, surgical engineering practices for any LLM-assisted development work. Use this skill whenever the assistant is writing, editing, debugging, or refactoring code — in ANY language, ANY framework, ANY project. Triggers on all coding tasks including: writing new code, editing existing files, fixing bugs, refactoring, code review, PR preparation, script generation, configuration changes, infrastructure-as-code, database migrations, or any task where the assistant touches source files. This is a behavioral layer, not a language-specific tool — it applies universally. If the assistant is about to write or modify code, this skill MUST activate. Also trigger when the user mentions 'careful changes,' 'minimal diff,' 'surgical edit,' 'don't break anything,' 'just fix this one thing,' or expresses frustration with over-engineered or scope-creeping AI code changes.

## Install

From the flagship monorepo (this skill lives at `packs/agent-discipline`):

```bash
git clone https://github.com/NukoTech/nukotech-agent-arc-forge.git
cd nukotech-agent-arc-forge/packs/agent-discipline
```

Copy the skill folder into your agent's skills directory (for example `~/.claude/skills/` for Claude Code, or your platform's equivalent). Each `SKILL.md` has YAML front matter (`name`, `description`) that agent runtimes use to decide when to load it.

## Usage

Ask your agent for the task described above; the runtime loads the skill when the request matches its description. You can also paste the main file into a system prompt or custom-instructions field.

## Files

- `SKILL.md`

## License

MIT. Copyright (c) 2026 Nuko Technologies LLC. See `LICENSE`.
