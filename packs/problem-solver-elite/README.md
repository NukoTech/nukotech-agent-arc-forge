# Problem Solver Elite

> Part of the NukoTech open skill set. MIT licensed. (c) 2026 Nuko Technologies LLC.

## What it is

Elite strategic problem-solving system using 8 interconnected analytical modules — first principles thinking, root cause analysis (5 Whys), SCQA framework, game theory, second-order consequences, design thinking, OODA loop, and solution synthesis. Use this skill whenever the user faces complex business challenges, strategic decisions, operational problems, competitive analysis, system design problems, recurring issues, high-stakes decisions, or any situation where surface-level thinking is insufficient. Also trigger when the user says things like "help me think through," "how should I approach," "what's the best strategy," "analyze this problem," "I'm stuck on," or asks for structured analysis of any kind. If the user has a problem that requires more than a quick answer, use this skill.

## Install

From the flagship monorepo (this skill lives at `packs/problem-solver-elite`):

```bash
git clone https://github.com/NukoTech/nukotech-agent-arc-forge.git
cd nukotech-agent-arc-forge/packs/problem-solver-elite
```

Copy the skill folder into your agent's skills directory (for example `~/.claude/skills/` for Claude Code, or your platform's equivalent). Each `SKILL.md` has YAML front matter (`name`, `description`) that agent runtimes use to decide when to load it.

## Usage

Ask your agent for the task described above; the runtime loads the skill when the request matches its description. You can also paste the main file into a system prompt or custom-instructions field.

## Files

- `SKILL.md`

## License

MIT. Copyright (c) 2026 Nuko Technologies LLC. See `LICENSE`.
