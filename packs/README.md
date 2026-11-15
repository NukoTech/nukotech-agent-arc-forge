# Packs

Each folder is a `SKILL.md` skill (YAML frontmatter `name`, `description`) under MIT. Import any of them into an Agent Arc registry with:

```sh
python -m nukotech_agent_arc import-skill packs/<name> --registry-root . --type skill
```

## In-tree packs

| Pack | What it is for |
|---|---|
| [`agent-discipline`](agent-discipline/SKILL.md) | Coding governance framework that enforces disciplined, surgical engineering practices for any LLM-assisted development work. Use this skill … |
| [`approval-gate-card`](approval-gate-card/SKILL.md) | Use before any consequential external action (send, publish, purchase, deploy, delete, permission change, disclosure, spend): produce the ga… |
| [`architecture-and-code-review`](architecture-and-code-review/SKILL.md) | Use to sketch an architecture (components, data flow, failure modes) or review code, a diff, config or plan with a red-team pass, and before… |
| [`bayes-brier-forecast`](bayes-brier-forecast/SKILL.md) | Log forecasts before outcomes, update them with odds and likelihood ratios, handle correlated evidence, and score with Brier using a simple … |
| [`evidence-tier-gate`](evidence-tier-gate/SKILL.md) | Tag every behavioral claim with its evidence tier (1 to 4) and block the Othello Error and automatic lie verdicts. Use before and during any… |
| [`feynman-method`](feynman-method/SKILL.md) | Use when someone wants to deeply understand a topic, not just look it up: explain simply, probe confusion, refine, test, then teach it back. |
| [`five-step-process-algorithm`](five-step-process-algorithm/SKILL.md) | Use when someone wants to fix, streamline, cut, or automate any process (a report, workflow, pipeline, routine, hiring, invoicing, agent loo… |
| [`fleet-build-integrity-governor`](fleet-build-integrity-governor/SKILL.md) | Govern long multi-agent build sessions: named actions, legitimate pause conditions only, and integrity checks before claiming done. |
| [`lincoln-99`](lincoln-99/SKILL.md) | Truth-integrity discipline for substantive answers: separate verified fact from inference, flag uncertainty, never overclaim. |
| [`problem-solver-elite`](problem-solver-elite/SKILL.md) | Elite strategic problem-solving system using 8 interconnected analytical modules — first principles thinking, root cause analysis (5 Whys), … |
| [`quantitative-rigor-protocol`](quantitative-rigor-protocol/SKILL.md) | Use before accepting any quantitative claim: check units, magnitude, base rates, distribution, independence, sample size, and sensitivity. |
| [`spot-dissect-predict-counter`](spot-dissect-predict-counter/SKILL.md) | Run a defensive counterparty analysis in the SPOT, DISSECT, PREDICT, COUNTER format. Use for any serious read of a person, negotiation, mess… |
| [`stair-toc-retrieval`](stair-toc-retrieval/SKILL.md) | Use when searching a long document, book, manual, or corpus that has a table of contents or heading tree, instead of flat chunk RAG. Works w… |

## Pinned upstream packs (not vendored)

The five public NukoTech packs are pinned by exact commit in [`upstream/lock.json`](upstream/lock.json) and fetched with `python packs/upstream/fetch.py`. One carries a small overlay until the same change lands upstream: the arc-gates text refresh. NZT99 is fetched directly from upstream at its pinned commit, with no overlay; its generic placeholders for domain-specific skill names now live upstream.

The workspace capability `capabilities/loop-gate` (loop gate + file memory) ships separately with its own tests.
