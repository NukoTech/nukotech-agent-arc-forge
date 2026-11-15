---
name: five-step-process-algorithm
description: >-
  Use when someone wants to fix, streamline, cut, or automate any process (a
  report, workflow, pipeline, routine, hiring, invoicing, agent loop): run
  Musk's five-step algorithm in strict order: question requirements, delete,
  simplify, speed up, automate last.
---
# Five-step process algorithm (question, delete, simplify, speed up, automate)

Inspired by Elon Musk's publicly described five-step engineering algorithm, and by a post from AI Guides (@free_ai_guides) on X that applied it as a chat prompt. This skill's text is original; see NOTICE.

Sequence matters more than any single step. A step that is sped up or automated before anyone has challenged it just produces unneeded work faster, so each stage only runs on what survived the stage before it.

## What you need first
- **A walk-through of the current process.** Get the real sequence of steps, not just its name. If you only have a label such as "the monthly close", ask for the walk-through or rebuild it from evidence (documents, scripts, schedules, logs) and have the requester confirm it.
- **A working mode.** In interactive mode the requester answers each stage before you continue. In review mode you answer from the evidence yourself and label anything you could not confirm as UNVERIFIED.

## The five stages (strict order, one stage per turn)

1. **Challenge each requirement.** For every step or rule, find the specific person who owns it (a named individual, not a team or department) and what would break if it were dropped. A requirement nobody can name an owner for is a finding in its own right.
2. **Remove steps.** Propose removals, and keep proposing until the requester objects; the first objection shows where the necessary core begins. Habit alone ("we have always done it this way") is not a reason to keep a step. Expect to restore a small share of what you removed later; if you never need to restore anything, the cut was too timid. If nothing at all can be removed, go back to stage 1.
3. **Simplify the survivors.** Reduce handoffs, formats, approval layers and duplicate copies of the same data until there is a single source of truth.
4. **Shorten the waits.** Locate the idle time (queues, approvals, handoffs, batch windows, polling) and propose how to reduce it.
5. **Automate what remains.** Only at this stage, name which of the surviving steps are worth automating.

Hard rule: no automation proposals during stages 1 to 4.

## What to deliver
1. A before-and-after view of the process (a two-column table is fine).
2. Any requirement that has no named owner.
3. The removed steps, and the one most likely to need restoring.
4. One small, concrete change to make this week.

## Guardrails for agents
- "Remove" applies to the process design only. Never delete files, data, accounts, routines or records while running this skill. Any real removal, retirement or irreversible change needs an explicit GO from the owner or approver under the normal change rules.
- Everything you produce is a proposal until the process owner approves it. Do not send messages, change schedules or spend money as part of this skill.
- Safety, legal, security, financial-control and human-approval gates are requirements with owners. You may ask who owns them, but do not recommend removing them without that owner's explicit decision.
- Never guess who owns a requirement. If no one can be named, record UNKNOWN and report it as a stage 1 finding.

## Paste-ready prompt

Help me improve a process using the five-step algorithm: challenge requirements, remove steps, simplify, shorten waits, then automate.

My process today, step by step: [describe it]

Work through one stage at a time and wait for my answer before moving to the next.

1. For each requirement, ask me which named person owns it and what would break without it.
2. Propose steps to remove, and keep going until I object to one.
3. Simplify the steps that are left.
4. Show me where work sits waiting and how to shorten it.
5. Only then, suggest what to automate.

Finish with: the process before and after, any requirement with no named owner, what we removed and what we will likely need to restore, and one change I can make this week.

Ground rules: no automation ideas before stage 5, habit is not a reason to keep a step, and if nothing can be removed, start again at stage 1.
