---
name: prompt-strategy-selector
description: Use when a task needs a deliberate prompting approach because its evidence, ambiguity, output shape, or need for diverse candidates materially affects reliability.
---

# Prompt Strategy Selector

## Purpose

Choose the smallest prompting strategy that makes a bounded task checkable. Treat prompts as plans tied to sources, authorization, and an output contract—not as substitutes for evidence or permission.

## Inputs

- Task objective and intended audience
- Authorization envelope and prohibited effects
- Available source records with provenance and freshness
- Required output shape or downstream consumer
- Up to five representative examples, when lawfully available

If the task, tenant, authority, or destination is unclear, stop and request the missing fact. Never request credentials or secret values as prompt context.

## Selection Contract

| Observable task condition | Add to the prompt plan |
|---|---|
| A repeated transformation has representative inputs and accepted outputs | Few-shot examples, limited to relevant and rights-cleared examples |
| A machine or deterministic verifier consumes the result | An explicit structured-output schema and validation rules |
| One answer would materially change the work or prevent rework | A concise active-reasoning question; ask only what changes the result |
| The task needs creative breadth | Several clearly labeled candidates and a deterministic selection rubric |
| The task is factual, regulated, financial, medical, legal, security-sensitive, or otherwise high impact | Source requirements, uncertainty labels, a verification checklist, and a human decision gate |
| None of the above applies | Direct instructions with scope, constraints, success criteria, and stop conditions |

Active-reasoning questions are a scoped clarification technique, not a universal accuracy guarantee. Candidate self-scores are uncalibrated model estimates; they are not probabilities of truth, quality, or compliance.

## Output Contract

Return a prompt plan with these fields, in this order:

1. `objective`
2. `selected_strategies`
3. `decision_summary` — short, checkable justification; never private hidden reasoning
4. `questions` — zero or more concise questions that materially affect the result
5. `evidence_requirements`
6. `output_contract`
7. `examples`
8. `constraints`
9. `stop_conditions`
10. `verification`

The plan must not request hidden chain-of-thought, fabricate citations, treat generated confidence as calibrated, or broaden the authorization envelope.

## Stop Conditions

- Missing tenant or task identity
- Missing authority for a requested effect
- Unverifiable or stale evidence where freshness matters
- Sensitive information exceeds the task's minimum necessary scope
- An example lacks a usable rights or provenance basis
- The requested output cannot be independently checked

## Research Basis

This is a clean-room first-party synthesis informed by prompt-strategy research and organization-context notes. Quantitative active-reasoning-question evidence is scoped to the benchmark reported in *Active Reasoning Questions: A New Approach to Understanding and Improving LLM Capabilities* (arXiv:2503.03669). Diversity guidance is informed by *Verbalized Sampling* (arXiv:2510.01171); its generated probability labels are explicitly not treated as calibrated confidence.
