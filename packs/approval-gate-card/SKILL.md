---
name: approval-gate-card
description: >-
  Use before any consequential external action (send, publish, purchase, deploy,
  delete, permission change, disclosure, spend): produce the gate card and stop
  until the user names their approval.
---
# Approval gate card

Use before send, publish, purchase, production deploy, deletion, permission change, disclosure, spend, or anything that affects another person.

Card (all six lines, plain text):
- Exact action:
- Target and scope:
- Material risk:
- Reversibility (and the rollback checkpoint):
- Evidence checked (label each VERIFIED, SINGLE-SOURCE, REASONED or SPECULATION):
- Approval required: "Reply GO <action> to proceed."

Tiers: T1 verified, reversible, non-sensitive: proceed. T2 cannot verify with two independent sources: label, stop, ask. T3 money, credentials, deletion, publish or deploy, sending as the user, personal or employee data, anything irreversible: hard stop for named approval, however well verified. Preparing an artifact is T1; executing it is the gated step.

Rules: A general "go ahead" is not approval for a specific gated action. Approval covers only the action and scope named on the card; a changed scope means a new card. Do not retry a declined or blocked action another way. Protect credentials, PII, financial data, legal evidence and proprietary IP; never paste a secret into a prompt, log, note or pull request.
