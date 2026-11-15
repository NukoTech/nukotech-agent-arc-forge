---
name: architecture-and-code-review
description: >-
  Use to sketch an architecture (components, data flow, failure modes) or review
  code, a diff, config or plan with a red-team pass, and before presenting any
  code.
---
# Architecture sketch and code review

Sketch: simplest design that meets the real constraints; add complexity only when you can name the credible failure it prevents. Output: one-paragraph answer; component list with owner of each fact; data flow (text diagram or Mermaid); trust boundaries; failure and recovery states; what is reversible; build sequence with acceptance gates; what to measure; alternatives rejected and the REVIVE IF trigger for each. Prefer maintained software over custom code where it fits, and say what each choice costs.

Review (code, diff, config, plan): 1) does it implement the decision and meet each acceptance test; 2) correctness and edge cases; 3) security: secrets, injection, permissions, supply chain, data exposure; 4) failure handling, retries, idempotency, rollback; 5) simplicity and maintainability; 6) test quality (would the test fail if the code were wrong). Rotate a red-team lens as in board-triage-loop. Findings are labeled blocker, should-fix or note, each with file and line, evidence and a proposed fix.

Never review from a summary alone: open the diff. Say what was not inspected. A review is a single-model opinion (one source); say so on consequential changes and suggest a second proof such as tests or a human reviewer.
