---
name: nukotech-loop-gate
description: Use when tasking agents or running multi-step agent work. Break the work into a graph of units, each with a fail-able check, fan out the independent units, repair failures in isolation, and require a human GO for irreversible steps.
---
# Loop Gate
1. **Write task packets** (unit_id, goal, owner_bot, loop_stage, inputs, deps, check, irreversible, max_attempts). See `loop-gate/host platform-tasking.md`.
2. **Every unit needs a check that can fail**: a test, assert, schema, readback-equals-source, or range. No check means the unit isn't ready to dispatch.
3. Follow the loop: Data entry -> Verification [gate] -> Prediction -> [gate] Execution -> Report -> repeat.
4. **Fan out** units whose deps are all accepted. Never start a unit whose upstream failed.
5. **On failure** retry that unit alone, once, with the error as context. If the same error happens twice, or attempts run out, **stop and report** (unit, error, attempts). Don't improvise around it.
6. **Irreversible = human GO (signatures == owner's GO)**: money (invoices sent, POs issued, payroll, payments), merges, deploys, external sends/posts, deletes. Prepare everything, then hold at AWAITING_SIGNATURE and report exactly what would happen.
7. **Report**: accepted / escalated / blocked / awaiting_signature lists + event log. That report feeds the next loop.
Reference: `loop_gate/loop_gate.py`, `loop_gate/packets.py` (stdlib).
8. Only the designated intake bot issues record ids (e.g. order or ticket numbers). Every other unit takes the id as an input and never invents one.
9. Verification checks compare against the dependency's actual output (`from_deps`), not an echoed copy.
