# NukoTech Loop Gate: design
Sources: @HoodieFade_ "Loops & Graphs" (x.com/HoodieFade_/status/2118010863038746652), karpathy/autoresearch (inspiration only). Clean-room design, no code copied.

1. **Graph of units.** Work is a DAG. `LoopGate._validate` rejects unknown deps, duplicate ids, and cycles.
2. **Every unit has a fail-able check.** The output is accepted only if `check(output)` doesn't raise. Packets with no valid check are rejected at load time.
3. **Parallel fan-out.** Ready units in each dependency wave run on a ThreadPoolExecutor.
4. **Isolated repair.** A failed unit is retried alone, with its last error passed in. Siblings are unaffected.
5. **Retry once, then escalate.** Default max_attempts is 2. The same error twice means ESCALATED: stop and report. Downstream units become BLOCKED and never run on bad input.
6. **Humans sign only irreversible steps (signatures == human GO).** The kinds are money, merge, deploy, send, delete, and post. Without a signature in `signatures` the unit is AWAITING_SIGNATURE.
7. **Event log.** `gate.log` is an append-only list of {t, unit, status, attempt, error}.

Code: `loop_gate/loop_gate.py`, `loop_gate/packets.py`. Tests: `tests/test_loop_gate.py`.

Checks can see dependency outputs (`check_uses_deps`, `from_deps` packet check), so verification compares against the real upstream value rather than an echoed copy.
