"""NukoTech Loop Gate: run agent work as a DAG of units, each gated by a fail-able check.

Rules: a unit is ACCEPTED only when its check passes; independent units fan out in
parallel; a failed unit is repaired in isolation (retry once with the failure as
context); the same error twice -> ESCALATED (stop and report); irreversible units
(money, merge, deploy, send) never run without a human signature. Stdlib only.
"""
from __future__ import annotations
import concurrent.futures as cf
import json, time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

IRREVERSIBLE_KINDS = {"money", "merge", "deploy", "send", "delete", "post"}
PENDING, ACCEPTED, FAILED, ESCALATED, BLOCKED, AWAITING_SIGNATURE = (
    "pending", "accepted", "failed", "escalated", "blocked", "awaiting_signature")


@dataclass
class Unit:
    id: str
    run: Callable[[dict, Optional[str]], Any]      # (inputs from deps, last_error) -> output
    check: Callable[..., None]                     # raise to fail; (output) or (output, dep_inputs)
    deps: list = field(default_factory=list)
    kind: str = "work"                             # set to an IRREVERSIBLE_KINDS value to gate
    max_attempts: int = 2                          # try + one isolated repair
    check_uses_deps: bool = False                  # True => check(output, dep_inputs)

    @property
    def irreversible(self) -> bool:
        return self.kind in IRREVERSIBLE_KINDS


@dataclass
class Result:
    status: str = PENDING
    output: Any = None
    errors: list = field(default_factory=list)
    attempts: int = 0


class GraphError(ValueError):
    pass


class LoopGate:
    def __init__(self, units, signatures=None, max_workers=4, log=None):
        self.units = {u.id: u for u in units}
        if len(self.units) != len(units):
            raise GraphError("duplicate unit id")
        self.signatures = set(signatures or ())   # signatures == human GO (unit ids a human approved)
        self.max_workers = max_workers
        self.log = log if log is not None else []
        self._validate()

    def _validate(self):
        for u in self.units.values():
            for d in u.deps:
                if d not in self.units:
                    raise GraphError(f"{u.id}: unknown dep {d}")
        seen, stack = set(), set()
        def visit(n):
            if n in stack: raise GraphError(f"cycle at {n}")
            if n in seen: return
            stack.add(n); [visit(d) for d in self.units[n].deps]; stack.discard(n); seen.add(n)
        for n in self.units: visit(n)

    def _event(self, unit, status, **kw):
        self.log.append({"t": time.time(), "unit": unit, "status": status, **kw})

    def _attempt(self, u: Unit, inputs: dict) -> Result:
        r, last = Result(), None
        while r.attempts < u.max_attempts:
            r.attempts += 1
            try:
                out = u.run(inputs, last)
                u.check(out, inputs) if u.check_uses_deps else u.check(out)
                r.status, r.output = ACCEPTED, out
                self._event(u.id, ACCEPTED, attempt=r.attempts)
                return r
            except Exception as e:  # check or run failure
                err = f"{type(e).__name__}: {e}"
                r.errors.append(err)
                self._event(u.id, FAILED, attempt=r.attempts, error=err)
                if last is not None and err == last:
                    r.status = ESCALATED  # same error twice -> stop and report
                    self._event(u.id, ESCALATED, reason="same error twice")
                    return r
                last = err
        r.status = ESCALATED
        self._event(u.id, ESCALATED, reason="attempts exhausted")
        return r

    def run(self) -> dict:
        """Execute in dependency waves; each wave's ready units fan out in parallel."""
        results = {n: Result() for n in self.units}
        remaining = set(self.units)
        with cf.ThreadPoolExecutor(self.max_workers) as pool:
            while remaining:
                ready = []
                for n in sorted(remaining):
                    u = self.units[n]
                    dst = [results[d].status for d in u.deps]
                    if any(s not in (PENDING, ACCEPTED) for s in dst):
                        results[n].status = BLOCKED; self._event(n, BLOCKED)
                    elif all(s == ACCEPTED for s in dst):
                        if u.irreversible and n not in self.signatures:
                            results[n].status = AWAITING_SIGNATURE
                            self._event(n, AWAITING_SIGNATURE, kind=u.kind)
                        else:
                            ready.append(n)
                remaining -= {n for n in remaining if results[n].status != PENDING}
                if not ready:
                    if remaining:
                        raise GraphError("stalled graph")  # unreachable after _validate
                    break
                futs = {pool.submit(self._attempt, self.units[n],
                                    {d: results[d].output for d in self.units[n].deps}): n
                        for n in ready}
                for f in cf.as_completed(futs):
                    n = futs[f]; results[n] = f.result(); remaining.discard(n)
        return results

    @staticmethod
    def report(results: dict) -> dict:
        out = {}
        for n, r in results.items():
            out.setdefault(r.status, []).append(n)
        return out


def summarize(results: dict) -> str:
    return json.dumps(LoopGate.report(results), sort_keys=True)
