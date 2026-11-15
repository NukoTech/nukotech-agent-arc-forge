"""Task-packet format for tasking agents through Loop Gate (stdlib only).

Packet (JSON):
{ "unit_id": "intake.request.001", "goal": "...", "owner_bot": "Intake Agent",
  "loop_stage": "data_entry|verification|prediction|execution|report",
  "inputs": {...}, "deps": ["..."],
  "check": {"type": "required_keys|nonempty|equals|range|all", ...},
  "irreversible": false, "irreversible_reason": "",   # true => needs human GO
  "max_attempts": 2 }                                  # retry once, then escalate
"""
from __future__ import annotations
import json
from .loop_gate import Unit

STAGES = ("data_entry", "verification", "prediction", "execution", "report")
# Guard terms, not business data: unit names that mean an irreversible money or release action.
# Any unit whose name contains one is held for the owner's GO; it never runs on its own.
MONEY_WORDS = ("invoice_send", "po_issue", "payroll", "payment", "send", "merge", "deploy")
REQUIRED = ("unit_id", "goal", "owner_bot", "loop_stage", "inputs", "deps", "check", "irreversible")


class PacketError(ValueError):
    pass


def _get(obj, path):
    for part in path.split("."):
        obj = obj[part] if isinstance(obj, dict) else obj[int(part)]
    return obj


def _uses_deps(spec):
    return spec.get("type") == "from_deps" or any(_uses_deps(c) for c in spec.get("checks", []))


def compile_check(spec: dict):
    """Returns check(output, deps). `equals` compares two paths in ONE output dict;
    `from_deps` compares an output path to a path in a dependency's output:
    {"type":"from_deps","field":"due","dep":"intake.request.001","dep_field":"due"}."""
    t = spec.get("type")
    if t == "from_deps":
        f, dep, df, tol = spec["field"], spec["dep"], spec.get("dep_field", spec["field"]), spec.get("tolerance", 0)
        def c(out, deps=None):
            assert deps and dep in deps, f"dep {dep} output not available"
            l, r = _get(out, f), _get(deps[dep], df)
            ok = abs(l - r) <= tol if isinstance(l, (int, float)) and isinstance(r, (int, float)) else l == r
            assert ok, f"{f}={l} != {dep}.{df}={r}"
        return c
    if t == "required_keys":
        keys = spec["keys"]
        def c(out, deps=None):
            missing = [k for k in keys if not isinstance(out, dict) or k not in out]
            assert not missing, f"missing keys {missing}"
    elif t == "nonempty":
        f = spec["field"]
        def c(out, deps=None):
            assert _get(out, f), f"{f} empty"
    elif t == "equals":
        a, b = spec["left"], spec["right"]
        tol = spec.get("tolerance", 0)
        def c(out, deps=None):
            l, r = _get(out, a), _get(out, b)
            assert abs(l - r) <= tol if isinstance(l, (int, float)) else l == r, f"{a}={l} != {b}={r}"
    elif t == "range":
        f, lo, hi = spec["field"], spec.get("min"), spec.get("max")
        def c(out, deps=None):
            v = _get(out, f)
            assert (lo is None or v >= lo) and (hi is None or v <= hi), f"{f}={v} outside [{lo},{hi}]"
    elif t == "all":
        subs = [compile_check(s) for s in spec["checks"]]
        def c(out, deps=None):
            for s in subs: s(out, deps)
    else:
        raise PacketError(f"unknown check type {t!r}")
    return c


def validate_packet(p: dict):
    missing = [k for k in REQUIRED if k not in p]
    if missing: raise PacketError(f"{p.get('unit_id')}: missing {missing}")
    if p["loop_stage"] not in STAGES: raise PacketError(f"{p['unit_id']}: bad stage")
    compile_check(p["check"])  # every unit must have a fail-able check
    if _uses_deps(p["check"]) and p["check"].get("dep") not in p["deps"] and p["check"].get("type") == "from_deps":
        raise PacketError(f"{p['unit_id']}: from_deps dep must be listed in deps")
    if any(w in p["unit_id"] for w in MONEY_WORDS) and p["irreversible"] is not True:
        raise PacketError(f"{p['unit_id']}: money/send step must be irreversible=true (human GO)")


def load_packets(path_or_list):
    if isinstance(path_or_list, str):
        with open(path_or_list, encoding="utf-8") as fh:
            ps = json.load(fh)
    else:
        ps = path_or_list
    for p in ps: validate_packet(p)
    return ps


def to_units(packets, handlers: dict):
    """handlers: owner_bot -> callable(packet, dep_outputs, last_error) -> output."""
    units = []
    for p in packets:
        h = handlers[p["owner_bot"]]
        units.append(Unit(id=p["unit_id"], deps=list(p["deps"]),
                          run=(lambda inp, err, p=p, h=h: h(p, inp, err)),
                          check=compile_check(p["check"]), check_uses_deps=True,
                          kind="money" if p["irreversible"] else "work",
                          max_attempts=p.get("max_attempts", 2)))
    return units
