"""NukoTech File Memory: durable agent memory as dated markdown facts (stdlib only).

Layout: <root>/memory/{profile,preferences,topics,projects}/<slug>.md
Each fact file = frontmatter + body. Lifecycle: write -> consolidate (dedupe,
supersede, forget) -> recall (BM25) -> apply. Consolidation emits a plan that
callers can route proposals through their own signed review/promotion path.
"""
from __future__ import annotations
import datetime as dt, hashlib, math, re
from collections import Counter
from pathlib import Path

CATEGORIES = ("profile", "preferences", "topics", "projects")
_TOK = re.compile(r"[a-z0-9]+")
STOP = set("the a an and or of to in on for is are was be with at by it this that as".split())


def tokens(text):
    return [t for t in _TOK.findall(text.lower()) if t not in STOP]


def _norm(text):
    return " ".join(tokens(text))


def fact_id(category, key):
    return hashlib.sha1(f"{category}:{key}".encode()).hexdigest()[:12]


class Fact:
    def __init__(self, category, key, text, date=None, status="active", source="", superseded_by="", path=None):
        if category not in CATEGORIES: raise ValueError(f"bad category {category}")
        self.category, self.key, self.text = category, key, text.strip()
        self.date = date or dt.date.today().isoformat()
        self.status, self.source, self.superseded_by, self.path = status, source, superseded_by, path

    @property
    def id(self):
        return fact_id(self.category, self.key) + "-" + hashlib.sha1(self.text.encode()).hexdigest()[:6]

    def to_md(self):
        fm = {"id": self.id, "category": self.category, "key": self.key, "date": self.date,
              "status": self.status, "source": self.source, "superseded_by": self.superseded_by}
        return "---\n" + "".join(f"{k}: {v}\n" for k, v in fm.items()) + "---\n" + self.text + "\n"

    @classmethod
    def from_md(cls, raw, path=None):
        m = re.match(r"---\n(.*?)\n---\n(.*)", raw, re.S)
        if not m: raise ValueError(f"no frontmatter in {path}")
        fm = dict(l.split(": ", 1) if ": " in l else (l.rstrip(":"), "") for l in m.group(1).splitlines())
        return cls(fm["category"], fm["key"], m.group(2), fm.get("date"), fm.get("status", "active"),
                   fm.get("source", ""), fm.get("superseded_by", ""), path)


class FileMemory:
    def __init__(self, root):
        self.root = Path(root) / "memory"
        for c in CATEGORIES: (self.root / c).mkdir(parents=True, exist_ok=True)

    # ---- write ----
    def write(self, category, key, text, source="", date=None):
        f = Fact(category, key, text, date=date, source=source)
        p = self.root / category / f"{f.date}_{re.sub(r'[^a-z0-9]+', '-', key.lower())}_{f.id[-6:]}.md"
        if p.exists():
            return Fact.from_md(p.read_text(), p)
        p.write_text(f.to_md()); f.path = p
        return f

    def all(self, include_inactive=False):
        out = []
        for p in sorted(self.root.glob("*/*.md")):
            f = Fact.from_md(p.read_text(), p)
            if include_inactive or f.status == "active": out.append(f)
        return out

    # ---- consolidate ----
    def consolidate(self, forget_keys=(), max_age_days=None, today=None, apply=True):
        """Dedupe identical text, supersede older facts with the same key, forget requested/expired.
        Returns plan list of {action, id, path, reason}. apply=False => dry-run (proposal only)."""
        today = dt.date.fromisoformat(today) if today else dt.date.today()
        plan, by_key, seen_text = [], {}, {}
        for f in sorted(self.all(), key=lambda f: (f.date, str(f.path))):
            n = (f.category, _norm(f.text))
            if n in seen_text:
                plan.append({"action": "dedupe", "fact": f, "reason": f"duplicate of {seen_text[n].id}"}); continue
            seen_text[n] = f
            by_key.setdefault((f.category, f.key), []).append(f)
        for (_, key), fs in by_key.items():
            for old in fs[:-1]:
                plan.append({"action": "supersede", "fact": old, "by": fs[-1].id, "reason": f"newer fact for {key}"})
            for f in fs:
                if key in forget_keys:
                    plan.append({"action": "forget", "fact": f, "reason": "explicit forget"})
                elif max_age_days and (today - dt.date.fromisoformat(f.date)).days > max_age_days and f.category == "topics":
                    plan.append({"action": "forget", "fact": f, "reason": "expired topic"})
        if apply:
            for item in plan:
                f = item["fact"]
                f.status = {"dedupe": "duplicate", "supersede": "superseded", "forget": "forgotten"}[item["action"]]
                f.superseded_by = item.get("by", f.superseded_by)
                f.path.write_text(f.to_md())   # tombstone, never hard-delete
        return [{"action": i["action"], "id": i["fact"].id, "path": str(i["fact"].path), "reason": i["reason"]} for i in plan]

    # ---- recall (BM25) ----
    def recall(self, query, k=5, category=None, k1=1.5, b=0.75):
        docs = [f for f in self.all() if category in (None, f.category)]
        if not docs: return []
        toks = [tokens(f.key + " " + f.text) for f in docs]
        N, avg = len(docs), sum(map(len, toks)) / len(docs)
        df = Counter(t for ts in toks for t in set(ts))
        q = tokens(query); scored = []
        for f, ts in zip(docs, toks):
            tf, s = Counter(ts), 0.0
            for t in q:
                if t not in tf: continue
                idf = math.log(1 + (N - df[t] + 0.5) / (df[t] + 0.5))
                s += idf * tf[t] * (k1 + 1) / (tf[t] + k1 * (1 - b + b * len(ts) / avg))
            if s > 0: scored.append((s, f))
        scored.sort(key=lambda x: (-x[0], x[1].date))
        return [f for _, f in scored[:k]]

    # ---- apply ----
    def apply_context(self, query, k=5, budget_chars=2000):
        lines, used = [], 0
        for f in self.recall(query, k):
            line = f"- [{f.category}/{f.key} @ {f.date}] {f.text}"
            if used + len(line) > budget_chars: break
            lines.append(line); used += len(line)
        return "## Recalled memory\n" + "\n".join(lines) if lines else ""
