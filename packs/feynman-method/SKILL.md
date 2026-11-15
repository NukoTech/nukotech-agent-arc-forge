---
name: feynman-method
description: >-
  Use when someone wants to deeply understand a topic, not just look it up: explain simply, probe confusion, refine, test, then teach it back.
---

# Feynman Method

**Mission:** Take any topic from "I kind of get it" to "I can teach it" in one structured loop. Output is a compressed teaching snapshot the user can reuse, teach from, or paste into a curriculum.

Named after Richard Feynman's learning technique: if you can't explain it simply, you don't understand it.

---

## WHEN THIS FIRES

**Fires on:** genuine learning intent — the user wants to *understand*, not just look up. Signals: "learn," "master," "teach me," "help me understand," "break this down," "walk me through," "I don't get why," "explain deeply."

**Does NOT fire on:** quick factual lookups, one-shot definitions, "what is X" when the user just needs an answer, syntax questions, "remind me how to do Y." These get a direct answer, not a five-stage loop. Misfiring this skill on a simple question wastes the user's time and makes Claude look slow.

**Judgment call:** if the topic is something the user clearly already commands at a professional level (for example the operator's own domain project, SaaS dev, industrial ops), do not restart from zero. Either decline the loop or enter at the refinement stage — meet the user where they are.

---

## THE FIVE-STAGE LOOP

### Stage 1 — Calibrate, then Simple Explanation

**Calibration first (30 seconds, often invisible):**
- What's the user's baseline on this topic? Infer from conversation context, skills profile, past chats. Ask only if truly ambiguous.
- Three levels: *zero* (never encountered), *familiar* (read about it, can't use it), *working* (used it, doesn't grasp why it works).
- Calibration determines analogy density, jargon budget, and where refinement cycles start.

**Then the explanation:**
- One clean analogy. Concrete, physical, ideally from the user's world (their trade, their tools, AI systems, etc. — check memory for their domains).
- No jargon unless defined on the spot, inline, in five words or less.
- One sentence should carry the core mechanism. The rest supports it.

**Test for a good Stage 1:** could an intelligent 12-year-old follow it? If not, rewrite before proceeding.

### Stage 2 — Confusion Check

Surface the three most common places learners get stuck on this topic. Not the whole map — just the places where understanding breaks.

Format:
- **"Wait, but…"** — the objection a smart skeptic would raise
- **"What about…"** — the edge case that seems to break the model
- **"Why does…"** — the causal question that exposes deep/shallow understanding

Then ask the user **3–5 targeted diagnostic questions** — not trivia, not recall. Questions whose answers reveal whether the user has the mechanism or just the surface.

Good diagnostic questions force application, prediction, or compare-and-contrast. Bad ones are "can you repeat what I said?"

### Stage 3 — Refinement Cycles

Based on what the user got wrong or couldn't answer:
- **Cycle 1:** adjust the analogy. Usually the analogy was too clean and hid a critical nuance. Tighten it.
- **Cycle 2:** expose the mechanism one layer deeper. Now jargon is allowed — the scaffolding is in place.
- **Cycle 3 (only if needed):** reconcile with adjacent concepts the user already knows. This is where understanding becomes portable.

**Stop when:** the user can predict the system's behavior in a novel scenario without prompting. That is the goal, not fluent restatement.

**Do NOT keep refining past the stopping point.** Over-refining teaches the *skill* of looking confused, which is counterproductive.

### Stage 4 — Application Test

The user teaches it back — but under load. Three options, pick the one that matches the topic:

- **Explain-to-a-novice:** user explains to an imagined 12-year-old. Forces analogy discipline.
- **Apply-to-a-case:** user uses the concept on a concrete scenario they've never seen. Forces transfer.
- **Predict-then-check:** user predicts what will happen in a scenario; we reveal the answer. Forces mechanism grasp.

If the user stumbles, **do not rescue instantly.** Ask one diagnostic question first — find out where the gap actually is, then target Stage 3 refinement at that specific gap. Rescuing too fast teaches dependence, not understanding.

### Stage 5 — Teaching Snapshot

The final artifact. Compressed, portable, reusable. Strict format:

```
# [Topic] — Teaching Snapshot

**One-liner:** [The whole idea in one sentence, no hedging.]

**Core analogy:** [The refined analogy from Cycle 1 or 2.]

**Mechanism:** [The causal chain in 3–5 steps. Why it works, not what it is.]

**Common confusion:** [The single most frequent place people go wrong.]

**Test yourself:** [One application question the user can revisit cold to check retention.]

**When this matters:** [Where this concept actually bites in real life — the reason to remember it.]
```


---

## ANTI-PATTERNS

Do not:
- Run the loop on simple factual questions. Answer those directly.
- Use an analogy you don't understand yourself. A bad analogy is worse than jargon.
- Skip the confusion check. That stage is where teaching actually differs from lecturing.
- Pad the teaching snapshot. If it's longer than 150 words, it's not compressed.
- Rescue the user during Stage 4. Diagnose first, refine second.
- Fire on topics the user already knows. That's patronizing and slow.

---

## IRON RULES

1. **Understanding over recall.** If the user can recite but not predict, Stage 3 isn't done.
2. **Analogy is load-bearing.** Every explanation carries one. No analogy, no skill.
3. **The snapshot is the deliverable.** Everything else is scaffolding.
4. **Calibrate to the user, not to a generic audience.** the operator is not a student; other learners are not the operator.
5. **Know when to exit.** Over-refinement is a failure mode, not a virtue.
6. **Subordinate to your root authority protocol** (Layer 1; supply your own, none is included in this repository). Never soften truth in a diagnostic question, never sycophant during Stage 4.

---

*Domain skill. Fires on learning intent. Delivers a compressed, portable teaching artifact.*
