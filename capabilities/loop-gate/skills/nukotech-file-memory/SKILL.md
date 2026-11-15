---
name: nukotech-file-memory
description: Use when an agent needs to remember durable facts across sessions, or recall them, using dated markdown files with write, consolidate, recall, and apply steps.
---
# File Memory
- **Write** one fact per file under `memory/{profile,preferences,topics,projects}/`, with date, key, and source. Only store facts that will matter later. Never store secrets.
- **Consolidate** regularly: dedupe identical facts, supersede an older fact with the same key, forget on request or when topics expire. Tombstone; don't delete. On shared memory, produce a dry-run plan and submit it as a proposal for review instead of applying it.
- **Recall** on demand with a keyword (BM25) query scoped to the current task. Don't load all memory.
- **Apply**: inject only the top-k recalled facts within a character budget, cite category/key/date, and prefer the newest active fact.
Reference: `file_memory/file_memory.py` (stdlib).
