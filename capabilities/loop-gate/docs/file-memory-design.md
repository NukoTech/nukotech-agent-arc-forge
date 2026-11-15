# NukoTech File Memory: design
Sources: @AnnatarXBT, Cyril article (x.com/i/article/2104042878343208960). Mem0 used as a conceptual reference only: no Mem0 cloud, no Mem0 code.

## Model
`memory/{profile,preferences,topics,projects}/<date>_<key>_<hash>.md`, each file with frontmatter (id, category, key, date, status, source, superseded_by) and a one-fact body.
- **write**: idempotent. The same category+key+text gives the same file.
- **consolidate**: *dedupe* (normalized text), *supersede* (an older fact with the same key is replaced by the newest), *forget* (explicit keys; `topics` older than max_age_days). Facts are tombstoned via status, never hard-deleted. `apply=False` gives a dry-run plan.
- **recall**: BM25 over key+text of active facts, optionally filtered by category. Local embeddings are a later add-on behind the same `recall()` signature.
- **apply**: `apply_context(query)` builds a budgeted "Recalled memory" block for the prompt.

