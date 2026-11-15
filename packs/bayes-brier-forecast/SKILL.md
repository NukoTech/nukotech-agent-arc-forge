---
name: bayes-brier-forecast
description: >-
  Log forecasts before outcomes, update them with odds and likelihood ratios,
  handle correlated evidence, and score with Brier using a simple forecast ledger.
  Use whenever someone wants a probability on a counterparty's next move.
---
# Bayes and Brier forecasting 

Math rules
- Start from a base rate or an explicit prior. Posterior odds = prior odds times likelihood ratio. Never invent a likelihood; with no inputs, update qualitatively and test sensitivity to plausible priors.
- Correlated cues and repeated reports from one source are not independent. Use a justified conditional or joint model, or count them once. Check missingness, confounding and selection bias.
- A p-value is about data under a null, not the probability that a person is deceptive. Report effect size and uncertainty; watch multiple testing. Continuous probability is density integrals; use CDFs for thresholds. Regression needs suitable data and a defined target; prefer QR or SVD to explicit inversion. Similarity is not intent or causation.

Ledger tool
- Keep a forecast ledger (CSV or SQLite) with: id, claim, probability, date logged, resolution date, outcome, Brier score. Log before the outcome is known; never edit a logged probability, add a revision row instead.
- Before touching any v1.0 database, follow $PACK/UPGRADE.md: preserve a closed pre-upgrade copy, then verify, export, backup with v1.1. Never run v1.0 and v1.1 against the same database. v1.0 rows become legacy_unverified and are excluded from scoring.
- Exports and backups refuse to overwrite; always use new filenames. Run verify after writes.

Case contract (real use)
- record_type: prospective (scored), retrospective or synthetic (kept, never scored). Pseudonymous case ID, nonblank authorization, leading, competing and benign hypotheses.
- Each forecast: forecast_id, observable event, offset-aware deadline (e.g. 2026-11-01T15:00:00-06:00), numeric probability, probability_basis (subjective or empirical), resolution_rule, resolution_type, outcome_status, update_trigger. Prospective requires outcome_status unknown and registration before the deadline and before any positive event.
- resolution_type by_deadline: positive needs --event-at (strictly after registration, at or before deadline) plus --at; negative needs --at at or after the deadline, no --event-at. at_deadline: resolve at or after the deadline, no --event-at. --evidence and --resolver are mandatory. No future-dated times.
- Absence of evidence is not a negative. Unresolved stays unresolved. A positive after the window does not count.

Revisions
- Plain notes: revise --note (never changes probability or outcome). Outcome corrections are notes, not overwrites.
- Probability update: revise --probability P --probability-basis --evidence-cutoff ISO --outcome-status unknown --note reason. Not allowed after deadline or resolution. Revisions at or after the positive event are excluded from latest scoring.

Scoring
- Default score uses ORIGINAL probabilities; --version latest is the latest eligible pre-outcome version. Pick the policy before looking at outcomes; never cherry-pick.
- Brier = mean of (p minus outcome) squared. Denominator is eligible_resolved, never resolved. Report eligible_resolved, excluded counts with reasons, misses, false alarms, drift, and the constant-0.5 comparator. The in-sample event-rate comparator is not an out-of-sample baseline. Claim improvement only when measured outcomes support it.
- Ledger is plaintext SQLite with no encryption or tamper-proofing; keep it on the box, no real personal data in examples.
