---
name: quantitative-rigor-protocol
description: >-
  Use before accepting any quantitative claim: check units, magnitude, base rates, distribution, independence, sample size, and sensitivity.
---
# QUANTITATIVE RIGOR PROTOCOL

Mathematical verification layer and applied foundations for all systems. Numbers don't have feelings. They're right or wrong.

## Verification Checklist

Before accepting any quantitative claim:

1. **Dimensional Analysis** — Do the units work out?
2. **Order of Magnitude** — Is it in the right ballpark?
3. **Base Rate** — What's typical for this kind of outcome?
4. **Distribution** — Is the assumed distribution appropriate? (Normal ≠ always correct)
5. **Independence** — Are "independent" inputs actually correlated?
6. **Sample Size** — Is there enough data to support the claim?
7. **Sensitivity** — How fragile is the conclusion to input changes?

## Applied Math Quick Reference

**Rates of Change:** Derivative (price velocity, learning rate), Chain Rule (backpropagation, cascading risk), Taylor Series (options Greeks, function approximation).

**Optimization:** Gradient ∇f (direction of improvement), Hessian H (curvature — peak, valley, or saddle?).

**Linear Algebra:** Dot Product a·b (attention, correlation), Eigenvalues Av=λv (factor analysis, PCA), SVD A=UΣVᵀ (compression, LoRA fine-tuning).

**Probability:** Bayes P(A|B)=P(B|A)P(A)/P(B) (belief updating), Independence P(A∩B)=P(A)P(B) (test before assuming), PDF/CDF (risk quantiles, VaR).

**Statistics:** CLT (averages converge to normal), OLS β̂=(XᵀX)⁻¹Xᵀy (best fit), Hypothesis Testing (signal vs noise — check p-value).

## Red Flags

- Normal distributions assumed for tail events
- Linear trends extrapolated indefinitely
- Correlation treated as causation
- Multiple comparisons without correction
- Precision without accuracy (projecting to the penny with ±20% uncertainty)
- Survivorship bias (only studying winners)
- Overfitting (perfect on training data, no holdout test)

## The Rule

Math doesn't negotiate. Verify it, respect it, but also know its limits. Models approximate reality — they don't replace judgment.
