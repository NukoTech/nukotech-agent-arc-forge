# Pinned SHAs for this repository's CI

All GitHub Action SHAs below were resolved with `gh api repos/<owner>/<repo>/tags?per_page=8` on Sat Nov 14, 2026 (America/Chicago). Each SHA is the commit the listed tag points at. Label: **VERIFIED**.

Required check job names (stable; please mark these required on the default branch):

- `arc-gates` (workflow `arc-gates`)
- `gitleaks` (workflow `security`)
- `license-check` (workflow `security`)
- `denylist` (workflow `security`)
- `denylist-tests` (workflow `security`)
- `author-email` (workflow `security`)

Additional jobs from workflow `ci` (do not duplicate the six jobs above):

- `tests (3.11)` and `tests (3.12)`
- `package`
- `demo`

Additional job from workflow `hivemind-tests` (every PR and push to main, because it is a required check; also nightly and workflow_dispatch):

- `hivemind-tests`

## Third-party GitHub Actions

| Action | Tag | Commit SHA | Status |
|--------|-----|------------|--------|
| `actions/checkout` | v7.0.1 (also current `v7`) | `3d3c42e5aac5ba805825da76410c181273ba90b1` | VERIFIED |
| `actions/setup-python` | v7.1.0 (also current `v7`) | `6d4fd22b20465ccc0f7354476588e8df7c9ca0e0` | VERIFIED |
| `fsfe/reuse-action` | v6.0.0 (also current `v6`) | `676e2d560c9a403aa252096d99fcab3e1132b0f5` | VERIFIED |
| `gitleaks/gitleaks-action` | v3.0.0 (also current `v3`) | `e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e` | VERIFIED, but **do not use as the required check** on a private org repo unless a `GITLEAKS_LICENSE` secret is in place. The v3 action requires a license for org/private repositories. The workflows pin the gitleaks **CLI binary** instead. |

No other third-party actions are used in these workflows.

Checkout is always invoked with `clean: true` and `persist-credentials: false`. Jobs that run Python from the repo root also refuse a top-level `build/` path, which can shadow the PyPA `build` package.

## gitleaks CLI binary (preferred scanner)

| Item | Value | Status |
|------|-------|--------|
| Release | v8.30.1, published 2026-03-21 02:17:58 UTC | VERIFIED via `gh api repos/gitleaks/gitleaks/releases/tags/v8.30.1` |
| Asset | `gitleaks_8.30.1_linux_x64.tar.gz` | VERIFIED |
| SHA-256 | `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb` | VERIFIED (GitHub release asset `digest` field) |
| URL | `https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz` | VERIFIED |

The `gitleaks` job calls `gitleaks detect --log-opts="--full-history --diff-filter=tuxdb HEAD"`. Without `--log-opts`, v8.30.1 defaults to `git log --full-history --all`, which with `fetch-depth: 0` scans every fetched branch. `HEAD` is the checked-out ref (the merge ref on a `pull_request`). The SHA-256 pin and `fetch-depth: 0` are unchanged.

## nukotech-agent-arc-gates pin

| Item | Value | Status |
|------|-------|--------|
| Public repo | `https://github.com/NukoTech/nukotech-agent-arc-gates` | VERIFIED |
| CI pin (only public commit) | `f4ff928378d46b1013a4c33f2ff443850a3dbd5b` | VERIFIED (`git rev-parse HEAD` of the review clone, and `gh api` commits: single commit "Initial public release", committer date 2026-11-13 00:43:59 UTC / Nov 12, 2026 6:43 PM CT) |
| Packaging | **None.** The public tree has no `pyproject.toml` or `setup.py` (VERIFIED via local tree and `gh api repos/NukoTech/nukotech-agent-arc-gates/contents`). `pip install "…@ git+…@f4ff928…"` will fail until packaging metadata is published. | VERIFIED |

**Recommendation:** keep CI on `f4ff928378d46b1013a4c33f2ff443850a3dbd5b` until a later genericized tree is published as a new public commit with a named GO, then re-pin that SHA. Do not vendor either tree into this repository.

## Denylist and author-email

- The denylist job reads rules from the `DENYLIST_PATTERNS_B64` repository Actions secret. Preferred rule format is `NAME<TAB>CLASS<TAB>regex` with `CLASS` in `{content, path, host, userpath}`. `NAME<TAB>regex` and plain regex lines still load, but a rule with no class cannot be excepted. The scanner never prints a rule body; hits report a rule name (or `rule-N` for unnamed lines), a path, and a line number. Line-hash exceptions live in `ci/denylist/allow.tsv` (`path`, `rule`, `line_sha256`, `reason`). Only `content`-classed rules may be excepted. The check must report 0 unexcepted hits and no stale, malformed, hash-mismatch, or wrong-rule entries. Local runs may pass `--patterns` pointing at a file outside the repository root. `--hash-line path:line` prints a line hash and matching rule names only.
- `denylist-tests` runs `pytest` against `ci/tests/` with synthetic patterns created at test time. It does not read the Actions secret.
- Banned commit author/committer emails are compared with HMAC-SHA256. The checker (`ci/scripts/author_email_check.py`) reads `ARCFORGE_AUTHOR_EMAIL_HMAC` (JSON: `v`, `alg`, `key_hex`, `digests`) and never prints a key, a digest, or an email. On pull requests it checks `base.sha..head.sha`; on push to `main` it checks full history. Missing or invalid configuration fails closed.

## Python tool pins (pip packages, not actions)

- `pytest==8.4.2` (matches Arc core's optional test extra; CI pins 8.4.2 for reproducibility)
- `setuptools==84.2.1` and `wheel==0.48.0` are pinned in the Arc `test` extra so `tests/test_install_uninstall.py` can run `pip wheel --no-build-isolation` in a clean `pip install -e .[test]` environment (current PyPI releases as of 2026-11-14; build-system already requires `setuptools>=77`).
- `build==1.6.1` — PyPA build frontend for the `package` job (current PyPI as of 2026-11-14)
- `pip-licenses==5.0.0` — confirm on PyPI before merge if a newer compatible release exists
- `reuse==6.2.0` — the REUSE *action* SHA above is verified. Enable `reuse lint` only after `REUSE.toml` / license headers exist in the new repo.
