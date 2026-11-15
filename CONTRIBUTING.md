# Contributing to NukoTech Agent Arc Forge

Thank you for contributing. This repository is PR-only: do not push to `main`. Open a pull request from a branch named for the area you are changing, and wait for the maintainer to merge after the required gates pass.

## Developer Certificate of Origin (DCO 1.1)

Every commit must be signed off with a `Signed-off-by:` line. That sign-off certifies that you agree to the Developer Certificate of Origin, version 1.1:

<https://developercertificate.org/>

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

Add the trailer with `git commit -s`, or append a `Signed-off-by:` line whose name matches the commit author and whose contact is your GitHub noreply identity (not a personal mailbox).

## GitHub noreply commit emails

Use the private GitHub-provided noreply identity as the commit author. Do not use a personal mailbox.

GitHub documents this identity under email settings as the option to keep your email private. Prefer the form that includes your numeric user id. Keep that identity consistent across commits on a pull request. Commits authored with a personal mailbox will fail the personal-email author gate.

## Branch-per-area naming

Name branches after the area of the tree they change, then a short slug:

```
<area>/<short-description>
```

Use the top-level directory as the area when the work lives there:

| Area | Branch prefix | Typical paths |
| --- | --- | --- |
| Arc Forge | `arc/` | `arc/` |
| NukoTech HiveMind | `hivemind/` | `hivemind/` |
| Packs | `packs/` | `packs/` |
| Capabilities | `capabilities/` | `capabilities/` |
| Demo | `demo/` | `demo/` |
| Docs | `docs/` | `docs/` |
| Community / legal hygiene | `hygiene/` | `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `NOTICE`, `TRADEMARKS.md` |
| GitHub config | `ci/` | `.github/` (except files owned by other tracks) |

Examples: `arc/composer-skeleton`, `hivemind/hive-layout`, `hygiene/community-files`.

Keep one area per branch. Cross-cutting work should still pick the primary area, or split into separate pull requests.

## PR-only workflow

1. Fork or clone, create a branch as above, and commit with DCO sign-off and a GitHub noreply author email.
2. Open a pull request against `main`. Nobody pushes to `main` directly.
3. The maintainer is the only person who merges, and only after the gates pass:
   - tests
   - gitleaks
   - license check
   - demo job
   - internal denylist scan
   - no personal-email commit authors
4. Secret-backed checks (`denylist` and `author-email`) do not receive repository secrets on pull requests from forks. Those jobs report as skipped on a fork PR (`Fork PR: secret-backed check skipped; a maintainer must re-run before merge`). A maintainer must re-run them from a same-repository branch, where secrets are available, before merge. Missing or invalid secrets still fail closed on same-repository pull requests and on push to `main`.
5. Do not request a merge, force-push to `main`, or bypass the gates.

## Security reports

Report security issues according to [SECURITY.md](SECURITY.md). Do not open a public issue for a vulnerability.

## License and trademarks

Contributions are offered under the project's license. The code license does not grant trademark rights. See [TRADEMARKS.md](TRADEMARKS.md) and [NOTICE](NOTICE).
