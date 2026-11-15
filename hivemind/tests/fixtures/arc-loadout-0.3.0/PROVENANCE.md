# Arc golden fixture provenance

Generated locally by the unchanged Agent Arc `0.3.0-alpha.1` composer at
`45c46b16da46e2a59f107c6dbede3039d975c68f`. Source example:
`examples/marketing-operator`, first-party NUKO draft-only component, MIT.

No ZIP archives are checked in. The plain package members live in
`package-src/marketing-operator-<version>/`. At test time,
`tests/arc_loadout_fixture.py` rebuilds each package deterministically: sorted
members, DEFLATE, fixed 1980-01-01 timestamps, Unix mode 0644, no comments or
extra fields. The rebuilt archives are byte-identical to the composer output, so
the package pins are unchanged.

Original recipe 1.0.0 package:
`ddf4e9cfd68f04b4cf18cf3c0fcb9920076da6db29f0f09c92adebf2974948b0`.

`upgrade/` was generated from an isolated copy changing only the recipe version to
1.0.1, leaving component bytes unchanged:
`4e5ee8adff84fcbb567d33028d0fc9b6fd2dbb76a03a423b82a121f3b134e0a0`.

No credentials, user documents, agent runtime, or fleet activation are present.
The adjacent SHA manifests are checksum evidence for the package members; they
are not signatures.
