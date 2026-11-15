# Hive Alpha release-artifact signing and verification policy

Status: `IMPLEMENTED FOR CANDIDATE PROOF / RELEASE HELD`

## Decision

Use Sigstore keyless blob signing issued from GitHub Actions OIDC. The signer identity is
the public release repository and the pinned release workflow, both bound at release.
No long-lived private signing key is
created, exported, stored on a build host, or placed in repository or CI secrets.

The artifact receives its own Sigstore bundle. A second signed checksum set binds its
embedded manifest and CycloneDX SBOM, exact source commit/tree receipt, and policy
checksum. The public transparency record exposes cryptographic digest and workflow
identity metadata, never the private artifact bytes. Candidate signing does not create a
release, tag, customer artifact, or production service.

The sanitized product wheel uses sorted, timestamp-zero, fixed-mode stored ZIP entries.
This removes zlib-version variability while preserving the alpha.1 canonical 38-file
product payload; the outer tarball remains compressed normally.

## Verification contract

`scripts/verify_release_attestation.py` requires all of the following:

1. Caller-provided expected artifact SHA-256 matches the local bytes.
2. An absolute, non-symlink Cosign 3.1.2 or newer matches the caller-pinned executable
   SHA-256 before it verifies the Sigstore bundle and transparency-log witness.
3. OIDC issuer is `https://token.actions.githubusercontent.com`.
4. Repository, signer repository, signer workflow, source ref, and source commit match.
5. Workflow name, trigger, ref, and exact source commit certificate extensions match.
6. The signer runs on the pinned GitHub-hosted workflow; self-hosted signing is absent.
7. A safe local ledger atomically consumes the claim ID and bundle fingerprint
   once. A repeated claim or bundle is a replay, not a success.

Release verification additionally requires a separately authorized immutable tag and
must substitute that exact tag ref in the reviewed policy before generation. This
milestone does not create or approve such a tag.

## Mandatory negative cases

The retained proof runner checks a valid acceptance followed by rejection of:

- modified artifact bytes;
- a mismatched expected digest;
- a signer/repository identity substituted with `example-org/unrelated-repo`;
- an unsigned artifact;
- reuse of the already consumed signature bundle under a different claim ID.

Any verification-tool error, missing signature bundle, mismatched subject digest, unsafe ledger
path, malformed policy, or unsupported CLI version is a refusal with nonzero status.

## Custody and rollback

GitHub holds the OIDC identity; Sigstore holds public issuance/transparency
infrastructure. The project retains the artifact,
downloaded bundle, source and tree IDs, checksums, policy, workflow pin, and replay
receipt. Rollback is a source/ref decision; a prior artifact remains independently
verifiable by its own digest and signature bundle. No verifier may treat a valid signature as
authorization to merge, tag, release, install, or route production traffic.
