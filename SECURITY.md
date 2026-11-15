# Security policy

This policy covers **nukotech-agent-arc** (Python package `nukotech_agent_arc`, modules `nukotech.agent_arc.*`) and the other components shipped in this repository: the local HiveMind vault (`nukotech-hive-local`), hash-pinned packs and gates, capabilities, and the documented demo.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting. In this repository, open the **Security** tab and choose **Report a vulnerability**.

Do not open a public issue, pull request, or discussion for a security vulnerability.

In the report, include:

- The affected component (composer, local vault, pack or gate validation, loopback operator UI, or CI)
- A reproduction that does not include live secrets or anyone else's data
- The impact as you understand it

Do not send production credentials, customer data, or material from products that are not part of this repository.

## Supported versions

Security updates are considered for the code on the default branch of this repository, including the current pre-release of nukotech-agent-arc (0.3.0a1) and nukotech-hive-local (0.1.0). Older snapshots and unofficial forks are not supported.

## What you can expect

We will acknowledge reports submitted through private vulnerability reporting within five business days, and will tell you when a fix is available or if we need more information.

If we confirm a vulnerability, we will work on a fix and credit reporters who want to be credited, unless they prefer to remain anonymous.

## Scope

**In scope**

- The composer: recipes, registries, authorization envelopes, hash-pinned components, packaging, and composition or refusal receipts
- Pack and gate handling used at compose time, including skill import into a pinned registry component
- The local HiveMind vault: import, retrieval, optional loopback model server, snapshot, rollback, portable export, and the loopback operator UI
- Protocol and product signatures, key handling, and the credential guard described below
- Continuous integration in this repository (tests and the security workflows)

**Out of scope**

- Products, services, or trees that are not part of this repository
- Vulnerabilities in third-party dependencies (please report those to the upstream project)
- Social engineering, physical access, or attacks on accounts and infrastructure you do not own
- Denial-of-service or resource-exhaustion findings against systems you do not operate
- Reports that require access to someone else's data, secrets, or machines

## Safe harbor

Good-faith security research conducted in accordance with this policy is welcome.

When you conduct vulnerability research according to this policy, we consider that research to be:

- Authorized concerning any applicable anti-hacking laws (including the U.S. Computer Fraud and Abuse Act and similar laws), and we will not initiate or support legal action against you for accidental, good-faith violations of this policy;
- Authorized concerning any relevant anti-circumvention laws (including the U.S. Digital Millennium Copyright Act and similar laws), and we will not bring a claim against you for circumvention of technology controls;
- Exempt from restrictions in any Terms of Service or Acceptable Use Policy we publish that would interfere with conducting security research, and we waive those restrictions on a limited basis for research under this policy; and
- Lawful, helpful to the overall security of the Internet, and conducted in good faith.

You are expected to:

- Use GitHub private vulnerability reporting, not public channels, for vulnerability details
- Avoid accessing, modifying, or exfiltrating data that is not yours
- Avoid degrading or disrupting any service you do not operate
- Stop immediately if you encounter someone else's data or a live secret, and include only what is needed to demonstrate the issue
- Not demand payment or use a finding to pressure a third party

You are expected, as always, to comply with all applicable laws. If legal action is initiated by a third party against you and you have complied with this policy, we will take steps to make it known that your actions were conducted in compliance with this policy.

If at any time you have concerns or are uncertain whether your security research is consistent with this policy, please submit a report through GitHub private vulnerability reporting before going any further.

This Safe Harbor applies only to legal claims under the control of Nuko Technologies LLC. It does not bind independent third parties. It does not authorize access to systems, data, or accounts you do not own, and it does not limit our ability to respond to activity that is not good-faith research.

## What this project is, and what refusal is

nukotech-agent-arc composes a hash-pinned agent architecture from a recipe, a registry, and an authorization envelope, then writes a package and a receipt — or refuses and writes a refusal receipt. HiveMind is a local vault: import documents, retrieve or ask (optionally via a local model server on loopback), take a snapshot, roll back, and export.

**Refusal is a policy check, not a sandbox.** The default local policy provider compares requested capabilities and side effects to an operator-supplied authorization envelope and denies on provenance or authorization gaps. A denied recipe writes no package. That check does not isolate, containerize, or syscall-restrict a later agent runtime. HiveMind's capability and web checks similarly enforce policy and request shape; they do not sandbox imported documents or the optional local model process.

## Security properties

These properties are implemented in the current default branch:

- **Ed25519 signatures, fail-closed verification.** Protocol documents, product and cognition receipts, portable export manifests, and snapshot checkpoints can be signed with Ed25519. Verification fails closed on a missing, malformed, unknown-key, or invalid signature when a signature is required. nukotech-agent-arc can attach an optional detached Ed25519 signature over a package manifest and composition receipt; verification of that signature is fail-closed.
- **Full SHA-256 key identifiers.** Public keys are identified as `ed25519:` followed by the SHA-256 digest of the raw public key. Verification accepts the full identifier and, where existing documents still use a truncated form, an equivalent trusted key.
- **Constant-time digest comparison.** Signature, manifest, session, CSRF, and bearer comparisons use `compare_digest` (or an equivalent helper) rather than a plain equality check on those secrets and digests.
- **Strict canonical base64url.** Signature values must decode as unpadded canonical base64url. Padding, whitespace, non-alphabet characters, wrong length, and non-canonical trailing bits are rejected, so an encoding variant of a valid signature does not verify.
- **Export trust is not inferred from an embedded key.** A portable export can carry a detached signature. If verification uses only the public key embedded in the bundle, the result is reported as self-signed (untrusted). A `verified` result requires a caller-supplied trusted key. Verification fails closed when a signature is required and cannot be checked that way.
- **Rollback protection.** Rollback requires a signed snapshot checkpoint that verifies against the workspace's trusted keys and binds the commit, tree, and portable inventory. An explicit legacy escape hatch can allow an ancestor that has no checkpoint; a present but invalid checkpoint still fails closed.
- **Credential guard.** Before adapter and related documents are persisted, string values are scanned for credential-like material. A `signature.value` field is exempted only if it is a 64-byte Ed25519 signature in canonical base64url that verifies over that exact document with a trusted key. Other fields, the rest of the signature object, unverified or failing signatures, and callers that do not supply trusted keys remain fully scanned.
- **CI gates.** Pull requests and the default branch are checked by a pinned gitleaks scan, a fail-closed denylist of unpublished material and similar internal patterns (rules are not listed here), an author-email check that keeps personal mail hosts out of commit history, and a license check.

Private keys are created as mode-0600 regular files in a mode-0700 directory, with exclusive no-follow creation. Symlinks are refused at key load, import, package, export, and rollback. Portable export tests assert that private key material is omitted from the archive. Hash pins, path confinement, strict YAML loading, and archive path/size checks apply at compose and export time. The loopback operator UI binds only to loopback, checks `Host` against the bound socket, and requires exact Origin, same-origin Fetch metadata, and a CSRF token (compared with `compare_digest`) for mutations.

## Known limitations

- **Private keys at rest are unencrypted** (tracked as follow-up C3). They are stored as PEM with mode 0600. A raw filesystem copy or backup of a vault can include them even though portable export omits them. Encrypting private keys at rest is planned; it is not implemented.
- **Authorization envelopes are unsigned policy documents**, not cryptographic capability tokens. Whoever can supply a matching envelope and hash-pinned components can compose what that envelope allows.
- **Refusal and capability checks are not a sandbox**, as described above.
- **Imported documents can carry prompt-injection text** into a local `ask`. A prompt instruction to treat sources as untrusted text is not a security boundary.
- **nukotech-agent-arc package signatures are optional** unless the caller requires a signature or supplies trusted keys. An unsigned package plus an unsigned hash list can still be swapped together.
- **Legacy rollback** can proceed without a checkpoint only when that escape hatch is explicitly enabled. Do not use it to ignore a checkpoint that fails verification.

## Threat model

A public threat model for this repository is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
