# Threat model — nukotech-agent-arc

This threat model covers **nukotech-agent-arc** (Python package `nukotech_agent_arc`, modules `nukotech.agent_arc.*`) and the local HiveMind vault, packs, gates, and loopback operator UI shipped in this repository. It is a companion to [SECURITY.md](../SECURITY.md).

Refusal is a policy check, not a sandbox. See SECURITY.md.

## Actors

| Actor | Access |
|-------|--------|
| Honest operator on the same machine | Can run the CLI, point at a vault, and bind the loopback UI. |
| Malicious or compromised pack or recipe author | Can ship YAML, Markdown, and files; cannot write the operator's disk unless a path bug allows it. |
| Local unprivileged user or malware on the same host | May read world-readable files, bind or race loopback ports, or read unencrypted keys if permissions slip. |
| Browser process or malicious webpage | May try CSRF or DNS rebinding against the loopback UI. |
| Recipient of a portable export | Holds a tarball that is supposed to be a complete, hash-checked copy of portable vault state. |
| Supply-chain attacker on CI or a git dependency | May try to move a pinned tool or action off its digest, or inject a secret into a pull request. |

## Trust boundaries

These inputs and surfaces are untrusted unless a named operator action says otherwise.

### Recipe, registry, and authorization envelope

Loaded through a strict YAML loader that rejects duplicate keys. Registry resolution recomputes SHA-256 of the file under the component root, requires the path to stay inside the root after resolution, and requires the recipe hash, registry hash, and disk hash to match. The authorization envelope is mapped to allowed and prohibited sets. It has no signature, expiry, or audience.

### Pack loading and skill import

A pack or skill directory is an untrusted tree. Skill import turns a `SKILL.md` folder into a hash-pinned registry component; only the skill document bytes are pinned. Package build refuses symlinks and rescans bytes for a small set of credential patterns. Gate validators emit pass or hold results; they are quality gates, not runtime sandboxes.

### HiveMind memory and vault

Import copies bytes, records provenance with a source digest, and indexes body text. Protocol memory and workflow documents can be Ed25519-signed and are verified against a trusted key map. Product and cognition receipts that carry a signature are verified when the index is rebuilt. String values that cross a persistence boundary are scanned by the credential guard; a signature value is exempted only when it verifies as described in SECURITY.md.

### Snapshot and rollback

A snapshot is a git commit of portable paths. Symlink trees are refused. Rollback requires a full commit SHA that is an ancestor of `HEAD`, then restores with literal pathspecs and removes leftover untracked portable files. Rollback also requires a signed snapshot checkpoint that verifies against the workspace's trusted keys and binds the commit, tree, and portable inventory. A present but invalid checkpoint fails closed. An explicit escape hatch can allow a legacy ancestor that has no checkpoint.

### Export path

Archive members must live under the export root, be regular files, and pass path-safety and size caps. Each file's SHA-256 is checked against an embedded manifest. The manifest can be signed. A result of `verified` requires a caller-supplied trusted key. If only the public key embedded in the bundle is used, the status is self-signed (untrusted). The private key directory is not part of the portable inventory; tests assert that private key material does not appear in the archive. Public workflow key material may be exported.

### Optional local model server

The endpoint is a literal loopback HTTP URL, not an operator-controlled remote. The prompt includes an instruction to treat source text as untrusted. That instruction is not a control.

### Loopback UI

The bind address is locked to loopback addresses. `Host` is compared with `compare_digest` to the bound socket, which blocks classic DNS rebinding to a hostname that later resolves to loopback. Mutations require an exact Origin, `Sec-Fetch-Site: same-origin`, a JSON content type, a CSRF header, and an idempotency key. The session cookie is `HttpOnly; SameSite=Strict; Path=/`. It has no `Secure` flag, which is expected on plain HTTP loopback.

## Attacker cases

### Malicious pack or recipe

- **Goal:** compose a prohibited capability, sneak a path escape, or plant a credential.
- **Controls:** hash pin, path confinement, symlink rejection, policy and security gate, credential scanning of package bytes, and a prohibited-recipe path that writes a refusal receipt and no package.
- **Residual:** a recipe shipped with a matching authorization envelope will be allowed if policy and hashes line up. That is by design for a local composer. It is not a sandbox.

### Hash-pin bypass

- **Goal:** change component bytes without changing the declared SHA-256, or change the declaration without being detected.
- **Controls:** three-way compare (recipe, registry, and disk) at resolve time and again at package time.
- **Residual:** whoever can rewrite the registry, the recipe, and the file together wins. The registry itself is not signed.

### Path traversal in packages or exports

- **Goal:** write outside the destination during verify, reopen, or bundle import.
- **Controls:** path helpers reject `..`, absolute paths, backslashes, and members outside the export root. Members are read with explicit file APIs and written through sanitized relative parts, not a blanket extract-all. Zip-bomb and export size caps apply.
- **Residual:** any new unpack path must use the same checks.

### Unsafe YAML loading

- **Goal:** deserialize a Python object from a recipe, pack, or memory file.
- **Controls:** a strict safe loader in the composer; safe loading in the vault. Review of the source trees found no unsafe YAML loaders.
- **Residual:** future loaders, including pack frontmatter, must stay on a safe loader.

### Symlinks

- **Goal:** make the composer or importer follow a link out of the component root or vault.
- **Controls:** symlink denials on import, export, keys, package sources, and rollback trees. Private key loading rejects a symlink even when the mode is 0600.
- **Residual:** resolving a path may follow a symlink *inside* the root to another in-root file; the hash is of the target. That is acceptable if confinement holds. Do not relax that check.

### Prompt injection via imported documents

- **Goal:** an imported Markdown file instructs the model to ignore the system prompt, exfiltrate vault text, or emit a step the operator might follow.
- **Controls:** retrieval-only behavior when nothing matches; when the optional local model server is used, a single instruction to treat sources as untrusted.
- **Residual:** there is no untrusted-document isolation. Do not treat the prompt sentence as a security boundary.

### Tampered snapshot or rollback

- **Goal:** roll the vault back to an attacker-chosen tree, or present a fake snapshot.
- **Controls:** full SHA, exact resolve, must be an ancestor of `HEAD`, symlink-free tree, literal pathspecs, and a signed checkpoint that binds commit, tree, and inventory to a trusted workspace key. An invalid checkpoint cannot be bypassed with the legacy escape hatch.
- **Residual:** the escape hatch can still roll back to a legacy ancestor that has no checkpoint, if it is explicitly enabled. Git history remains a trust anchor for that path.

### Tampered export

- **Goal:** alter exported Markdown or receipts and still pass inspect, reopen, or verify.
- **Controls:** embedded SHA-256 inventory, exact file-set match, size checks, and an optional detached signature over the manifest. A `verified` status requires a trusted key supplied by the caller. Using only the key embedded in the bundle is reported as self-signed (untrusted) and is an integrity check, not a trust decision.
- **Residual:** an unsigned export, or an export accepted as self-signed, can still be altered if the files and the unsigned or self-signed manifest are changed together.

### Signing-key theft

- **Goal:** steal an Ed25519 private key and mint protocol, agent, or workflow documents.
- **Controls:** mode 0600 PEM, mode 0700 directory, no symlink, exclusive create, omission from portable export, and tests that the archive does not contain private key material. Signature values that merely resemble credentials are not exempt from the credential guard unless they verify.
- **Residual:** keys are unencrypted at rest (follow-up C3). A disk image, backup, or accidental future addition of the key directory to the export list would leak them. Public workflow keys may appear in an export; a private key must never appear there.

### Credential-shaped values in signed documents

- **Goal:** persist a live token by placing it in a document field, or confuse a scanner with a random signature that happens to look like a token.
- **Controls:** the credential guard scans strings at persistence boundaries. A signature value is skipped only after strict canonical decoding to 64 bytes and a successful verify over that exact document with a trusted key. Other fields stay scanned. Failed, missing, or untrusted verification fails closed and the value is scanned.
- **Residual:** a verified 64-byte signature can still collide with a token pattern by chance; that collision is not a chosen credential. The same string is still denied if it appears anywhere else.

### UI CSRF or DNS rebinding on loopback

- **Goal:** a visited website triggers a state change on the loopback operator UI, or tricks the browser into sending the operator's cookie to a rebinding host.
- **Controls:** bind and peer must be loopback; `Host` must equal the bound socket; mutations require exact Origin, same-origin Fetch metadata, and CSRF, all compared with `compare_digest`; the cookie is `SameSite=Strict`.
- **Residual:** Origin is optional on non-mutation requests (checked only when present). Older browsers without Fetch metadata rely on Host and CSRF for mutations. The cookie has no `Secure` flag (acceptable for HTTP loopback). Residual risk is mainly an older browser or a second process bound to the same port; treat the launch URL as a secret.

## Automated checks

CI pins tools and actions at full digests, not branches. Required security checks include a scoped gitleaks scan, a fail-closed denylist (patterns are not published), an author-email check, and a license check. The denylist and leak scans are meant to keep unpublished material out of a tree that could be released; they are not a substitute for reviewing a specific release tag.
