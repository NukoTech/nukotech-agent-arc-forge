# Native dependency selection

## Protocol serialization and filesystem state

- Python 3.11+ standard library (`json`, `hashlib`, `pathlib`, `uuid`, `datetime`, `os.replace`) supplies deterministic serialization, hashes, paths, identifiers, time handling, and atomic same-filesystem replacement.
- A database or custom storage abstraction would add a service boundary the first disposable filesystem slice does not need.
- Decision: use the standard library and explicit files; add no custom database, retry framework, queue engine, or template engine.

## Signatures

- Python standard-library HMAC authenticates with a shared secret but cannot provide portable public-key verification across mutually isolated surfaces.
- `cryptography` provides audited Ed25519 primitives. An August 25 dependency audit found four advisories against the original `<47` constraint; current release `50.0.1` contains the required fixes.
- Decision: require `cryptography>=50.0.1,<51`, use Ed25519 with disposable LAB keys, and implement no cryptographic primitive.

## Schema validation

- Hand-written field checks are easy to drift and hard for other providers to implement consistently.
- JSON Schema Draft 2020-12 is provider-neutral; `jsonschema` supplies a maintained validator and is widely packaged.
- Decision: publish JSON Schemas and validate them with `jsonschema`; keep policy/authorization checks separate from structural validation.

## Obsidian Bases and frontmatter

- Obsidian Bases uses YAML `.base` files and Markdown YAML frontmatter. Hand-writing a YAML parser would create avoidable ambiguity around scalars, lists, quoting, and malformed input.
- `PyYAML` supplies maintained safe parsing and deterministic emission for the bounded LAB records. Only `safe_load` and `safe_dump` are used; arbitrary Python object construction is unavailable.
- Decision: require `PyYAML>=6.0.2,<7`; validate Base structure and view inventory against the current official Obsidian syntax, while treating Bases as read models rather than transaction authority.

## Governance distribution

- Git and GitHub already supply immutable objects, reviews, protected branches, releases, and artifact transport. M003 does not add a custom updater, package registry, credential manager, or network retry layer.
- Decision: define signed release and node-pin JSON contracts, verify exact artifact hashes locally, and stage only inside the disposable Node LAB. Publishing or activating a release remains held.
