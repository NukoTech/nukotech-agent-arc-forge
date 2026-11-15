# Cycle 2 Mac local research adapter

`LocalResearchNotebook` is a thin provider-neutral adapter. It does not call a vendor API, install a service, store credentials, or designate any third-party notebook as canonical.

Manual and watched-folder capture require a project and privacy classification. Local content is immutable under a SHA-256 address, deduplicated by that address, and indexed in rebuildable SQLite FTS5. Citations must be literal excerpts from the recorded source. Graph and backlinks are deterministic SHA-addressed wikilinks.

The adapter rejects symlink escapes, missing governance choices, citation mismatches, unavailable Keychain references, and pilot exports outside a `staging` or `unreviewed` destination. Offline operations are append-only queued locally. Signed receipts require an injected Keychain-backed signer; no secret is accepted in configuration. Durable provenance sidecars preserve source governance across an index rebuild. `rollback_and_uninstall()` removes only a notebook root bound by a valid ownership marker and fails closed if that marker is absent or changed.

Native validation remains held until the candidate packet supplies its missing source binding and manifest and all candidate-bound tests pass.
