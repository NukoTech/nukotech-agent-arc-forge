# Security Provider Contract

## Boundary

A security provider is any separately owned policy service. Agent Arc does not copy, implement or control a provider; it consumes a provider-neutral decision contract.

## Request

An adapter receives a stage and a JSON-compatible context containing only declared recipe metadata, component provenance and hashes, an authorization envelope, requested capabilities, declared side effects, and prior receipt hashes. Raw credentials, private-key material, customer content, and undeclared environment data are prohibited.

Supported stages are `pre_compose`, `pre_package`, `pre_install`, `pre_execute`, and `post_execute`. The local composer invokes only the first two stages.

## Response

The adapter returns:

- `decision`: `allow`, `deny`, `hold`, or `escalate`;
- `code`: stable machine-readable reason;
- `reasons`: non-secret explanatory strings;
- `evidence_hash`: SHA-256 binding the evaluated request;
- `provider`: provider identifier;
- `stage`: evaluated stage.

Only `allow` permits the current bounded transition. A denial, hold, escalation, timeout, malformed response, transport failure, missing adapter, or provider exception fails closed.

## Local fallback

Community Core includes a deterministic local provider. Missing provider configuration selects that restrictive provider; it never bypasses security evaluation. A third-party adapter must pass the same contract tests plus the provider's own independent validation before it can be marked verified.

## Prohibited coupling

- Agent Arc cannot grant a provider authority.
- A provider cannot mutate Agent Arc source, recipes, registries, or receipts through this interface.
- Neither product may embed the other's secrets or signing keys.
- Provider identity and security decision evidence must be included in composition receipts.
- Product release and commercial ownership remain independent.

