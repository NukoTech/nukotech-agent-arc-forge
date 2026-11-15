# Organization Context Bootstrap Loop

Status: candidate component 0.1.0

Owner: example

Provenance: clean-room first-party synthesis from organization-context research notes; no supplied prompt text is copied verbatim.

## Contract

Build scoped organization context through a one-question-at-a-time interview. Each answer becomes a staged candidate for a named module; no answer becomes durable memory automatically.

## Required Inputs

- `tenant_ref`
- `project_id`
- `requesting_owner`
- `allowed_modules`
- `authorization_id`
- Current context manifest, if one exists

Stop if any required identifier or authority is missing. Never ask for passwords, API keys, recovery codes, private keys, payment-card data, or unrestricted account exports.

## Loop

1. Explain the current module, why the next answer is needed, and where the candidate will be staged.
2. Ask exactly one concise question.
3. Capture the answer without silently expanding its scope.
4. Attach provenance, observation date, sensitivity, freshness requirement, and the authorizing owner.
5. Summarize the candidate back to the owner for correction.
6. Stage the reviewed candidate under its module; do not promote it.
7. Continue only when the owner confirms or corrects the summary.
8. End with a manifest preview showing complete, incomplete, stale, conflicting, and withheld modules.

## Module Order

Use only modules allowed by the task. The default order is:

1. Organization identity and ownership
2. Products and services
3. Customers and users
4. Brand voice and communication constraints
5. Current priorities
6. Quality and acceptance standards
7. Prohibited behavior and escalation boundaries

Do not merge these into one company-brain file. Each module remains independently reviewable, hashable, replaceable, and revocable.

## Output

For every answer, emit one staged context candidate containing:

- Tenant, project, and module identifiers
- Exact owner-supplied fact or a clearly labeled summary
- Source type and source reference
- Observed and last-verified dates
- Sensitivity and freshness labels
- Conflicts or uncertainty
- Candidate status: `staged_unreviewed` or `staged_reviewed`
- Proposed rollback: remove the candidate and restore the prior manifest pointer

## Stop Conditions

- Owner requests stop or skip
- The next question exceeds allowed modules
- Sensitive data is unnecessary or cannot be safely referenced
- Sources conflict and the owner cannot resolve them
- A promotion, external send, account connection, or public action is requested
