# Contributing

## Change workflow

1. Create a dedicated branch from the current `main`.
2. Keep each change focused on a documented issue or clearly stated outcome.
3. Do not push secrets, customer data, production configurations, or raw sensitive evidence.
4. Open a pull request and document the observed problem, the change, risks, rollback considerations, and validation actually performed.
5. Do not merge while required checks are failing or material security findings remain unresolved.

## Security-sensitive changes

Changes to SSH trust, credentials, collection completeness, parsing, baseline provenance, comparison semantics, or evidence storage must include negative-path tests. A success-path test alone is insufficient.

## Evidence expectations

A pull request must distinguish:

- implemented behavior
- tests actually executed
- checks observed in GitHub
- remaining limitations or follow-up issues

Do not claim a check passed unless it was run against the exact candidate commit.

## Licensing and provenance

The upstream repository does not currently declare a license. Do not add a guessed license or publish derivative releases until licensing/provenance is resolved through the tracked governance issue.
