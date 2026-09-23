# Security Policy

## Project status

This fork is undergoing security hardening and must not be treated as production-ready until the documented hardening and release gates are complete.

## Reporting a vulnerability

Do not disclose exploitable security details in a public issue.

Use GitHub private vulnerability reporting or a repository security advisory when available. If private reporting is temporarily unavailable, open only a minimal public coordination issue without exploit details, credentials, customer information, production IP addresses, raw FortiGate configurations, or sensitive evidence.

## Security-sensitive areas

Changes involving any of the following require explicit security review and negative-path testing:

- SSH host-key verification and authentication
- credential handling
- FortiGate command collection and completion detection
- terminal/PTY handling
- filesystem-hash parsing
- baseline provenance and integrity
- FortiOS version/build compatibility gates
- evidence storage and file permissions
- comparison status and exit-code semantics
- CI/CD token permissions and supply-chain controls

## Fail-closed requirement

A clean integrity result is valid only after all applicable collection, completion, parsing, record-count, metadata compatibility, and baseline-provenance checks succeed. Partial or unverifiable evidence must never be reported as clean.

## Sensitive data

Do not commit or attach:

- real passwords, API tokens, private keys, or SSH private material
- raw production FortiGate configurations
- customer-identifying evidence unless explicitly approved
- production management IP inventories
- unredacted incident artifacts

Use sanitized fixtures for tests.

## Supported versions

No production-ready version is currently declared by this fork. Support claims must be tied to explicit test and compatibility evidence.
