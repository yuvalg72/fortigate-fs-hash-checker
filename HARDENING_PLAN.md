# Production Hardening Plan

This fork is being hardened from an upstream utility/reference implementation into a fail-closed, evidence-backed FortiGate filesystem integrity tool.

## Non-negotiable security principles

- A clean result is valid only after transport, collection-completion, parser, record-count, compatibility, and baseline-provenance gates pass.
- Partial or unverifiable evidence fails closed and must never be reported as clean.
- SSH server identity must be verified. Trust-on-first-use is not acceptable for the production path.
- Plaintext credentials must not be carried in command-line arguments or CSV inventories.
- Baselines are security-sensitive evidence and must be versioned and tamper-evident.
- FortiOS version/build compatibility is checked before comparison. Cross-build comparison is blocked by default.
- The tool is not remote attestation. If the FortiGate control plane is already fully compromised, command output itself may be untrustworthy.
- No production-ready release is permitted while P0/P1 release blockers or upstream licensing remain unresolved.

## Milestones

### M1 - Critical Security Hardening

1. Enforce SSH host-key verification and remove trust-on-first-use behavior.
2. Make hash collection completion-driven and fail closed.
3. Prevent PTY/terminal wrapping and output truncation.
4. Validate FortiOS reported file count against parsed records.
5. Eliminate plaintext password exposure in CLI arguments and CSV.
6. Strictly validate prompts, SHA-256 records, paths, duplicates, and parser behavior.
7. Fix CSV schema validation and row-level failure isolation.
8. Gate success messaging on validated collection completeness.

### M2 - Integrity & Evidence Assurance

9. Add FortiGate identity and FortiOS build metadata to every snapshot.
10. Block cross-build comparisons unless explicitly authorized.
11. Make baselines tamper-evident with cryptographic provenance.
12. Define a versioned evidence schema and retain raw collection evidence.
13. Harden output paths, permissions, atomic writes, and secret-safe logging.
14. Add stable exit codes and machine-readable comparison reports.

### M3 - Engineering Quality & Automation

15. Build a sanitized regression corpus and unit tests for supported FortiOS branches.
16. Establish CI, CodeQL, dependency, and secret-scanning gates.
17. Pin dependencies and define the supported Python runtime policy.
18. Refactor transport, parser, evidence model, and comparison engine into testable components.
19. Publish a threat model, limitations, and operator runbook.

### M4 - Production Readiness

20. Resolve upstream licensing before redistribution or derivative release.
21. Establish versioning, release qualification, and production-readiness gates.
22. Define firmware-upgrade baseline rotation and exception governance.
23. Publish and enforce a supported FortiOS compatibility matrix.
24. Add release checksums, SBOM, signing/provenance, and artifact verification where applicable.

## Closure standard

An issue is not complete merely because code exists. Closure requires evidence that the acceptance criteria were exercised against the exact merged commit, including negative-path behavior where applicable.
