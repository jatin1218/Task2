# Verification results

- `python -m unittest discover -s tests -v`: **28 tests passed**.
- `python -m abac demo`: **9 scenarios**, with **4 ALLOW and 5 DENY**.
- `python -m abac audit`: nine persisted access-decision records verified.
- Standard-library-only implementation; no third-party packages to install.

Tests cover tenant isolation, permitted rows, SQL-level PII masking, PII grants,
clearance, active users, dataset/purpose attributes, MFA, strict boolean comparison,
network/region checks, explicit deny overrides, default denial, missing attributes,
unknown principals, injected resource names, unsupported actions, bounded queries,
allow/deny auditing, query-error auditing, audit-storage failure, role-independent
subject grants, and invalid-policy rejection.

Executed on Linux using the available Python runtime. Windows instructions use
portable Python commands; a Windows runtime was not available for direct testing.
Identity and environmental attributes are deliberately simulated, as documented in
README. Authentication, protected remote audit storage, and hosted deployment are
outside this assignment implementation.
