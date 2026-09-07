# Title: ADR-001: Verified Authorization Decisions

**Context**: We need a process-local, non-cryptographic authorization boundary for M56A that cannot be forged by downstream logic but is cheap to pass.

**Decision**: We use an opaque Symbol-branded object `VerifiedAuthorizationDecision` established exactly once at the API boundary. This object references an immutable M46 `AuthorizedScopeGrant`. Downstream components (M38, M39, M40) accept this object and extract the grant via a trusted module-scoped accessor. We explicitly reject cryptographic JWTs for internal boundaries to avoid symmetric key distribution overhead.

**Consequences**: All service methods must update their signatures to accept `VerifiedAuthorizationDecision` rather than primitive strings or loose boolean flags. Tests must use `establishVerifiedAuthorizationDecision` to generate valid fixtures.
