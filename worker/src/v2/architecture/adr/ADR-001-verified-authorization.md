# Title: ADR-001: Verified Authorization Decisions

**Context**: Prior to Milestone 56A, callers could bypass authorization checks by supplying boolean flags (e.g. `confirmed: true`) or plain structural JSON lookalikes. This created a P1 self-authorization vulnerability where the caller acted as its own authorization source. We need a process-local, non-forgeable authorization boundary that cannot be synthesized or cloned by downstream logic or adversarial callers.

**Decision**: We enforce a process-local, non-forgeable runtime brand using a module-private `WeakSet<object>` (implemented canonically in `worker/src/v2/authorization/VerifiedAuthorizationDecisionService.ts`). Only objects instantiated via `establishVerifiedAuthorizationDecision()` are registered in the `WeakSet`. Structural copies (`structuredClone`, spread operator `{ ... }`, JSON round-trips, `Object.assign`) are stripped of authority and rejected by `isRuntimeEstablishedVerifiedAuthorizationDecision()`. This object references an immutable M46 `AuthorizedScopeGrant`. Downstream components accept this object and extract the grant via trusted accessors. We explicitly reject cryptographic JWTs for internal in-process boundaries to avoid symmetric key distribution overhead while avoiding reflection-accessible Symbol leaks.

*(Canonical Reference: `docs/DECISIONS.md` — ADR-001)*

**Consequences**: All service methods and adapters must accept and validate `VerifiedAuthorizationDecision` rather than primitive strings or loose boolean flags. Downstream services must never self-authorize. Tests cannot use plain mocked object literals; they must invoke `establishVerifiedAuthorizationDecision()` to generate valid fixtures.

