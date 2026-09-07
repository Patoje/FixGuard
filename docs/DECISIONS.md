# FixGuard Architectural Decision Records (ADR)

> **Standard:** Light-weight Architecture Decision Records (ADR).  
> **Integrity Rule:** No historical motive is invented. If reasoning is not explicitly established by repository evidence (ADR files, commit logs, issue plans), it is marked as `"Reason not established from available repository evidence."`

---

## ADR-001: Runtime-Branded `VerifiedAuthorizationDecision` via Module-Private `WeakSet`

- **ID:** ADR-001
- **Status:** `ACCEPTED` (`CONFIRMED` in `worker/src/v2/authorization/VerifiedAuthorizationDecisionService.ts`)
- **Context:**
  Prior to Milestone 56A, callers could bypass authorization checks by supplying boolean flags (e.g., `confirmed: true`) or plain structural JSON lookalikes. This created a P1 self-authorization vulnerability where the caller acted as its own authorization source.
- **Decision:**
  Enforce a process-local, non-forgeable runtime brand using a module-private `WeakSet<object>`. Only objects instantiated via `establishVerifiedAuthorizationDecision()` are added to the `WeakSet`. Structural copies (`structuredClone`, spread operator, JSON round-trips, `Object.assign`) are stripped of authority and rejected by `isRuntimeEstablishedVerifiedAuthorizationDecision()`.
  *(Note: An early draft in `ADR-001-verified-authorization.md` referenced a Symbol brand, but active production code uses `WeakSet<object>` to prevent extraction via reflection).*
- **Motive:**
  Prevent structural lookalike forgery without the operational overhead and key-distribution complexity of asymmetric cryptography within an in-memory process boundary.
- **Consequences:**
  All active recon services, comparison validators, and pipeline runners must accept and validate a runtime-branded `VerifiedAuthorizationDecision`. Tests cannot use mocked object literals; they must invoke `establishVerifiedAuthorizationDecision()`.
- **Alternatives Considered:**
  1. Cryptographic JWTs: Rejected due to key distribution and signing overhead for in-process boundaries.
  2. Primitive boolean flags: Rejected due to self-authorization defect.
- **What NOT to do:**
  - Never allow downstream services to extract authorization from unverified caller parameters.
  - Never export or expose the `_runtimeBrand` `WeakSet` outside its service module.

---

## ADR-002: Two-Pass Atomic Batch Preflight in Active Reconnaissance

- **ID:** ADR-002
- **Status:** `ACCEPTED` (`CONFIRMED` in `ActiveReconOriginRunService.ts` and `ActiveReconDocumentProbeRunner.ts`)
- **Context:**
  In early recon implementations, probe batches executed iteratively: valid probes executed while invalid probes were skipped or logged as errors. This caused partial execution side effects before an invalid probe was detected.
- **Decision:**
  Implement a strict two-pass execution model:
  - *Pass 1 (Preflight Validation)*: Validate all requested probes against scope, target, and supported capabilities.
  - *Pass 2 (Execution)*: Execute probes only if **ALL** probes in the batch are valid.
  If any probe fails, the entire batch is aborted (`preflight_denied`), resulting in:
  - `0` network adapter calls.
  - `0` repository save calls.
  - `0` repository get calls.
- **Motive:**
  Guarantee atomicity and predictability. Prevent unauthorized or malformed batches from leaving partial side-effects or executing network scans before rejection.
- **Consequences:**
  A batch containing `[validProbe, invalidProbe]` will execute neither. Sibling probes in a failed batch receive status `batch_preflight_aborted`.
- **What NOT to do:**
  - Never execute probes sequentially while preflight validation is incomplete.
  - Never write partial recon run records to the database when a preflight check fails.

---

## ADR-003: Exact-Key Closed-World Structural Shape Validation

- **ID:** ADR-003
- **Status:** `ACCEPTED` (`CONFIRMED` across `v2/recon/active/`, `v2/evidence/`, `v2/evidence-store/`)
- **Context:**
  Persisted records and trust boundary inputs previously risked property injection, prototype tampering, or accepting unexpected executable fields (such as `rawToolOutput`, `shellCommand`, or unvalidated claims).
- **Decision:**
  Enforce exact-key closed-world validation on all persisted records and trust boundaries. Any object containing keys not explicitly present in the allowed whitelist is unconditionally rejected.
- **Motive:**
  Prevent schema drift, silent corruption, and accidental leakage of sensitive or executable payload attributes into persistent storage.
- **Consequences:**
  Every record schema must maintain an explicit array of allowed keys. Upgrading a schema requires bumping the version tag (e.g. `v0` vs `v1`) and updating the exact key validator.
- **What NOT to do:**
  - Never use open-ended object spreads (`{ ...data }`) into persistence records without exact-key filtering.
  - Never permit unknown properties to pass silently through storage boundaries.

---

## ADR-004: Double Gate Architecture: Scope Policy vs Egress Policy

- **ID:** ADR-004
- **Status:** `ACCEPTED` (`CONFIRMED` in `AuthorizedScopePolicyService.ts` and `PassiveEgressPolicy.ts`)
- **Context:**
  Early designs conflated network-level SSRF defenses with human authorization boundaries.
- **Decision:**
  Decouple human authorization from network safety into two independent gates:
  - **Gate 1 (Human Scope & Authorization)**: `AuthorizedScopePolicyService` (M46) verifies that the operator authorized the domain, port, and HTTP method.
  - **Gate 2 (Network Egress Safety)**: `PassiveEgressPolicy` (M30) verifies that the resolved IP target does not target loopback (`127.0.0.1`), private networks (`RFC1918`), link-local addresses, or cloud metadata endpoints (`169.254.169.254`).
- **Motive:**
  Even if a human operator mistakenly or maliciously authorizes `http://169.254.169.254/latest/meta-data/`, the network egress policy acts as a hard safety boundary that refuses transmission.
- **Consequences:**
  Every network adapter invocation must query `PassiveEgressPolicy` immediately prior to dispatch, regardless of whether human authorization passed.
- **What NOT to do:**
  - Never treat human authorization as a bypass for egress policy checks.
  - Never treat egress policy pass as proof of human authorization.

---

## ADR-005: Human-in-the-Loop Review Boundary for Evidence & Candidate Promotion

- **ID:** ADR-005
- **Status:** `ACCEPTED` (`CONFIRMED` in `HumanReviewedEvidencePromotionService.ts` and `ReviewedEvidenceFindingCandidatePromotionService.ts`)
- **Context:**
  Traditional automated DAST tools produce high volumes of false-positive vulnerability reports by automatically converting anomalies into findings without human triage.
- **Decision:**
  1. Differential validation outputs are strictly classified as non-persisted drafts (`EvidenceDraftEnvelope`).
  2. Promotion of a draft to an `EvidenceRecord` (M50) requires explicit human review (`approve_evidence`).
  3. Grouping evidence into a formal finding candidate (M54) requires an explicit human triage decision (`approve_finding_candidate_promotion`).
  4. Both promotion services enforce explicit non-claims: `noConfirmedVulnerability: true`, `noSeverityRiskOrImpactClaim: true`, `noRemediationAdvice: true`.
- **Motive:**
  Preserve the core philosophy: "Tools execute. Intelligence decides. Humans authorize." Protect clients from autonomous, unverified exploit or vulnerability claims.
- **Consequences:**
  Automated routines can propose candidates, but cannot mark them as approved findings. Rejection by human review halts persistence and discards unapproved drafts.
- **What NOT to do:**
  - Never auto-promote evidence drafts without a human reviewer decision.
  - Never allow an automated scanner to set `humanApprovedPromotion: true`.

---

## ADR-006: Dual Architecture Segregation (Freezing V1 vs Developing V2)

- **ID:** ADR-006
- **Status:** `ACCEPTED` (`CONFIRMED` in root `FIXGUARD_V2_ARCHITECTURE.md`)
- **Context:**
  FixGuard V1 had accumulated severe architectural debt: direct `exec()` calls, unredacted requests/responses in SQL, no lifecycle transactions, and mixed responsibilities across Express routes.
- **Decision:**
  Freeze V1 completely in place without modifying or refactoring it. Develop FixGuard V2 from scratch under `worker/src/v2/` using DDD and Ports & Adapters. Do not migrate legacy V1 routes into V2 until V2's core boundaries are validated and stabilized.
- **Motive:**
  Allow the development of a clean, secure, defensible architecture without breaking the operational prototype or getting bogged down in legacy refactoring.
- **Consequences:**
  The repository maintains two `package.json` configurations, two tsconfigs (`tsconfig.json` and `tsconfig.v2.json`), and two database schemas (`src/db/` and `src/v2/storage/postgres/`).
- **What NOT to do:**
  - Never import V1 modules into V2.
  - Never refactor V1 code during V2 milestones.

---

## ADR-007: Relational Index + JSONB Hybrid Storage Model with Prefixed Tables

- **ID:** ADR-007
- **Status:** `ACCEPTED` (`CONFIRMED` in `worker/src/v2/storage/postgres/schema.ts` and `drizzle-v2/`)
- **Context:**
  FixGuard V2 needed durable persistence for sessions, evidence, audit logs, and recon records. Pure relational schemas were too rigid for evolving security artifacts, while pure document/event-sourcing models introduced significant read-time overhead.
- **Decision:**
  Adopt a hybrid storage model using PostgreSQL + Drizzle ORM:
  - All V2 tables are strictly prefixed with `v2_` (e.g. `v2_assessment_sessions`, `v2_active_recon_run_records`).
  - Core searchable fields (`session_id`, `target_uri`, `lifecycle_status`, `created_at_ms`) are stored in indexed relational columns.
  - Deep domain entities (`AssessmentState`, `EvidenceCollection`, `AuditEntry`, `PersistedActiveReconRunRecord`) are stored in `JSONB` columns and re-validated upon retrieval.
- **Motive:**
  Provide high-performance indexed queries and listings while preserving full domain payload fidelity without complex multi-table joins.
- **Consequences:**
  Repositories must implement defensive deserialization: data read from `JSONB` must be validated against runtime contracts before being returned to callers.
- **What NOT to do:**
  - Never mix V1 and V2 tables in the same schema migrations.
  - Never trust raw `JSONB` contents from the database without validation.

---

## ADR-008: Safe Display & Redaction Discipline (Zero Sensitive Raw Leaks)

- **ID:** ADR-008
- **Status:** `ACCEPTED` (`CONFIRMED` in `v2/recon/active/ActiveReconContracts.ts`, `v2/evidence/EvidenceBoundaryService.ts`)
- **Context:**
  Raw URLs, HTTP headers, and server responses often contain credentials, session cookies, bearer tokens, or API keys that leak into logs, DTOs, and reports.
- **Decision:**
  1. Never echo raw target URLs containing queries or fragments; use `safeDisplayUrl` or `normalizedOrigin`.
  2. Strip and hash sensitive body and header contents (`bodyHash`, `rawOutputHash`).
  3. Run all user-facing strings through a `forbiddenContentScan` rejecting terms like `bearer`, `cookie:`, `password`, `secret`, `token`, `raw_request`, `raw_response`.
  4. Excerpts must be strictly bounded in length and marked `redacted: true`.
- **Motive:**
  Prevent data leakage and ensure compliance with defensive auditing standards.
- **Consequences:**
  Any evidence record failing the redaction check is rejected during boundary validation.
- **What NOT to do:**
  - Never persist or display raw HTTP authorization headers or raw request bodies.
  - Never bypass the `forbiddenContentScan` for user-facing DTOs.

---

## ADR-009: Single Consolidated Smoke Suite per Milestone

- **ID:** ADR-009
- **Status:** `ACCEPTED` (`CONFIRMED` in `worker/package.json` scripts)
- **Context:**
  Past development iterations fragmented tests into dozens of tiny scripts (`milestone38_a`, `milestone38_b`, etc.) which often swallowed rejected promises or masked integration failures.
- **Decision:**
  Consolidate all verification for a milestone into **one** comprehensive smoke test script (e.g., `milestone56a_verified_authorization_active_recon_smoke.ts`, `milestone57_recon_to_reviewed_evidence_vertical_smoke.ts`). The script must:
  - Test the happy path.
  - Test adversarial/negative cases (forgery, mutation, malformed input).
  - Explicitly exit with `process.exit(1)` upon any unhandled rejection or assertion failure.
- **Motive:**
  Ensure fast, deterministic, reliable CI regression testing (`npm run check:v2`) that guarantees zero silent test passes.
- **Consequences:**
  Every new milestone introduces exactly one smoke test file chained into `"smoke:v2"`.
- **What NOT to do:**
  - Never use `runTest().catch(console.error)` without `process.exit(1)`.
  - Never leave a smoke test disconnected from `npm run check:v2`.

---

## ADR-010: Continuous Lineage & Authorization Provenance Tracking

- **ID:** ADR-010
- **Status:** `ACCEPTED` (`CONFIRMED` in `worker/src/v2/lineage/AuthorizedExecutionLineageContracts.ts` and `AuthorizedComparisonValidationService.ts`)
- **Context:**
  Milestone 49 originally had an authorization discontinuity where snapshots from one target or scan could theoretically be validated against an authorization grant belonging to a different scan or operator.
- **Decision:**
  Introduce an explicit lineage tuple:
  `{ assessmentId, scanId, authorizationGrantId, authorizationDecisionId, actorId }`.
  This tuple must be preserved and matched across all intermediate boundaries (Recon $\rightarrow$ Snapshots $\rightarrow$ Comparison $\rightarrow$ Review $\rightarrow$ Evidence Store $\rightarrow$ Candidate).
- **Motive:**
  Guarantee complete cryptographic-style chain of custody and forensic traceability for all security actions.
- **Consequences:**
  If an incoming request presents a `scanId` or `grantId` that does not match the attached authorization decision, the service halts with `blocked_lineage_mismatch`.
- **What NOT to do:**
  - Never drop lineage IDs when mapping or promoting data between layers.
  - Never synthesize fake or default lineage IDs in production services.

---

## ADR-011: DB-Free Milestone Design Principle (Contracts & Invariants First)

- **ID:** ADR-011
- **Status:** `ACCEPTED` (`CONFIRMED` in Milestones M45 through M57)
- **Context:**
  Coupling domain logic to PostgreSQL tables during early design phases slows iteration, introduces database migration churn, and obscures core domain invariants.
- **Decision:**
  All new architectural boundaries must be designed and proven **DB-free** first. Repositories and stores must initially be implemented using in-memory, mutation-safe adapters with deep cloning. Database persistence (PostgreSQL/Drizzle) is only introduced after domain contracts, lineage invariants, and state transitions are sealed.
- **Motive:**
  Ensure that domain invariants are tested for pure logical correctness without database flakiness, connection latency, or migration overhead.
- **Consequences:**
  Testing is blazing fast and deterministic. PostgreSQL adapters are added as clean, swappable ports without changing domain interfaces.
- **What NOT to do:**
  - Never require a live database connection to run standard unit or regression smoke tests.
  - Never embed database queries or Drizzle constructs inside domain services.
