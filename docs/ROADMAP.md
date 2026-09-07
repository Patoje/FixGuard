# FixGuard V2 Technical Roadmap & Architecture Status

> **Document Purpose:** Accurate, evidence-grounded tracking of completed milestones, work in progress, planned milestones, and proposed architectural directions.  
> **Integrity Rule:** Proposed changes are strictly separated from confirmed project decisions.

---

## 1. Status Overview

```text
[M0 ─── M55] COMPLETED ───> [M56A / M56B] COMPLETED ───> [M57] COMPLETED
                                                                │
                                                                ▼
                                                        [M58] IN PROGRESS
                                                                │
                                                                ▼
                                                        [M59 / M60] PLANNED
```

---

## 2. Completed Milestones (`CONFIRMED`)

All completed milestones are verified via active TypeScript contracts and the regression test suite (`npm run check:v2` with 19 passing smoke suites).

### Foundation Era (M0 – M29)
- **M0 – M6.5 (Core Loop Foundation)**: `TargetContext`, `CapabilityRequest`, `ExecutionRequest`, `RawExecutionOutput`, `ProcessRunner` (safe spawn without shell interpolation), `SubfinderAdapter`, `SubfinderParser`.
- **M7 – M14 (Runtime Foundation)**: `V2AssessmentRuntime`, `AssessmentState`, lifecycle state machines, optimistic versioning, mutation guards.
- **M15 – M23 (Storage Boundary & Postgres Integration)**: `AssessmentRepository` port, `InMemoryAssessmentRepository`, `PostgresAssessmentRepository` (Drizzle ORM, tables prefixed `v2_`), transactional unit-of-work boundaries, rollback guarantees.
- **M24 – M29 (Boundary Hardening)**: `AssessmentApplicationService`, safe DTO mappers (zero raw command or executable payload leaks), capability registry enforcement.

### Active Recon & Policy Era (M30 – M44)
- **M30 (Egress Policy Boundary)**: `PassiveEgressPolicy` SSRF gate (`allow` / `block` / `candidate`), private subnet blocking (`RFC1918`, loopback, cloud metadata).
- **M31 – M37 (Guarded Active Recon Foundations)**: Safe HTTP header inspection, opt-in network execution seams, safe document metadata.
- **M38 (Document Probe Runner)**: Sondas documentales (`http.robots.inspect`, `http.security_txt.inspect`).
- **M39 (Active Recon Origin Run)**: Two-pass atomic batch preflight (if any probe in a batch fails, abort with 0 side effects).
- **M40 – M42 (Persisted Origin Run & Execution Persistence)**: Closed-world persistence validation, defensive persistence reload verification.
- **M43 – M44 (Read Model & Application Use Cases)**: Read model query segregation, initial application use case boundary.

### Evidence & Candidate Era (M45 – M55)
- **M45 (Evidence Boundary)**: `EvidenceRecord`, `IndicatorRecord`, explicit non-claim classification flags.
- **M46 (Authorized Scope Policy Refinement)**: `AuthorizedScopeGrant`, `ScopeActionRequest`, explicit permission sets and boundary matching.
- **M47 (Response Comparator)**: `SafeResponseSnapshot`, differential HTTP signal comparison.
- **M48 (Comparison Evidence Mapping)**: Differential signals mapped to non-persisted drafts (`EvidenceDraftEnvelope`).
- **M49 (Authorized Comparison Validation)**: Scope-gated differential validation.
- **M50 (Human-Reviewed Evidence Promotion)**: Reviewer gate (`approve_evidence`, `reject`, `needs_more_review`), producing un-persisted `EvidenceRecord`.
- **M51 (Reviewed Evidence Store & Read Model)**: Mutation-safe in-memory repository for reviewed evidence records.
- **M52 (Reviewed Evidence Query & Selection)**: Query and selection sets over reviewed evidence.
- **M53 (Finding Candidate Draft Boundary)**: Grouping reviewed evidence into non-persisted candidate drafts.
- **M54 (Human-Triaged Finding Candidate Promotion)**: Explicit human triage gate producing `ReviewedEvidenceFormalFindingCandidate`.
- **M55 (Core Candidate Pipeline Reality Check)**: Comprehensive end-to-end diagnostic proving ID and metadata continuity across M51 $\rightarrow$ M54.

### Continuity & Vertical Composition Era (M56A – M57)
- **M56A (Verified Authorization Boundary)**: Runtime-established `VerifiedAuthorizationDecision` using module-private `WeakSet<object>` brand. Forgery resistance against spread, structuredClone, and JSON round-trips. Strict exact-key persistence validation. ADR-001 sealed.
- **M56B (Lineage & Comparison Continuity)**: Integrated verified authorization and lineage references (`assessmentId`, `scanId`, `authorizationGrantId`, `authorizationDecisionId`, `actorId`) into M49 comparison validation.
- **M57 (Real Recon-to-Reviewed-Evidence Vertical Slice)**: Implemented `ReconToReviewedEvidenceApplicationService` unifying the 7-step flow from authorized URL to reviewed evidence store.

---

## 3. In Progress (`CURRENT TASK`)

### Milestone 58: Evidence Substance & Canonical Candidate Semantics
- **Objective**:
  1. Define explicit **Evidence Substance Criteria**: move beyond "a record exists" to requiring concrete, verifiable payload data per `EvidenceType` (HTTP differential snapshots, timing deltas, OOB callback hashes).
  2. Preserve complete provenance across M50 promotion.
  3. Formally establish `ReviewedEvidenceFormalFindingCandidate` (M54) as the canonical candidate of FixGuard V2 and resolve semantic overlap with legacy M45 candidate records.
  4. Enforce strict claim discipline: zero automatic severities, zero exploitability claims, zero automated remediation recipes.

---

## 4. Planned Milestones (`PLANNED`)

### Milestone 59: Persistence Readiness for Candidates & Evidence Store
- Design and implement durable PostgreSQL storage for:
  - `v2_reviewed_evidence_records` (migrating M51 in-memory store to Postgres).
  - `v2_formal_finding_candidates` (persisting M54 formal candidates).
- Enforce relational foreign keys to `v2_assessment_sessions`.
- Provide defensive deserialization and reload verification conformance tests.

### Milestone 60: Defensive Report Readiness Gate
- Implement the reporting boundary for defensive security assessments.
- Requirements:
  - Human verification and operator signature present.
  - Evidence substance verified.
  - Explicit non-claims and audit limitations prominently included.
  - Zero speculative severity inflation.

---

## 5. Architectural Proposals (`PROPOSED` — NOT YET DECIDED)

> [!NOTE]
> The following items are technical proposals identified during the architectural audit. They represent recommendations for future consideration and **HAVE NOT BEEN DECIDED OR APPROVED YET**.

### Proposal A: V2 Unified API Gateway / HTTP Controller Layer
- **Problem**: The Next.js web dashboard (`web/`) currently connects only to the legacy V1 Express API (`worker/src/index.ts`). There is no HTTP layer exposing FixGuard V2 application services.
- **Proposal**: Build a clean V2 Application Controller (or Next.js API route integration) exposing `AssessmentApplicationService` and `ReconToReviewedEvidenceApplicationService` via OpenAPI/REST or JSON-RPC.

### Proposal B: Deprecation and Decommissioning Plan for V1 Monolith
- **Problem**: The codebase carries legacy V1 code (`worker/src/scanner/`, `worker/src/recon/`, `worker/src/index.ts`) with unredacted SQL persistence and direct binary execution.
- **Proposal**: Identify salvageable parsers or tool logic, re-implement them as clean V2 adapters (`worker/src/v2/adapters/`), and systematically decommission the V1 Express server.

### Proposal C: Dependency Hygiene & Pruning
- **Problem**: `worker/package.json` contains dependencies that are completely unused in V2 (e.g. `@upstash/redis`, `@ai-sdk/google`, `playwright`, `wappalyzer`).
- **Proposal**: Once V1 is formally retired, prune unused packages from `worker/package.json` to reduce attack surface and dependency bloat.

### Proposal D: Distributed Authorization Token Provider (Cross-Process Scaling)
- **Problem**: ADR-001 enforces authorization branding via an in-memory `WeakSet<object>`, which is process-local. It cannot cross process or worker node boundaries.
- **Proposal**: If FixGuard evolves from a single-node system into a distributed cluster, introduce an asymmetric cryptographic signing port (e.g. Ed25519) to verify decisions across process boundaries without sacrificing non-forgery guarantees.

---

## 6. Problems, Risks & Technical Debt

### 6.1. Known Issues (`CONFIRMED`)
1. **Evidence Substance Gap (Addressed in M58)**: Prior to M58, `EvidenceRecord`s could be constructed with empty snapshot and difference fields, satisfying TypeScript contracts but carrying zero substantive proof.
2. **ADR-001 Documentation Inconsistency**: The text in `ADR-001-verified-authorization.md` states that a Symbol brand is used; the actual code uses a module-private `WeakSet<object>` (a superior implementation that resists reflection).
3. **Dead Dependency in Worker**: `@upstash/redis` is installed in `worker/package.json` and listed in `.env.example`, but has zero imports across the entire repository.
4. **Web Frontend Disconnected from V2**: The Next.js frontend (`web/`) queries the V1 database schema (`scans`, `recon_profiles`, `findings`) and knows nothing about `v2_` tables.

### 6.2. Architectural Risks (`CONFIRMED`)
1. **Dual System Confusion**: Having both V1 and V2 in the same repository creates cognitive load and the risk that a future agent or engineer accidentally modifies V1 files or imports V1 patterns into V2.
2. **Process-Local Authorization Constraint**: `VerifiedAuthorizationDecision` is bound to the Node.js memory space. Any architectural decision requiring background worker queues (like BullMQ or Celery) would break runtime brand validation unless all execution remains in-process.

### 6.3. Technical Debt (`CONFIRMED`)
1. **Dual Configurations**:
   - `tsconfig.json` (V1) vs `tsconfig.v2.json` (V2).
   - `drizzle.config.ts` (V1) vs `drizzle.v2.config.ts` (V2).
   - `drizzle/` migrations (V1) vs `drizzle-v2/` migrations (V2).
2. **Legacy HTML Reports**: A static artifact `FixGuard_Report_https___balbuenabarber_vercel_app__137.html` sits in the root directory reflecting unvalidated V1 severity outputs.

---

## 7. Open Questions for External Lead Architect

The following questions should be submitted to the senior architect for strategic direction:

1. **API Integration Strategy**:
   *Should V2 be exposed to the Next.js frontend via an Express 5 REST API, a Fastify service, or directly via Next.js Route Handlers / Server Actions calling the V2 application service as an in-process library?*
2. **Execution Environment / Worker Architecture**:
   *Is FixGuard intended to remain an in-process single-instance application (where in-memory `WeakSet` authorization is sufficient), or will workers be distributed across multiple containers/machines (requiring cryptographic authorization tokens)?*
3. **Legacy V1 Retirement Timeline**:
   *Should V1 be removed immediately once V2 has its own API/UI, or should it be archived in a separate git branch?*
4. **Candidate Database Architecture (M59)**:
   *In M59, should `ReviewedEvidenceFormalFindingCandidate` be persisted as relational rows with normalized evidence join tables, or as a versioned state snapshot with relational summary indexes matching the M15 hybrid model?*
