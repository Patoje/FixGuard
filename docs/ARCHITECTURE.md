# FixGuard Technical Architecture Reference

> **Status:** ACTIVE CANONICAL ARCHITECTURE REFERENCE  
> **Target Audience:** Software Architects, Security Engineers, AI Coding Agents  
> **Core Axiom:** "Tools execute. Intelligence decides. Humans authorize."  
> **Confidence Level:** `CONFIRMED` across all analyzed source files and regression test suites.

---

## 1. Executive Summary & Dual-System Reality

FixGuard is an authorized web security assessment and Attack Surface Management (ASM) platform. Its mission is to perform defensive reconnaissance, hypothesis generation, and differential validation against web targets where explicit human consent and authorization exist.

The codebase currently contains two distinct architectural generations:

| Dimension | FixGuard V1 (Legacy) | FixGuard V2 (Canonical Core) |
|---|---|---|
| **Location** | `worker/src/` (excluding `v2/`), `web/` | `worker/src/v2/` |
| **Paradigm** | Monolithic Procedural / Scripted | Domain-Driven Design (DDD) / Clean Architecture |
| **Execution** | Direct `child_process.exec` string commands | Injected `ProcessRunner` (`spawn`, `shell: false`, timeouts) |
| **Authorization** | Implied / Single boolean (`confirmed: true`) | Runtime-branded `VerifiedAuthorizationDecision` + `AuthorizedScopeGrant` |
| **Network Gate** | None (direct outgoing HTTP/socket calls) | Strict `PassiveEgressPolicy` (M30 SSRF / private IP gate) |
| **Evidence** | Speculative strings inserted into database | Immutable, redacted `EvidenceRecord` with continuous lineage |
| **Findings** | Automated `severity: 'critical'` claims | Explicit non-claims; human triage gate required for formal candidates |
| **Database** | Shared Postgres tables (`scans`, `findings`, `recon_profiles`) | Schema-prefixed `v2_*` tables with optimistic concurrency |
| **Status** | **FROZEN / DEPRECATED** (`CONFIRMED`) | **ACTIVE PRODUCTION BASELINE** (`CONFIRMED`) |

```text
                                  FIXGUARD REPOSITORY
                                           │
           ┌───────────────────────────────┴───────────────────────────────┐
           ▼                                                               ▼
    FixGuard V1 (Legacy)                                            FixGuard V2 (Canonical)
  [worker/src/* (excl v2)]                                            [worker/src/v2/*]
  - Express 5 Monolith (port 4000)                                  - DDD / Ports & Adapters
  - Direct shell script execution                                   - Atomic Preflight Runner
  - Unverified severity claims                                      - Verified Authorization (M56A)
  - Next.js 16 Web Dashboard (port 3000)                            - Response Comparator (M47)
                                                                    - Human Review Gate (M50/M54)
                                                                    - 19 Consolidated Smoke Suites
```

---

## 2. Core Architectural Principles

1. **Evidence Substance Over Finding Volume (`CONFIRMED`)**:
   A high volume of unverified findings degrades defensive value. FixGuard rejects speculative findings. An evidence record requires concrete differential signals (status code changes, response length deltas, header anomalies).
2. **Abstention Over Fabrication (`CONFIRMED`)**:
   If the system cannot prove a condition, it records `observed` or `inferred_not_confirmed`. It never fills gaps with guesses.
3. **Strict Claim Discipline (`CONFIRMED`)**:
   - `OBSERVED`: Raw verifiable signals observed on the target.
   - `INFERRED`: Hypotheses derived from observations (strictly unconfirmed).
   - `RECOMMENDED`: Actions proposed for human authorization.
4. **Double Gate on Network Operations (`CONFIRMED`)**:
   No network packet can be transmitted without passing both:
   - *Gate 1 (Human Authority)*: `VerifiedAuthorizationDecision` + `AuthorizedScopeGrant`.
   - *Gate 2 (Network Safety)*: `PassiveEgressPolicy` (M30), rejecting localhost, RFC1918 private subnets, and cloud metadata endpoints.
5. **Exact-Key Closed-World Validation (`CONFIRMED`)**:
   All untrusted input, persisted records, and boundary contracts reject unknown, unexpected, or executable payload keys.

---

## 3. V2 System Layers & Component Directory Map

FixGuard V2 is organized into 9 cleanly separated architectural layers under `worker/src/v2/`:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        9. APPLICATION LAYER                            │
│   [AssessmentApplicationService]  [ReconToReviewedEvidenceService]     │
├────────────────────────────────────────────────────────────────────────┤
│                  8. HUMAN APPROVAL & REVIEW BOUNDARY                   │
│   [VerifiedAuthorizationDecision]  [AuthorizedScopeGrant]              │
│   [HumanReviewedEvidencePromotion] [FormalCandidatePromotion]          │
├───────────────────────────────────┬────────────────────────────────────┤
│       7. RECONNAISSANCE & POLICY  │    6. COMPARISON & VALIDATION      │
│   [DocumentProbeRunner (robots/sec)]│  [ResponseComparatorService]       │
│   [ActiveReconOriginRunService]   │  [ComparisonEvidenceMappingService]│
│   [PassiveEgressPolicy (M30 SSRF)]│  [AuthorizedComparisonValidation]  │
├───────────────────────────────────┴────────────────────────────────────┤
│                       5. EVIDENCE & CANDIDATE PIPELINE                 │
│   [ReviewedEvidenceStore]        [ReviewedEvidenceSelection]           │
│   [FindingCandidateDraft]        [CoreCandidatePipelineRealityCheck]   │
├────────────────────────────────────────────────────────────────────────┤
│                       4. INTELLIGENCE LAYER                            │
│   [EvidenceAccumulator]  [CorrelationEngine]  [TargetProfileBuilder]   │
│   [RecommendationEngine]                                               │
├────────────────────────────────────────────────────────────────────────┤
│                       3. EXECUTION CORE                                │
│   [ProcessRunner (spawn, no shell)]  [ToolAdapter]  [ToolRegistry]     │
├────────────────────────────────────────────────────────────────────────┤
│                       2. RUNTIME & LIFECYCLE                           │
│   [V2AssessmentRuntime]  [RuntimeLifecycleGuards]  [RuntimeTransaction]│
├────────────────────────────────────────────────────────────────────────┤
│                       1. STORAGE PORT & ADAPTERS                       │
│   [AssessmentRepository]  [PostgresAssessmentRepository]               │
│   [InMemoryAssessmentRepository]  [v2_active_recon_records]            │
└────────────────────────────────────────────────────────────────────────┘
```

### 3.1. Layer 1: Storage Layer (`worker/src/v2/storage/`)
- **Responsibility**: Persist and retrieve assessment state, evidence logs, audit entries, and recon records.
- **Inputs**: Domain entities (`AssessmentState`, `PersistedActiveReconRunRecord`).
- **Outputs**: Rehydrated domain entities.
- **Key Files**:
  - `AssessmentRepository.ts`: Abstract storage port.
  - `InMemoryAssessmentRepository.ts`: In-memory implementation with deep cloning.
  - `postgres/PostgresAssessmentRepository.ts`: PostgreSQL adapter using Drizzle ORM.
  - `postgres/schema.ts`: Drizzle schema defining tables prefixed with `v2_`.
- **Invariants**: Must remain repository-agnostic at domain level; never expose SQL/Drizzle types to upper layers.

### 3.2. Layer 2: Runtime & Lifecycle (`worker/src/v2/runtime/`)
- **Responsibility**: Orchestrate session lifecycle transitions (`created` $\rightarrow$ `recon` $\rightarrow$ `active` $\rightarrow$ `paused` $\rightarrow$ `completed`), enforce optimistic concurrency versioning, and guarantee atomic state updates.
- **Key Files**:
  - `V2AssessmentRuntime.ts`: Core runtime coordinator.
  - `AssessmentState.ts`: Snapshot representation of assessment state.
  - `RuntimeLifecycleGuards.ts`: Guard clauses preventing invalid lifecycle state transitions.
  - `RuntimeTransaction.ts`: Capability-based transactional unit-of-work boundary.
- **Invariants**: Lifecycle violations must never mutate state or trigger tool execution.

### 3.3. Layer 3: Execution Core (`worker/src/v2/core/`, `adapters/`, `parsers/`)
- **Responsibility**: Low-level invocation of external binaries and formatting of raw outputs into structured findings.
- **Key Files**:
  - `ExecutionContracts.ts`: Definitions for `CapabilityRequest`, `ExecutionRequest`, `RawExecutionOutput`.
  - `ProcessRunner.ts`: `LocalProcessRunner` executes binaries using `child_process.spawn` with `shell: false`, capturing stdout/stderr and enforcing timeouts via SIGTERM.
  - `adapters/SubfinderAdapter.ts`: Translates `subdomain_discovery` into an `ExecutionRequest`, enforcing `-j` (JSON) and `-silent`.
  - `parsers/SubfinderParser.ts`: Parses raw JSON stdout into structured `Finding` objects.
- **Invariants**: The Execution Core CANNOT decide what to run; it only executes what has passed the approval boundary.

### 3.4. Layer 4: Intelligence Layer (`worker/src/v2/intelligence/`)
- **Responsibility**: Correlate accumulated evidence, build target profiles, and generate attack recommendations.
- **Key Files**:
  - `EvidenceAccumulator.ts`: Ingests and stores all `EvidenceCollection` outputs.
  - `CorrelationEngine.ts`: Deduplicates and combines findings across multiple capabilities.
  - `TargetProfileBuilder.ts`: Synthesizes findings into a coherent `TargetProfile`.
  - `RecommendationEngine.ts`: Applies deterministic rules to emit `AttackRecommendation` objects.
- **Invariants**: Intelligence CANNOT execute capabilities, CANNOT authorize actions, and CANNOT construct executable `CapabilityRequest`s directly.

### 3.5. Layer 5: Active Recon & Egress Boundary (`worker/src/v2/recon/`)
- **Responsibility**: Safely perform network reconnaissance against authorized targets.
- **Key Files**:
  - `policy/PassiveEgressPolicy.ts` (M30): Strict SSRF filter. Normalizes URLs, blocks loopback (`127.0.0.1`, `localhost`), RFC1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and AWS/GCP cloud metadata endpoints (`169.254.169.254`).
  - `active/ActiveReconDocumentProbeRunner.ts` (M38): Sondas documentales (`http.robots.inspect`, `http.security_txt.inspect`).
  - `active/ActiveReconOriginRunService.ts` (M39): Two-pass atomic batch preflight runner.
  - `active/ActiveReconRunExecutionPersistenceService.ts` (M42): Orchestrates execution, local record construction, repository persistence, and defensive reload verification.
- **Invariants**: If any probe in a requested batch fails preflight, the entire batch is aborted with 0 network calls and 0 persistence side-effects.

### 3.6. Layer 6: Comparison & Validation Boundary (`worker/src/v2/comparison/`, `evidence-mapping/`, `validation/`)
- **Responsibility**: Differential HTTP analysis and evidence mapping.
- **Key Files**:
  - `ResponseComparatorService.ts` (M47): Compares baseline vs validation `SafeResponseSnapshot`s (status code, content length, header names, response times).
  - `ComparisonEvidenceMappingService.ts` (M48): Translates differential signals into non-persisted drafts (`EvidenceDraftEnvelope`).
  - `AuthorizedComparisonValidationService.ts` (M49/M56B): Enforces scope boundaries, verified authorization decisions, and lineage continuity, attaching `AuthorizedComparisonValidationProvenance`.
- **Invariants**: Disconnected targets, invalid authorizations, or lineage mismatches fail closed (`blocked_authorization_invalid`, `blocked_lineage_mismatch`).

### 3.7. Layer 7: Evidence Review & Evidence Store (`worker/src/v2/evidence-review/`, `evidence-store/`)
- **Responsibility**: Human review gate for promoted evidence and in-memory evidence storage.
- **Key Files**:
  - `HumanReviewedEvidencePromotionService.ts` (M50): Evaluates human decisions (`approve_evidence`, `reject`, `needs_more_review`). Promotes approved drafts into `EvidenceRecord`s.
  - `ReviewedEvidenceStoreService.ts` (M51): In-memory storage repository (`InMemoryReviewedEvidenceStoreRepository`) with deep mutation-safe cloning.
  - `ReviewedEvidenceReadModel.ts`: Safe query and retrieval of reviewed evidence summaries.
- **Invariants**: Rejected or unreviewed drafts are never persisted.

### 3.8. Layer 8: Candidate Pipeline (`worker/src/v2/evidence-selection/`, `finding-candidate-draft/`, `finding-candidate-promotion/`)
- **Responsibility**: Group reviewed evidence into candidate hypotheses without making vulnerability claims.
- **Key Files**:
  - `ReviewedEvidenceSelectionService.ts` (M52): Queries and selects reviewed evidence by criteria.
  - `ReviewedEvidenceFindingCandidateDraftService.ts` (M53): Groups selected evidence into non-persisted candidate drafts.
  - `ReviewedEvidenceFindingCandidatePromotionService.ts` (M54): Requires human triage decision (`approve_finding_candidate_promotion`) to produce a formal candidate (`ReviewedEvidenceFormalFindingCandidate`).
  - `pipeline-reality-check/CoreCandidatePipelineRealityCheckService.ts` (M55): End-to-end diagnostic proving data continuity across M51 $\rightarrow$ M54.
- **Invariants**: Formal candidates carry explicit non-claims: `noConfirmedVulnerability: true`, `noSeverityRiskOrImpactClaim: true`, `noRemediationAdvice: true`.

### 3.9. Layer 9: Application Services (`worker/src/v2/application/`)
- **Responsibility**: High-level application orchestrators serving external consumers.
- **Key Files**:
  - `AssessmentApplicationService.ts`: Manages session lifecycles and DTO mapping.
  - `ReconToReviewedEvidenceApplicationService.ts` (M57): Vertical pipeline coordinating authorization establishment, active recon, response snapshots, comparison validation, human review, and evidence storage.

---

## 4. Real Data & Execution Flows

### 4.1. The M57 Real Recon-to-Reviewed-Evidence Vertical Flow (`CONFIRMED`)

```text
Operator Command (URL, OperatorId, ReviewDecision)
       │
       ▼
[establishVerifiedAuthorizationDecision]  <─── Validates Actor & Scope Grant
       │
       │ (VerifiedAuthorizationDecision with WeakSet brand)
       ▼
[executeAndPersistActiveReconOriginRun]   <─── Pass 1: Atomic Preflight
       │                                        Pass 2: Adapter Execution (robots / security.txt)
       │                                        Pass 3: Persist & Reload Verification
       │ (PersistedActiveReconRunRecord)
       ▼
[Construct SafeResponseSnapshots]        <─── Baseline Snapshot (200 OK) vs Validation Snapshot (403/Delta)
       │
       ▼
[runAuthorizedComparisonValidation]       <─── Validates Lineage, Scope, & Decision Continuity
       │                                  Emits Provenance & EvidenceDraftEnvelope
       │
       ▼
[evaluateHumanReviewedEvidencePromotion] <─── Evaluates Human Reviewer Decision
       │                                  - If "reject" ──> Halts, saves nothing
       │                                  - If "approve_evidence" ──> Emits EvidenceRecord
       │
       ▼
[saveReviewedEvidence]                   <─── Persists to ReviewedEvidenceStoreRepository
       │
       ▼
ReconToReviewedEvidencePipelineResult (status: 'completed', storedRecordId, evidenceId, lineage)
```

### 4.2. The Candidate Promotion Pipeline (M51 $\rightarrow$ M55) (`CONFIRMED`)

```text
Reviewed Evidence Store (M51)
       │
       ▼
[selectReviewedEvidence] (M52)            ──> Emits ReviewedEvidenceSelectionSet
       │
       ▼
[createReviewedEvidenceFindingCandidateDraft] (M53) ──> Emits Draft (requires_human_triage)
       │
       ▼
[Human Triage Decision]                  ──> Operator approves with explicit attestations
       │
       ▼
[promoteReviewedEvidenceFindingCandidateDraft] (M54) ──> ReviewedEvidenceFormalFindingCandidate
       │                                                 (no confirmed finding, no severity claims)
       ▼
[summarizeReviewedEvidenceFormalFindingCandidate]   ──> Closed safe read model for reports
```

---

## 5. Persistence & Database Audit

### 5.1. Database Schema Divergence (V1 vs V2)

The repository contains two completely separate database architectures:

#### V1 Schema (`worker/src/db/schema.ts` & `web/src/db/schema.ts`) (`CONFIRMED`):
- Relational tables: `users`, `scans`, `vulnerabilities`, `reconProfiles`, `findings`, `authorizations`, `sessions`.
- Anti-patterns present: Stores raw unredacted requests/responses (`requestRaw`, `responseRaw`), arbitrary JSON blobs (`techStack`, `attackSurface`), and unverified severities (`severity: 'critical'`).
- Migrations located in: `worker/drizzle/`.

#### V2 Schema (`worker/src/v2/storage/postgres/schema.ts`) (`CONFIRMED`):
- Designed under Milestone 15/20/41 hybrid architecture (state snapshots + append-only logs).
- Tables strictly prefixed with `v2_`:
  1. `v2_assessment_sessions`: Active session state snapshot (`state_json: jsonb`), version number, and relational indexes (`session_id`, `target_uri`, `lifecycle_status`).
  2. `v2_evidence_records`: Append-only log of immutable `EvidenceCollection`s.
  3. `v2_audit_entries`: Append-only log of operator approvals and rejections.
  4. `v2_approved_request_records`: Append-only log of approved execution requests.
  5. `v2_execution_failure_records`: Append-only log of tool failures.
  6. `v2_active_recon_run_records`: Active recon origin run records with exact-key validation and JSONB payload.
- Migrations located in: `worker/drizzle-v2/` (`0000_last_venus.sql`, `0001_tiresome_warhawk.sql`).
- DB Configuration: `worker/drizzle.v2.config.ts`.

---

## 6. Authentication & Authorization Architecture

### 6.1. Runtime-Established Authorization Brand (ADR-001) (`CONFIRMED`)
- Authorization in FixGuard V2 is enforced via `VerifiedAuthorizationDecision`.
- **Implementation Mechanism**: Module-private `WeakSet<object>` (`_runtimeBrand`).
- **Forgery Resistance**: Structural lookalikes, `structuredClone`, JSON serialization round-trips, `Object.assign`, and spread copies are rejected because the runtime brand resides in memory.
- **Authority Flow**:
  1. Operator passes request to `establishVerifiedAuthorizationDecision()`.
  2. The service validates actor ID format, timestamp sanity, and `AuthorizedScopeGrant`.
  3. The decision object is stamped into the module-private `WeakSet`.
  4. Downstream services verify the brand using `isRuntimeEstablishedVerifiedAuthorizationDecision()`.

---

## 7. Evidence & Finding Candidate Architecture

### 7.1. Evidence Record Anatomy (M45 / M50) (`CONFIRMED`)
An `EvidenceRecord` contains:
- `contractVersion: "fixguard-evidence-boundary/v0"`
- `evidenceId`, `scanId`, `indicatorId`, `collectedAt`, `collectedBy`, `evidenceType`, `strength`
- `baseline` / `attackOrValidation` snapshots (redacted, hashes of bodies/headers)
- `difference` (structural diff: status code, content length, JSON keys)
- `redaction: { isRedacted: true, redactionMethod: string }`
- `classification`: 6 flags strictly set to `false` (`createsRealFindings`, `confirmsVulnerabilities`, `makesRiskClaims`, `makesSeverityClaims`, `makesImpactClaims`, `createsPersistedEvidence`).

### 7.2. Candidate Semantics (M54) (`CONFIRMED`)
A formal finding candidate (`ReviewedEvidenceFormalFindingCandidate`) is **NOT** a confirmed vulnerability. It is a structured hypothesis tied to reviewed evidence references with explicit attestations that no exploitability, severity, or remediation claims have been made.

---

## 8. Technology Stack & Dependencies Audit

| Component | Technology | Version | Usage / Notes |
|---|---|---|---|
| **Runtime** | Node.js | v20+ / v25+ | ES Modules (`"type": "module"`) |
| **Language** | TypeScript | `^6.0.3` (worker), `^5` (web) | Strict mode, `tsconfig.v2.json` |
| **Package Manager**| npm | v10+ | Root, `worker/`, and `web/` workspaces |
| **Database** | PostgreSQL / Neon | Serverless | `@neondatabase/serverless` `^1.1.0` |
| **ORM / Migration**| Drizzle ORM | `^0.45.2` (ORM), `^0.31.10` (Kit) | Dual configs: `drizzle.config.ts`, `drizzle.v2.config.ts` |
| **Backend (V1)** | Express | `^5.2.1` | Legacy server on port 4000 (`worker/src/index.ts`) |
| **Frontend (V1)** | Next.js / React | Next 16.2.9 / React 19.2.4 | Dashboard on port 3000 (`web/`) |
| **Testing** | Node assert / tsx | `tsx ^4.22.4` | DB-free regression smoke ladder |
| **Dead Dep** | `@upstash/redis` | `^1.38.0` | `CONFIRMED`: In package.json, but 0 imports in codebase |
| **V1-Only Dep** | `@ai-sdk/google` | `^3.0.80` | `CONFIRMED`: Used only in V1 `ExposureIntelligenceEngine.ts` |
| **V1-Only Dep** | `playwright` | `^1.60.0` | `CONFIRMED`: Used only in V1 crawler |
| **V1-Only Dep** | `wappalyzer` | `^7.0.3` | `CONFIRMED`: Used only in V1 tech stack profiler |

---

## 9. Testing & Quality Assurance Ladder

FixGuard V2 uses a single-command test ladder to guarantee zero regressions:

```bash
npm run check:v2
```

This script executes:
1. `npm run typecheck:v2`: Runs `tsc -p tsconfig.v2.json` (zero type errors allowed).
2. `npm run smoke:v2`: Sequentially runs **19 consolidated smoke suites**:
   - `smoke:v2:verified-authorization-active-recon` (M56A)
   - `smoke:v2:runtime` (M14, M21, M25)
   - `smoke:v2:storage` (M17, M20)
   - `smoke:v2:application` (M24)
   - `smoke:v2:capabilities` (M27, M28, M29)
   - `smoke:v2:recon` (M30, M31, M33, M34, M36, M38, M39, M40, M42, M43, M44)
   - `smoke:v2:evidence-boundary` (M45)
   - `smoke:v2:scope-policy` (M46)
   - `smoke:v2:response-comparator` (M47)
   - `smoke:v2:comparison-evidence-mapping` (M48)
   - `smoke:v2:authorized-comparison-validation` (M49)
   - `smoke:v2:lineage-comparison-continuity` (M56B)
   - `smoke:v2:human-reviewed-evidence-promotion` (M50)
   - `smoke:v2:reviewed-evidence-store` (M51)
   - `smoke:v2:reviewed-evidence-selection` (M52)
   - `smoke:v2:finding-candidate-draft` (M53)
   - `smoke:v2:finding-candidate-promotion` (M54)
   - `smoke:v2:core-candidate-pipeline-reality-check` (M55)
   - `smoke:v2:recon-to-reviewed-evidence` (M57)
