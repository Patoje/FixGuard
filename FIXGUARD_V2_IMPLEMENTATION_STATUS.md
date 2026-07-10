# FixGuard V2 — Implementation Status

> This document tracks the current state of the V2 migration.
> It is updated as milestones are completed.
> For architectural decisions and frozen contracts, see: FIXGUARD_V2_ARCHITECTURE.md

---

## Quick Reference

| Layer | Status |
|---|---|
| Execution Core — Contracts | FROZEN |
| Execution Core — ProcessRunner | FROZEN |
| Execution Core — Subfinder Adapter | FROZEN |
| Execution Core — Subfinder Parser | FROZEN |
| Execution Core — Orchestrator (minimal) | FROZEN |
| Execution Core — ToolDefinition Registry | COMPLETE |
| Intelligence Layer | FOUNDATION COMPLETE |
| Approval Boundary | FROZEN |
| Second Capability | COMPLETE |
| End-to-End Smoke Test | PASSING |
| V1 Legacy System | UNTOUCHED (intentional) |

---

## Completed Components

### worker/src/v2/core/ExecutionContracts.ts
**Status:** Complete and frozen.

Defines the foundational data contracts for the entire V2 execution pipeline:
- `TargetContext` — extensible target descriptor (uri, headers, env)
- `CapabilityRequest` — input to the execution core (capability string, TargetContext, config)
- `ExecutionRequest` — instruction passed to the runner (binary, args[], env, timeoutMs)
- `RawExecutionOutput` — captured result (stdout, stderr, exitCode, durationMs, timedOut)

These types must not be modified without a formal architectural review.

---

### worker/src/v2/core/Evidence.ts
**Status:** Complete and frozen.

Defines the output contracts of the execution pipeline:
- `Finding` — a single structured observation (id, type, severity, title, description, target, evidence, confidence, metadata)
- `EvidenceCollection` — the complete output of one execution cycle (findings[], metadata)

These types must not be modified without a formal architectural review.

---

### worker/src/v2/core/ProcessRunner.ts
**Status:** Complete.

- Defines the `ProcessRunner` interface: `execute(request: ExecutionRequest): Promise<RawExecutionOutput>`
- Implements `LocalProcessRunner`:
  - Spawns binaries using `child_process.spawn` with `shell: false` (no string interpolation, no shell injection)
  - Collects stdout and stderr independently
  - Captures exit code and wall-clock duration
  - Handles timeout via SIGTERM and sets `timedOut: true` in output
  - ProcessRunner receives `ExecutionRequest.env` from adapters
  - Runner performs no tool-specific environment configuration

---

### worker/src/v2/adapters/ToolAdapter.ts
**Status:** Complete and frozen.

Defines the `ToolAdapter` interface:
- `readonly capability: string`
- `prepare(request: CapabilityRequest): ExecutionRequest`
- `validate(config: Record<string, unknown>, targetUri: string): ValidationResult`

Also defines `ValidationResult`:
- `isValid: boolean`
- `errors: string[]`

---

### worker/src/v2/adapters/SubfinderAdapter.ts
**Status:** Complete. First V2 adapter implementation.

Implements `ToolAdapter` for the `subdomain_discovery` capability:
- Extracts bare domain from any valid URL or raw domain string
- Enforces `-j` (JSON output) unconditionally — this is a hard contract, not a config option
- Enforces `-silent` to suppress progress noise
- Sets `timeoutMs: 120000` (2 minutes)
- Validates that the target is a domain name and not a bare IP address

The `-j` flag must never be made optional. Removing it breaks the parser contract.

---

### worker/src/v2/adapters/ToolAdapterRegistry.ts
**Status:** DEPRECATED.

Current state:
- Unused by V2 code.
- Retained temporarily only for V1 proofOfConcepts.
- Will be deleted once V1 dependencies are removed.

---

### worker/src/v2/parsers/Parser.ts
**Status:** Complete and frozen.

Defines the `Parser` interface:
- `parse(output: RawExecutionOutput): EvidenceCollection`

---

### worker/src/v2/parsers/SubfinderJsonParser.ts
**Status:** Complete. First V2 parser implementation.

Implements `Parser` for Subfinder's newline-delimited JSON output (`-j` flag):
- Splits stdout by newline and parses each line as a JSON record independently
- Maps each valid record to a `Finding` with `type: 'subdomain_discovery'`, `severity: 'info'`, `confidence: 0.9`
- Skips malformed lines without crashing — parse errors are recorded in `EvidenceCollection.metadata`
- Returns empty `EvidenceCollection` for empty stdout (not an error condition)

---

### worker/src/v2/core/MinimalOrchestrator.ts
**Status:** COMPLETE and FROZEN.

Current behavior:
1. Accepts a `CapabilityRequest`
2. Resolves a `ToolDefinition` from `ToolRegistry.resolve()`
3. Validates the request via `adapter.validate()`
4. Calls `adapter.prepare()` to produce an `ExecutionRequest`
5. Calls `LocalProcessRunner.execute()` to produce `RawExecutionOutput`
6. Calls `parser.parse()` to produce `EvidenceCollection`
7. Returns `EvidenceCollection` to the caller

**Final Architecture Flow:**
CapabilityRequest
→ ToolRegistry.resolve()
→ ToolDefinition
→ Adapter.prepare()
→ Runner.execute()
→ Parser.parse()
→ EvidenceCollection

---

## Current Migration State

### V1 Legacy System

The V1 system (`worker/src/scanner/`, `worker/src/recon/`, `worker/src/targetedOrchestrator.ts`) is **intentionally untouched**.

It remains in production use during the V2 migration.
V1 files contain pre-existing TypeScript errors that are **not V2 issues** and must not be fixed as part of V2 work.

The V1-to-V2 migration path is additive, not destructive:
- V2 is built alongside V1 in `worker/src/v2/`
- Individual capabilities migrate when their V2 equivalents are proven
- V1 components are deprecated only when V2 coverage is confirmed complete

### TypeScript Compilation State

V2 files (`worker/src/v2/**`) compile with zero TypeScript errors.
The overall `npx tsc --noEmit` reports failures due to pre-existing V1 errors only.

Pre-existing V1 errors are documented separately and are not a V2 concern.

---

## Completed Milestones

### Milestone 0 — Architecture Design (DONE)
- Execution Core boundaries defined and frozen
- Intelligence Layer designed
- Approval Boundary designed
- Full lifecycle reviewed and validated
- FIXGUARD_V2_ARCHITECTURE.md created

### Milestone 1 — V2 Core Isolation (DONE)
- `worker/src/v2/` namespace established
- Zero imports from V1 legacy code
- All core contracts defined in TypeScript with no `any` types

### Milestone 2 — Subfinder Vertical Slice (DONE)
- End-to-end flow proven: CapabilityRequest → Adapter → Runner → Parser → EvidenceCollection
- No shell string interpolation at any point
- No V1 code touched or invoked
- TypeScript clean within v2 namespace

### Milestone 3 — ToolDefinition Registry (DONE)
- `ToolDefinition` created as the single wiring point.
- `ToolRegistry` implemented focusing strictly on resolution and static requirements.
- Multiple tools per capability supported (priority-based).
- `MinimalOrchestrator` refactored to depend only on `ToolRegistry`.
- `ToolAdapterRegistry` deprecated.
- Execution Core now architecturally FROZEN.

### Milestone 41 — Postgres Active Recon Run Persistence (IMPLEMENTED, REAL DB SMOKE PENDING)
- Implemented real Postgres table `v2_active_recon_run_records` and migration via Drizzle.
- Added `PostgresActiveReconRunRepository` implementing `ActiveReconRunRepository`.
- Reuses robust strict safety validation from M40 both before DB insert and upon reading from DB.
- Implemented strict safety bounds on reading invalid/corrupt database records.
- The opt-in Postgres smoke is implemented and was verified to skip safely with no env, fail closed on partial/wrong env, and remain excluded from defaults. Real DB insert/get/list/reload validation is pending until `FIXGUARD_PG_TEST_URL` and the explicit confirmation env are provided.
- Maintained zero UI/API, findings, evidence, scanner dependencies, and real adapter modifications.

---

### Milestone 42 — Active Recon Execution Persistence Service (IMPLEMENTED, PENDING AUDIT)
- Composes M39 active recon origin execution with M40 persistence validation into a complete safe run -> persist -> reload boundary.
- Defines closed M42 result envelope with fixed safe persistence error messages to guarantee no raw unsafe exceptions leak.
- Supports DB-free smoke proving run -> persist -> reload with fake adapters and in-memory repository.
- Supports explicitly opt-in real smoke proving run -> persist -> reload with guarded real adapters and in-memory repository.
- Strictly validates real environment and guards real adapter instantiation.
- Remains repository-generic, introducing zero Postgres schema/migration changes in M42.
- Maintains zero UI/API, findings, evidence, and scanner dependencies.

---

## Next Milestones

---

### Milestone 43 — Active Recon Run Read Model + Safe Report Snapshot (IMPLEMENTED, PENDING AUDIT)

*   `v2/recon/active/ActiveReconRunReadModelContracts.ts`
*   `v2/recon/active/ActiveReconRunReadModelService.ts`
*   `v2/recon/active/ActiveReconRunSafeReportContracts.ts`
*   `v2/recon/active/ActiveReconRunSafeReportService.ts`
*   `v2/smoke/milestone43_active_recon_run_read_model_smoke.ts`

### Milestone 44 — Active Recon Application Use Cases Boundary (IMPLEMENTED, PENDING AUDIT)

*   `v2/recon/active/ActiveReconApplicationUseCaseContracts.ts`
*   `v2/recon/active/ActiveReconApplicationUseCaseService.ts`
*   `v2/smoke/milestone44_active_recon_application_use_cases_smoke.ts`

### Milestone 45 — Evidence Boundary + Finding Candidate Promotion Contracts DB-free (IMPLEMENTED, PENDING AUDIT)

*   `v2/evidence/EvidenceBoundaryContracts.ts`
*   `v2/evidence/EvidenceBoundaryService.ts`
*   `v2/evidence/README.md`
*   `v2/smoke/milestone45_evidence_boundary_smoke.ts`

### Milestone 46 — Layered Authorized Scope + Permission Policy Boundary DB-free (IMPLEMENTED, PENDING AUDIT)

M46 defines a DB-free, pure-function boundary for representing and evaluating layered authorization and scope policy decisions. M46 represents the "Humans authorize" part of the `Tools execute. Intelligence decides. Humans authorize.` architecture principle.

*   `v2/scope/AuthorizedScopeContracts.ts`
*   `v2/scope/AuthorizedScopePolicyService.ts`
*   `v2/scope/README.md`
*   `v2/smoke/milestone46_authorized_scope_policy_smoke.ts`

Key properties:

*   M46 defines DB-free authorized scope and permission policy contracts.
*   M46 separates authorization declaration (what a human has permitted) from per-action permission decisions (whether a specific action is allowed).
*   M46 does not verify domain ownership.
*   M46 does not execute tools.
*   M46 does not touch the network.
*   M46 does not persist scope grants.
*   M46 does not create findings, evidence, severity, risk or impact claims.
*   M46 denies destructive operations at all times (`destructiveOperations` is always `false`; `destructive_operation` actionKind and `destructive` intensity are always denied).
*   M46 does not replace M30 egress policy. Future active execution must pass both M46 authorized-scope/permission decision and M30/M33 egress policy decision.
*   Caller-supplied `requiredPermission` is never trusted. The service always derives the required permission from `actionKind` and `intensity`, and rejects any mismatch.
*   All `ScopePolicyDecision` outputs are sanitized: IDs are validated before embedding; unsafe values use sentinels (`invalid_decision_id`, `invalid_grant_id`, etc.); forbidden terms never appear in decision output.
*   Path matching is explicit: `exact` (equality) and `prefix` (path + `/` separator); `/api` does NOT match `/apiary`. No glob or regex.
*   Decision evaluation uses a fixed 15-step deterministic precedence order.

### Milestone 47 — Response Comparator Core DB-free (IMPLEMENTED, PENDING AUDIT)

M47 defines a DB-free, pure-function boundary for comparing sanitized HTTP response snapshots and producing sanitized comparison results.

*   `v2/comparison/ResponseComparatorContracts.ts`
*   `v2/comparison/ResponseComparatorService.ts`
*   `v2/comparison/README.md`
*   `v2/smoke/milestone47_response_comparator_smoke.ts`

Key properties:

*   M47 computes differences in status code, content length, response time, body hash, header names, JSON structure, redirect, and auth state.
*   M47 derives comparison signal strength (`none`, `weak`, `moderate`, `strong`) — not severity, risk, or impact.
*   M47 produces `EvidenceMappingHint` as a non-persisted pointer toward a future M45 `EvidenceRecord` type.
*   M47 does not execute network requests or tools. All inputs must be pre-captured snapshots.
*   M47 does not import M45 types or build `EvidenceRecord` / `FindingCandidateRecord`. M47 is independent of M45.
*   M47 does not persist any data.
*   M47 does not create findings or confirm vulnerabilities.
*   M47 does not make severity, risk, or impact claims.
*   All outputs contain explicit flags asserting no vulnerability, finding, evidence, or severity claims.
*   All IDs and metadata timestamps are validated. Unsafe values are replaced with sentinels (e.g. `invalid_comparison_id`, `1970-01-01T00:00:00.000Z`) to prevent echoing raw user inputs or secrets in error outputs or valid outputs.
*   Raw secrets, tokens, auth headers, cookies, or any raw request/response text are forbidden from appearing in the comparison result or text arrays.

### Milestone 48 — Response Comparison to Evidence Mapping Boundary DB-free (IMPLEMENTED, PENDING AUDIT)

M48 defines a DB-free boundary for mapping safe response comparison results (M47) to non-persisted evidence drafts (M45 format hints).

*   `v2/evidence-mapping/ComparisonEvidenceMappingContracts.ts`
*   `v2/evidence-mapping/ComparisonEvidenceMappingService.ts`
*   `v2/evidence-mapping/README.md`
*   `v2/smoke/milestone48_comparison_evidence_mapping_smoke.ts`

Key properties:

*   M48 consumes safe `ResponseComparisonResult` objects from M47.
*   M48 produces `EvidenceMappingDecision` and `EvidenceDraftEnvelope`.
*   M48 requires human review for all mappings (`requiresHumanReview: true`).
*   M48 produces a "draft" (`EvidenceDraftEnvelope`), not a persisted record.
*   M48 does not create findings or finding candidates.
*   M48 makes no claims about vulnerability, severity, risk, or impact.
*   M48 operates entirely independently and does NOT call or import services from M45 or M47. It only uses shared safe types.
*   M48 evaluates mapping mode alignment tightly (e.g. `sourceComparisonMode === time_based_difference` is required for `time_based_signal_to_evidence`).
*   All output fields are scanned for forbidden contents (e.g. `authorization`, `password`, `confirmed vulnerability`). Unsafe values cause the mapping to be rejected or replaced with sentinels.

### Milestone 4 — Intelligence Layer Foundation (DONE)
**Goal:** Implement the first version of the Intelligence Layer.

Components to create (in `worker/src/v2/intelligence/`):
- `EvidenceAccumulator.ts` — session-scoped evidence ledger
- `CorrelationEngine.ts` — deduplication and signal combination
- `TargetProfileBuilder.ts` — semantic interpretation via ProfilerRules
- `RecommendationEngine.ts` — produces AttackRecommendations via RecommendationRules
- `TargetProfile.ts` — the central intelligence contract
- `AttackRecommendation.ts` — the frozen output contract

First rules to implement:
- ProfilerRule: subdomain → infrastructure signal
- RecommendationRule: live subdomain → suggest HTTP probing capability

**Verification:** Feeding a Subfinder `EvidenceCollection` into the Intelligence Layer produces a `TargetProfile` and at least one `AttackRecommendation` for HTTP probing.

---

### Milestone 5 — Approval Boundary Foundation (DONE)
**Goal:** Implement the structural human approval layer.

Components created (in `worker/src/v2/approval/`):
- `ApprovalContracts.ts`
- `RecommendationInbox.ts`
- `ApprovalGateway.ts`
- `IntentTranslator.ts`
- `AuditLog.ts`

**Verification:** An `AttackRecommendation` can be approved via the `ApprovalGateway` and produces a valid `CapabilityRequest` with a `sourceRecommendationId` field that traces back to the original recommendation.

---

### Milestone 6 — Second Capability (DONE)
**Goal:** Prove the architecture is genuinely extensible by adding a second tool.

**Capability implemented:** `http_probe` (using `httpx`)

Files created:
- `worker/src/v2/adapters/HttpxAdapter.ts`
  - implements capability: `http_probe`
  - uses binary: `'httpx'`
  - uses discrete args[]
  - single-target only via `-u <targetUri>`
  - enforces JSON output via `-json`
  - does not execute or parse
  - validation rejects malformed/multi-target/shell-control inputs
- `worker/src/v2/parsers/HttpxJsonParser.ts`
  - parses JSONL stdout
  - emits only `http_live_host` findings
  - skips failed records
  - skips malformed JSON lines safely
  - records parse errors in metadata
  - stores scheme and raw record in finding metadata/evidence
- `worker/src/v2/intelligence/rules/HttpProbeProfilerRule.ts`
  - reasons only over `finding.type === 'http_live_host'`
  - never references the tool name
  - adds only semantic `'http_service_detected'` to exposedCapabilities
  - stores concrete service details in TargetProfile.metadata.httpServices[]
  - deduplicates services by URL
- `worker/src/v2/composition/createV2ToolRegistry.ts`
  - introduces the first formal V2 composition root
  - wires subdomain_discovery and http_probe ToolDefinitions
  - does not modify ToolRegistry, ToolDefinition, or MinimalOrchestrator

**Verification:** The `MinimalOrchestrator` and `ToolRegistry` required zero changes. Only new files were added.

---

## Known Technical Debt

No active V2 architectural technical debt is currently tracked.

V1 TypeScript errors remain intentionally out of scope for V2 migration work.

*Operational / Repository Hygiene Note:*
- `worker/src/v2/` should be committed/tracked cleanly so future git diff audits can prove file boundaries precisely.

---

## Forbidden Shortcuts

These shortcuts will not be accepted regardless of time pressure.

1. **Importing V1 code into V2** — No V2 file may import from `worker/src/scanner/`, `worker/src/recon/`, or any V1 path. If shared logic is needed, it must be extracted into a shared utility and kept separate from both V1 and V2.

2. **Using shell: true in spawn()** — All process execution must use `shell: false` with explicit argument arrays. No exceptions. Shell interpolation is a security violation in a security tool.

3. **Adding tool names to Intelligence rules** — Any rule inside the Intelligence Layer that references a specific binary name (subfinder, nuclei, katana, etc.) is an architectural violation. All rules must reason over capability names and profile concepts only.

4. **Making AttackRecommendation executable** — The `AttackRecommendation` type must never gain fields for binary paths, argument arrays, or direct execution parameters. It is a human-facing proposal record.

5. **Skipping ToolDefinition and coupling Adapter to Parser directly** — Adapters and parsers must remain mutually unaware. They are wired exclusively through the `ToolDefinition` record. No adapter may import a parser or vice versa.

6. **Bypassing Approval Boundary for attack capabilities** — No code path may programmatically create an attack `CapabilityRequest` without a corresponding `ApprovalDecision`. Reconnaissance capabilities may be initiated programmatically. Attack capabilities may not.

7. **Modifying V1 files to accommodate V2** — V1 files must not be changed to support V2 needs. If V2 needs something V1 has, extract it into a shared utility. If that is not possible, reimplement it cleanly in V2.

---

### Milestone 6.5 — End-to-End V2 Smoke Test (DONE)
**Goal:** Verify the first complete V2 loop.

This smoke test successfully validated the first full V2 loop:

`subdomain_discovery`
→ EvidenceCollection
→ Intelligence
→ AttackRecommendation: `http_probe`
→ Approval Boundary
→ CapabilityRequest
→ `http_probe`
→ new EvidenceCollection
→ updated TargetProfile

**Files created:**
- `worker/src/v2/smoke/milestone6_5_smoke.ts`
  - standalone smoke/demo harness
  - not a production entrypoint
  - executable from `worker/` with: `npx tsx src/v2/smoke/milestone6_5_smoke.ts`

**Runtime result:**
- `subfinder` and `httpx` preflight checks passed
- `subdomain_discovery` returned zero findings for `https://example.com`
- deterministic fallback trigger was injected
- Intelligence produced `http_probe` recommendation
- Approval Boundary produced approved `CapabilityRequest`
- `http_probe` returned 1 live host
- second intelligence pass enriched `TargetProfile.metadata.httpServices`
- smoke test completed successfully

---

### Milestone 7 — V2 Runtime Integration Planning (DONE)
**Goal:** Plan how V2 will be invoked from the real application flow without turning the smoke harness into production code.
**Status:** Completed via FIXGUARD_V2_RUNTIME_INTEGRATION_PLAN.md

---

### Milestone 8 — V2 Runtime Foundation Implementation (DONE)
**Goal:** Implement the thin application-service coordinator.
- Implements `V2AssessmentRuntime` and `V2AssessmentSession` (in-memory).
- `AssessmentState` defines strict, serializable boundaries with transient `CapabilityRequest`s.
- `milestone8_runtime_smoke.ts` validates the end-to-end loop via runtime methods.

---

### Milestone 8.5 — Runtime Boundary Audit / Hardening (DONE)
**Goal:** Harden the runtime boundaries before adding persistence or APIs.
**Focus:**
- `cloneState` helper to ensure safe state snapshotting.
- Stable intent key helper for recommendation deduplication.
- Smoke assertion against raw `approvedRequests` to prevent executable leakage into state.
- Runtime README clearly defining limitations (in-memory only, no API/UI/persistence).

### Milestone 9 — Persistence / Storage Contract Planning (DONE)
**Goal:** Design the storage boundaries and rules.
**Status:** Completed via FIXGUARD_V2_PERSISTENCE_CONTRACT_PLAN.md

---

### Milestone 10 — Storage Port Contracts (DONE)
**Goal:** Define the TypeScript storage contracts.
- `AssessmentRepository` created.
- Storage never creates `CapabilityRequest` or calls runtime services.
- `StaleStateError` added for future optimistic locking.

### Milestone 11 — In-Memory AssessmentRepository Adapter (DONE)
**Goal:** Implement the storage contracts safely in memory.
- `InMemoryAssessmentRepository` created.
- Deep cloning prevents external state mutation.
- Strict session-scoping applied to all append methods.
- Optimistic concurrency (expectedVersion) implemented and throwing StaleStateError.
- Storage smoke test asserts behavior independently from runtime.

### Milestone 12 — Runtime Storage Integration (DONE)
**Goal:** Safely integrate V2AssessmentRuntime with AssessmentRepository.
- Constructor injection used for `AssessmentRepository`.
- `InMemoryAssessmentRepository` is the default.
- Optional constructor injection used for `MinimalOrchestrator` to enable deterministic, storage-boundary-respecting smoke tests without direct repository patching.
- Runtime methods involved in persistence are now `async` (`Promise<AssessmentState>`).
- Persistence is awaited inline directly after the in-memory state transition completes.
- Strict optimistic versioning enforced: no dynamic `expectedVersion` repair, and no background queue.
- Repository failures reject/throw through async runtime methods naturally.
- All state transitions correctly persist full snapshots and append appropriate evidence/audit/approval/failure records.
- Zero raw `CapabilityRequest` objects are persisted.

### Milestone 13 — Runtime Session Resume / Repository-backed Session Lookup (DONE)
**Goal:** Add snapshot-only repository-backed session loading to `V2AssessmentRuntime`.
- Added `V2AssessmentSession.fromState` to rehydrate active session from a snapshot (deep clone, no version increment).
- Added `loadSession(sessionId)` to perform repository-backed snapshot load.
- Active collision handled: returns active session directly.
- Missing session handled: returns undefined.
- Strict optimistic versioning preserved across loads.
- No auto-execution, no append-only log replay, no `CapabilityRequest` reconstruction.
- Deterministic smoke test implemented.
- No DB/Drizzle/API/UI/queues added.

### Milestone 14 — Runtime Lifecycle Mutation Guards (DONE)
**Goal:** Add explicit lifecycle mutation guards to `V2AssessmentRuntime`.
- Created `RuntimeLifecycleError` for invalid transitions.
- Added explicit method-specific guards (`assertCanStartInitialRecon`, `assertCanRunIntelligence`, etc.).
- Protected terminal (`completed`, `failed`) and running states from mutations.
- Ensured invalid attempts throw immediately without side effects (no mutation, no persistence, no appends, no execution).
- Created deterministic smoke test (`milestone14_runtime_lifecycle_guards_smoke.ts`) verifying that all 5 mutating methods are rejected for all terminal (`completed`, `failed`) and running (`initial_execution_running`, `intelligence_running`, `approved_execution_running`) states.
- No new DB/Drizzle/API/UI/queues added.

### Milestone 15 — Drizzle/PostgreSQL Persistence Planning (DONE)
**Goal:** Write a precise durable persistence plan for a future Drizzle/PostgreSQL-backed `AssessmentRepository`.
- Created `FIXGUARD_V2_DRIZZLE_POSTGRES_PLAN.md`.
- Explicitly defined a hybrid persistence model (snapshot + append-only logs).
- Defined conceptual schema design separating JSONB payload storage from relational columns.
- Documented strict optimistic concurrency and non-executable persistence rules.
- Documented transaction strategy and gap analysis.
- **No implementation code, schemas, or migrations were written (planning only).**

### Milestone 16 — Drizzle/PostgreSQL Schema Implementation (DONE)
**Goal:** Implement the pg-core schema definitions for V2 AssessmentRepository tables.
- Created `schema.ts` defining 5 core tables matching the Milestone 15 plan exactly.
- Enforced strict structural types leveraging `AssessmentState`, `EvidenceCollection`, etc via Drizzle's `$type`.
- Established required compound indexes for lookup optimization.
- **Implemented schema only.** (No adapter, no DB client, no migrations, no runtime integration).

### Milestone 17 — AssessmentRepository Conformance Suite (DONE)
**Goal:** Create a reusable conformance suite that validates any `AssessmentRepository` implementation against the same behavioral contract.
- Created `AssessmentRepositoryConformanceSuite.ts`.
- Validates 21 explicit behaviors, including session isolation, StaleStateError, snapshot loading, external mutation protection, and append-only constraints.
- Created `milestone17_repository_conformance_smoke.ts` and successfully verified the existing `InMemoryAssessmentRepository`.
- Did not modify production storage logic, schemas, or runtime execution.

### Milestone 18 — PostgresAssessmentRepository Adapter (DONE)
**Goal:** Implement a Drizzle/PostgreSQL-backed `AssessmentRepository` adapter that satisfies the existing `AssessmentRepository` contract.
- Safely patched `schema.ts` to add a DB-generated `insertion_order` column and corresponding index to the four append-only tables to support deterministic insertion ordering.
- Implemented `PostgresAssessmentRepository.ts` accepting an injected Drizzle `db` connection.
- Deep clones and rigorously rejects JSON objects containing executable keys (e.g. `binary`, `command`, `args`, `env`, `shell`).
- Strictly enforces optimistic concurrency explicitly returning `StaleStateError` on failure (using robust `.returning()` checks rather than driver-specific rowCount heuristics).
- Properly includes `created_at_ms` in all update and upsert conflict paths.
- Exported from the postgres namespace only. 
- Fully compiles, no real DB connectivity or migrations added yet. Note: The Postgres adapter is NOT yet ready to run the M17 conformance suite unchanged. Real Postgres conformance requires a future DB test setup/migration milestone that handles creating parent session rows (due to FK constraints on append tables) or adapts setup/teardown appropriately.

### Milestone 19 — Postgres Migration + DB Conformance Smoke (DONE)
**Goal:** Add env-gated DB conformance testing support for the Postgres adapter.
- Created `worker/drizzle.v2.config.ts` to cleanly isolate V2 schemas from V1.
- Generated real V2 Drizzle migration artifacts under `worker/drizzle-v2/`.
- Created `milestone19_postgres_repository_conformance_smoke.ts` to run the suite against Postgres.
- Milestone 19 adds V2-specific migrations and an env-gated Postgres repository conformance smoke. The configured Neon test branch run passed with `FIXGUARD_PG_TEST_URL` and `FIXGUARD_PG_TEST_ALLOW_DESTRUCTIVE=1`. DB-free regression smokes and the missing-env skip path also pass. Runtime integration with Postgres remains future work. Postgres is not the runtime default, and no production DB client/composition exists yet.
- Migration metadata is explicitly isolated from legacy Drizzle by using a V2-specific namespace (`drizzle_v2` / `__drizzle_migrations_v2`).
- Adapted `AssessmentRepositoryConformanceSuite.ts` with test-layer hooks (`beforeEachCase`, `afterEachCase`, `seedParentSession`) to handle schema FK dependencies without polluting production persistence logic.
- Runtime integration remains untouched and defaults to `InMemoryAssessmentRepository`.

### Milestone 20 — Persistence Transaction Boundary (DONE)
**Goal:** Add explicit repository transaction-boundary support before any runtime Postgres integration.
- Created `TransactionalAssessmentRepository.ts` as an optional extension to `AssessmentRepository`.
- Added `withTransaction` deep-clone rollback implementation to `InMemoryAssessmentRepository`.
- Added `withTransaction` using Drizzle's `db.transaction` to `PostgresAssessmentRepository`.
- Created `AssessmentRepositoryTransactionConformanceSuite.ts` to verify commit, rollback (snapshot + append), and `StaleStateError` rollback behaviors.
- Created `milestone20_repository_transaction_smoke.ts` and `milestone20_postgres_repository_transaction_smoke.ts`.
- InMemory transaction conformance passed.
- The configured Neon Postgres transaction smoke passed with `FIXGUARD_PG_TEST_URL` and `FIXGUARD_PG_TEST_ALLOW_DESTRUCTIVE=1` using the transaction-capable Neon serverless Pool driver.
- Runtime integration remains out of scope. Postgres is not the runtime default, and no production DB client/composition exists yet.
- Nested transactions remain out of scope for M20.

### Milestone 21 — Runtime Transaction Adoption (DONE)
**Goal:** Update `V2AssessmentRuntime` to use optional repository transactions for multi-write flows.
- Added `isTransactionalAssessmentRepository` type guard to `TransactionalAssessmentRepository.ts`.
- Added `runWithRepositoryTransactionIfAvailable` helper to `V2AssessmentRuntime.ts`.
- Wrapped `startInitialRecon`, `approveRecommendation`, and `rejectRecommendation` in transactions to ensure snapshot and append-only records commit atomically.
- Ensured `StaleStateError` propagates unchanged and triggers rollbacks.
- Verified lifecycle guard semantics remain unchanged (they perform no writes and prevent execution).
- Created DB-free `milestone21_runtime_transaction_smoke.ts` to prove transactional commits, rollbacks on append failures, and non-transactional fallback.
- Postgres transaction runtime integration remains future work (not the default repository).

---




## Intelligence Layer Rule

The Intelligence Layer may transform evidence into understanding.
It may never transform understanding directly into execution.

### Milestone 22 - Explicit Postgres Runtime Composition Boundary (DONE)
**Goal:** Add an explicit, opt-in composition boundary for Postgres without polluting runtime core.
- Added \worker/src/v2/runtime/composition/PostgresV2RuntimeComposition.ts\.
- Exposed \createPostgresBackedV2Runtime\ and \createPostgresBackedV2RuntimeFromEnv\.
- Enforced strict env opt-in: \FIXGUARD_V2_RUNTIME_REPOSITORY=postgres\, \FIXGUARD_V2_ENABLE_POSTGRES_RUNTIME=1\, and \FIXGUARD_V2_DATABASE_URL\.
- Used Neon serverless Pool driver for full transaction compatibility.
- Ensured Postgres is explicitly NOT the runtime default.
- Added \worker/src/v2/smoke/milestone22_postgres_runtime_composition_smoke.ts\ with safe-by-default behavior (skips if env vars, destructive guard, or explicit test branch confirmation missing).
- Runtime remains completely repository-agnostic and free of DB client imports.
- Production API/UI/queue integration utilizing this boundary remains future work.

---



### Milestone 23 - DB-Proven Postgres Runtime Composition Validation (DONE)
**Goal:** Validate M22 composition boundary against a real Postgres database.
- Milestone 23 DB-proven validation passed against a configured disposable Neon test branch.
- This proves explicit Postgres runtime composition works end-to-end with a real DB.
- It proves:
  - V2 migrations/conformance through M19.
  - Postgres-backed runtime creation through composition.
  - deterministic stub orchestration, no real tools/scanners.
  - snapshot persistence to Postgres.
  - independent reload from a fresh runtime/composition.
  - append-only evidence row persistence in `v2_evidence_records`.
  - expected finding type `subdomain_discovery`.
  - V2-only cleanup.
  - pool close behavior.
- Postgres remains explicit opt-in.
- Postgres is still not runtime default.
- No production API/UI/queue/worker integration exists yet.
- This is test-branch DB proof, not a production readiness claim.
- **Safety Note:** The DB URL must never be committed or documented. Because a DB connection string was exposed during manual validation, the disposable Neon branch/password should be deleted or rotated after validation. Do not include the actual URL in any file.

---
### Milestone 24 - Application Service Boundary (DONE)
**Goal:** Add a narrow application-layer boundary that future API/UI/queue/worker code can call safely.
- Added `worker/src/v2/application/AssessmentApplicationService.ts`.
- Added `worker/src/v2/application/ApplicationDtos.ts` with safe DTO mappings that explicitly strip out internal runtime fields, repository identifiers, and executable keys (`binary`, `args`, etc.).
- Created DB-free `milestone24_application_service_boundary_smoke.ts` using stub orchestration to prove DTO isolation.
- M24 does not add API/UI/queues/workers.
- M24 does not add production bootstrap.
- M24 does not make Postgres default.
- M24 does not expand scanner/tool execution.
- M24 does not claim production readiness.

---
### Milestone 25 - Recommendation Continuity / Approval Resume Boundary (DONE)
**Goal:** Fix recommendation approval continuity after session reload.
- Modified `ApprovalGateway` and `V2AssessmentRuntime` to translate `AttackRecommendation` directly from `AssessmentState.pendingRecommendations` during explicit approval.
- Approval after `loadSession` in a fresh runtime now succeeds without depending on the ephemeral `RecommendationInbox`.
- `CapabilityRequest` remains strictly transient and is never persisted.
- `ExecutionRequest` is never persisted.
- Executable keys (`binary`, `args`, `env`, `command`, `shell`, `stdin`) are strictly not exposed or persisted.
- Created deterministic DB-free `milestone25_recommendation_continuity_smoke.ts`.
- M25 does not add API/UI/queues/workers.
- M25 does not change Postgres schemas/migrations or storage contracts.
- M25 prioritizes correctness and continuity over speed.

---

---
### Milestone 26 - Formal V2 Validation Scripts / Smoke Command Boundary (DONE)
**Goal:** Create formal, repeatable V2 validation scripts so future milestones no longer depend on manually remembered chat commands.
- Updated `worker/package.json` with explicit `smoke:v2`, `check:v2`, and `typecheck:v2` npm scripts.
- Replaced the placeholder `test` script with safe DB-free validation (`npm run check:v2`).
- Default validations (`npm test`, `npm run check:v2`, `npm run smoke:v2`) are fully DB-free and safe.
- Added explicit opt-in script `npm run smoke:v2:db` for destructive DB validation, guarded by environment variables.
- Created `FIXGUARD_V2_VALIDATION_SCRIPTS_PLAN.md` and `worker/src/v2/smoke/README.md` to document DB safety policies, environment guards, and validation workflows.
- Reaffirmed that DB validation uses disposable test branches only and does not claim production readiness.
- No DB URLs are committed or documented.
- Did not change `worker/package-lock.json`, and no new dependencies were added.
- Did not modify runtime, approval, storage, composition, or application behavior.

---

---
### Milestone 27 - Capability Contract / Safe Tool Invocation Boundary (DONE)
**Goal:** Add a standalone safe capability contract boundary.
- Created `worker/src/v2/capabilities/CapabilityDefinition.ts` and `SafeCapabilityInput.ts`.
- Created `worker/src/v2/capabilities/CapabilityRegistry.ts`.
- Added strict recursive validation to reject executable keys (`binary`, `command`, `spawn`, etc.) from both capability metadata and invocation inputs.
- Registry acts purely as a contract boundary. It is not a tool runner, process spawner, or executor.
- Preserved existing transient `CapabilityRequest` behavior without modifications.
- Added `milestone27_capability_contract_smoke.ts` to prove rejection of unsafe nested shapes without requiring database interaction.
- M27 does not expand scanner execution, API/UI, or database orchestration.
- M27 remains fully DB-free.
- Default `npm run check:v2` updated to include M27 smoke.


---
### Milestone 28 - Capability Registry Integration / Approval Enforcement Boundary (DONE)
**Goal:** Enforce capability registry during approval.
- Updated `IntentTranslator` to consult the `CapabilityRegistry` during translation.
- Unknown capability ids are rejected before mutation/persistence/execution.
- Unsafe final capability inputs are rejected before mutation/persistence/execution via `CapabilityValidationError`.
- Registered safe capabilities still approve successfully.
- Preserved M25 approval-after-reload behavior.
- `CapabilityRequest` remains transient and unchanged.
- `ExecutionRequest` is never persisted.
- Registry remains metadata/validation only.
- No real scanner, tool, or process execution was added.
- No runtime DB, Postgres coupling, or storage schema changes were introduced.
- Default `npm run check:v2` updated to include M28 smoke test.


---
### Milestone 29 - First Passive Recon Vertical Flow (DONE)
**Goal:** Introduce the first deterministic passive execution boundary (`http.header.inspect`) utilizing human approval and safe observation extraction without external network dependencies.
- `http.header.inspect` registered as a passive capability.
- Established passive adapter boundary (`worker/src/v2/recon/passive/`).
- `FixtureHttpHeaderInspectAdapter` provides deterministic safe execution and avoids real fetch.
- `V2AssessmentRuntime` injects and routes passive execution efficiently.
- Unsafe configs continue to be completely rejected at the capability layer, preventing mutated records.
- Evidence strictly enforces no bodies, cookies, tokens, or raw requests are saved.
- No vulnerability findings created.
- Application/Postgres/Schema/UI unmodified.
- No production readiness claims.
- M29 included securely in DB-free `check:v2`.


---
### Milestone 30 - Authorized Scope / Egress Policy Boundary (DONE)
**Goal:** Introduce a pure deterministic egress/scope policy module that answers "is this outbound request authorized and safe?" before real network execution.
- Policy module (`worker/src/v2/recon/policy/`) implements strict SSRF/internal target blocking and permissive authorized scope matching.
- Developed `TargetUrlNormalizer` to enforce valid URL constraints and classify sensitive query keys without destructive internal loss.
- `EgressPolicyDecision` models strict allows, blocks, and subdomains as `DiscoveredScopeCandidate`.
- Zero network requests, zero DNS resolutions, zero child process imports.
- Pure decision outputs without runtime, storage, evidence, or finding persistence.

---
### Milestone 31 - Guarded Real HTTP Header Inspect Adapter (DONE)
**Goal:** Introduce the first real network-backed passive adapter for `http.header.inspect` guarded by the M30 egress policy.
- Real egress is opt-in (`RealHttpHeaderInspectTransport`).
- Transport abstraction separates policy/sanitization from `node:http`/`node:https` fetching.
- M30 egress policy is strictly evaluated before transport invocation.
- DNS IP resolution guard blocks internal/loopback/SSRF targets.
- Headers are sanitized heavily before evidence creation, masking auth/tokens/cookies.
- Response bodies are strictly ignored.
- Fake transport (`FakeHttpHeaderInspectTransport`) ensures DB-free, network-free default smokes.

---
---
### Milestone 32 - Explicit Opt-in Real HTTP Header Inspect Validation (DONE)
**Goal:** Prove that real egress can be invoked explicitly for one bounded guarded HTTP header inspection, while remaining impossible by default.
- Added explicitly opted-in real validation script `worker/src/v2/smoke/milestone32_opt_in_real_http_header_inspect_smoke.ts`.
- `smoke:v2:recon:real` script added to `package.json`.
- Strict environment variables are required to activate real egress (`FIXGUARD_V2_REAL_HTTP_HEADER_INSPECT`, `FIXGUARD_V2_REAL_HTTP_HEADER_INSPECT_URL`, `FIXGUARD_V2_REAL_HTTP_HEADER_INSPECT_ALLOWED_ORIGIN`, `FIXGUARD_V2_REAL_HTTP_HEADER_INSPECT_CONFIRM_AUTHORIZED`).
- Fails closed safely if environment variables are partial, missing, or mismatched.
- Executes one bounded guarded HEAD request using `RealHttpHeaderInspectTransport`.
- Explicit real egress testing is excluded from default validations (`check:v2`, `smoke:v2`).
- Did not touch production runtime, storage, application boundaries, Postgres schemas, API, or package-lock.


---
### Milestone 33 - Egress Policy Decision Audit Boundary (DONE)
**Goal:** Represent M30 egress policy decisions as sanitized control-plane audit events without treating blocks/candidates as findings, without leaking secrets, and without adding persistence/Postgres/runtime defaults.
- Created `worker/src/v2/recon/audit/` boundary with three files:
  - `EgressPolicyAuditContracts.ts` — strict event shape with literal classification/safety flags.
  - `EgressPolicyAuditMapper.ts` — pure mapper from `EgressPolicyDecision` → `EgressPolicyAuditEvent`.
  - `InMemoryEgressPolicyAuditRecorder.ts` — in-memory, test-only recorder with clone isolation and forbidden-field rejection.
- Policy audit events carry literal flags: `controlPlaneEvent: true`, `finding: false`, `evidence: false`, `vulnerability: false`, `riskClaim: false`.
- Block and candidate decisions can never be mistaken for findings, evidence, vulnerabilities, or risk claims.
- `safeDisplayUrl` from M30 is always used — no raw URLs reconstructed.
- Credentials, tokens, passwords, and sensitive query values are never present in events.
- Recorder stores and returns deep clones; external mutation cannot affect internal state.
- Recorder rejects events containing forbidden executable/secret fields.
- M33 smoke proves all 21 required behaviors (allow/block/candidate mapping, recorder mutation-safety, secret redaction, classification flags, no executable fields, etc.).
- M33 is DB-free, network-free, runtime-free, and storage-free.
- M33 smoke added to `smoke:v2:recon` (flows into `smoke:v2` and `check:v2`).
- `smoke:v2:recon:real` untouched.
- No package-lock changes. No forbidden files touched.


---
### Milestone 34 - Active Recon Adapter Boundary (DONE)
**Goal:** Introduce the first Active Recon boundary in FixGuard V2 while remaining completely DB-free, network-free, runtime-free, and storage-free.
- Defined `ActiveReconProbeKind` for `http.robots.inspect` and `http.security_txt.inspect` only.
- Created `ActiveReconAdapter` interface and a `FakeActiveReconAdapter` that returns modeled safe observations.
- Active probes are strictly gated by M30 `EgressPolicyDecision`.
- Blocked and candidate targets do not execute fake adapter behavior.
- Results use `safeDisplayUrl` with no raw requests, tokens, or credentials persisted.
- M33 audit events are purely generated in smoke tests to confirm mapped shape, but not integrated into runtime/storage.
- No scanner binaries, subprocesses, or real network dependencies were introduced.
- No `Finding` or `Evidence` entities are created.
- Package-lock and other milestones remain completely untouched.

---
### Milestone 35 - Explicit Opt-in Real Active Robots Probe Validation (DONE)
**Goal:** Introduce the first guarded real Active Recon probe path in V2, but only behind explicit opt-in validation and excluded from all default checks.
- Introduced `RealActiveReconHttpProbeAdapter` supporting only `http.robots.inspect`.
- Enforces strict 3000ms timeout, max 16 KiB read, and 0 redirects for the `GET` request.
- Integrates the M31-style DNS resolution guard to block SSRF and internal targets at the socket level.
- Excluded from all default DB-free and network-free checks (`check:v2`, `smoke:v2`, `smoke:v2:recon`).
- Real egress is protected by explicit strict environment variables (`FIXGUARD_V2_REAL_ACTIVE_RECON` etc.) and the M30 egress policy check.
- Emits only safe metadata summaries (`SafeActiveReconObservation`); never persists or emits raw body, headers, or directive values.
- M33 audit events remain smoke-only; no new runtime, storage, Postgres, API, or UI integration was introduced.
- Verified default no-egress behavior and programmatic out-of-scope/invalid URL checks.

---
### Milestone 36 - Active Recon Safe Document Metadata Boundary (DONE)
**Goal:** Create safe, fixed-shape, DB-free/network-free sanitizers for active recon document-like probes.
- Created `worker/src/v2/recon/active/ActiveReconDocumentSanitizers.ts` with explicit sanitizers for `robots.txt` and `security.txt`.
- Restricted `SafeActiveReconObservation` in `ActiveReconContracts.ts` to be a discriminated union (`robots_metadata` / `security_txt_metadata`) containing strictly defined metadata shapes without arbitrary index signatures.
- Updated `FakeActiveReconAdapter.ts` to process modeled hostile fixtures through the new sanitizers, returning safe parsed metadata.
- Implemented `worker/src/v2/smoke/milestone36_active_recon_safe_document_metadata_smoke.ts` to prove hostile paths, parameters, emails, API keys, tokens, and PGP blocks never survive serialization.
- Fully DB-free, network-free, finding-free, and evidence-free.
- The real M35 adapter remains entirely untouched. No real `security.txt` probe execution was implemented.

---
### Milestone 37 - Explicit Opt-in Real security.txt Probe Validation (DONE)
**Goal:** Add exactly one new explicit opt-in real active recon probe for `http.security_txt.inspect`.
- Created `worker/src/v2/recon/active/RealActiveReconSecurityTxtProbeAdapter.ts` — isolated from the M35 robots adapter.
- Enforces exact `/.well-known/security.txt` path only; `/security.txt`, root paths, queries, and fragments are explicitly rejected before transport.
- Integrates the M31/M35-style literal IP SSRF pre-request guard and request-bound DNS resolution guard.
- Uses the M36 `sanitizeSecurityTxtMetadata` for all output — no contact emails, policy URLs, PGP blocks, encryption keys, or raw field values survive serialization.
- GET only; 3000ms timeout; max 16 KiB; 0 redirects; no Location header forwarded.
- `RealActiveReconHttpProbeAdapter.ts` (M35 robots adapter) is completely untouched.
- Real egress is opt-in via `FIXGUARD_V2_REAL_ACTIVE_RECON_CONFIRM_AUTHORIZED=I_CONFIRM_AUTHORIZED_SECURITY_TXT_TARGET`.
- Created `worker/src/v2/smoke/milestone37_opt_in_real_security_txt_probe_smoke.ts` covering all negative cases (absent/partial/wrong env, wrong probe kind, wrong/root/query/fragment paths, IPv4/IPv6/IPv4-mapped-IPv6 literals, DNS-resolved blocked IP) and the opt-in real flow.
- Added `smoke:v2:recon:active:security-txt:real` to `package.json` — excluded from `check:v2`, `smoke:v2`, `smoke:v2:recon`, and `npm test`.
- No findings, evidence, risk, severity, impact, or exploit claims.
- No runtime/storage/Postgres/API/UI integration.
- No scanner, crawler, or subprocess execution.
- No package-lock changes.

---
### Milestone 38 - Active Recon Document Probe Runner Boundary (DONE)
**Goal:** Create a controlled DB-free active recon document probe runner that orchestrates already-approved probes.
- Created `worker/src/v2/recon/active/ActiveReconDocumentProbeRunContracts.ts` with explicit run request and result shapes. `targetUrl` is transient input only and never appears in output.
- Created `worker/src/v2/recon/active/ActiveReconDocumentProbeRunner.ts` — a pure async function that accepts a fixed injected adapter table (`ActiveReconDocumentProbeAdapters`) and does not instantiate real adapters by default.
- Runner supports only `http.robots.inspect` and `http.security_txt.inspect`. Unsupported probe kinds are rejected safely.
- Runner evaluates M30 egress policy per-target before any adapter invocation. Blocked/candidate decisions do not invoke adapters.
- Blocked → `policy_blocked`, candidate → `policy_candidate`, adapter missing → `adapter_missing`, adapter throws → `adapter_failed` (raw exception message is never echoed).
- Result shape never includes raw `targetUrl`, raw bodies, raw headers, raw request/response, or any finding/evidence/risk/severity/impact/exploit claims.
- Result target contains only `normalizedOrigin` and `safeDisplayUrl` from M30 policy output.
- Safe per-probe statuses and aggregate counts are always returned.
- `classification` flags are always `false` (`finding`, `evidence`, `vulnerability`, `riskClaim`).
- M38 does not add new probe kinds beyond those in M35/M37.
- M38 does not derive target URLs from origins (no auto-generation). Origin-derived planning deferred to M39.
- `RealActiveReconHttpProbeAdapter.ts` and `RealActiveReconSecurityTxtProbeAdapter.ts` are completely untouched.
- Implemented `worker/src/v2/smoke/milestone38_active_recon_document_probe_runner_smoke.ts` proving 15 runner safety test groups, including runtime authorization enforcement, safe generated run/probe identifiers, unsupported-kind sanitization, blocked/candidate non-invocation, adapter failure safety, sanitized aggregation, and no findings/evidence/risk claims.
- Created `worker/src/v2/smoke/milestone38_opt_in_real_active_recon_document_probe_runner_smoke.ts` for real combined opt-in validation — excluded from defaults.
- Added `smoke:v2:recon:active:runner` to `package.json` and included in `smoke:v2:recon` chain.
- Added `smoke:v2:recon:active:runner:real` to `package.json` — excluded from `check:v2`, `smoke:v2`, `smoke:v2:recon`, and `npm test`.
- No findings, evidence, risk, severity, impact, or exploit claims.
- No runtime/storage/Postgres/API/UI integration.
- No scanner, crawler, or subprocess execution.
- No package-lock changes.

---
### Milestone 39 - Authorized Origin Active Recon Run v0 (DONE)
**Goal:** Create the first DB-free authorized origin active recon flow.
- Created `worker/src/v2/recon/active/ActiveReconOriginRunContracts.ts` and `ActiveReconOriginRunService.ts`.
- Validates runtime authorization (`authorization.confirmed === true`) and fails closed securely.
- Enforces strict origin shape requirements: must be `http:` or `https:`, rejects paths, queries, fragments, and credentials.
- Rejects unsafe literal IP origins using M30 logic.
- Safely deduplicates and filters explicitly requested document probes (`http.robots.inspect`, `http.security_txt.inspect`), returning the safe `unknown` sentinel and omitting raw requested strings for unsupported values.
- M39 generates exact targets internally (`/robots.txt`, `/.well-known/security.txt`) and delegates entirely to the M38 runner (`ActiveReconDocumentProbeRunner.ts`).
- No scanner behavior, crawler behavior, endpoint discovery, subdomain enumeration, or arbitrary paths exist.
- Does not modify the real adapters (`RealActiveReconHttpProbeAdapter.ts`, `RealActiveReconSecurityTxtProbeAdapter.ts`).
- Emits no raw URL with queries, fragments, or secrets; no raw `targetUrl` appears in safe output.
- Generates its own safe internal `runId` and does not echo caller-provided IDs.
- Implemented `worker/src/v2/smoke/milestone39_active_recon_origin_run_smoke.ts` to prove DB-free boundary integrity with 25 test points (e.g., missing auth fails closed, unsafe IPs blocked, unsupported kinds sanitized, fake outputs not represented as real evidence).
- Implemented `worker/src/v2/smoke/milestone39_opt_in_real_active_recon_origin_run_smoke.ts` to demonstrate real combined origin run (excluded from defaults).
- DB-free origin-run smoke included in `smoke:v2:recon`.
- No findings, evidence, risk, severity, impact, or exploit claims.
- No storage/runtime/Postgres/API/UI integration.
- No package-lock changes.

---
### Milestone 40 - Active Recon Origin Run Persistence Boundary (DONE)
**Goal:** Persist safe M39 authorized origin active recon run summaries behind a DB-free repository boundary.
- Created `worker/src/v2/recon/active/ActiveReconOriginRunPersistenceContracts.ts` and `ActiveReconOriginRunRepository.ts`.
- Introduced `InMemoryActiveReconOriginRunRepository.ts` to store persistence states without using Postgres or any DB.
- Created `worker/src/v2/recon/active/ActiveReconOriginRunPersistenceService.ts`.
- Enforces strict safety validation before saving: rejects any serialized candidate that contains raw target URLs, internal generated URLs, or raw body/headers/request/response/payloads.
- Validates classification flags (ensures all are false), explicitly rejecting true finding/evidence/vulnerability/riskClaim claims.
- Validates that persisted item union remains closed to document items only.
- In-memory repository clones on save/read/list to prevent external state mutation.
- Does not create findings or evidence records.
- Does not integrate UI, API surfaces, scanners, or crawlers.
- Safe `runId` generated; duplicate save rejected.
- Failed runs and run errors (like `empty_probe_set`) persist safely.
- Implemented `worker/src/v2/smoke/milestone40_persisted_active_recon_origin_run_smoke.ts` to prove DB-free boundary integrity with comprehensive checks for safe fields, no raw secrets, and cloning semantics.
- Included M40 smoke in `smoke:v2:recon` pipeline.
- No real adapters were modified; no new real network behavior introduced.
- No package-lock changes.

---
*Last Updated: After Milestone 40 - Active Recon Origin Run Persistence Boundary*
*Next update due: After further V2 boundaries are established.*

### Milestone 48.1 - Response Comparison / Evidence Mapping Compatibility Correction DB-free (IMPLEMENTED)
- M48.1: aligned response difference validation with M47 and kept enum/free-text safety separation.

### Milestone 49 - Authorized Comparison Validation Boundary DB-free (IMPLEMENTED)
- M49 is DB-free.
- M49 orchestrates M46/M47/M48 pure services.
- M49 consumes already-safe snapshots only.
- M49 does not execute network/tools/adapters.
- M49 does not persist data.
- M49 does not create M45 EvidenceRecord.
- M49 does not create FindingCandidateRecord.
- M49 does not confirm vulnerabilities.
- M49 does not make severity/risk/impact claims.
- M49 derives internal IDs from validationId.
- M49 blocks non-validation actionKinds before comparison/mapping.
- M49 short-circuits if M46 denies.
- M49 short-circuits if M47 fails.
- M49 maps M48 statuses exactly (draft_ready -> completed_with_evidence_draft, needs_more_review -> needs_more_review_from_mapping, blocked -> blocked_mapping_blocked, failed -> failed_mapping_failed).
- M49 exposes closed summaries instead of full upstream objects.
- M49 validates EvidenceDraftEnvelope before copying.

### Milestone 50 - Human-Reviewed Evidence Promotion Boundary DB-free (IMPLEMENTED)
- M50 is DB-free.
- M50 is a human-review gate over M49/M48 into M45.
- M50 creates only a non-persisted M45 EvidenceRecord.
- M50 requires approve_evidence.
- M50 requires sourceIndicatorRef and never synthesizes fake indicator IDs.
- M50 validates M49 result, M49/M48 draft, sourceIndicatorRef, and constructed EvidenceRecord.
- M50 does not persist.
- M50 does not create findings/candidates/report items.
- M50 does not confirm vulnerabilities.
- M50 does not make severity/risk/impact claims.
- M50 uses closed summaries and safe sentinels/no raw echo.

### Milestone 51 - Reviewed Evidence Store + Read Model Boundary DB-free (IMPLEMENTED)
- M51 is DB-free/in-memory only.
- M51 stores reviewed M45 EvidenceRecord only after M50 promotion.
- M51 does not promote evidence.
- M51 does not create findings/candidates/report items.
- M51 does not confirm vulnerabilities.
- M51 does not make severity/risk/impact claims.
- M51 does not use Postgres/DB/runtime/API/UI.
- M51 validates M50 result, M45 EvidenceRecord, and store record before saving.
- M51 returns closed summaries/read models.
- M51 repository is clone-safe and mutation-safe.
- Postgres persistence remains a later milestone.

### Milestone 52 — Reviewed Evidence Query + Selection Boundary DB-free
- DB-free and non-persistent.
- Uses M51 read model as primary source boundary.
- Selects reviewed evidence into non-persisted selection sets.
- Always includes safe M51 summaries.
- Can summarize provided selection sets.
- Does not create findings/candidates/report items.
- Does not confirm vulnerabilities.
- Does not make severity/risk/impact claims.
- Does not use Postgres/DB/runtime/API/UI.

### Milestone 53 — Reviewed Evidence Selection to Finding Candidate Draft Boundary DB-free
- DB-free and non-persistent.
- Consumes validated M52 reviewed evidence selection sets.
- Creates non-persisted finding candidate drafts only.
- Does not create formal finding candidates.
- Does not create confirmed findings.
- Does not create safe report items or external reports.
- Does not confirm vulnerabilities.
- Does not make exploitability, severity, risk, or impact claims.
- Does not provide remediation advice.
- Does not use Postgres, database storage, runtime composition, application services, APIs, or UI.
- Uses selected refs and observed-only evidence summary counts.
- Includes a summarize-provided-draft read model.
- Future milestones may route drafts to human triage or explicit formal promotion.
