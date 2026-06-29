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

---

## Next Milestones

---

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
*Last Updated: After Milestone 34 - Active Recon Adapter Boundary*
*Next update due: After guarded real HTTP active probe adapter is introduced (M35).*
