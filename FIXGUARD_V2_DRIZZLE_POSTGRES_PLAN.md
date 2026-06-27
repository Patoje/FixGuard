# FixGuard V2 Drizzle/PostgreSQL Persistence Plan

## 1. Purpose and Scope of Milestone 15
This milestone is strictly planning-only. The goal is to define a precise, durable persistence plan for a future Drizzle/PostgreSQL-backed `AssessmentRepository` that will support FixGuard V2's execution and intelligence cycles. This plan establishes the data model, indexing strategy, concurrency model, and non-executable persistence rules before any database code is written.

## 2. Explicit Out-of-Scope
The following are explicitly **out of scope** for this milestone:
* Writing TypeScript code.
* Modifying existing runtime, core, or intelligence contracts.
* Modifying `worker/src/v2/**`.
* Adding Drizzle schemas or PostgreSQL clients.
* Adding database migrations.
* Adding API routes, UI, queues, or workers.
* Touching V1 code.

## 3. Current Architecture Recap
FixGuard V2 currently has:
* Execution Core, Intelligence Layer, and Approval Boundary foundations.
* A Runtime foundation that uses strict lifecycle mutation guards.
* Storage port contracts (`AssessmentRepository`).
* A fully working `InMemoryAssessmentRepository`.
* Runtime integrated with `AssessmentRepository` via dependency injection.
* Snapshot-only session resume (`loadSession(sessionId)`).
* A deterministic smoke seam for testing without live binaries.
* The core architecture rule: **Tools execute. Intelligence decides. Humans authorize.**

## 4. Future Postgres/Drizzle Persistence Model
The plan uses a **hybrid persistence model**:
* A versioned `AssessmentState` snapshot for active state tracking and rapid loading.
* Append-only tables for evidence records, audit entries, approved request records, and execution failure records.
* Relational columns for filtering, listing, and session summaries, ensuring query efficiency without complex JSONB parsing in the database layer.

This hybrid approach (snapshot + append-only logs) avoids the complexity of full event sourcing. Event sourcing is unnecessary at this stage, as rebuilding state from a massive stream of tool events would introduce significant read-time overhead and parsing complexity. Snapshots provide immediate readiness for the Runtime, while the append-only logs guarantee immutable traceability.

## 5. Conceptual Schema Design
The design consists of one primary state table and four append-only log tables. It relies heavily on `JSONB` for deep structural data (e.g., findings, capabilities) while keeping identifying fields, statuses, and counts natively relational to support fast listing.

## 6. Tables and Columns
### `v2_assessment_sessions` (Snapshot)
* `session_id` (PK, String)
* `target_uri` (String)
* `lifecycle_status` (String)
* `version` (Integer)
* `created_at_ms` (BigInt)
* `updated_at_ms` (BigInt)
* `finding_count` (Integer)
* `pending_recommendation_count` (Integer)
* `execution_failure_count` (Integer)
* `state_snapshot` (JSONB - full AssessmentState)

### `v2_evidence_records` (Append-only)
* `id` (PK, String)
* `session_id` (FK to v2_assessment_sessions, String)
* `capability` (String)
* `recorded_at_ms` (BigInt)
* `source_approved_request_record_id` (String, nullable)
* `finding_count` (Integer)
* `evidence_json` (JSONB - EvidenceCollection)

### `v2_audit_entries` (Append-only)
* `id` (PK from AuditEntry.id, String)
* `session_id` (FK to v2_assessment_sessions, String)
* `recommendation_id` (String, nullable)
* `decision` (String, nullable)
* `recorded_at_ms` (BigInt)
* `entry_json` (JSONB - AuditEntry)

### `v2_approved_request_records` (Append-only)
* `id` (PK from ApprovedRequestRecord.id, String)
* `session_id` (FK to v2_assessment_sessions, String)
* `recommendation_id` (String)
* `capability` (String)
* `target_uri` (String)
* `operator_id` (String)
* `source_recommendation_id` (String, nullable)
* `approved_at_ms` (BigInt)
* `request_summary_json` (JSONB)
* `record_json` (JSONB - ApprovedRequestRecord)

*Note: This is durable traceability only and must never be executable.*

### `v2_execution_failure_records` (Append-only)
* `id` (PK from ExecutionFailureRecord.id, String)
* `session_id` (FK to v2_assessment_sessions, String)
* `capability` (String)
* `target_uri` (String)
* `failed_at_ms` (BigInt)
* `recoverable` (Boolean)
* `source_recommendation_id` (String, nullable)
* `lifecycle_status_at_failure` (String)
* `error_message` (String)
* `record_json` (JSONB - ExecutionFailureRecord)

## 7. Optional Future Projection Tables
The following projection tables may be added in the future for advanced cross-session querying or full-text search, but are **explicitly out of scope** for the first adapter:
* `v2_finding_projections`
* `v2_recommendation_projections`
* `v2_target_profile_projections`

## 8. JSONB vs Relational Split
**Store as JSONB (Schema-less payloads):**
* Full `AssessmentState`
* `EvidenceCollection`
* `Finding`
* `TargetProfile`
* `AttackRecommendation`
* `AuditEntry`
* `ApprovedRequestRecord`
* `ExecutionFailureRecord`

**Normalize as Relational Columns (Indexed / Queryable):**
* IDs (Primary Keys and Foreign Keys like `session_id`)
* `targetUri`
* `lifecycle_status`
* `version`
* `capability`
* `decision`
* `operator ID`
* Timestamps (`created_at_ms`, `updated_at_ms`, `recorded_at_ms`, `failed_at_ms`)
* Summary counts

## 9. Optimistic Concurrency Strategy
Strict optimistic concurrency must be enforced at the database level:
* **Creation:** `expectedVersion = 0` means an `INSERT` statement must be used. It fails if the `session_id` already exists.
* **Updates:** Existing session updates must use conditional updates: `UPDATE v2_assessment_sessions SET ... WHERE session_id = ? AND version = ?`.
* **Conflict Resolution:** If zero rows are affected during an update, the adapter must throw a `StaleStateError`.
* **No Auto-Repair:** There is no dynamic version repair or silent overwrite. The adapter must throw `StaleStateError`; runtime operations must surface/reject that failure without dynamic repair or silent overwrite.

## 10. Indexing Strategy
* **`v2_assessment_sessions`:**
  * Primary Key: `session_id`
  * Indexes: `target_uri`, `lifecycle_status`, `created_at_ms`, `updated_at_ms`
  * Compound Index: `target_uri` + `lifecycle_status`
* **Append Tables:**
  * Base Index for all append tables: `session_id`
  * Time-based Index for all append tables: `session_id` + `recorded_at_ms` (or `failed_at_ms`)
  * `v2_evidence_records`: `session_id` + `capability`
  * `v2_approved_request_records`: `session_id` + `capability`
  * `v2_execution_failure_records`: `session_id` + `recoverable`
  * `v2_execution_failure_records`: `session_id` + `failed_at_ms`

## 11. Security and Non-Executable Persistence Rules
The database must **never** become an execution vector. The future DB adapter must never persist:
* `CapabilityRequest`
* `ExecutionRequest`
* Binary paths
* Args arrays
* Shell commands
* Process runner internals
* Tool definitions
* Adapters/parsers
* Executable retry payloads

**Rule Enforcement:**
* `ApprovedRequestRecord` must remain durable traceability metadata only, it cannot be transformed back into executable work.
* The adapter must validate JSON payloads before `INSERT`/`UPDATE` to reject suspicious executable fields. Payloads containing executable fields such as `binary`, `args`, `command`, `shell`, `stdin`, `env`, `executionRequest`, or `capabilityRequest` must be rejected at the persistence boundary. The adapter must not silently strip or rewrite executable payloads.

## 12. Transaction Strategy
**Current Known Gap:** The runtime currently calls snapshot persistence (`persistState`) and log appending (`repository.appendX`) as entirely separate, distinct repository calls. 
While a first Postgres adapter can make each individual repository method atomic, it cannot make the multiple runtime calls atomic without a new transaction boundary.

**Future Options (Out of Scope for this milestone):**
* Add a repository transaction/unit-of-work API in the future.
* Add runtime persistence methods that group the snapshot + append operations into a single repository method.
* Accept the non-transactional append risk for early adapter milestones, prioritizing a functional adapter over perfect atomicity initially.

*(Do not change the repository port in this milestone to solve this.)*

## 13. Future Milestone Breakdown
1. **Milestone 15:** Planning document only (This Milestone).
2. **Milestone 16:** Drizzle schema only (No adapter logic).
3. **Milestone 17:** Reusable AssessmentRepository conformance test suite.
4. **Milestone 18:** PostgresAssessmentRepository implementation.
5. **Milestone 19:** Transaction-boundary hardening (if needed).
6. **Later:** API/UI/queues (only after real persistence is stable).

## 14. Testing Strategy
A future reusable adapter conformance suite should be built.
* This suite must be able to run against both the `InMemoryAssessmentRepository` and the `PostgresAssessmentRepository`.
* Postgres tests should be strictly optional and gated by an environment variable (e.g., `FIXGUARD_PG_TEST_URL`).
* This avoids mandatory local DB friction in normal V2 smoke runs, keeping the barrier to entry low for standard testing.

## 15. Acceptance Criteria
* [x] Planning-only document created.
* [x] Status doc updated without claiming implementation exists.
* [x] Hybrid model clearly defined.
* [x] Tables/columns conceptually specified.
* [x] JSONB vs relational split explicit.
* [x] Optimistic concurrency explicit.
* [x] Non-executable persistence rules explicit.
* [x] Transaction gap documented.
* [x] Future milestone breakdown clear.
* [x] No code/package/schema files changed.
