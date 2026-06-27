# FixGuard V2 — Persistence Contract Plan

## 1. Context

The FixGuard V2 migration has successfully established the core architectural boundaries: Execution Core, Intelligence Layer, and Approval Boundary. In Milestone 8, we built the `V2AssessmentRuntime`, which acts as the thin application-service coordinator managing the assessment lifecycle via `V2AssessmentSession`.

Currently, the state is entirely in-memory. The runtime coordinates `AssessmentState`, tracking `LifecycleState`, `ApprovedRequestRecord`, `ExecutionFailureRecord`, `EvidenceCollection`, `TargetProfile`, `pendingRecommendations`, and `auditEntries`. The state snapshot uses a simple `version` and `timestamps` to enforce safe updates.

Because the runtime is currently ephemeral, data is lost upon process termination. Before we implement a durable database (e.g., PostgreSQL with Drizzle) or expose APIs/UIs, we must meticulously plan the storage boundary. If persistence is implemented haphazardly, it risks storing executable intent (`CapabilityRequest`), bypassing the human approval boundary, or turning the storage layer into a "mega-orchestrator" containing business logic.

## 2. Milestone Type

**Milestone 9 is strictly a planning-only milestone.**

There is no TypeScript implementation in this milestone. We will not create Drizzle schemas, database adapters, storage interfaces, API routes, UI integrations, queues, or background workers. The sole deliverable is this architectural blueprint.

## 3. Recommended Persistence Architecture

We recommend a **hybrid persistence model**:
*   **Snapshotting:** The current `AssessmentState` is stored as a versioned snapshot (e.g., serialized JSON or highly normalized relational tables for current status).
*   **Append-Only Logs:** High-fidelity tracing data—such as `EvidenceCollection`, `AuditEntry`, `ApprovedRequestRecord`, and `ExecutionFailureRecord`—should be persisted as append-only records.
*   **Future Projections:** Relational normalized projections can be derived from these append-only logs in the future for query-heavy UI/API views.

*Why not pure snapshot only?* A pure snapshot overwrites history, destroying the append-only audit trail necessary for a security product.
*Why not pure event sourcing yet?* Pure event sourcing introduces massive complexity (event replays, projections, CQRS) that is currently over-engineered for our simple, linear assessment lifecycle. A hybrid approach perfectly balances auditability with state simplicity.

## 4. Storage Boundary

The future conceptual port should be named **`AssessmentRepository`**.

*Why this name?* "Store" often implies a dumb key-value cache. "Repository" accurately conveys that this port acts as the durable collection of Domain objects, abstracting away the database implementation (PostgreSQL, SQLite, In-Memory) while adhering strictly to Domain-Driven Design (DDD) principles.

**Supported Conceptual Methods:**
*   `saveSession(state: AssessmentState): Promise<void>`
*   `loadSession(sessionId: string): Promise<AssessmentState>`
*   `appendEvidence(record: EvidenceCollection): Promise<void>`
*   `appendAuditEntry(entry: AuditEntry): Promise<void>`
*   `appendApprovedRequest(record: ApprovedRequestRecord): Promise<void>`
*   `appendExecutionFailure(record: ExecutionFailureRecord): Promise<void>`
*   `listSessions(filter: SessionFilter): Promise<SessionSummary[]>`

**Strict Non-Responsibilities (The Storage MUST NOT):**
*   Execute capabilities.
*   Create or synthesize `CapabilityRequest` objects.
*   Call `MinimalOrchestrator`, `ApprovalGateway`, or `RecommendationEngine`.
*   Interpret findings.
*   Import concrete adapters, parsers, or V1 legacy code.
*   Mutate security decisions or trigger any execution whatsoever.

**Dependency Direction:**
`Runtime` → `Storage Port (Interface)` → `Future Storage Adapter (Drizzle)`
The storage layer must *never* call the runtime.

## 5. Namespace Recommendation

The future storage port and implementations should reside in:
`worker/src/v2/storage/`

*Why separate from runtime?* The `runtime/` namespace is specifically for the application-service coordinator and in-memory lifecycle wrappers. Storage concerns (DTOs, relational mapping, database connections) will pollute the pure domain orchestration logic if mixed into `runtime/`. By separating it, we strictly enforce the Dependency Inversion Principle.

*(Note: Do not create this folder in Milestone 9).*

## 6. Persisted Entities

The following entities must be persisted durably:

**AssessmentSession:**
*   `id` (session id)
*   `targetUri`
*   `lifecycleStatus`
*   `created` timestamp
*   `updated` timestamp
*   `version`
*   *(Future: operator/user reference)*

**AssessmentState Snapshot:**
*   Serialized current state (enough to restore runtime state upon load)
*   `version`
*   `timestamps`

**EvidenceCollection (Append-Only):**
*   `id`
*   `sessionId`
*   `capability`
*   Finding count
*   `metadata`
*   `timestamp`
*   `sourceApprovedRequestRecordId` (if applicable)

**Finding (Initially embedded in Evidence JSON):**
*   `id`
*   `type`
*   `severity`
*   `target`
*   `confidence`
*   `metadata`
*   *(Future: relational projection for UI querying)*

**TargetProfile:**
*   Current profile snapshot (likely JSON initially)
*   `version`
*   `timestamp`

**AttackRecommendation:**
*   `id` (recommendation id)
*   `sessionId`
*   `capability`
*   `targetContext`
*   `rationale`
*   `confidence`
*   `severity`
*   `status` (pending / rejected / approved / superseded)
*   `sourceFindingIds` (if available)

**ApprovedRequestRecord (Append-Only):**
*   `id`
*   `sessionId`
*   `capability`
*   `targetUri`
*   `operatorId`
*   `approvedAt`
*   `sourceRecommendationId`
*   `requestSummary`
*   *(CRITICAL: No binary, no args, no CapabilityRequest, no ExecutionRequest)*

**ExecutionFailureRecord (Append-Only):**
*   `id`
*   `sessionId`
*   `capability`
*   `targetUri`
*   `errorMessage`
*   `recoverable` boolean
*   `failedAt`
*   `sourceRecommendationId` (if applicable)
*   `lifecycleStatusAtFailure`

**AuditEntry (Append-Only):**
*   `id`
*   `decision`
*   `sourceRecommendationId`
*   `recordedAt`
*   `operatorIdentity` (if available)

## 7. Explicit Non-Persisted Entities

The following entities **MUST NEVER** be persisted as durable executable state:
*   `CapabilityRequest`
*   `ExecutionRequest`
*   `RawExecutionOutput` (unless explicitly authorized by a future evidence retention policy; currently out of scope).
*   Binary paths or argument arrays.
*   Shell commands or process handles.
*   Concrete adapters or parsers.
*   `ToolDefinition.adapter` / `ToolDefinition.parser`.

**The Transient Rule:** `CapabilityRequest` must remain strictly transient. It flows exclusively through `ApprovalGateway → Runtime → MinimalOrchestrator`. To guarantee traceability, we persist the `ApprovedRequestRecord`, ensuring storage cannot be manipulated to launch arbitrary binaries.

## 8. Security and Integrity Rules

*   Storage must never trigger execution or synthesize a `CapabilityRequest`.
*   Storage must never bypass the `ApprovalGateway`.
*   The Intelligence Layer must never write directly to execution storage.
*   The Runtime remains the sole coordinator allowed to read/write state.
*   Approval logs and evidence collections are strictly append-only.
*   State snapshots are strictly versioned, utilizing optimistic version checks for all updates.
*   Storage adapters must not import V1 code, concrete tools, binaries, or args.
*   Storage must never turn a rejected recommendation into an executable state.

## 9. Versioning and Optimistic Updates

*   `AssessmentState` tracks a sequential `version` number.
*   Every saved transition strictly increments this version.
*   The storage adapter must reject stale writes (e.g., throwing a `StaleStateError` if the DB version does not match the saving version minus one).
*   This compare-and-swap / optimistic locking pattern prevents concurrent API, UI, or queue operations from overwriting each other, supporting safe optimistic concurrency at the domain level.

## 10. Session Scoping

Currently, `RecommendationInbox` and `AuditLog` operate as runtime-global singletons in-memory. Persistence solves this critical limitation by permanently scoping all records (recommendations, audit entries, evidence) by `sessionId`.
*   Approval lookups will become strictly session-scoped in the DB.
*   Future queries must structurally guarantee that a recommendation from Session A cannot be approved by or leaked into Session B.

## 11. Future Drizzle/PostgreSQL Path

The planned sequence for migrating from in-memory to PostgreSQL:
*   **Milestone 10:** Define storage port contracts (TypeScript interfaces only).
*   **Milestone 11:** Implement an in-memory `AssessmentRepository` adapter that complies with the interfaces to replace the current inline arrays.
*   **Milestone 12:** Drizzle / PostgreSQL schema design and normalization planning.
*   **Milestone 13:** Drizzle adapter implementation and integration into the runtime registry.

*(None of these milestones are implemented now).*

## 12. Out of Scope

The following are strictly out of scope for Milestone 9:
*   Writing TypeScript storage interfaces.
*   Drizzle schemas or database migrations.
*   Database client instantiation.
*   API routes, UI integrations, or webhooks.
*   Queues or background workers.
*   Auth, RBAC, or multi-tenant permission modeling.
*   New tools or capabilities.
*   V1 migration or runtime refactoring.
*   Event sourcing frameworks.
*   Raw execution output (stdout/stderr) retention policies.

## 13. Acceptance Criteria

This plan is acceptable because it defines:
*   The strict planning-only scope.
*   A hybrid persistence architecture (snapshot + append-only logs).
*   Storage boundary, name (`AssessmentRepository`), and dependency direction.
*   Persisted entities vs. non-persisted executable entities.
*   The absolute transient rule for `CapabilityRequest` and persistence of `ApprovedRequestRecord`.
*   The ban on binary/args persistence.
*   Append-only and optimistic update rules.
*   Session scoping constraints.
*   A logical path toward Drizzle/PostgreSQL.
*   Strict out-of-scope boundaries to prevent scope creep.
*   No implementation files were modified.

## 14. Risks of Premature Implementation

If persistence were implemented too early without this rigid contract:
*   Durable storage might accidentally cache and preserve raw `CapabilityRequest`s, opening security loopholes.
*   The database schema might encode temporary runtime decisions (like global inboxes) too early, making them permanently difficult to unpick.
*   The runtime and persistence layers could blur into a monolithic "mega-orchestrator", violating the separation of concerns.
*   API/UI needs could prematurely distort the storage contracts, prioritizing query performance over security domain boundaries.
*   Multi-session boundaries could remain weak, causing cross-session leakage.
*   V1 schema legacy patterns could heavily pollute the clean V2 DDD architecture.
