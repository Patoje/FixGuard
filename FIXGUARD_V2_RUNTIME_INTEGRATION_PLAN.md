# FixGuard V2 Runtime Integration Plan

## 1. Context

The FixGuard V2 architecture has successfully established three distinct, isolated layers:
*   **Execution Core:** Handles the safe execution of external binaries and parsing of their outputs. It is architecturally frozen. It uses `ToolRegistry` and `ToolDefinition` to resolve capabilities (e.g., `subdomain_discovery`, `http_probe`) to concrete tools without tight coupling.
*   **Intelligence Layer:** Foundation is complete. It consumes raw `EvidenceCollection`, deduplicates signals via `CorrelationEngine`, enriches a central `TargetProfile`, and proposes new actions via `RecommendationEngine`.
*   **Approval Boundary:** Foundation is frozen. It ensures human-in-the-loop authorization by intercepting recommendations in a `RecommendationInbox` and translating human `ApprovalDecision`s into safe `CapabilityRequest`s.

We have also created a **smoke harness** (`worker/src/v2/smoke/milestone6_5_smoke.ts`). This harness is a standalone smoke/demo harness and not a production runtime or application entrypoint. It manually orchestrates the sequence of events and lacks state persistence, concurrency controls, lifecycle management, and failure recovery necessary for a real application. 

This document plans the transition from a manual smoke harness to a formal runtime integration.

---

## 2. Runtime Responsibility

The core responsibility of the **`V2AssessmentRuntime`** is to act as a thin application-service coordinator that moves data between the existing V2 layers. It governs the lifecycle of an assessment session.

**The `V2AssessmentRuntime` MUST NOT:**
*   Execute tools directly (that is the job of the `MinimalOrchestrator` / Execution Core).
*   Know concrete tool names like `httpx` or `subfinder` (it only knows about abstract capabilities).
*   Decide the security meaning of findings (that is the job of the Intelligence Layer).
*   Bypass the `ApprovalGateway` for active capabilities.
*   Generate `CapabilityRequest`s directly from recommendations (that is the job of the `IntentTranslator` inside the Approval Boundary).
*   Own UI, HTTP API, or database persistence concerns (it should remain an application service).
*   Become a mega-orchestrator that tightly couples the layers together.

---

## 3. Proposed Concepts

The following concepts form the structural backbone of the runtime. (Note: These are planning-level definitions and are not yet implemented).

### V2AssessmentRuntime
*   **Responsibility:** The singleton/service-level coordinator that starts sessions, injects dependencies, and handles the macro-level routing of data between the Execution Core, Intelligence Layer, and Approval Boundary.
*   **State Ownership Model:** Milestone 8 must explicitly choose one runtime state ownership model:
    *   **A. Stateful in-memory runtime:** `V2AssessmentRuntime` owns active `V2AssessmentSession` instances in memory. This is simpler for the first implementation. It must still avoid becoming a mega-orchestrator.
    *   **B. Stateless runtime:** `V2AssessmentRuntime` receives an `AssessmentState` snapshot and returns a new `AssessmentState` snapshot. Session storage belongs to a separate future store. This is cleaner for API/persistence integration later.
    *   *Planning Recommendation:* Milestone 8 should start with the stateful in-memory model for simplicity, while keeping the `AssessmentState` serializable so it can later move to a persistent store.
*   **Non-responsibility:** Executing processes, storing long-term data in a DB, handling HTTP requests.
*   **Owned Data:** Active sessions in memory (if stateful) or the coordination logic (if stateless).
*   **Dependencies Allowed:** `MinimalOrchestrator`, `createV2ToolRegistry`, `ToolRegistry`, `TargetProfileBuilder`, `RecommendationEngine`, `ApprovalGateway`.
*   **Dependencies Forbidden:** Concrete parsers, concrete adapters, instantiating concrete tools directly, V1 legacy files.

### V2AssessmentSession
*   **Responsibility:** Represents a single logical security assessment against a specific target. It encapsulates the current state of the assessment as it moves through its lifecycle.
*   **Non-responsibility:** Executing logic on its own. It is a state container managed by the Runtime.
*   **Owned Data:** The `AssessmentState`.
*   **Dependencies Allowed:** None (it is purely a data/domain entity).
*   **Dependencies Forbidden:** Any external service, core orchestrator, or gateway.

### AssessmentState
*   **Responsibility:** A serializable snapshot of everything known about the current session.
*   **Non-responsibility:** Business logic, mutative methods.
*   **Owned Data:** Session ID, current lifecycle status, collected evidence, the `TargetProfile`, pending recommendations.
*   **Dependencies Allowed:** Only V2 data contracts (`TargetProfile`, `EvidenceCollection`, etc.).
*   **Dependencies Forbidden:** Execution contracts, services.

---

## 4. AssessmentState Model

The `AssessmentState` should be a strictly versioned, immutable snapshot that represents the assessment at a given point in time. Any changes should produce a new version of the state (or be append-only for logs).

Proposed fields:
*   `sessionId: string`
*   `target: string` (The root target URI)
*   `lifecycleStatus: LifecycleState`
*   `evidenceCollections: EvidenceCollection[]` (Append-only log of all collected evidence)
*   `currentProfile: TargetProfile` (The latest enriched profile)
*   `pendingRecommendations: AttackRecommendation[]`
*   `approvedRequestRecords: ApprovedRequestRecord[]` (Audit-friendly record of approved requests)
*   `executionFailures: ExecutionFailureRecord[]` (Append-only log of non-fatal execution failures)
*   `auditEntries: AuditEntry[]` (Append-only log of approval actions)
*   `errors: string[]`
*   `timestamps: { created: number, lastUpdated: number }`
*   `version: number` (Monotonically increasing)

**ApprovedRequestRecord (Conceptual)**
*   `recommendationId: string`
*   `decisionId: string`
*   `capability: string`
*   `targetUri: string`
*   `approvedAt: number`
*   `operatorId: string`
*   `requestSummary: Record<string, unknown>`
*   `sourceRecommendationId: string`

**ExecutionFailureRecord (Conceptual)**
*   `capability: string`
*   `targetUri: string`
*   `failedAt: number`
*   `errorMessage: string`
*   `recoverable: boolean`
*   `sourceRequestId?: string`
*   `sourceRecommendationId?: string`

*Note on Execution:* `CapabilityRequest` remains a transient boundary output from `ApprovalGateway` to Execution Core. `AssessmentState` stores `ApprovedRequestRecord` for auditability and replay reasoning, not executable intent.

---

## 5. Lifecycle States

The assessment session progresses through a defined state machine:

1.  `initialized`: Session created, target set, ready to begin.
2.  `initial_execution_running`: The seed/passive capability (e.g., `subdomain_discovery`) is actively running.
3.  `intelligence_running`: Evidence is being processed, correlated, and recommendations generated.
4.  `awaiting_approval`: The system is paused, waiting for human operator interaction on pending recommendations.
5.  `approved_execution_running`: An approved active capability (e.g., `http_probe`) is currently executing.
6.  `profile_updated`: The target profile has been enriched after new evidence. (Often loops back to `intelligence_running` or `awaiting_approval`).
7.  `completed`: The assessment has finished (no pending recommendations, or operator explicitly ended the session).
8.  `failed`: The session encountered a fatal, unrecoverable error.

**Allowed Transitions:**
*   `initialized` -> `initial_execution_running`
*   `initial_execution_running` -> `intelligence_running` | `failed`
*   `intelligence_running` -> `awaiting_approval` | `profile_updated` | `failed`
*   `awaiting_approval` -> `approved_execution_running` | `completed` | `failed`
*   `approved_execution_running` -> `intelligence_running` | `failed`
*   `profile_updated` -> `completed` | `awaiting_approval`

---

## 6. Approval Boundary Flow

To adhere to the core rule—"Tools execute. Intelligence decides. Humans authorize"—the runtime must strictly enforce the following data path. The `RecommendationEngine` and its rules **must never** create a `CapabilityRequest` directly.

**Exact Intended Path:**
1.  Intelligence Layer produces an `AttackRecommendation`.
2.  Runtime routes the `AttackRecommendation` into the `RecommendationInbox`.
3.  Human Operator interacts with the UI/API, which calls `ApprovalGateway.approve(id)`.
4.  `ApprovalGateway` creates an `ApprovalDecision` and passes it to the `IntentTranslator`.
5.  `IntentTranslator` safely synthesizes a `CapabilityRequest` tagged with the `sourceRecommendationId`.
6.  `ApprovalGateway` returns this `CapabilityRequest` to the Runtime.
7.  Runtime passes the `CapabilityRequest` to the `MinimalOrchestrator` (Execution Core) to run.

---

## 7. Capabilities and Approval Policy

Not all capabilities require human intervention. 

*   **Implicitly Approved:** Initial passive, reconnaissance, or seed capabilities (e.g., `subdomain_discovery`) are implicitly approved when the human user creates and starts the `V2AssessmentSession`.
*   **Requires Explicit Approval:** Recommendations generated by the Intelligence Layer for additional active capabilities (e.g., `http_probe`, fuzzing, vulnerability scanning) MUST pass through the `ApprovalGateway`. 

*(Note: We will not add new capabilities in this milestone; we are only defining the policy for the existing two).*

---

## 8. Dependency Rules

To maintain strict modularity, the following dependency directions are enforced for the future runtime integration:

**The Runtime MAY compose:**
*   `createV2ToolRegistry`
*   `ToolRegistry`
*   `MinimalOrchestrator` (or a future execution facade)
*   `EvidenceAccumulator`
*   `CorrelationEngine`
*   `TargetProfileBuilder`
*   `RecommendationEngine`
*   `RecommendationInbox`
*   `ApprovalGateway`
*   `AuditLog`

**The Runtime MUST NOT:**
*   Import concrete tool adapters directly.
*   Import concrete parsers directly.
*   Instantiate concrete tools directly.
*   Import any files from the V1 legacy system.
*   Bypass the `ApprovalGateway` by manually constructing `CapabilityRequest`s for attack actions.
*   Embed tool-specific logic (e.g., parsing CLI flags).
*   Embed HTTP API, UI routing, or database persistence logic (the runtime is purely a domain/application service).

---

## 9. Failure Behavior

At the planning level, the runtime must gracefully handle the following failure modes:

*   **Tool execution failure:** Tool execution failure should usually append an `ExecutionFailureRecord`. The session should move to `failed` only if the failure breaks a runtime invariant, corrupts session state, or prevents safe continuation.
*   **Parser failure:** Handled internally by the parser (usually emitting a metadata error in the `EvidenceCollection`). The runtime continues normally; the Intelligence Layer simply receives fewer findings.
*   **Zero findings:** Execution completes, but yields no findings. The runtime processes the empty collection. The Intelligence Layer updates the profile (if applicable), generates 0 recommendations, and the session naturally transitions to `completed`.
*   **Recommendation generation failure:** If a rule crashes, the runtime catches the error, logs it, and transitions the session to `failed`.
*   **Approval rejection:** If the operator rejects a recommendation, the `ApprovalGateway` records the rejection. No `CapabilityRequest` is generated. The runtime removes it from the pending queue.
*   **Approval translation failure:** If `IntentTranslator` throws, the runtime catches it, logs a critical error, and transitions to `failed` to prevent unauthorized execution. Approval translation failure should remain fatal because it risks unsafe execution.

---

## 10. Audit Points

The runtime must ensure the following lifecycle events are securely audited/logged:

*   Session created and initialized.
*   Capability execution started (with target URI).
*   Capability execution completed (with exit status and finding count).
*   Evidence accepted into the accumulator.
*   Target profile rebuilt/version incremented.
*   New recommendation generated.
*   Recommendation submitted to the inbox.
*   Approval explicitly accepted or rejected by an operator.
*   Approved capability request safely synthesized.
*   Approved execution completed.
*   Session cleanly completed or fatally failed.

---

## 11. Out of Scope

Milestone 7 is strictly for planning. The following are **out of scope** and must NOT be implemented in this milestone:

*   HTTP API routes (Express/Fastify/etc.).
*   UI frontend integration.
*   Database persistence (Postgres, Redis, etc.).
*   Job queues or background workers (BullMQ, etc.).
*   Authentication, RBAC, or user ownership.
*   Multi-tenant session storage logic.
*   Complex retries, scheduling, or a concurrency engine.
*   New tools or capabilities beyond `subdomain_discovery` and `http_probe`.
*   Modifications to the frozen Execution Core.
*   Modifications to Approval Boundary contracts.
*   Modifications to the `TargetProfile` interface.
*   Converting the existing `milestone6_5_smoke.ts` directly into production runtime code.
*   Automatic exploitation mechanics.
*   LLM-based decision-making.
*   Migrating V1 logic.

---

## 12. Acceptance Criteria for Implementation Milestone

Before moving to Milestone 8 (actual implementation of the runtime), the following must be true:

1.  Runtime state ownership model approved.
2.  `AssessmentState` data model approved.
3.  `ApprovedRequestRecord` representation approved.
4.  Recoverable execution failure model approved.
5.  Lifecycle states and allowed transitions are formally approved.
6.  Approval flow path is formally approved.
7.  Runtime dependency on `createV2ToolRegistry` approved.
8.  `CapabilityRequest` remains transient and is not stored raw in `AssessmentState`.
9.  Audit points are formally approved.
10. **NO** frozen contracts (Execution, Intelligence, Approval) have been modified.
11. The Milestone 6.5 smoke harness remains completely separate and untouched.
