# FixGuard V2 Runtime Foundation

This module acts as the thin application-service coordinator that moves data between the V2 layers (Execution Core, Intelligence Layer, and Approval Boundary).

**Core Philosophy:** Tools execute. Intelligence decides. Humans authorize.

## Key Concepts
*   `AssessmentState`: The core data object containing findings, recommendations, profiles, and immutable trace logs (evidence, audits).
*   `V2AssessmentSession`: The state container that enforces immutable state transitions and version increments via `update()`.
*   `V2AssessmentRuntime`: The workflow controller. It accepts two optional constructor arguments:
    *   `repository?: AssessmentRepository` — defaults to `InMemoryAssessmentRepository`.
    *   `orchestratorOrRegistry?: MinimalOrchestrator | ToolRegistry` — when omitted, the default production registry (`createV2ToolRegistry()`) and `LocalProcessRunner` are used. Smoke tests inject a deterministic `MinimalOrchestrator` (backed by `StubToolRegistry` + `StubProcessRunner`) to exercise the full runtime/intelligence/approval flow without spawning real processes.

## Important Constraints
*   **Awaited Inline Persistence:** The runtime methods present an asynchronous API (`Promise<AssessmentState>`) and wait for the repository to safely persist the state transition before returning.
*   **Strict Optimistic Versioning:** Optimistic locking is strictly enforced without dynamic repair. A new session saves with `expectedVersion = 0`, and any subsequent update saves with `expectedVersion = state.version - 1`.
*   **Repository Failures:** Any failures during `saveAssessmentState` or appending records (such as `StaleStateError`) propagate naturally, rejecting the runtime operation.
*   **Storage Boundaries:** Storage strictly persists `ApprovedRequestRecord`. Executable `CapabilityRequest` objects are transient and never stored or leaked in state summaries.
*   **Transaction Adoption:** The runtime now detects if the injected repository implements `TransactionalAssessmentRepository`. If it does, mutating multi-write flows (such as `startInitialRecon`, `approveRecommendation`, and `rejectRecommendation`) are wrapped in transactions to ensure atomicity. If a non-transactional repository is provided, the runtime gracefully falls back to the original non-transactional behavior.
*   **Postgres Not Default:** The default injected repository remains the `InMemoryAssessmentRepository`. Postgres runtime integration remains future work.
*   **No Unrelated Services:** The runtime does not implement APIs, UIs, database persistence, or queues.
*   **Global Singletons:** `RecommendationInbox` and `AuditLog` are currently runtime-global, which is acceptable only for the current in-memory scope.
*   **Transient Requests:** `CapabilityRequest` remains transient only and is NOT stored in the session state. `AssessmentState` stores `ApprovedRequestRecord` instead. There is no CapabilityRequest reconstruction during session load.
*   **Session Resume:** `loadSession(sessionId)` supports snapshot-only loading. It checks the active collision map first (returning the active session if one exists) and returns undefined for missing sessions. It does not trigger auto-execution or replay append-only logs.
*   **Lifecycle Guards:** Explicit lifecycle guards prevent invalid state transitions before mutation or persistence occurs. Terminal states (`completed`, `failed`) and running states (`initial_execution_running`, etc.) reject mutations by throwing a `RuntimeLifecycleError`. Invalid transitions have zero side effects (no mutation, no persistence, no logs).
*   **Deduplication:** The current recommendation deduplication key is intentionally simple (`capability + targetUri`). Future richer deduplication may need configuration, source findings, or auth context.
*   **Internal State API:** `V2AssessmentSession.update` is for runtime/internal use only.
*   **Composition Bound:** The runtime uses `createV2ToolRegistry` and `LocalProcessRunner` by default. Smoke tests may inject a deterministic `MinimalOrchestrator` through the constructor. The runtime MUST NOT import concrete adapters, parsers, or V1 legacy code directly.
*   **Execution Recovery:** `ExecutionFailureRecord` handles recoverable capability failures safely.
