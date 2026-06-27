# FixGuard V2 Runtime Foundation

This module acts as the thin application-service coordinator that moves data between the V2 layers (Execution Core, Intelligence Layer, and Approval Boundary).

**Core Philosophy:** Tools execute. Intelligence decides. Humans authorize.

## Key Concepts
*   `V2AssessmentRuntime`: Coordinates the assessment session lifecycle.
*   `V2AssessmentSession`: In-memory container for an assessment.
*   `AssessmentState`: Serializable, versioned snapshot of the current state.

## Rules & Limitations
*   **In-Memory Only:** For Milestone 8, the runtime manages sessions strictly in memory.
*   **No Unrelated Services:** The runtime does not implement APIs, UIs, database persistence, or queues.
*   **Global Singletons:** `RecommendationInbox` and `AuditLog` are currently runtime-global, which is acceptable only for the current in-memory scope.
*   **Transient Requests:** `CapabilityRequest` remains transient only and is NOT stored in the session state. `AssessmentState` stores `ApprovedRequestRecord` instead.
*   **Deduplication:** The current recommendation deduplication key is intentionally simple (`capability + targetUri`). Future richer deduplication may need configuration, source findings, or auth context.
*   **Internal State API:** `V2AssessmentSession.update` is for runtime/internal use only.
*   **Composition Bound:** The runtime MUST use `createV2ToolRegistry` and MUST NOT import concrete adapters, parsers, or V1 legacy code directly.
*   **Execution Recovery:** `ExecutionFailureRecord` handles recoverable capability failures safely.
