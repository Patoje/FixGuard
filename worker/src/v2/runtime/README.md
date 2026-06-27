# FixGuard V2 Runtime Foundation

This module acts as the thin application-service coordinator that moves data between the V2 layers (Execution Core, Intelligence Layer, and Approval Boundary).

**Core Philosophy:** Tools execute. Intelligence decides. Humans authorize.

## Key Concepts
*   `V2AssessmentRuntime`: Coordinates the assessment session lifecycle.
*   `V2AssessmentSession`: In-memory container for an assessment.
*   `AssessmentState`: Serializable, versioned snapshot of the current state.

## Rules
*   **In-Memory Only:** For Milestone 8, the runtime manages sessions strictly in memory.
*   **No Unrelated Services:** The runtime does not implement APIs, UIs, database persistence, or queues.
*   **Transient Requests:** `CapabilityRequest` remains transient only and is NOT stored in the session state.
*   **Composition Bound:** The runtime MUST use `createV2ToolRegistry` and MUST NOT import concrete adapters, parsers, or V1 legacy code directly.
*   **Internal State API:** `V2AssessmentSession.update` is for runtime/internal use only.
*   **Execution Recovery:** `ExecutionFailureRecord` handles recoverable capability failures safely.
