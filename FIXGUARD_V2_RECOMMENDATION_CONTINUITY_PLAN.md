# FixGuard V2 Recommendation Continuity Plan (Milestone 25)

## Purpose
Ensure that pending recommendations remain actionable after a session is reloaded from persistent storage. Approval logic must not depend solely on an ephemeral runtime-local `RecommendationInbox`.

## Implementation
- Modify `ApprovalGateway` interface and `LocalApprovalGateway` to accept an `AttackRecommendation` directly.
- Modify `V2AssessmentRuntime` to resolve the pending recommendation from `AssessmentState.pendingRecommendations` using the `recommendationId`.
- Translate the persisted `AttackRecommendation` to a transient `CapabilityRequest` at explicit approval time.
- Remove the recommendation from `AssessmentState.pendingRecommendations` after approval/rejection.
- Append a safe `ApprovedRequestRecord` containing no executable payloads.

## Constraints Preserved
- `CapabilityRequest` remains strictly transient.
- `ExecutionRequest` is never persisted.
- Executable keys (`binary`, `args`, `env`, `command`, `shell`, `stdin`) are never exposed or persisted.
- Approval remains explicitly human-authorized.
- `loadSession` does not auto-approve or auto-execute.
- The runtime remains fully repository-agnostic and free of Postgres/DB imports.
- No DB/schema/migrations changes are required.
