# FixGuard V2 Storage Port Contracts

This directory contains the Storage Port Contracts for FixGuard V2 (Milestone 10).

**Rules:**
*   **Contracts Only:** There is no implementation, no database code, no schemas, no Drizzle, and no migrations here.
*   **Passive Storage:** Storage never executes capabilities, never creates `CapabilityRequest`, and never calls runtime/orchestrator/approval/intelligence services.
*   **Safe Persistence:** Storage persists `ApprovedRequestRecord`, not executable requests. `CapabilityRequest` remains strictly transient. Durable traceability uses `ApprovedRequestRecord` instead.
*   **No Binary/Args:** No binary names, arguments, or raw execution commands are persisted.

**Current Implementation:**
*   `InMemoryAssessmentRepository` exists but it is local/test-only for now.
*   It is not durable persistence and contains no database code.
*   It does not integrate with the runtime yet.
*   It never executes and never creates `CapabilityRequest`.
*   It persists `ApprovedRequestRecord`-style durable traceability only.

**Future Implementation Path:**
*   Milestone 12/13 can handle Drizzle/PostgreSQL planning and implementation later.
