# FixGuard V2 Storage Port Contracts

This directory contains the Storage Port Contracts for FixGuard V2 (Milestone 10).

**Rules:**
*   **Contracts Only:** There is no implementation, no database code, no schemas, no Drizzle, and no migrations here.
*   **Passive Storage:** Storage never executes capabilities, never creates `CapabilityRequest`, and never calls runtime/orchestrator/approval/intelligence services.
*   **Safe Persistence:** Storage persists `ApprovedRequestRecord`, not executable requests. `CapabilityRequest` remains strictly transient. Durable traceability uses `ApprovedRequestRecord` instead.
*   **No Binary/Args:** No binary names, arguments, or raw execution commands are persisted.

**Future Implementation Path:**
*   Milestone 11 should implement an in-memory `AssessmentRepository` adapter complying with these contracts.
*   Milestone 12/13 can handle Drizzle/PostgreSQL planning and implementation later.
