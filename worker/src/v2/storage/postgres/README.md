# FixGuard V2 PostgreSQL Storage Namespace

This namespace contains the relational schema definitions for the future PostgreSQL adapter for FixGuard V2.

## Current Milestone (16) Constraints
* **Schema-only:** This namespace contains only passive table definitions.
* **No Repository:** No `PostgresAssessmentRepository` exists yet.
* **No Database Client:** There is no database connection code or client logic.
* **No Migrations:** Migrations have not been generated yet.
* **Decoupled Runtime:** The V2 runtime remains entirely decoupled from Drizzle and PostgreSQL. It continues to operate via the `AssessmentRepository` interface.

## Future Milestones
* **Milestone 17:** Conformance tests for the repository interface.
* **Milestone 18:** Implementation of the full `PostgresAssessmentRepository`.
* **Milestone 19+:** Migrations, transaction hardening, API/UI integration.

## Persistence Security Rules
Persistence is explicitly isolated from execution logic.
* **No Executable Payloads:** The database must never persist `CapabilityRequest`, `ExecutionRequest`, executable binaries, shell commands, or runner internals.
* **Traceability Only:** `ApprovedRequestRecord` is stored strictly for durable traceability and audit purposes. It is not executable work.
* **Boundary Validation:** When `PostgresAssessmentRepository` is implemented (Milestone 18), it must validate and reject incoming JSON payloads if they contain suspicious executable keys (`binary`, `args`, `command`, `shell`, `stdin`, `env`, `executionRequest`, `capabilityRequest`) before inserting into these tables.
