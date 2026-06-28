# FixGuard V2 PostgreSQL Storage Namespace

This namespace contains the relational schema definitions and the implementation for the PostgreSQL adapter for FixGuard V2.

## Current Status (Milestone 19)
* **Schema Exists:** V2-specific Drizzle schema is fully defined in `schema.ts`.
* **Adapter Exists:** `PostgresAssessmentRepository.ts` implements the `AssessmentRepository` contract.
* **DB Conformance Testing:** Milestone 19 adds env-gated DB conformance testing support. It can validate the adapter against a real PostgreSQL instance when configured, using the `AssessmentRepositoryConformanceSuite`. (Note: In the current local environment, only compilation and the DB-free missing-env skip path were verified).
  * **Migration Metadata Isolation:** The M19 smoke uses a V2-specific migration metadata namespace (schema: `drizzle_v2`, table: `__drizzle_migrations_v2`) to completely separate it from any legacy/default Drizzle migration metadata.
* **Runtime is NOT Integrated:** The V2 runtime remains entirely decoupled from Drizzle and PostgreSQL. It continues to operate via the `AssessmentRepository` interface and defaults to the InMemory adapter.

## Conformance Testing
To run the Postgres conformance smoke test, you must provide a real database URL and an explicit destructive guard:
```bash
FIXGUARD_PG_TEST_URL="postgresql://user:pass@host/db"
FIXGUARD_PG_TEST_ALLOW_DESTRUCTIVE=1
npx tsx src/v2/smoke/milestone19_postgres_repository_conformance_smoke.ts
```

* **Graceful Skip:** If `FIXGUARD_PG_TEST_URL` is missing, the smoke test will gracefully skip and exit.
* **Destructive Cleanup Guard:** The test aggressively truncates the V2 tables (`v2_execution_failure_records`, `v2_approved_request_records`, `v2_audit_entries`, `v2_evidence_records`, `v2_assessment_sessions`) using `RESTART IDENTITY CASCADE`. This operation is strictly gated behind the `FIXGUARD_PG_TEST_ALLOW_DESTRUCTIVE=1` flag.
* **No Legacy Interference:** The setup strictly targets V2 tables. Legacy tables and V1 schemas are completely untouched.

## Persistence Security Rules
Persistence is explicitly isolated from execution logic.
* **No Executable Payloads:** The database must never persist `CapabilityRequest`, `ExecutionRequest`, executable binaries, shell commands, or runner internals.
* **Traceability Only:** `ApprovedRequestRecord` is stored strictly for durable traceability and audit purposes. It is not executable work.
* **Boundary Validation:** `PostgresAssessmentRepository` rigorously validates and rejects incoming JSON payloads if they contain suspicious executable keys (`binary`, `args`, `command`, `shell`, `stdin`, `env`, `executionRequest`, `capabilityRequest`) before inserting into these tables.
