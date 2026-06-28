# V2 Runtime Composition

This directory contains explicit outer composition boundaries for \V2AssessmentRuntime\.

**Key Principles:**

* **Explicit Outer Boundary:** Environment variables, database clients (Neon/Drizzle), and configuration setup belong here, strictly separated from the pure runtime and domain logic.
* **Not the Default:** Postgres is not the runtime default. The \V2AssessmentRuntime\ remains fully repository-agnostic. Postgres usage must be explicitly opted-in via composition boundaries.
* **Transaction Compatibility:** We utilize \@neondatabase/serverless\ (Pool) instead of HTTP because the runtime is designed to leverage repository transactions when available (introduced in M20/M21).
* **Future Integration:** Production API/UI/queue/worker integration that uses this composition boundary is considered future work.
* **Migrations:** This composition boundary expects that Postgres migrations have already been successfully executed via the deployment pipeline.
* **Smoke Test Safety Gate:** The real DB smoke test is strictly env-gated and must **never** be run against production. It skips cleanly if the opt-in vars are missing, and refuses to run DB work if the safety guards are missing. The full required safety gate is:
  * \FIXGUARD_V2_RUNTIME_REPOSITORY=postgres\
  * \FIXGUARD_V2_ENABLE_POSTGRES_RUNTIME=1\
  * \FIXGUARD_V2_DATABASE_URL=...\
  * \FIXGUARD_V2_RUNTIME_COMPOSITION_ALLOW_DESTRUCTIVE=1\ (allows destructive V2-table cleanup)
  * \FIXGUARD_V2_RUNTIME_COMPOSITION_CONFIRM_TEST_BRANCH=1\ (explicit human confirmation that the DB is a disposable/test branch)
* **No Overclaims:** This demonstrates architectural capability but does not inherently claim production readiness on its own.
