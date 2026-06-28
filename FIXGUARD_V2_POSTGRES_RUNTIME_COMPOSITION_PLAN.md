# FixGuard V2 Postgres Runtime Composition Plan (Milestone 22)

## Purpose
Add a narrow outer composition boundary to instantiate a Postgres-backed `V2AssessmentRuntime` directly from environment/configuration without polluting the core runtime or domain layers.

## Baseline
* M20 added robust, optional transaction capability to repositories.
* M21 modified `V2AssessmentRuntime` to dynamically adopt transactions when passed a compatible repository.
* Postgres is currently *not* the default runtime repository.

## Composition Boundary Responsibilities
* Explicitly require opt-in via specific environment variables.
* Instantiate the Neon serverless `Pool` and Drizzle DB instance.
* Create the `PostgresAssessmentRepository`.
* Construct the `V2AssessmentRuntime` using constructor injection.
* Manage resource cleanup (`close()` method to terminate the connection pool).
* Maintain strict decoupling from API/UI/queue bindings.

## Env Strategy
Composition demands three distinct variables:
* `FIXGUARD_V2_RUNTIME_REPOSITORY=postgres`
* `FIXGUARD_V2_ENABLE_POSTGRES_RUNTIME=1`
* `FIXGUARD_V2_DATABASE_URL=...`

## DB Driver Strategy
Leverages `@neondatabase/serverless` (specifically the `Pool` class) and `drizzle-orm/neon-serverless` to ensure database transactions are fully supported, meeting the prerequisites established in M21.

## Smoke Strategy
* **Safe-by-Default:** Silently skips when environment variables are missing to protect local dev.
* **Destructive Guard:** Demands `FIXGUARD_V2_RUNTIME_COMPOSITION_ALLOW_DESTRUCTIVE=1` to run.
* **Production DB Safety:** Requires an explicit human confirmation via FIXGUARD_V2_RUNTIME_COMPOSITION_CONFIRM_TEST_BRANCH=1 to ensure destructive tests are never run against a production database.
* **Behavior Check:** Re-uses the deterministic `StubToolRegistry` and performs a minimal e2e run. Validates that persistence hits Postgres and can be reloaded correctly. Cleans up *only* V2 tables.

## Safety Restrictions
* Under no circumstances will Postgres be made the default behavior of the system.
* No changes allowed to DB structure or migrations.

## Future Work
* Integrating this composition boundary with actual REST API routes, UI hooks, and background worker queues.

## Milestone 23 DB-Proven Validation Safety Note
Because a DB connection string was exposed during manual validation, the disposable Neon branch/password should be deleted or rotated after validation. Do not include the actual URL in any file.
