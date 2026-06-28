# FixGuard V2 Validation Scripts Plan

## Goal
Make V2 validation repeatable through explicit npm scripts, ensuring that DB-free smoke tests are the default and DB-gated tests remain explicitly opt-in. This guarantees stability and removes the reliance on manually entered chat commands.

## Strategy

### Default DB-Free Validation
The default validation script `npm run check:v2` (aliased to `npm test`) will execute:
1. `npm run typecheck:v2`
2. `npm run smoke:v2`

The `smoke:v2` script aggregates the strongest DB-free regression suites across:
* **Runtime:** M14 lifecycle guards, M21 runtime transaction adoption, M25 recommendation continuity.
* **Storage:** M17 repository conformance, M20 in-memory transaction conformance.
* **Application:** M24 application service boundary.

### DB Opt-In Validation
The `npm run smoke:v2:db` script runs the DB-dependent smoke tests (M19, M20 DB, M22 DB). It is explicitly opted into and expects the following environment variables to be configured:
* `FIXGUARD_PG_TEST_URL`
* `FIXGUARD_PG_TEST_ALLOW_DESTRUCTIVE=1`
* `FIXGUARD_V2_RUNTIME_REPOSITORY=postgres`
* `FIXGUARD_V2_ENABLE_POSTGRES_RUNTIME=1`
* `FIXGUARD_V2_DATABASE_URL`
* `FIXGUARD_V2_RUNTIME_COMPOSITION_ALLOW_DESTRUCTIVE=1`
* `FIXGUARD_V2_RUNTIME_COMPOSITION_CONFIRM_TEST_BRANCH=1`

### Safety Policies
* **No DB credentials in chat or git:** DB URLs must never be committed or pasted into chat.
* **Disposable Neon Branches:** Only use disposable Neon test branches for DB validation. Never use production databases.
* **Credential Rotation:** Rotate/delete branch credentials after manual validation.
* **Not Production Readiness:** Passing DB validation implies the persistence and boundary logic works, but does not claim production readiness.
