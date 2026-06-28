# FixGuard V2 Smoke Tests

This directory contains the formal, repeatable validation scripts for FixGuard V2. They ensure the architectural boundaries, contracts, and core features work correctly without relying on manual chat commands or tribal memory.

## DB-Free Validation (Default)

The default local validation strategy is DB-free, deterministic, and safe. It groups the most comprehensive tests to ensure boundaries remain intact.

To run the default validation:

```powershell
npm run check:v2
```
Or simply:
```powershell
npm test
```

This runs:
1. `npm run typecheck:v2`
2. `npm run smoke:v2` (aggregates DB-free runtime, storage, and application boundary tests)

**Sub-commands:**
- `npm run smoke:v2:runtime`: M14 lifecycle guards, M21 runtime transactions, M25 recommendation continuity.
- `npm run smoke:v2:storage`: M17 repository conformance, M20 in-memory transactions.
- `npm run smoke:v2:application`: M24 application service boundary.

## DB Opt-In Validation

Database-backed smoke tests are **explicitly opt-in only**. They are potentially destructive and require a specific environment setup.

To run the DB validation:

```powershell
npm run smoke:v2:db
```

This validates Postgres integration (M19, M20 DB, M22 DB).

### DB Safety Policies

DB validations must strictly follow these rules:
1. **Never commit DB URLs** or paste them into chat.
2. **Use disposable Neon test branches only.**
3. **Never use a production database.**
4. **Rotate or delete branch credentials** after validation.
5. **DB validation is not a production-readiness claim.**

**Required DB Environment Guards:**
* `FIXGUARD_PG_TEST_URL`
* `FIXGUARD_PG_TEST_ALLOW_DESTRUCTIVE=1`
* `FIXGUARD_V2_RUNTIME_REPOSITORY=postgres`
* `FIXGUARD_V2_ENABLE_POSTGRES_RUNTIME=1`
* `FIXGUARD_V2_DATABASE_URL`
* `FIXGUARD_V2_RUNTIME_COMPOSITION_ALLOW_DESTRUCTIVE=1`
* `FIXGUARD_V2_RUNTIME_COMPOSITION_CONFIRM_TEST_BRANCH=1`
