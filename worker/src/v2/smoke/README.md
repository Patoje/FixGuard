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
- `npm run smoke:v2:capabilities`: M27 capability contract boundary, M28 capability registry enforcement, and M29 passive http header inspect vertical flow.
- `npm run smoke:v2:recon`: M30 authorized scope / egress policy boundary, M31 guarded real HTTP header inspect adapter, M33 egress policy audit boundary, M34 active recon adapter boundary, and M36 active recon safe document metadata boundary. These tests are included in `smoke:v2` and `check:v2`. All are DB-free and network-free (M31 uses a fake transport, M33 uses a pure in-memory mapper/recorder, M34 uses a fake adapter, M36 uses local sanitizers and fake adapter).

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

## Real Egress Opt-In Validation

Real egress validations are **explicitly opt-in only**. By default, all tests (including `check:v2` and `smoke:v2`) use fake transports and are strictly DB-free and network-free. 

To run the M32 real egress validation:

```powershell
npm run smoke:v2:recon:real
```

### Real Egress Safety Policies

* M32 is opt-in only.
* M32 is real egress validation only.
* M32 is not production readiness.
* M32 is not crawling, scanning, or vulnerability validation.
* M32 performs one bounded `HEAD` request.
* M32 reads no body and follows no redirects.
* M32 creates no findings.
* M32 is excluded from `check:v2`, `smoke:v2`, and `smoke:v2:recon`.
* Default validations remain DB-free and external-network-free.

**Required M32 Real Egress Environment Guards:**
* `FIXGUARD_V2_REAL_HTTP_HEADER_INSPECT=1`
* `FIXGUARD_V2_REAL_HTTP_HEADER_INSPECT_URL=<https://your-authorized-url.com/>`
* `FIXGUARD_V2_REAL_HTTP_HEADER_INSPECT_ALLOWED_ORIGIN=<https://your-authorized-url.com>`
* `FIXGUARD_V2_REAL_HTTP_HEADER_INSPECT_CONFIRM_AUTHORIZED=I_CONFIRM_AUTHORIZED_TEST_TARGET`

To run the M35 real active recon validation:

```powershell
npm run smoke:v2:recon:active:real
```

### M35 Real Active Recon Safety Policies

* M35 is opt-in only.
* M35 is real egress validation only.
* M35 is not production readiness.
* M35 is not crawling, scanning, or vulnerability validation.
* M35 performs exactly one bounded `GET` request to `/robots.txt`.
* M35 reads max 16 KiB and follows no redirects.
* M35 emits no raw bodies, headers, URLs, or directive paths.
* M35 creates no findings or product evidence.
* M35 is excluded from `check:v2`, `smoke:v2`, and `smoke:v2:recon`.

**Required M35 Real Egress Environment Guards:**
* `FIXGUARD_V2_REAL_ACTIVE_RECON=1`
* `FIXGUARD_V2_REAL_ACTIVE_RECON_PROBE=http.robots.inspect`
* `FIXGUARD_V2_REAL_ACTIVE_RECON_URL=<https://your-authorized-url.com/robots.txt>`
* `FIXGUARD_V2_REAL_ACTIVE_RECON_ALLOWED_ORIGIN=<https://your-authorized-url.com>`
* `FIXGUARD_V2_REAL_ACTIVE_RECON_CONFIRM_AUTHORIZED=I_CONFIRM_AUTHORIZED_ACTIVE_RECON_TARGET`

To run the M37 real security.txt active recon validation:

```powershell
npm run smoke:v2:recon:active:security-txt:real
```

### M37 Real security.txt Active Recon Safety Policies

* M37 is opt-in only.
* M37 is real egress validation only.
* M37 is not production readiness.
* M37 is not crawling, scanning, or vulnerability validation.
* M37 adds exactly one real opt-in active recon probe: `http.security_txt.inspect`.
* M37 allows only `/.well-known/security.txt` — `/security.txt` is explicitly forbidden.
* M37 performs exactly one bounded `GET` request to `/.well-known/security.txt`.
* M37 reads max 16 KiB and follows no redirects.
* M37 uses the M36 `sanitizeSecurityTxtMetadata` — no emails, URLs, PGP, or field values survive serialization.
* M37 emits no raw bodies, headers, or field values.
* M37 creates no findings or product evidence.
* M37 does not integrate runtime, storage, Postgres, API, or UI.
* M37 is excluded from `check:v2`, `smoke:v2`, and `smoke:v2:recon`.
* M35 robots adapter (`RealActiveReconHttpProbeAdapter.ts`) remains untouched.

**Required M37 Real Egress Environment Guards:**
* `FIXGUARD_V2_REAL_ACTIVE_RECON=1`
* `FIXGUARD_V2_REAL_ACTIVE_RECON_PROBE=http.security_txt.inspect`
* `FIXGUARD_V2_REAL_ACTIVE_RECON_URL=<https://your-authorized-url.com/.well-known/security.txt>`
* `FIXGUARD_V2_REAL_ACTIVE_RECON_ALLOWED_ORIGIN=<https://your-authorized-url.com>`
* `FIXGUARD_V2_REAL_ACTIVE_RECON_CONFIRM_AUTHORIZED=I_CONFIRM_AUTHORIZED_SECURITY_TXT_TARGET`

## M38 Active Recon Document Probe Runner

### M38 DB-Free Runner Smoke

The M38 DB-free runner smoke is included in `smoke:v2:recon` (and by extension `smoke:v2` and `check:v2`):

```powershell
npm run smoke:v2:recon:active:runner
```

### M38 Real Combined Opt-in Runner Smoke

To run the M38 real combined opt-in validation:

```powershell
npm run smoke:v2:recon:active:runner:real
```

### M38 Safety Policies

* M38 is a runner boundary — it orchestrates already-approved probes only.
* M38 does not add new probe kinds beyond `http.robots.inspect` and `http.security_txt.inspect`.
* M38 does not derive target URLs from origins (no auto-generation of `/robots.txt` or `/.well-known/security.txt`).
* M38 does not modify real adapters (`RealActiveReconHttpProbeAdapter.ts`, `RealActiveReconSecurityTxtProbeAdapter.ts`).
* M38 does not persist anything. No findings or evidence are created.
* M38 does not integrate runtime, storage, Postgres, API, or UI.
* M38 uses dependency injection — real adapters must be explicitly injected, never instantiated by default.
* M38 evaluates M30 egress policy per-target before adapter invocation. Blocked/candidate decisions never reach adapters.
* Fake fixtures in the DB-free smoke are not real target evidence.
* No production-readiness claims are made.

**Required M38 Real Opt-in Environment Guards:**
* `FIXGUARD_V2_REAL_ACTIVE_RECON_RUN=1`
* `FIXGUARD_V2_REAL_ACTIVE_RECON_RUN_PROBES=http.robots.inspect,http.security_txt.inspect`
* `FIXGUARD_V2_REAL_ACTIVE_RECON_ROBOTS_URL=<https://your-authorized-url.com/robots.txt>`
* `FIXGUARD_V2_REAL_ACTIVE_RECON_SECURITY_TXT_URL=<https://your-authorized-url.com/.well-known/security.txt>`
* `FIXGUARD_V2_REAL_ACTIVE_RECON_ALLOWED_ORIGIN=<https://your-authorized-url.com>`
* `FIXGUARD_V2_REAL_ACTIVE_RECON_CONFIRM_AUTHORIZED=I_CONFIRM_AUTHORIZED_ACTIVE_RECON_RUN_TARGET`

## M39 Authorized Origin Active Recon Run

### M39 DB-Free Smoke

The M39 DB-free smoke is included in `smoke:v2:recon` (and by extension `smoke:v2` and `check:v2`):

```powershell
npm run smoke:v2:recon:active:origin-run
```

### M39 Real Opt-in Smoke

To run the M39 real opt-in validation:

```powershell
npm run smoke:v2:recon:active:origin-run:real
```

### M39 Safety Policies

* M39 is the first authorized origin active recon run boundary.
* M39 does not crawl, does not discover endpoints, does not guess subdomains, and does not accept arbitrary paths.
* M39 maps a clean authorized origin to exactly two targets: `/robots.txt` and `/.well-known/security.txt`.
* M39 uses the M38 runner internally and injects real adapters only in the explicit real opt-in smoke.
* M39 does not add new probe kinds or modify real adapters.
* M39 does not persist anything, create findings, or create evidence.
* M39 does not integrate runtime, storage, Postgres, API, or UI.
* Fake outputs in DB-free smoke are not real target evidence.
* No production-readiness claims are made.

**Required M39 Real Opt-in Environment Guards:**
* `FIXGUARD_V2_REAL_ACTIVE_RECON_ORIGIN_RUN=1`
* `FIXGUARD_V2_REAL_ACTIVE_RECON_ORIGIN=<https://your-authorized-url.com>`
* `FIXGUARD_V2_REAL_ACTIVE_RECON_ORIGIN_RUN_PROBES=http.robots.inspect,http.security_txt.inspect`
* `FIXGUARD_V2_REAL_ACTIVE_RECON_CONFIRM_AUTHORIZED=I_CONFIRM_AUTHORIZED_ACTIVE_RECON_ORIGIN_RUN_TARGET`

## M40 Active Recon Origin Run Persistence Boundary

### M40 DB-Free Persistence Smoke

The M40 DB-free persistence smoke is included in `smoke:v2:recon` (and by extension `smoke:v2` and `check:v2`):

```powershell
npm run smoke:v2:recon:active:persistence
```

### M40 Safety Policies

* M40 persists only safe M39 origin run summaries.
* M40 uses a DB-free in-memory repository (`InMemoryActiveReconOriginRunRepository.ts`).
* M40 does not add Postgres or migrations.
* M40 does not persist raw target URLs, internal generated URLs, or raw body/headers/request/response/payloads.
* M40 does not persist cookies/auth/tokens/passwords/API keys.
* M40 does not create findings or evidence records.
* M40 does not integrate UI or API surfaces.
* M40 does not run scanners or crawlers.
* Fake smoke output is not real target evidence.
* No production-readiness claim.

## M41 Postgres Active Recon Run Persistence Validation

M41 introduces real Postgres-backed persistence for the validated M40 active recon run record shape. It is strictly explicitly opt-in and validates that the Postgres adapter (`PostgresActiveReconRunRepository`) integrates safely with Drizzle migrations without persisting executable findings, evidence, or raw request/response boundaries.

To run the M41 Postgres smoke validation:

```powershell
npm run smoke:v2:recon:active:persistence:postgres
```

### M41 Postgres Safety Policies

* M41 is explicitly opt-in only.
* M41 does NOT run in `check:v2` or `smoke:v2`.
* M41 requires a real, disposable Neon Postgres branch.
* M41 uses a strict `run_id` test prefix (`m41_pg_smoke_`) for targeted record deletion, rather than broad table truncation.
* M41 enforces `validatePersistedActiveReconRunRecord` on all `saveRun`, `getRun`, and `listRuns` calls to ensure database-layer corruption or tampering is rejected before re-entering the application boundary.

**Required M41 Environment Guards:**
* `FIXGUARD_PG_TEST_URL`
* `FIXGUARD_V2_POSTGRES_ACTIVE_RECON_RUN_PERSISTENCE=1`
* `FIXGUARD_V2_POSTGRES_ACTIVE_RECON_CONFIRM=I_CONFIRM_POSTGRES_ACTIVE_RECON_PERSISTENCE_TEST`

## M42 Active Recon Execution Persistence Service

M42 composes M39 (execution) and M40 (persistence) without duplicating either. It enforces DB-free, scanner-free, and API/UI-free boundaries while orchestrating real behavior. 

**DB-Free Smoke (Included in `smoke:v2:recon`)**
```powershell
npm run smoke:v2:recon:active:execution-persistence
```
Proves run -> persist -> reload using fake adapters and the in-memory repository.

**Real Opt-in Smoke (Excluded from defaults)**
```powershell
npm run smoke:v2:recon:active:execution-persistence:real
```
Proves run -> persist -> reload using existing guarded real adapters and the in-memory repository. M42 does not introduce Postgres-integrated components; the real smoke is generic.

### M42 Real Smoke Safety Policies

* M42 real smoke is explicitly opt-in only.
* M42 real smoke does NOT run in `check:v2`, `smoke:v2`, or `smoke:v2:recon`.
* Validates origin and probes BEFORE adapter construction.
* Fails safely and completely on partial/missing environment variables.


**Required M42 Environment Guards:**
* `FIXGUARD_V2_REAL_ACTIVE_RECON_PERSISTED_RUN=1`
* `FIXGUARD_V2_REAL_ACTIVE_RECON_PERSISTED_RUN_ORIGIN` (must be strict origin)
* `FIXGUARD_V2_REAL_ACTIVE_RECON_PERSISTED_RUN_PROBES`
* `FIXGUARD_V2_REAL_ACTIVE_RECON_PERSISTED_RUN_CONFIRM=I_CONFIRM_AUTHORIZED_ACTIVE_RECON_PERSISTED_RUN_TARGET`

## M43 Active Recon Run Read Model + Safe Report Snapshot Validation

M43 adds read models and safe report snapshots from persisted active recon records. M43 consumes persisted safe records only and does not execute probes.

**DB-Free Smoke (Included in `smoke:v2:recon`)**
```powershell
npm run smoke:v2:recon:active:read-model
```
Proves read model list/detail functions and report snapshot builder using the M42 DB-free execution flow into an in-memory repository.

### M43 Safety Policies

* M43 does not execute probes.
* M43 does not add Postgres schema/migrations.
* M43 does not add UI/API.
* M43 does not create findings/evidence records.
* Report snapshot contains explicit non-claims and is not a vulnerability report.
* Smoke fixtures are test-only and not real target evidence.
