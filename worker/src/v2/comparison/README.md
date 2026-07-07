# M47 — Response Comparator Core

## Purpose

M47 defines a DB-free, pure-function boundary for comparing sanitized HTTP response snapshots and producing sanitized comparison results.

## Contract Version

`fixguard-response-comparator/v0`

## Files

- `ResponseComparatorContracts.ts` — TypeScript interfaces and closed enum constants
- `ResponseComparatorService.ts` — Pure comparison logic, validators, and result builders

## Public API

```ts
validateSafeResponseSnapshot(snapshot): ValidationResult
validateResponseComparisonRequest(request): ValidationResult
compareResponses(request, comparedAt): ResponseComparisonResult
buildResponseDifference(baseline, validation, thresholds): ResponseDifference
deriveComparisonSignificance(difference, mode): ComparisonSignificance
deriveEvidenceMappingHint(difference, significance, mode): EvidenceMappingHint
```

## Architecture Position

```
M46 authorization decision
  -> M30/M33 egress decision
    -> tool/adapter executes
      -> sanitized snapshots
        -> M47 response comparison     <-- HERE
          -> future mapper
            -> M45 EvidenceRecord
              -> M45 promotion decision
```

## What M47 Does

- Compares `SafeResponseSnapshot` (baseline vs. validation) and produces `ResponseComparisonResult`.
- Computes differences in status code, content length, response time, body hash, header names, JSON structure, redirect, and auth state.
- Derives comparison signal strength (`none`, `weak`, `moderate`, `strong`) — **not severity, risk, or impact**.
- Produces `EvidenceMappingHint` as a non-persisted pointer toward a future M45 `EvidenceRecord` type.
- All outputs contain `explicitNonClaims` asserting no vulnerability, finding, evidence, or severity/risk/impact claims.

## What M47 Does NOT Do

- **Does not execute network requests or tools.** All inputs must be pre-captured snapshots.
- **Does not import M45 types or build `EvidenceRecord` / `FindingCandidateRecord`.** M47 is independent of M45.
- **Does not persist any data.** No repositories, no DB, no Postgres.
- **Does not create findings or confirm vulnerabilities.**
- **Does not make severity, risk, or impact claims.**
- **Does not echo raw responses, headers, bodies, or secrets.**
- **Does not integrate runtime, API, or UI.**

## Key Safety Properties

### Decision metadata sanitization

`compareResponses(request, comparedAt)` validates and sanitizes all IDs before constructing any result:

| Field | Invalid sentinel |
|---|---|
| `comparisonId` | `invalid_comparison_id` |
| `baselineSnapshotId` / `validationSnapshotId` | `invalid_snapshot_id` |
| `scanId` | `invalid_scan_id` |
| `comparedAt` | `1970-01-01T00:00:00.000Z` |

### Subject exactness

- `SnapshotSubject` must include either `routeId` OR `(normalizedOrigin + method + pathTemplate)`.
- An empty subject is invalid.
- `baseline.subject` must exactly equal `validation.subject` in M47 (no cross-subject comparison mode).

### Header name safety

- `headerNames` contains only header **names**, never values.
- Sensitive header names (`Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization`, `X-Api-Key`) are **rejected** even as names.

### Error signals

- `errorSignals.signalNames` is a **closed enum** array. No free-text error messages, no stack traces, no exception text.
- Allowed values: `sql_error_like`, `stack_trace_like`, `auth_error_like`, `server_error_like`, `rate_limit_like`, `validation_error_like`.

### Time-based difference safety

- `time_based_difference` evidence mapping hint is **only** produced when `comparisonMode === "time_based_difference"` **AND** `responseTimeSignificant === true`.
- Generic/http mode + `responseTimeSignificant` → `http_difference` hint (not `time_based_difference`).
- No SQLi implication. No "time-based attack worked" claim. No vulnerability claim.

### Classification flags

All outputs carry explicit `false` flags:

```ts
createsRealFindings: false
createsPersistedEvidence: false
confirmsVulnerabilities: false
makesRiskClaims: false
makesSeverityClaims: false
makesImpactClaims: false
executesNetwork: false
executesTools: false
persistsData: false
```

## Relationship to Other Milestones

| Milestone | Relation |
|---|---|
| M30 | M47 does not evaluate egress policy |
| M33 | M47 does not generate audit events |
| M45 | M47 does not import M45 types; a future mapper will translate M47 results to M45 `EvidenceRecord` |
| M46 | M47 does not evaluate authorization; M46 decision precedes tool execution |

## DB-Free Smoke

```powershell
npm run smoke:v2:response-comparator
```
