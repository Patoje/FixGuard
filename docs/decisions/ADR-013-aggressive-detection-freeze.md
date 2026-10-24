# ADR-013: Freeze of Active/Aggressive Differential Detection Layer

- **ID:** ADR-013
- **Status:** `ACCEPTED`
- **Date:** 2026-10-24

## Context

FixGuard V2's product direction was reset (operator decision, 2026-10-24,
captured in conversation, not in a prior written doc): the product's core
value is reconnaissance, application modeling, and classification depth —
building an accurate, well-organized picture of what a target exposes — not
running the broadest possible catalog of active exploitation-style probes
automatically.

A repository-wide trace (grepping actual call sites, not just file
presence) found that most of the ~36 files under `worker/src/v2/detection/`
were already unreachable from any production code path — reachable only
from their own smoke test. The live, automatically-invoked exception was a
set of 6 differential/injection-style detectors wired into the automatic
read-investigation loop in `worker/src/v2/investigation/ReadDetectionPass.ts`,
executed against every discovered route without a separate operator
authorization step beyond the assessment's own scope grant:

- `open_redirect` (`OpenRedirectDetectionService`)
- `cors_misconfiguration` (`CorsMisconfigurationDetectionService`)
- `parameter_reflection` (`ParameterReflectionDetectionService`)
- `auth_bypass` (`AuthBypassDetectionService`)
- `auth_boundary_differential` (`AuthBoundaryDifferentialDetectionService`)
- `idor_differential` (`IdorDifferentialDetectionService`)

## Decision

1. The 6 detectors above are gated behind a module-level constant
   (`AGGRESSIVE_DETECTION_FROZEN = true`) in `ReadDetectionPass.ts`. They are
   **not deleted** — source code, contracts, and smoke tests are untouched —
   only unwired from the automatic loop. When frozen, each gate records a
   `{ detector, reasonCode: 'aggressive_layer_frozen' }` entry in the
   pass's `skipped` list instead of silently doing nothing, preserving
   auditability of what did *not* run and why.
2. `attack-execution/*`, `attack-planning/*`, `attack-authorization/*`,
   `verification/ControlledActiveVerificationService`, `oob/*`, and
   `post-exploitation/*` are **not code-gated** by this ADR — they already
   require an explicit operator-authorized `AttackPlan` + `activeValidation`
   permission + `execute()` call (ADR-001, and the `AttackExecutionService`
   Gate 6 hardening landed prior to this ADR) and never run automatically.
   They are declared **frozen for further development** (no new
   capabilities, no new wiring) under the same policy, without a code
   change.
3. Detectors that were already unreachable from production code
   (`JwtAlgorithmConfusionDetectionService`, `SessionFixationDetectionService`,
   `SqlErrorOracleDetectionService`, `HttpMethodManipulationDetectionService`,
   `ObjectMappingAnomalyDetectionService`, `StateTransitionAnomalyDetectionService`,
   `CredentialedCorsDetectionService`, `BlindSsrfDetectionService`,
   `BlindXssDetectionService`, `NextServerActionDifferentialDetectionService`,
   `SupabaseBolaBflaWriteExpansionService`) required no change — they were
   already inert in production; this ADR records that fact so it is not
   mistaken for "frozen by this change."
4. Passive/classification-oriented detectors remain active and are the
   product's development focus going forward: `SecurityHeaderDetectionService`,
   `InformationDisclosureDetectionService`, `GraphQLSurfaceDetectionService`,
   `SourcemapExposureDetectionService`, `ManifestExposureDetectionService`,
   `SubdomainTakeoverDetectionService`, `WordPressSurfaceDetectionService`,
   `CmsPluginVulnerabilityDetectionService`, `ApiVersioningSprawlDetectionService`,
   `DependencyConfusionDetectionService`, the SAST engines under `sast/`, all
   `recon/adapters/*`, and `intelligence/*` — these gather endpoints, routes,
   technologies, frameworks, application structure, and services/microservices
   without injecting payloads or attempting to force a confirmation, which is
   the explicit operator-approved scope of "recon/classification."

## Motive

Active, injection-style confirmation of a vulnerability (CORS exploitation,
IDOR differential probing, auth-bypass attempts, reflected-payload probing)
is the part of the workflow the operator wants to perform manually, using a
dedicated environment (Parrot), under direct human judgment — not have it
run automatically against every discovered route during routine
reconnaissance. This keeps FixGuard's own execution surface narrower and
puts "aggressive" validation decisions back under explicit human control,
consistent with "Tools execute. Intelligence decides. Humans authorize."

## Consequences

- An assessment run today will not produce `Finding`s or evidence drafts
  for open redirect, CORS misconfiguration, parameter reflection, auth
  bypass, auth boundary differential, or IDOR differential — those gaps
  are visible in the `skipped` list with `reasonCode: 'aggressive_layer_frozen'`,
  not silently absent.
- No smoke suite behavior for the frozen detectors' own unit-level smoke
  tests changes, since those call the detector services directly, not
  through `ReadDetectionPass`.
- Re-enabling is a single-line flip (`AGGRESSIVE_DETECTION_FROZEN = false`)
  plus a new ADR superseding this one — not a rewrite.

## Amendment (2026-10-24, operator decision, found via live testing)

Live testing against 3 real authorized targets found that
`AttackCapabilityRegistry` had no registered wrapper for any of the 6
passive read capabilities the plan generator produces
(`security_header_probe`, `information_disclosure_probe`,
`cors_misconfiguration_probe`, `open_redirect_probe`,
`graphql_surface_probe`, `session_fixation_probe`) — so even a fully
human-authorized plan (explicit `activeValidation` permission + authorized
`AttackPlan` + explicit `execute()` call) failed as
`capability_not_implemented`, indistinguishable in the transcript from a
genuine preflight denial. This produced zero findings on every target
regardless of how much the recon layer discovered.

The operator's instruction: any URL submitted for assessment already
carries full permissions and explicit authorization by the nature of this
product (a personal, single-operator workbench — nothing runs against a
target the operator didn't explicitly point FixGuard at), so that
authorization should never leave a capability unavailable through the
fully-authorized execute path. This section 2's original phrasing
("already gated... no new wiring") is **amended**: it correctly describes
why `attack-execution/*` needed no *code change* to satisfy the freeze
(the automatic paths were already closed), but it did not anticipate gaps
where a capability had *no* path to execution at all, defeating the whole
point of having an authorized path. Resolution:

- Wrappers for all 6 passive capabilities above are now registered in
  `AttackCapabilityRegistry.createDefault()`, bridging directly to their
  existing, R5-confirmed-sound `detection/*Service.ts` functions — no new
  detection logic, only the missing bridge.
- This explicitly includes `cors_misconfiguration_probe`, one of this
  ADR's original 6 frozen detectors. It remains frozen from FixGuard's own
  **automatic** `ReadDetectionPass.ts` sweep (unchanged, `
  AGGRESSIVE_DETECTION_FROZEN = true` still applies there) — this
  amendment only makes it reachable through the pre-existing, already
  mandatory `activeValidation` + plan-authorization gate, the same gate
  every other registered capability (including `idor_read_differential`
  and `auth_boundary_differential`, both on this ADR's original frozen
  list) already sat behind before this amendment.
- No automatic execution path changed. No detector's confirmation logic
  changed. This is purely closing a registration gap, not reopening the
  freeze.

## What NOT to do

- Do not delete the frozen detector services, their contracts, or their
  smoke tests — they remain available for a future, explicitly re-approved
  re-enablement or for manual/offline use.
- Do not add new active/injection-style detectors to the automatic
  read-investigation loop while this ADR is in effect.
- Do not treat `attack-execution/*` staying code-reachable (behind its
  existing authorization gates) as a contradiction of this freeze — it was
  never auto-invoked, and remains behind explicit operator authorization.
