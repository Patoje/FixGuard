# FixGuard V2 — Implementation Plan: Recon-First Depth (Phase R, next increments)

## Milestone P0 — Bridge passive detectors into AttackCapabilityRegistry (URGENT, found via live testing)

**Status:** COMPLETED (2026-10-24). 6 thin wrappers added in
`attack-execution/capabilities/` (`SecurityHeaderProbeCapability.ts`,
`InformationDisclosureProbeCapability.ts`, `OpenRedirectProbeCapability.ts`,
`GraphQLSurfaceProbeCapability.ts`, `SessionFixationProbeCapability.ts`,
`CorsMisconfigurationProbeCapability.ts`) and registered in
`AttackCapabilityRegistry.createDefault()`. Operator decision: register all
6 including `cors_misconfiguration_probe` (one of ADR-013's originally
frozen 6) — see the ADR-013 amendment for the reasoning (the authorized
plan→execute path already requires explicit per-target `activeValidation`,
so a capability being unavailable there served no additional safety
purpose once that gate exists; `idor_read_differential` and
`auth_boundary_differential`, also on ADR-013's original list, were
already registered this way before this change).

**Verified live, end to end, against `negocios-inmobiliarios.vercel.app`**:
re-ran the assessment after registering the wrappers — `security_header_probe`
steps now show `invocation.kind: 'http'` (a real request was sent, not
`not_invoked`) and produced a genuine evidence draft, `requiresHumanReview:
true`: the target is missing all 8 recommended security headers (CSP,
HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP, CORP,
COEP). This is the first real, substantive output FixGuard V2 has produced
end-to-end this session — recon → classification → authorized execution →
evidence pending human review, exactly as designed, nothing auto-confirmed.

**Re-verified against all 3 original targets (2026-10-25, Ruta G of the
strategic review, after the ADR-013 reclassification, the subdomain-takeover
capability fix, the two detector retirements/fixes, and the dev-cache
isolation fix — real production pipeline, no mocks):**

| Target | Endpoints classified | Hypotheses | Attack plans | Evidence drafts | Auto findings |
|---|---|---|---|---|---|
| `firma-nu.vercel.app` | 87 (0% unknown) | 50 | 96 | 3 | 0 |
| `inmobiliaria-cornejo-web-rho.vercel.app` | 36 (0% unknown) | 16 | 26 | 4 | 0 |
| `negocios-inmobiliarios.vercel.app` | 190 (0% unknown) | 50 | 58 | 1 | 0 |

Classification counts match the original 190/87/36 exactly (R2 was never
broken). Everything downstream of it — hypotheses, attack plans, evidence
drafts — went from 0/0/0 (the bug this milestone fixed) to real, specific
output: `missing_security_headers` on all 3, plus `api_versioning_sprawl`
(legacy `/api/v1/*` exposed alongside v2) on 2 of them. 0 auto findings on
all 3 is correct, not a regression — CORS/open-redirect/etc. stay frozen
per ADR-013, and these specific drafts are soft/cosmetic signals that stay
drafts for optional human review by design, never auto-promoted.

**How this was found:** ran real assessments against 3 authorized Vercel
sites (`firma-nu.vercel.app`, `inmobiliaria-cornejo-web-rho.vercel.app`,
`negocios-inmobiliarios.vercel.app`, 2026-10-24). Recon + R2 classification
worked well on all three (190/87/36 endpoints classified, 0% unknown), but
all three produced **zero findings**. Traced to two separate, both real,
root causes:

1. **FIXED**: `shouldEnableSpaDiscovery()` in
   `CompositeActiveReconOrchestratorService.ts` only auto-enabled
   Playwright-based SPA discovery on detected Next.js signals. All 3 test
   sites are Vite/React SPAs (no Next.js signals) — so Playwright never
   ran, no route got classified `screen` (`InventoryRouteClass.ts` only
   trusts `playwright_spa`/`spa_network`/`rsc_discovery`/
   `html_link_extraction`/`html_hop_extra` as confirmed screens), so
   `applicationUrlsFromInventory()` returned empty, so zero read-plans were
   ever generated regardless of what was discovered. **Changed (operator
   decision, 2026-10-24): SPA/Playwright discovery is now enabled by
   default for every assessment**, overridable via
   `config.enableSpaDiscovery: false`. Verified live: re-ran
   `inmobiliaria-cornejo-web-rho.vercel.app` with no config flag — `
   playwright_spa` now appears in discovered sources, 20 plans went
   `ready_for_authorization` (was 0 before the fix).
2. **NOT YET FIXED (this milestone's real scope)**: even with plans
   `ready_for_authorization`, executing them still failed —
   `AttackCapabilityRegistry.createDefault()` has **no registered
   `AttackCapabilityPort` wrapper** for any of the 6 passive/read
   capabilities that `DeferredSurfaceProbePlans.ts` generates
   (`security_header_probe`, `information_disclosure_probe`,
   `cors_misconfiguration_probe`, `open_redirect_probe`,
   `graphql_surface_probe`, `session_fixation_probe`). Only the
   ADR-013-frozen "aggressive" capabilities
   (`cors_chain_exploit`, `auth_bypass_probe`, `jwt_alg_none_probe`,
   `sql_oracle_advancement`, `nuclei_xss_scan`, `sql_injection_verification`,
   `credential_reuse`, the Supabase/NextServerAction ones) have real
   wrappers. `AttackExecutionService` falls back to
   `createNotImplementedCapability()` for the 6 passive ones, which the
   transcript surfaces indistinguishably from a genuine `preflight_denied`
   (`executionStatus()` maps anything that isn't `'completed'`/`'failed'`
   to `'preflight_denied'`). The 19 passive detectors R5 confirmed sound
   (`SecurityHeaderDetectionService.ts` etc., under `detection/`) are real
   and working — they're just never invoked by this pipeline. Only
   `ReadDetectionPass.ts` calls them directly, and nothing in the default
   `startAssessment` → `InvestigationRuntimeCoordinator` plan-execution path
   routes through `ReadDetectionPass` for AttackPlan-originated read steps.

**Plan for the remaining scope:**
1. Write thin `AttackCapabilityPort` wrapper(s) in
   `attack-execution/capabilities/` for the 6 passive capability kinds,
   each delegating to its existing `detection/*Service.ts` function
   (`runSecurityHeaderDetection`, `runInformationDisclosureDetection`,
   `runCorsMisconfigurationDetection`, `runOpenRedirectDetection`,
   `runGraphQLSurfaceDetection`, `runSessionFixationDetection`) — no new
   detection logic, just the bridge `AttackCapabilityRegistry` expects.
2. **ADR-013 check before registering `cors_misconfiguration_probe`**: this
   plan-level capability name maps to `CorsMisconfigurationDetectionService`,
   which is on the frozen list (it's one of the 6 originally frozen in
   `ReadDetectionPass.ts`). Confirm with the operator whether registering
   it here (a different code path than the frozen one) re-opens exactly
   what ADR-013 closed, or whether it's fine since this path still requires
   `activeValidation` + explicit plan authorization (unlike the fully
   automatic `ReadDetectionPass` sweep). Likely resolution: register the
   other 5, leave `cors_misconfiguration_probe` unregistered (stays
   `capability_not_implemented`) to honor ADR-013 consistently.
3. Register the new wrappers in `AttackCapabilityRegistry.createDefault()`.
4. Re-run against the 3 test sites; confirm `findings` is no longer always
   `[]` and the transcript shows genuine `completed`/`secure_target_abstained`
   outcomes instead of `capability_not_implemented`-as-`preflight_denied`.
5. Update `docs/ROADMAP.md` and this plan with the result.

**Depends on:** nothing new (R5's audit already confirmed these 19
detectors are sound).
**Non-goal:** does not touch any of the 6 ADR-013-frozen capabilities'
registration status.


**Original status (2026-10-24, kept for history):** DRAFT — awaiting operator
approval before any file is touched. **All 5 milestones below (P1–P5) have
since been approved and completed** — see each one's own `**Status:**` line.
**Scope:** the 5 gaps identified against the recon-first vision (deep recon →
classify → find real gaps → hand off aggressive validation to Parrot). Each
milestone below is independently shippable, in the stated order.
**Out of scope for this plan:** anything already closed this session (ADR-013
freeze, R1/R2/R3/R4 increment 1, R5 audit, R6 cleanup) — not revisited here
except where a milestone explicitly builds on it.

---

## Milestone P1 — Investigation loop consumes R1/R2 to prioritize (highest value)

**Status:** COMPLETED (2026-10-24, commit `1dc8f92`). This file was never
updated after execution — the "DRAFT, awaiting operator approval" line
below is what it said before landing; see `docs/ROADMAP.md` R1 for the
actual result (3 new `SecurityHypothesisKind` gap values, scoring rules fed
by a new surface-gap signal projection, `InvestigationRuntimeCoordinator`'s
`prioritizeUnclassifiedInventoryEntries()` reorder). Added 2026-10-25.

**Problem:** `InvestigationRuntimeCoordinator` still spends its step budget
sweeping discovered routes uniformly. `HypothesisSchedulerService` ranks
mostly attack hypotheses (now tagged `deferredToManualValidation`), not
recon gaps. There is no signal today that says "this is the biggest unknown,
go here first."

**Invariants (MUST):**
- No new active/injection-style probing — this milestone only re-prioritizes
  existing passive/classification capabilities (R2's keep-active list) and
  existing recon adapters.
- Hypothesis scoring stays deterministic (no ML, no magic) — same rule-table
  style as the existing `HypothesisSchedulerService`.
- `deferredToManualValidation` tagging from this session must not regress.

**MUST NOT:**
- Touch any of the 6 frozen detectors or re-enable them.
- Change `AGGRESSIVE_DETECTION_FROZEN` without a separate, explicit decision.

**Plan:**
1. Add new `SecurityHypothesisKind` values for recon/classification gaps to
   `HypothesisSchedulerContracts.ts`: `endpoint_classification_gap`,
   `technology_unconfirmed`, `auth_boundary_unmapped` (names open to
   adjustment once we see real data).
2. Extend `HypothesisSchedulerInput` with the richer signal these rules
   need — specifically a reference to the `AttackSurfaceGraph` (or a
   pre-computed `AttackSurfaceQueryService.summarizeEndpointSurfaceClassification()`
   + `findUnclassifiedEndpoints()` result), since today's input only carries
   `asgNodeKinds: string[]`, which isn't enough to generate a grounded gap
   hypothesis.
3. Add scoring rules in `HypothesisSchedulerService.schedule()` producing
   one hypothesis per meaningful gap category (not one per endpoint — cap
   and group, same spirit as the existing `spa_surface_probe` rule).
4. Wire the ranked gap hypotheses into `InvestigationRuntimeCoordinator`'s
   step-budget allocation so passive/classification capabilities for the
   highest-ranked gaps run before the undifferentiated sweep continues.
5. Update `docs/ROADMAP.md` R1 entry to "increment 2" status.

**Depends on:** nothing new (R1/R2 increment 1, already landed).
**Done when:** given a real assessment with some unclassified endpoints, the
investigation transcript shows those endpoints' passive detectors running
before the generic sweep, with a hypothesis explaining why.
**Risk:** the real risk here is cosmetic "intelligence" — rules that look
smart but are just relabeled iteration order. Validate against a real
`AttackSurfaceGraph`, not a synthetic fixture built to make the rule look
good.

---

## Milestone P2 — Classification depth: service/microservice boundaries + static-route graph integration

**Status:** COMPLETED (2026-10-24–25, commits `e74beaa`, `0408d10`). Static
routes now reach `AttackSurfaceGraphBuilder` as `INFERRED` `EndpointNode`s;
a `service_boundary` node kind + `groups` edge kind group endpoints by path
prefix; `ApplicationNode.metadata.detectedTechnologies` carries the full
`DetectedTechnology[]` (name/category/confidence/signal), not just a
flattened `string[]`. Live-verified against an authorized target. See
`docs/ROADMAP.md` R2, increments 2 and 3. Added 2026-10-25.

**Problem:** two concrete gaps, both verified against the actual code this
session:
1. `StaticRouteExtractionService` output (`scanFilesForStaticRoutes`) only
   becomes evidence drafts / HITL-approved findings — it never reaches
   `AttackSurfaceGraphBuilder`, so statically-discovered routes aren't part
   of the same endpoint graph as recon-discovered ones.
2. `ServiceNode`/`ApplicationNode` in `AttackSurfaceContracts.ts` exist but
   are not correlated into a real "which endpoints belong to which
   service/microservice" boundary — today a `ServiceNode` is created mostly
   from `web.webServer` banner strings, not from a structural grouping.

**Invariants (MUST):**
- Stay zero-network, zero-additional-probing — this is pure graph
  enrichment from data already collected.
- Preserve `EpistemicStatus` discipline: statically-extracted routes are
  `INFERRED` (code presence ≠ live confirmation), never `OBSERVED`, until a
  passive detector actually confirms the route responds.

**Plan:**
1. Feed `StaticRouteExtractionResult` entries into `AttackSurfaceGraphBuilder`
   as `EndpointNode`s with `epistemicStatus: 'INFERRED'`, tagged with
   `surfaceClassification` via the existing `classifyEndpointSurface()` (R2),
   and a provenance `sourceKind: 'finding'` or a new `'static_analysis'`
   `AsgProvenanceSourceKind` if the existing ones don't fit cleanly — check
   before adding a new enum value.
2. Design a lightweight "service boundary" grouping rule: group endpoints by
   shared path prefix + shared technology/header fingerprint (e.g. all
   `/api/orders/*` sharing the same `X-Service` or CORS origin) into a
   `ServiceNode`, linked via `exposes` edges — deterministic, no guessing
   beyond what's structurally observable.
3. Extend `AttackSurfaceQueryService` with a query to list endpoints grouped
   by inferred service boundary (mirrors `summarizeEndpointSurfaceClassification`).
4. Update `docs/ROADMAP.md` R2 entry to "increment 2".

**Depends on:** nothing new.
**Done when:** a real multi-route target shows statically-extracted routes
in the same `AttackSurfaceGraph` as recon-discovered ones, and endpoints
sharing an obvious service boundary are grouped under one `ServiceNode`.
**Risk:** service-boundary inference is the part most likely to overreach
into guessing — keep the rule conservative (structural signal only) and
clearly `INFERRED`, never claim a confirmed architecture.

---

## Milestone P3 — Target Dossier: real file export + download

**Status:** COMPLETED (2026-10-24). JSON + Markdown companion (resolved the
open question in favor of both, since the dossier's rationale/hypothesis
fields read well as Markdown and JSON stays the machine-readable source of
truth). New `TargetDossierMarkdownRenderer.ts` (pure formatting, no new
data). New `GET /assessments/:assessmentId/dossier/export?format=json|md`
(+ `/orchestrated/...` alias), `Content-Disposition: attachment` on both
formats. Minimal UI affordance added: a "Descargar Dossier (Markdown)"
button next to the existing HTML-report button in
`ExecutiveResultsPanel.tsx`. Verified live (one light, single run against
`inmobiliaria-cornejo-web-rho.vercel.app`, respecting today's rate
concerns): both formats return correct `Content-Type` and
`Content-Disposition` headers and well-formed content. `npm run
typecheck:v2` and `cd web && npm run build` both exit 0.

**Problem:** R3 increment 1 is a JSON API response, not the "versioned file
an operator carries to Parrot" the vision describes.

**Plan:**
1. Add a dossier serialization format suited to a standalone file — the
   existing `TargetDossier` JSON shape is already a reasonable file format;
   this milestone is mostly about delivery, not a new shape. Confirm with
   the operator whether JSON alone is sufficient or whether a short
   human-readable Markdown companion is wanted (the dossier's `nonClaims`
   and hypothesis rationale read fine as Markdown).
2. Add a download-friendly response (`Content-Disposition: attachment`) on
   the existing `GET /assessments/:assessmentId/dossier` endpoint, or a
   dedicated `GET .../dossier/export` variant if we don't want to change the
   existing JSON-API response's headers.
3. Add a minimal UI affordance in `web/src/app/v2/` (likely the assessment
   detail page) — a "Download Target Dossier" button hitting that endpoint.

**Depends on:** R3 increment 1 (done).
**Done when:** an operator can click one button in the UI and get a file on
disk, no curl required.
**Open question for the operator:** JSON-only, or JSON + Markdown
companion? (Affects step 1's scope.)

---

## Milestone P4 — Close the Parrot loop: import → human review → Finding

**Status:** Backend COMPLETE and live-verified (2026-10-24); UI NOT done
(session hit its usage limit). New `ParrotImportPromotionService.ts`:
`evaluateParrotPromotion()`, fixed hypothesisKind -> Finding type/severity
table (covers both HypothesisSchedulerService naming and the live
InvestigationRuntimeCoordinator capability-name path — a real bug caught
during verification, fixed before commit). `ParrotImportedObservation`
gained an optional `review` field; repository gained `getObservation` +
`recordReview` (fails closed on double-review). New
`POST /assessments/:assessmentId/parrot-import/:observationId/review`.
New `ParrotConfirmedMetadata` added to `core/Evidence.ts`'s `FindingMetadata`
union (no type-bypass casts). Live-verified end to end against
`inmobiliaria-cornejo-web-rho.vercel.app`: imported a Parrot observation
referencing a real `cors_misconfiguration_probe` hypothesis, approved it,
got a real `CORS_MISCONFIGURATION`/`high` Finding, confirmed it persisted
in the dossier, confirmed double-review fails closed with
`observation_already_reviewed`. `web/src/lib/v2Api.ts` gained the client
methods/types for this (`getParrotImportObservations`,
`reviewParrotImportObservation`) — `cd web && npm run build` exits 0.
**UI done (2026-10-24, later increment)**: not in `/v2/review/` as originally
scoped — operator decided it belongs in Stage 4 (Attack Mode) instead, next
to the existing evidence/recommendations panel. See
`web/src/app/v2/attack/components/ParrotHandoffPanel.tsx`. P4 is now fully
closed, backend and UI.

**Problem:** R4 increment 1 stores `ParrotImportedObservation`s in their own
silo. There's no path from "Parrot confirmed this" to an actual `Finding` —
defeating the point of importing in the first place.

**Invariants (MUST):**
- An imported observation becomes a `Finding` **only** through the same
  explicit human `approve_evidence` decision every other detector in this
  codebase requires (verified during R5: zero exceptions) — never
  auto-promoted because it came from Parrot.
- Preserve `sourceKind: 'parrot_file_import'` provenance all the way through
  to the final `Finding`'s metadata, so a reviewer can always tell a
  Parrot-confirmed finding apart from a FixGuard-detected one.

**Plan:**
1. Design a minimal promotion path for `ParrotImportedObservation` →
   `Finding` that does NOT force it through the `ResponseComparisonResult`-
   shaped M45-M54 pipeline (same reasoning as R4 increment 1's note) — a
   new, small `ParrotImportedObservation` → `Finding` promotion function
   requiring an explicit `humanReviewDecision`, mirroring the pattern every
   `detection/*` service already uses (`if (humanReviewDecision?.decision
   === 'approve_evidence')`).
2. Add `POST /assessments/:assessmentId/parrot-import/:observationId/review`
   endpoint (decision: `approve_evidence` | `reject` | `needs_more_review`),
   following the existing triage endpoint pattern
   (`POST /candidates/promote` et al.).
3. Add a minimal UI list in `web/src/app/v2/review/` for pending Parrot
   import observations, reusing the existing review page's layout.
4. Update `docs/ROADMAP.md` R4 entry to "increment 2".

**Depends on:** R4 increment 1 (done).
**Done when:** an operator can import a Parrot file, see the pending
observations in the review UI, approve one, and see it appear as a
`Finding` with `sourceKind: 'parrot_file_import'` traceable in its metadata.

---

## Milestone P5 — Operator UI for everything landed this session (cross-cutting)

**Status:** COMPLETED (2026-10-24, item 1 via commit `7e59fd1`; items 2
and 3 already closed by P3 and P4 respectively). Item 1: a "diferido" badge
plus a per-target cooldown on `deferredToManualValidation` recommendations,
visible in `web/src/app/v2/attack/`. This file never got its own status
block after execution — added 2026-10-25.

**Problem:** none of ADR-013's `deferredToManualValidation` tagging, the
dossier, or Parrot import are visible in `web/` yet — only reachable by
calling the API directly.

**Plan (deliberately last, smallest-detail here since it depends on P1-P4
landing first):**
1. Surface `deferredToManualValidation` as a visible badge wherever
   hypotheses/recommendations already render in `web/src/app/v2/attack/`.
2. A dossier view/download affordance (ties into P3).
3. A Parrot import upload + review affordance (ties into P4).

**Depends on:** P1-P4 (at least their backend halves) landing first, so the
UI has something real to point at.

---

## Suggested execution order

**P1 and P2 first** (parallel-friendly, both pure backend enrichment, no UI
dependency, directly serve "intelligence decides"). **P3 and P4 next**
(make the Parrot handoff actually operable end-to-end). **P5 last** (or
whenever the operator wants to start using this from the browser instead of
the API).

## What I need from you before starting

**Closed out 2026-10-25 — all 3 were resolved in practice but never written
back here:**

1. **Order:** the suggested order (P1+P2, then P3+P4, then P5) was kept as
   proposed — no reprioritization happened.
2. **P3 dossier format:** JSON + Markdown companion (see P3's own status
   block above).
3. **Naming:** no objections surfaced; the hypothesis kinds from P1
   (`endpoint_classification_gap`, `technology_unconfirmed`,
   `auth_boundary_unmapped`) and P2's `AsgProvenanceSourceKind` extension
   shipped exactly as proposed and are already wired into contracts.
