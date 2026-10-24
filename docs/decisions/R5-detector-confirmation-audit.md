# R5 — Detector Confirmation-Discipline Audit

**Scope:** read-only review of all 30 production services under `worker/src/v2/detection/`
(excludes `DetectionContracts.ts`, `DetectionTargetBridge.ts`, `PublicStaticAsset.ts`,
`DeferredSurfaceProbeLedger.ts` — not detectors). No code changed by this audit.

**Method:** read each service's actual trigger condition for `vulnerability_detected` /
`potential_weakness` / `observed_anomaly`, not its comments or the ROADMAP's own
description of itself. Checked specifically whether a `Finding` is ever produced
without an explicit human review decision.

## Headline finding (architecture-level, good news)

Every detector that can produce a `Finding` gates it behind
`request.humanReviewDecision?.decision === 'approve_evidence'` (directly, or via
`evaluateHumanReviewedEvidencePromotion` / `promoteReviewedEvidenceFindingCandidateDraft`,
the M49–M54 pipeline). None of the 30 services auto-create a `Finding` without a
human explicitly approving the draft first. ADR-005's "never auto-promote without
review" concern does not materialize as a systemic violation. What varies is the
**quality of the signal presented to the human for that approval** — a
`confidence: 1.0` / `verificationState: 'validated_vulnerability'` label on a weak
heuristic can still mislead a reviewer into approving something that isn't as solid
as it looks.

## Decision table

### Retire permanently — confirmation logic is structurally unsound, not just frozen

| Detector | Why |
|---|---|
| `ObjectMappingAnomalyDetectionService` | "Confirmation" is `evaluateBindingEcho()`: checks whether injected field names (e.g. `isAdmin`) appear echoed in the response body. Reflecting a submitted key back does **not** prove the server stored or applied it — most APIs echo the request payload as acknowledgment regardless of whether they honor it. `bindingAccepted: true` + `confidence: 1.0` overstates what was actually checked. Already unreachable in production (never wired past its own smoke test). |
| `StateTransitionAnomalyDetectionService` | "Confirmation" is `evaluateStateBypass()`: matches a bare 2xx status or hardcoded English success strings (`'Order Placed'`, `'Payment Successful'`, `'Action Approved'`, `'Transaction Completed'`). Fragile on any non-English app, any app using different copy, and prone to false positives if those strings appear in unrelated content (help text, static pages). Already unreachable in production. |

### Keep frozen — methodology is plausible but needs a stronger differential before any future re-enable

| Detector | Why |
|---|---|
| `AuthBypassDetectionService` | Confirmation is `calculateBodySimilarity(authBody, anonBody) >= 0.85` — a text-similarity heuristic, not a structural/semantic comparison against a known-protected resource. Two different pages can render similarly (generic templates, shared layout) without the anonymous request having actually reached the protected content. Already frozen via ADR-013/`ReadDetectionPass`. |
| `JwtAlgorithmConfusionDetectionService` | Confirms by checking the forged `alg:none` token gets the same 2xx as baseline. Reasonable, but its soundness depends entirely on the baseline request having genuinely required a valid signature — worth adding an explicit "baseline rejects a tampered signature" check before trusting this. Already unreachable in production. |
| `NextServerActionDifferentialDetectionService` | See the detailed entry above (follow-up pass) — the `unauthAccepted===true` branch is sound, the bare status-mismatch branch is not. Reachable via `attack-execution` capability, but gated behind `AttackExecutionService` Gate 6 (`activeValidation===true` mandatory) same as the ADR-013 group below. |

### Reviewed in the follow-up pass ("Arranca con todo los puntos", item 4)

| Detector | Verdict |
|---|---|
| `MultiIdentityAuthzMatrixService` | **Sound — inherits `IdorDifferentialDetectionService` directly.** Read in full: it has no confirmation logic of its own — `runMultiIdentityAuthzMatrix` is a pure pairwise orchestrator (`identity_a_vs_b`, `unauth_vs_a`, `unauth_vs_b`) that calls `runIdorDifferentialDetection` per pair and returns its results unchanged. Once IDOR's own differential (already in the "most rigorous" ADR-013 group) is trusted, this wrapper adds no new risk. |
| `SupabaseBolaBflaWriteExpansionService` | **Sound — objective write-acceptance differential, canary-tagged.** Confirmation is `writeAccepted(status) = status === 200 \|\| 201` on a real POST carrying a random `fg_canary` marker per pair (`identity_a_vs_b_write`, `unauth_vs_*_write`) — a structural fact (did the write return success), not a text-similarity or keyword heuristic. Same class of soundness as the already-confirmed IDOR/CORS detectors. Gated behind `scopeGrant.constraints.allowStateChangingRequests` + POST in `allowedMethods`, and reachable only through `AttackExecutionService`, whose Gate 6 requires `permissionSet.activeValidation === true` unconditionally for every step (`AttackExecutionService.ts:451`) before any capability dispatches — so it is already covered by the ADR-013 freeze in practice, for policy reasons, not signal weakness. Moved to the ADR-013 group below. |
| `NextServerActionDifferentialDetectionService` | **Real finding — one of its two trigger branches is a weak heuristic.** `authzDifferential` is true if EITHER `unauthAccepted === true` (sound: an unauthenticated POST to a Next.js Server Action got a 2xx/3xx "accepted" response — genuine authz-bypass evidence) OR `unauthRes.statusCode !== authStatus` (weak: ANY status-code mismatch between the unauth and authenticated calls, including two different denial/error codes that have nothing to do with an authz bypass, e.g. unauth=400 vs auth=500). The second branch does not require either side to have actually succeeded, so it will label ordinary status-code noise as an "authz differential" and hand the human reviewer a misleadingly labeled candidate. **Recommendation for any future tightening:** drop the bare status-mismatch branch, or narrow it to "auth explicitly denied (401/403) while unauth was accepted" — mirroring how `AuthBypassDetectionService`'s heuristic was flagged above. Not fixed in this pass (detector is frozen behind Gate 6 / ADR-013 same as the others, so this is a backlog note, not a live risk); not moved out of "keep frozen, needs stronger check" because of this. Separately: its own internal `permissionCheck` (`endpointDiscovery \|\| lightValidation \|\| activeValidation \|\| authenticatedTesting`, `NextServerActionDifferentialDetectionService.ts:104-110`) is looser than `SupabaseBolaBflaWriteExpansionService`'s (`activeValidation \|\| lightValidation \|\| authenticatedTesting`) — harmless today only because `AttackExecutionService` Gate 6 already requires `activeValidation === true` for both before either is reached, but worth tightening to match for defense-in-depth consistency if this detector is ever called from a second call site that doesn't go through Gate 6. |

### Re-confirm as valid passive/classification signal — keep active, no change needed

| Detector | Why it's sound |
|---|---|
| `SecurityHeaderDetectionService`, `InformationDisclosureDetectionService`, `SourcemapExposureDetectionService`, `ManifestExposureDetectionService`, `GraphQLSurfaceDetectionService` | Fact-observation only (header present/absent, file reachable, introspection enabled); caps at `potential_weakness`, never overclaims. |
| `SubdomainTakeoverDetectionService` | Fingerprint-match against known hosting-provider CNAME signatures — a standard, well-understood technique, not a guess. |
| `TlsConfigurationAnalysisService` | Protocol/cipher support is an objective fact from the handshake, not a heuristic judgment. |
| `ParameterIntegrityDetectionService` | Looks for actual leaked system-file content signatures (`root:x:0:0:`, `[boot loader]`, etc.) in the response — a real structural leak, not a guessed pattern. Caps at `observed_anomaly`. |
| `ApiVersioningSprawlDetectionService`, `CmsPluginVulnerabilityDetectionService`, `DependencyConfusionDetectionService`, `WordPressSurfaceDetectionService`, `HttpMethodManipulationDetectionService`, `SessionFixationDetectionService` | Each uses a concrete status-code/header differential (not text-similarity or hardcoded strings) and is HITL-gated; methodology is standard and defensible as a draft worth a human's review. |

### Already covered by ADR-013 — frozen for policy reasons, not signal weakness

`IdorDifferentialDetectionService`, `CorsMisconfigurationDetectionService`,
`CredentialedCorsDetectionService`, `ParameterReflectionDetectionService`,
`AuthBoundaryDifferentialDetectionService`, `OpenRedirectDetectionService`,
`BlindSsrfDetectionService`, `BlindXssDetectionService`,
`MultiIdentityAuthzMatrixService`, `SupabaseBolaBflaWriteExpansionService`.
Worth noting explicitly:
these are among the **most rigorous** detectors in the codebase — real differential
comparison via `ResponseComparatorService`/`evaluateHumanReviewedEvidencePromotion`
(CORS/IDOR/reflection) or genuine out-of-band canary interaction (Blind SSRF/XSS).
They are frozen because the product decided active confirmation is a manual,
Parrot-driven step — not because their methodology is weak. Good candidates for
the cleanest possible Parrot handoff later (R3/R4) precisely because the signal
is strong.

## Follow-up pass (2026-10-24, "Arranca con todo los puntos" item 4)

The 3 detectors left as "needs a focused review" above were read in full. `MultiIdentityAuthzMatrixService` and `SupabaseBolaBflaWriteExpansionService` are sound and reclassified into the ADR-013 group; `NextServerActionDifferentialDetectionService` has one real but non-live finding (weak status-mismatch branch) recorded as a backlog note — it changes no runtime behavior since Gate 6 already blocks this detector outside an operator-approved `activeValidation` run. Read-only review; no production code changed by this pass.

## Net effect on current risk

The two structurally weak detectors (`ObjectMappingAnomaly`, `StateTransitionAnomaly`)
and the one with a workable-but-shaky heuristic already frozen (`AuthBypass`) are
**already not running automatically** today — so this audit changes no immediate
runtime behavior. Its value is the decision record for later: don't spend effort
redesigning or re-enabling `ObjectMappingAnomaly`/`StateTransitionAnomaly` as-is;
any future `AuthBypass`/`JwtAlgorithmConfusion` re-enable should first replace their
current confirmation heuristic with a stronger structural/differential check.
