# FixGuard V2 — Current State (Handoff Document)

> **Purpose:** A complete, cold-start picture of FixGuard as it exists today, written so a new agent or engineer can understand the system, its objective, its real capabilities, and what is dormant or broken — without reading the entire codebase or the retired planning docs.
>
> **Permanent Axiom:** *"Tools execute. Intelligence decides. Humans authorize."*
>
> **Grounding rule:** Every claim here was verified against the working tree on the date below (file counts, wiring, ADRs, git history), not against prior documentation. Prior status/plan/architecture/audit markdown was intentionally deleted because it no longer reflected reality.

**Last reconciled:** 2026-11-09 · **Branch:** `v2` · **HEAD:** `a059c7e`

---

## 1. What FixGuard Is (The Objective)

FixGuard is an **authorized web security assessment platform** — DAST (Dynamic Application Security Testing) plus Attack Surface Management — for defensive auditing of **targets the operator is authorized to test**.

The product direction was deliberately reset on 2026-10-24 (see `docs/decisions/ADR-013`): the core value is **reconnaissance, application modeling, and classification depth** — building an accurate, well-organized picture of what an authorized target exposes — **not** running the broadest possible catalog of automated exploitation probes.

The governing discipline (enforced by `AGENTS.md`, the ADRs, and the test suite):

- **No self-authorization.** Authority flows only through `establishVerifiedAuthorizationDecision()` with a runtime brand. A caller cannot authorize itself by passing `confirmed: true`.
- **Discipline of claims.** Every statement is one of `OBSERVED` (what the target actually did), `INFERRED` (an unconfirmed hypothesis), or `RECOMMENDED` (an action proposed for human authorization). No fabricated findings, no automatic severities.
- **Double gate on network execution.** Every network action passes a `VerifiedAuthorizationDecision` + `AuthorizedScopeGrant` **and** an egress/SSRF policy (`evaluateEgressPolicy`, blocking loopback, RFC1918, cloud metadata).
- **Atomic, two-pass preflight.** In active recon, a whole batch of probes is validated before any execution; one unsupported/denied probe aborts the entire batch with zero side effects.
- **Lineage preservation.** The tuple `{assessmentId, scanId, authorizationGrantId, authorizationDecisionId, actorId}` stays continuous end to end.
- **Human review boundary.** Observations become candidate evidence, which a human promotes to formal findings. Attack plans are advisory and non-executing until a human authorizes a step.

---

## 2. The Two-System Reality

| System | Location | Status |
|---|---|---|
| **V1 (legacy monolith)** | `worker/src/` (excluding `v2/`) and `web/` | **FROZEN / DEPRECATED.** Express 5 + Next.js, direct Postgres via Drizzle, binaries via `child_process.exec`, unvalidated severities written straight to SQL. Do **not** add features or refactor. It still physically exists in the tree but is not the product. |
| **V2 (production core)** | `worker/src/v2/` | **ACTIVE CANONICAL CORE.** DDD, Clean Architecture, Ports & Adapters. All new development belongs here. |

**Scale of V2 today:** ~385 non-test TypeScript source files across ~50 subsystem directories, plus **194 smoke-test files** driven by **178 `smoke:v2:*` npm scripts** aggregated under `npm run check:v2`.

---

## 3. The Pipeline (How an Assessment Flows)

```
Authorization (verified decision + scope grant)
      │
      ▼
Active Recon Orchestrator  ──  CompositeActiveReconOrchestratorService
  Stage 1  Domain & DNS         (subfinder, dnsx)
  Stage 2  Ports & Services     (naabu)
  Stage 3  HTTP & TLS           (httpx, tlsx)
  Stage 4  Crawl & Parameters   (katana, gau, ffuf, arjun) + SPA/Playwright discovery
  Stage 5  Secret Inspection    (trufflehog)
      │
      ├─ Session Sanctuary      (isolated anon / authenticated contexts, credential confinement)
      ├─ Challenge Continuation (automatic, bounded, multi-strategy — never a terminal dead end)
      ▼
Intelligence Layer
  Target Profile → Attack Surface Graph → classification / recommendations
      │
      ▼
Evidence / Candidate Pipeline
  Observed facts → evidence drafts → human review → formal finding candidates → findings
      │
      ▼
Attack Planning (advisory)  →  Attack Authorization (HITL)  →  Attack Execution (gated)
      │
      ▼
Reporting / Target Dossier (read-only export: JSON + Markdown)
```

### Subsystem map (directory → responsibility, file counts approximate)

- **`core/` (13), `runtime/` (11)** — execution core, process runner, target-execution coordinator, circuit breaker, step-invocation capture.
- **`authorization/` (2), `scope/` (3), `lineage/` (1)** — verified authorization decisions, scope grants, lineage tuples.
- **`recon/` adapters + `recon/orchestration/`** — httpx, ffuf, arjun, trufflehog, composite URL discovery, Playwright SPA adapter, and the multi-stage orchestrator.
- **`session/` (2)** — `SessionSanctuaryService` and contracts: isolated anonymous / authenticated contexts, cookie/credential confinement, canary health.
- **`challenge/` (3)** — challenge classification + browser continuation (automatic, bounded, multi-strategy).
- **`detection/` (34)** — detection verticals. **Mostly dormant** — see §5.
- **`investigation/` (10), `observation/` (7)** — read-investigation loop, probe inventory, observed-fact catalog.
- **`intelligence/` (13), `attack-surface/` (4)** — target profile, attack-surface graph, correlation, recommendations.
- **`evidence/`, `evidence-store/`, `evidence-review/`, `evidence-selection/`, `evidence-mapping/`, `finding-candidate-draft/`, `finding-candidate-promotion/`, `finding-auto-promotion/`** — the human-review evidence pipeline.
- **`attack-planning/` (10), `attack-authorization/` (2), `attack-execution/` (3), `attack-chain/` (4), `attack-recommendation/` (2), `approval/` (5)** — advisory plan generation, HITL authorization, gated execution scaffolding.
- **`application/` (8), `api/` (4), `composition/` (1)** — orchestrated assessment application service, HTTP controllers/routes, composition root.
- **`storage/` (9)** — repositories. **Live path is in-memory; Postgres exists but is unwired** — see §5.
- **`dossier/` (3), `reporting-boundary/` (6)** — read-only dossier export and report-readiness gating.
- **`supabase/` (10), `sast/` (3), `post-exploitation/` (5), `oob/` (2), `parrot-import/` (4)** — specialized surfaces and operator-tooling integrations.

---

## 4. What Actually Works (Verified-Live Capabilities)

These are reachable from the production API path and covered by executing smoke suites:

1. **Verified authorization + scope + egress double-gate.** No network action runs without a branded decision, a scope grant, and an SSRF-safe egress check.
2. **Multi-stage active recon orchestration** with per-stage circuit breaking, budget caps, and structured "why did this run degrade" recon-health signals (`ReconHealthClassificationService`).
3. **Session Sanctuary credential isolation** — anonymous and authenticated contexts never share cookies/headers; credentials are confined to the exact authorized origin.
4. **Automatic challenge continuation** — a WAF/JS/edge challenge is treated as a recoverable state, retried across bounded strategies (`fresh_context` → `persistent_context`) within a fixed budget, with positive application-access verification (canary) before any success is claimed. No manual operator resume step exists or is required. A genuinely interactive challenge (Turnstile/CAPTCHA) is reported honestly as a coverage limitation, never silently claimed resolved, and never blocks the rest of the assessment.
5. **Session continuity into HTTP inspection + SPA discovery** — a resolved session reaches httpx, ffuf, and arjun probes and the Playwright SPA adapter, with per-hop exact-origin credential confinement (no cross-origin / cross-port leakage; verified by a real two-origin + real-Chromium integration test).
6. **Intelligence layer** — target profile, attack-surface graph, classification, and operator recommendations, all grounded in real observations.
7. **Human-review evidence pipeline** — observed facts → drafts → reviewed candidates → findings, with no auto-promotion of ungated kinds (ADR-005, hardened in recent commits).
8. **Advisory attack planning** — non-executing plans generated additively from observed surface; never auto-authorized or auto-executed.
9. **Target Dossier export** — read-only JSON + Markdown.

---

## 5. What Exists But Does Not Work (Dormant / Broken / Frozen)

This is the most important section for planning. These are real pieces of code that exist, often with their own passing smoke tests, but are **not wired into any live path** or are **deliberately frozen**:

1. **Persistence is in-memory only in the live path.** `V2CompositionRoot.ts` wires `InMemory*Repository` for every store (assessments, candidates, drafts, orchestrated assessments, attack plans, attack chains, post-exploitation). **Postgres repositories and a schema exist** (`storage/postgres/schema.ts`, `PostgresReviewedEvidenceStoreRepository`, `PostgresFormalFindingCandidateRepository`, `PostgresAttackChainRepository`, `runtime/composition/PostgresV2RuntimeComposition.ts`) but are **not wired into the production API composition**. **Consequence: assessments do not survive a process restart.**
2. **Most of the detection layer is unreachable.** ADR-013 (2026-10-24) froze the active/aggressive differential-detection direction. A repository-wide call-site trace found most of the ~34 `detection/` services were already reachable **only from their own smoke test**, never from production. The handful that were in the live read-investigation loop were then gated down. So dozens of detector services + their smoke suites exist as effectively dead code relative to the live pipeline.
3. **V1 monolith still physically present.** `worker/src/` (non-v2) and the legacy `web/` surface are frozen/deprecated but remain in the tree, adding noise and confusion.
4. **Interactive challenges have no automated solver.** Turnstile/CAPTCHA cannot be solved automatically; this is reported as an honest coverage limit (not a bug), but it means authenticated access behind an interactive challenge is not reachable without an out-of-band, owner-controlled mechanism that is not yet built.
5. **Several recon transports remain session-blind.** Katana, gau, and trufflehog are intentionally **not** given session credentials, because their per-request credential-scoping / redirect behavior could not be verified safe (unlike httpx/ffuf/arjun/Playwright, which were verified and fixed). **Consequence: authenticated crawl/URL/secret coverage is incomplete.**
6. **No scheduled re-entry after in-run challenge-budget exhaustion.** Once the bounded in-run strategies are exhausted for a time-based challenge, nothing re-enters that specific assessment later; it is simply reported as degraded.

---

## 6. Uncommitted Work In Flight (as of this reconciliation)

The working tree contains a large, **uncommitted** hardening of credential isolation across recon transports (28 modified files + 1 new real integration test, `worker/src/v2/smoke/milestone_credential_redirect_integration_smoke.ts`). It is **not yet committed**; HEAD is still `a059c7e`. Summary of what it changed and verified:

- **PlaywrightSpaAdapter** — session credentials (Cookie **and** Authorization) no longer use the browser cookie jar or context-level `extraHTTPHeaders`. Both travel through one combined header set, attached only inside an **explicit, bounded, per-hop origin-validated redirect loop** (`route.fetch({ maxRedirects: 0 })` + `fulfill`), with cross-invocation loop detection. Verified empirically that a Playwright route handler fires once per request and does not re-intercept the browser's own redirect auto-navigation — so credentials never cross origin **or port**, even on redirects.
- **HttpxInspectionAdapter** — drops `-follow-redirects` when session credentials are present (httpx forwards Cookie + Authorization across cross-origin redirects); the redirect is still observed via a new `redirectLocation` field, never auto-followed with credentials.
- **ArjunAdapter** — adds `--disable-redirects` when session credentials are present (arjun follows redirects by default and forwards both credentials).
- **FfufAdapter** — confirmed already safe (never passes a follow-redirect flag); no change.
- **SessionSanctuary** — cookie metadata (domain/path/secure/httpOnly/sameSite + original expiry) is preserved through import instead of being flattened to `name=value`; a new `getLiveCookies()` enforces the original expiry at **use** time and applies a bounded TTL for genuinely-unknown-expiry cookies. Expired cookies are never sent.
- **Manual challenge-resume surface removed** — the earlier operator "paste cookies / resume" UI + API was removed; recovery is fully automatic (see §4.4).
- **Verification:** `npm run typecheck:v2` = 0, targeted smoke suites + a new real two-origin / real-Chromium / real-binary integration test all pass. The full `npm run check:v2`, frontend typecheck, and `git diff --check` had **not** been re-run across the very latest cookie-fidelity changes at the time of this reconciliation — re-run them before committing.

---

## 7. How To Run / Verify

```bash
cd worker
npm run typecheck:v2          # strict TS, must exit 0
npm run check:v2              # typecheck + the full ~178-script smoke suite
npm run test:v2:credential-redirect-integration   # real two-origin + real Chromium + real binaries
git diff --check             # whitespace sanity
```

Governance documents an agent must read before editing a subsystem:
- `AGENTS.md` (root) — the inviolable working rules and Definition of Done.
- `docs/decisions/` and `worker/src/v2/architecture/adr/` — the ADRs (why decisions were made). **These are kept; they are not "old docs."**
- `docs/DECISIONS.md` — the running decisions log.
- `docs/ROADMAP.md` — the forward roadmap, deficits, and strengths (companion to this document).
