# FixGuard V2 — Full External System Audit
## Runtime Wiring, End-to-End Data Flow, Architecture & Product Readiness

> **Auditor posture**: External Principal Architect + AppSec Engineer. Not the author. No assumption that existence = functionality, or that test passing = production readiness.

---

## Part I — One-URL Trace: What Actually Happens

### Entry → POST /api/v2/orchestrated/assessments/start

**Request body** consumed by `parseStartOrchestratedAssessmentBody`:
- `targetDomain` (required string)
- Optional: `actorId`, `relatedAllowedHosts`, `seedUrls`, `seedPaths`, `sessionIdentities`, `allowStateChangingRequests`, `allowedMethods`, `config`

**What happens synchronously (before 202 response):**

1. **Concurrency ceiling check** — max 3 concurrent assessments (env: `FIXGUARD_MAX_CONCURRENT_ASSESSMENTS`).
2. **Domain cleaning** — strips `http(s)://`, lowercases, validates `[a-z0-9.-]` only.
3. **SSRF Gate 1** — `isInternalOrSsrfTarget(cleanedDomain)` checks string against loopback/RFC1918/localhost patterns.
4. **DNS resolution** — resolves A records. **Fails closed if DNS returns 0 IPs** (throws `ApiValidationError`).
5. **SSRF Gate 2** — checks every resolved IP via `isInternalOrSsrfTarget()`.
6. **Tool availability check** — `ReconToolAvailabilityService.verifyRequiredTools()` against all non-skipped stages. Missing binaries are recorded as `degradedBinarySet` — **does NOT abort**. Deliberate degraded-mode behavior.
7. **Seed validation** — `validateAssessmentSeeds()` cross-checks seeds against the scope grant. Atomic: all seeds must pass or none are accepted.
8. **Scope grant construction** — `AuthorizedScopeGrant` built with `permissionSet.aggressiveValidation = false`, `oobTesting = false`, `destructiveOperations = false`; methods `['GET','HEAD','OPTIONS']` unless operator explicitly expands.
9. **Authorization decision** — `establishVerifiedAuthorizationDecision()` → runtime-branded `VerifiedAuthorizationDecision` sealed in process-local `sealedVerifiedDecisions` Map. **Never serialized to DB.**
10. **Initial record persisted** → `repository.save(initialRecord)` with `status: 'running'`.
11. **Pipeline launched in background** → `runPipeline()` → non-blocking, tracked in `activeAssessments` Map.
12. **202 Accepted** returned immediately with `{ assessmentId, scanId, status: 'running', lineage }`.

---

### Background Pipeline: `executePipelineStages()`

**Timeout/liveness infrastructure:**
- `AssessmentLivenessHeartbeat` — writes `lastHeartbeatAt` every N ms.
- `AssessmentActivityDeadline` — hard max + idle deadline. If breached → `AssessmentTimeoutError` → `status: 'failed'`.
- `TargetSessionKeepAlive` — only when BYOT session identities have auth headers.

#### Stage 0: Seed Liveness Filter (Phase D1/W1)
If `seedUrls` provided, `filterSeedsByLiveness()` probes each seed (4s timeout). Dead/soft-404 seeds dropped.

#### Stages 1–5: Composite Active Recon (`CompositeActiveReconOrchestratorService.orchestrate()`)

All stages gated behind `TargetExecutionCoordinator` (4 req/s, max 2 concurrent).

| Stage | Tools | Notes |
|---|---|---|
| `stage_1_domain_zone` | Subfinder, CrtSh, Dnsx | CrtSh **fail-closed by default** — 0 CT results in production unless fixed |
| `stage_2_port_service` | Naabu | Top ports only |
| `stage_3_web_tls` | Gated HTTP GET, Tlsx | 2-hop HTML extraction; robots.txt + sitemap.xml; seed URL probing |
| `stage_4_crawling_parameters` | Katana, Gau, Ffuf, Arjun, Playwright SPA | Deep crawl; SPA JS execution; parameter fuzzing |
| `stage_deep_recon` | JsLuice, Trufflehog | Secret scanning from JS/source |
| `stage_5_secret_inspection` | Trufflehog | Secondary pass on collected bodies |

**Stage 3 (HTTP/TLS) detail:**
- URL set = open ports → URL variants + primary domain + seed URLs
- Each URL: `webTool.inspectWeb()` → `runAdapterPreflight()` (auth brand + egress + SSRF + scope) → real HTTP GET
- HTML body → `HtmlRouteExtractionService.extract()` → Hop-1 (max 25 new URLs)
- Hop-1 `app_endpoint` bodies → Hop-2 (capped). No Hop-3.
- robots.txt + sitemap.xml merged into URL inventory
- TLS: one `tlsTool.inspectTls()` per HTTPS hostname
- Circuit breaker: `TargetInstabilityError` → partial_failure or circuit_broken

**Playwright SPA adapter:**
- Gate 1: `runAdapterPreflight()` before browser launch
- Gate 2: `page.route()` interceptor aborts OOS navigations/XHR/fetch; allows OOS static for hydration; blocks SSRF
- Gate 3: discovered routes filtered by scope + path before emission
- Outcome: SPA routes, XHR/fetch URLs, DOM inputs → merged into URL inventory

---

#### Detection Pass (after recon success)

**`runReadDetectionPass()`** dispatches all passive/semi-active read detectors:

| Detector | Trigger | Output |
|---|---|---|
| CORS Misconfiguration | All URLs | Finding or draft |
| Parameter Reflection | Discovered parameters | Finding or draft |
| Security Headers | Web observations | Draft |
| Open Redirect | Discovered params | Draft |
| Auth Bypass | BYOT sessions | Draft (human review) |
| Information Disclosure | Web responses | Finding or draft |
| Subdomain Takeover | DNS/CNAME | Draft |
| Credentialed CORS | BYOT sessions | Draft |
| GraphQL Surface | GraphQL URLs | Finding or draft |
| JWT Confusion | BYOT sessions with JWT | Draft |
| Session Fixation | PHP-gated (suppressed for Next.js/SPA) | Draft |
| API Versioning Sprawl | Multiple version paths | Draft |
| HTTP Method Manipulation | Discovered endpoints | Draft |
| Dependency Confusion | JS manifests | Draft |
| Manifest Exposure | /.env and similar paths | Finding or draft |
| Parameter Integrity (LFI) | Discovered params | Draft |
| Object Mapping Anomaly | POST endpoints | Draft |
| State Transition Anomaly | Multi-step flows | Draft |
| Supabase RLS | Supabase hosts + anon key | Observed facts |
| Sourcemap Exposure | .js URLs | Finding or draft |
| WordPress Surface | Root domain (XML-RPC, REST Users) | Finding or draft |
| CMS Plugin Vulnerabilities | Non-SPA/non-Next.js | Draft |
| TLS Configuration Analysis | tlsObservations | Finding or draft |
| Static Secret Exposure | JS/source bodies | Draft |
| Dependency Vulnerability | Manifest content | Draft |
| Static Route Extraction | Source bundles | Draft |
| OOB Canary / Blind SSRF / Blind XSS | OOB callbacks (P7) | Draft (only on confirmed callback) |

**Epistemic discipline:** Each detector emits a `Finding` (high-confidence OBSERVED) or `EnrichedEvidenceDraft` (requires `POST .../evidence/:draftId/review`). No auto-promotion. All detectors pass through `runAdapterPreflight()` before any network calls.

---

#### Attack Surface Graph + Plan Generation

1. `buildTargetProfile()` → `TargetProfile` (hosts, technologies, ports, TLS, WAF identity)
2. `correlateTargetProfile()` → advisory `recommendations[]` (no execution)
3. `AttackSurfaceGraphBuilder.buildFromAssessmentResults()` → `AttackSurfaceGraph` (nodes + edges)
4. `AttackPlanGeneratorService.generate()` → advisory `AttackPlan[]`:
   - `status: 'prerequisite_missing'` if BYOT identity count < 2 (for IDOR)
   - `executable: false` until A4 authorization flow
5. Plans saved to `attackPlanRepository`

---

#### Assessment Completion

```
→ record.status = 'completed'
→ record.profile (TargetProfile)
→ record.findings[] (0..N human-promoted findings)
→ record.pendingEvidenceDrafts[] (awaiting human review)
→ record.recommendations[] (advisory)
→ record.attackSurfaceGraph
→ record.observedFacts[]
→ record.transcript (AssessmentTranscript)
```

---

## Part II — Architecture Correctness Assessment

### What Is Genuinely Solid

| Invariant | Status | Evidence |
|---|---|---|
| No self-authorization | Enforced | `establishVerifiedAuthorizationDecision()` required; sealed in Map; JSON copies rejected |
| SSRF double-gate | Enforced | DNS resolution + IP check before pipeline; `evaluateEgressPolicy()` in every adapter preflight |
| Atomic batch preflight | Enforced | `runAdapterPreflight()` in every adapter; preflight_denied = zero network side effects |
| No `as any` in production | Enforced | AGENTS.md rule; typecheck:v2 gate |
| Lineage continuity | Enforced | `{ assessmentId, scanId, authorizationGrantId, authorizationDecisionId, actorId }` threaded everywhere |
| No fabricated findings | Enforced | Findings only from OBSERVED differentials; drafts require human review |
| Human-in-the-loop required | Enforced | `reviewEvidenceDraft()` is sole promotion gate; forbidden synthetic reviewer IDs checked |
| InMemory default | By design (ADR-011) | No DB dependency for core; Postgres adapter available |
| Circuit breaker | Implemented | `TargetExecutionCoordinator` + `TargetInstabilityError` → partial_failure or circuit_broken |
| Scope boundary checks | Implemented | `isScopeAllowed()`, `isPathAllowedByScopeBoundaries()` at every egress decision |
| Degraded-mode visibility | Implemented | Missing CLIs → `degradedCapabilities[]` on record, never silent |

---

### Real Gaps and Weaknesses

#### GAP 1 — CT Transport Fail-Closed by Default (Silent Subdomain Gap)

**Location:** [`createDefaultPassiveCtTool()`](file:///Users/patohe/Desktop/FixGuard/worker/src/v2/application/OrchestratedAssessmentApplicationService.ts#L927-L942)

`createProductionReconAdapters()` wires `CrtShAdapter` with `createFailClosedCtFetch()`. In production this means **CrtSh always returns 0 subdomains** unless the caller explicitly injects `fetchApi: fetch`.

**Severity: MEDIUM operational.** Passive CT enumeration is silently disabled in the default production composition.

**Fix (3 lines):**
```typescript
// In createProductionReconAdapters():
passiveCtTool: new CrtShAdapter({ dnsResolver, fetchApi: fetch }),
```

---

#### GAP 2 — Playwright Has No Binary Preflight Check

**Location:** [`PlaywrightSpaAdapter.ts:32`](file:///Users/patohe/Desktop/FixGuard/worker/src/v2/recon/adapters/PlaywrightSpaAdapter.ts#L32)

Unlike `subfinder`, `naabu`, `httpx`, etc., Playwright Chromium is not checked by `ReconToolAvailabilityService`. If `playwright install chromium` was not run, SPA discovery silently returns `browser_unavailable` with no entry in `degradedCapabilities[]`.

**Severity: MEDIUM.** SPA-heavy targets (Next.js, Vue) get zero route discovery without any visible warning.

**Fix:** Add a `playwright:chromium` probe spec to `TOOL_PROBE_SPECS` in `ReconToolAvailabilityService`.

---

#### GAP 3 — In-Memory Persistence: Process Restart = Total Data Loss

**Location:** [`InMemoryOrchestratedAssessmentRepository.ts`](file:///Users/patohe/Desktop/FixGuard/worker/src/v2/storage/InMemoryOrchestratedAssessmentRepository.ts) + [`V2CompositionRoot.ts`](file:///Users/patohe/Desktop/FixGuard/worker/src/v2/api/V2CompositionRoot.ts)

Any process restart (crash, deploy, OOM) loses all assessment records. The `activeAssessments` Map tracking pipeline promises is also process-local — a restart mid-pipeline leaves the record stuck at `status: 'running'` with no recovery path.

**Severity: HIGH operational.** Acceptable for dev/demo; unacceptable in production.

**Mitigation available:** Postgres adapter exists at `/worker/src/v2/storage/postgres/`. Must be wired as default in `V2CompositionRoot`.

---

#### GAP 4 — `sealedVerifiedDecisions` Map is Process-Local (No Horizontal Scale)

**Location:** `OrchestratedAssessmentApplicationService.ts:1354`

In a horizontally scaled deployment, the sealed `VerifiedAuthorizationDecision` only lives in the originating process instance. A5 execute, investigation gate, or scope expansion routed to a different instance will receive `authorization_decision_missing`.

**Severity: HIGH for scale.** Single-instance deployments unaffected.

---

#### GAP 5 — `AuthorizedScopeGrant.classification` is All `false` While Pipeline Executes Network

**Location:** `OrchestratedAssessmentApplicationService.ts:1666-1676`

The pipeline executes network calls, runs CLIs, and can create findings. The `classification` object says `executesNetwork: false`, `executesTools: false`, `createsRealFindings: false`. These are factually incorrect and could mislead operators or auditors reading the scope grant.

**Severity: LOW functional, MEDIUM trust surface.**

---

#### GAP 6 — Detection Verticals Are Sequential (No Parallelism)

All 30+ detectors are called sequentially inside `executePipelineStages()`. The rate limiter (4 req/s, max 2 concurrent) governs individual HTTP calls, but inter-detector `await` sequencing means no concurrent detector dispatch.

**Severity: MEDIUM performance.** A target with 20 discovered parameters and 10 detection types = hundreds of sequential HTTP calls.

---

#### GAP 7 — WordPress/CMS Probes Run on ALL Non-SPA Targets

**Location:** `executePipelineStages()` ~line 5966

XML-RPC + REST User probes + 5 WordPress plugin slug probes run on every non-Next.js/non-Nuxt target, even with zero WordPress signals in recon data (Rails API, Django, etc.).

**Severity: LOW.** Probes are safe and fail gracefully. 7+ wasted HTTP requests per non-WP assessment.

---

#### GAP 8 — HTML Extraction Caps Are Hard-Coded Constants

`HTML_ROUTE_EXTRACTION_MAX_PER_STAGE` and `HTML_ROUTE_EXTRACTION_MAX_HOP2` cannot be tuned per-assessment. Large SPAs with hundreds of routes are silently capped.

**Severity: LOW-MEDIUM.** Not operator-configurable.

---

#### GAP 9 — `reconResult.aggregatedObservations` Mutated via `Object.assign`

**Location:** ~line 5743

```typescript
Object.assign(reconResult, {
  aggregatedObservations: { ...reconResult.aggregatedObservations, urls: Object.freeze(merged) },
});
```

Mutates a `const` variable. Violates the no-in-place-mutation invariant in AGENTS.md. If `reconResult` were `Readonly<...>`, this would not compile.

**Severity: LOW.** Technical debt / latent mutation risk.

---

#### GAP 10 — `actorId` Silently Falls Back to Magic String

**Location:** `startAssessment()` line 1600–1603

```typescript
const actorId =
  command.actorId && isStrictSafeId(command.actorId)
    ? command.actorId
    : 'usr_secops_api';    // ← all unauthenticated callers share this identity
```

Missing or invalid `actorId` silently assigns `'usr_secops_api'`. All such assessments share the same fake identity in the lineage audit trail.

**Severity: MEDIUM for audit integrity.** Multi-operator or multi-tenant contexts lose attribution.

---

## Part III — Tool Integration Reality Check

| Tool | Adapter | Binary Check | Scope Gate | Degraded-Mode | Real Output Consumed |
|---|---|---|---|---|---|
| `subfinder` | `SubfinderAdapter` | ✅ | ✅ | ✅ | ✅ subdomains |
| `dnsx` | `DnsxAdapter` | ✅ | ✅ | ✅ | ✅ DNS records |
| `naabu` | `NaabuPortDiscoveryAdapter` | ✅ | ✅ | ✅ | ✅ open ports |
| `httpx` | `HttpxInspectionAdapter` + gated HTTP | ✅ | ✅ | ✅ | ✅ web observations |
| `tlsx` | `TlsxAdapter` | ✅ | ✅ | ✅ | ✅ TLS observations |
| `gau` / `katana` | `CompositeUrlDiscoveryAdapter` | ✅ | ✅ | ✅ | ✅ URL inventory |
| `ffuf` | `FfufAdapter` | ✅ | ✅ | ✅ | ✅ discovered paths |
| `arjun` | `ArjunAdapter` | ✅ | ✅ | ✅ | ✅ parameters |
| `trufflehog` | `TrufflehogAdapter` | ✅ | ✅ | ✅ | ✅ secret findings |
| `jsluice` | `JsLuiceAdapter` | ✅ | ✅ | ✅ | ✅ JS endpoint extraction |
| `playwright` | `PlaywrightSpaAdapter` | ❌ no preflight check | ✅ | ✅ browser_unavailable | ✅ SPA routes |
| `nuclei` | `NucleiAdapter` | ✅ | ✅ | ✅ | ✅ A-series execution only |
| `sqlmap` | `SqlmapAdapter` | ✅ | ✅ | ✅ | ✅ A-series execution only |
| `crt.sh` | `CrtShAdapter` | N/A | ✅ | ⚠️ fail-closed by default | ❌ 0 results without live fetch |

---

## Part IV — Detection Capability Inventory

### Recon-Phase (Automatic, No BYOT Required)

| Capability | Automated | Human Review | Notes |
|---|---|---|---|
| Subdomain enumeration | ✅ | No | subfinder + CT |
| DNS resolution | ✅ | No | |
| Port discovery | ✅ | No | |
| HTTP observation | ✅ | No | |
| TLS observation | ✅ | No | |
| URL discovery | ✅ | No | |
| Content discovery (ffuf) | ✅ | No | Wordlist-dependent |
| Parameter discovery | ✅ | No | |
| Secret scanning | ✅ | No | Finding created directly |
| SPA route discovery | ✅ | No | Requires playwright |
| JS endpoint extraction | ✅ | No | JsLuice |
| robots.txt / sitemap | ✅ | No | |
| Security headers | ✅ | Draft | |
| CORS misconfiguration | ✅ | Draft | |
| TLS weak configuration | ✅ | Draft | |
| Sourcemap exposure | ✅ | Finding | Directly promoted |
| WordPress XML-RPC | ✅ | Draft | |
| WordPress user enum | ✅ | Draft | |
| GraphQL surface | ✅ | Draft | |
| Open redirect | ✅ | Draft | |
| Information disclosure | ✅ | Draft | |
| Subdomain takeover | ✅ | Draft | |
| Dependency confusion | ✅ | Draft | |
| Manifest exposure | ✅ | Draft or Finding | Severity-dependent |
| SQL error oracle | ✅ | Draft | |
| CMS plugin vulnerabilities | ✅ | Draft | Non-WP targets skip |
| Anon vs session delta | ✅ | Fact only | No finding without confirmation |
| Published advisory match | ✅ | Fact only | Against LOCAL_PUBLIC_ADVISORIES |

### Attack-Phase (Requires Human Authorization + AttackAuthorizationToken)

| Capability | Needs BYOT | Needs 2 Identities | Notes |
|---|---|---|---|
| IDOR read differential | ✅ | ✅ (A+B) | A5 execute |
| Auth bypass probe | ✅ | No | A5 execute |
| CORS chain exploit | No | No | A5 execute |
| JWT alg:none probe | ✅ | No | A5 execute |
| LFI/path traversal | No | No | A5 execute |
| SQL oracle advancement | No | No | A5 execute |
| SQL injection verification | No | No | sqlmap-backed |
| Nuclei XSS scan | No | No | nuclei-backed |
| Auth boundary differential | ✅ | ✅ | A5 execute |
| Supabase RLS read/write | ✅ | No | Needs anon key |
| Next.js Server Action diff | ✅ | No | |
| Serverless race condition | No | No | |
| Credential reuse | No | No | Lateral movement API |
| Parameter reflection probe | No | No | A5 execute |

---

## Part V — Product Readiness Score

| Dimension | Score | Notes |
|---|---|---|
| Authorization framework | **Mature** | Runtime branding, sealed decisions, no self-auth, scope gates, SSRF double-gate |
| Recon pipeline | **Operational** | All 12 adapters wired; degraded-mode; circuit breaker; seed validation |
| CT enumeration | **Implemented, NOT operational** | Fail-closed by default; 0 subdomains unless fixed |
| Playwright SPA | **Operational** | No binary preflight check; requires separate `playwright install` |
| Detection layer | **Operational** | 30+ detectors; all gate on preflight; drafts require human review |
| Human review boundary | **Mature** | Strong epistemic discipline; forbidden synthetic reviewer IDs; draft promotion gate |
| Attack plan generation | **Operational** | Pure advisory; correct prerequisite tracking; no auto-execute |
| Attack authorization (A4) | **Operational** | Runtime token; branded; sealed; no JSON lookalike |
| Attack execution (A5) | **Operational** | 7 safety gates; branded token required; per-capability CLI adapters |
| Attack chains (A6) | **Operational** | Correct epistemic status mapping; no fabricated steps |
| Post-exploitation (A10) | **Implemented** | Vault-backed; no secrets in API responses |
| Lateral movement (A11–A13) | **Implemented** | Discovery ≠ authorization; human promote required |
| Impact assessment (A12) | **Implemented** | Derived from chains; no inflation |
| Persistence | **NOT mature** | InMemory by default; Postgres adapter available but not default-wired |
| Multi-instance / scale | **NOT ready** | sealedVerifiedDecisions is process-local; no session handoff |
| Reporting | **Operational** | HTML report with operator attestation; adversarial context |
| Test coverage | **High** | ~190 smoke tests; reasonable milestone coverage |

---

## Part VI — Prioritized Build Roadmap

### P0 — Production Blockers

1. **Fix CT fetch injection** in `createProductionReconAdapters()` — inject `fetchApi: fetch` into `CrtShAdapter`. 3 lines. **Critical for subdomain coverage.**

2. **Default to Postgres repository** — wire Postgres adapter as default in `V2CompositionRoot` (env-controlled override). Without this, process restarts lose all assessments.

3. **Add Playwright binary check** to `ReconToolAvailabilityService.TOOL_PROBE_SPECS` — surface `degraded_mode_missing_binary: playwright` loudly instead of silent failure.

### P1 — Operational Quality

4. **Replace `actorId` magic string fallback** — require valid actorId in `StartOrchestratedAssessmentCommand`; reject with `ApiValidationError` if missing.

5. **Fix `AuthorizedScopeGrant.classification` flags** — populate correctly to reflect actual pipeline capabilities (`executesNetwork: true`, etc.).

6. **Multi-instance sealed decision handoff** — sticky routing per assessmentId OR externalize decision reference to Redis keyed by assessmentId.

7. **WordPress/CMS probes: gate on fingerprint** — only run when `detectedTechnologies` contains WordPress signals. Saves 7+ HTTP requests per non-WP target.

### P2 — Capability Expansion

8. **Parallel detection dispatcher** — run independent detection verticals concurrently. Expected speedup: 3–5x on detection phase.

9. **Operator-configurable URL inventory caps** — expose `maxHop1Routes`, `maxHop2Routes` in `ActiveReconOrchestrationConfig`.

10. **Assessment resume** — relaunch from checkpoint after process crash (requires Postgres first).

11. **Continuous CT monitoring** — scheduled CrtSh poll post-assessment vs one-shot passive CT during recon.

---

## Part VII — Summary Verdict

| Phase | Works? | Quality |
|---|---|---|
| Authorization + SSRF gates | ✅ Yes | Excellent |
| Domain recon (subfinder, dnsx, naabu) | ✅ Yes | Good — degraded if binaries missing |
| CT subdomain discovery | ❌ No | Fail-closed by default bug |
| HTTP/TLS inspection | ✅ Yes | Solid; 2-hop HTML extraction |
| Playwright SPA crawl | Conditional (if installed) | No binary preflight warning |
| Parameter/content discovery | ✅ Yes | CLI-dependent; degraded-mode if missing |
| Security header / CORS / TLS detection | ✅ Yes | Draft → human review |
| WordPress / GraphQL surface | ✅ Yes | May probe unnecessary non-WP targets |
| IDOR / Auth bypass (A5) | Conditional | Requires BYOT + 2nd identity + human A4 |
| Attack plan generation | ✅ Yes | Advisory only; correct |
| Human review + finding promotion | ✅ Yes | Strong epistemic discipline |
| Reporting | ✅ Yes | HTML report with attestation |
| Data persistence | ❌ (InMemory) | Lost on restart |

**Genuine working product surface: ~70% operational, ~20% partial/conditional, ~10% silently broken or not production-ready.**

The architecture is exemplary for its category — strong epistemic discipline, no fabricated findings, mandatory human authorization for execution, correct layering. The gaps are **operational rather than architectural**. Fix the CT fetch injection, default-wire Postgres, and add the Playwright preflight check — the system is then substantially production-ready for single-instance deployments.
