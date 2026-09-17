# FixGuard V2 Technical Roadmap & Architecture Status

> **Document Purpose:** Single, canonical source of truth tracking completed milestones, foundations, active roadmap, and architectural boundaries across FixGuard V2.  
> **Permanent Axiom:** "Tools execute. Intelligence decides. Humans authorize."  
> **Integrity Rule:** Proposed changes are strictly separated from confirmed project decisions. Zero speculative claims or synthetic finding counts.

---

## 1. Status Overview

```text
[M0 ─── M55] COMPLETED ───> [M56A / M56B] COMPLETED ───> [M57 / M58] COMPLETED
                                                                │
                                                                ▼
                                                        [M59 / M60] COMPLETED
                                                                │
                                                                ▼
                                                       [M61 / M61.1] COMPLETED
                                                                │
                                                                ▼
                                                            [M62] COMPLETED (Web MVP)
                                                                │
                                                                ▼
                                                            [M63] COMPLETED (V1 Decommission)
                                                                │
                                                                ▼
                                                       [M64 ─── M72] COMPLETED (Recon Adapters)
                                                                │
                                                                ▼
                                                       [MILESTONE F0] COMPLETED (API Security & Foundations)
                                                                │
                                                                ▼
                                                       [MILESTONE F1] COMPLETED (Unified Preflight Pipeline)
                                                                │
                                                                ▼
                                                       [MILESTONE F2] COMPLETED (First Real Detection Engine)
                                                                │
                                                                ▼
                                                       [MILESTONE F3] COMPLETED (Scale Infrastructure)
                                                                │
                                                                ▼
                                                       [MILESTONE F4] COMPLETED (Detection Coverage Expansion)
                                                                │
                                                                ▼
                                                       [MILESTONE F5] COMPLETED (Real Intelligence Layer)
                                                                │
                                                                ▼
                                                       [MILESTONE 73] COMPLETED (Composite Active Recon Orchestrator)
                                                                │
                                                        [MILESTONE F6] COMPLETED (V2 API Orchestrator Controller & Assessment Gateway)
                                                                │
                                                                ▼
                                                         [MILESTONE F7] COMPLETED (V2 Orchestrated Assessment UI Integration)
                                                                │
                                                                ▼
                                                        [MILESTONE F8] COMPLETED (Blast Radius Hardening & Target Circuit Breaker)
                                                                │
                                                                ▼
                                                        [MILESTONE 7] COMPLETED (Browser Automation Engine for SPA & DOM Discovery)
                                                                │
                                                                ▼
                                                        [MILESTONE 8] COMPLETED (Controlled Active Verification & Safe PoC Engine)
                                                                │
                                                                ▼
                                                        [PHASE 0: P0-1, P0-2, P0-3] COMPLETED (Human Review Gate, Typed Finding, Binary Availability)
                                                                │
                                                                ▼
                                                        [PHASE 1: P1-1] COMPLETED (Async Assessment HTTP API Lifecycle)
                                                                │
                                                                ▼
                                                        [PHASE 1: P1-2] COMPLETED (First Real Integration Test Suite - Level 2)
                                                                │
                                                                ▼
                                                        [PHASE 1: P1-3] COMPLETED (Human Review UI Flow & Real HITL Triage)
                                                                │
                                                                ▼
                                                        [PHASE 2: P2-1] COMPLETED (Security Header Detection Engine)
                                                                │
                                                                ▼
                                                        [PHASE 2: P2-2] COMPLETED (Open Redirect Detection Engine)
                                                                │
                                                                ▼
                                                        [PHASE 2: P2-3] COMPLETED (Information Disclosure Detection Engine)
                                                                │
                                                                ▼
                                                        [PHASE 2: P2-4] COMPLETED (Subdomain Takeover Detection Engine)
                                                                │
                                                                ▼
                                                        [PHASE 2: P2-5] COMPLETED (TLS Configuration Analysis Engine)
                                                                │
                                                                ▼
                                                        [PHASE 2: P2-6] COMPLETED (HTML Report Generation & Operator Attestation)
                                                                │
                                                                ▼
                                                        [PHASE 3: P3-1] COMPLETED (BYOT Session Injection & Anti-Leak Boundary)
                                                                │
                                                                ▼
                                                        [PHASE 3: P3-3] COMPLETED (Multi-Identity Differential IDOR with BYOT)
                                                                 │
                                                                ▼
                                                        [PHASE 4: P4-1] COMPLETED (Authentication Bypass Detection Engine)
                                                                │
                                                                ▼
                                                        [PHASE 4: P4-2] COMPLETED (Technology Fingerprint Engine)
                                                                │
                                                                ▼
                                                        [PHASE 4: P4-3] COMPLETED (Sourcemap Exposure Detection Engine)
                                                                │
                                                                ▼
                                                        [PHASE 4: P4-4] COMPLETED (WordPress XML-RPC and User Enumeration Probes)
                                                                │
                                                                ▼
                                                        [PHASE 4: P4-5] COMPLETED (SQL Error Oracle Detection Engine)
                                                                │
                                                                ▼
                                                        [PHASE 4: P4-6] COMPLETED (GraphQL Surface Mapper)
```

---

## 2. Completed Milestones (`CONFIRMED`)

All completed milestones are verified via active TypeScript contracts and the regression test suite (`npm run check:v2` with 61 passing smoke suites, 100% pass rate).



### Foundation Era (M0 – M29)
- **M0 – M6.5 (Core Loop Foundation)**: `TargetContext`, `CapabilityRequest`, `ExecutionRequest`, `RawExecutionOutput`, `ProcessRunner` (safe spawn without shell interpolation), `SubfinderAdapter`, `SubfinderParser`.
- **M7 – M14 (Runtime Foundation)**: `V2AssessmentRuntime`, `AssessmentState`, lifecycle state machines, optimistic versioning, mutation guards.
- **M15 – M23 (Storage Boundary & Postgres Integration)**: `AssessmentRepository` port, `InMemoryAssessmentRepository`, `PostgresAssessmentRepository` (Drizzle ORM, tables prefixed `v2_`), transactional unit-of-work boundaries, rollback guarantees.
- **M24 – M29 (Boundary Hardening)**: `AssessmentApplicationService`, safe DTO mappers (zero raw command or executable payload leaks), capability registry enforcement.

### Active Recon & Policy Era (M30 – M44)
- **M30 (Egress Policy Boundary)**: `PassiveEgressPolicy` SSRF gate (`allow` / `block` / `candidate`), private subnet blocking (`RFC1918`, loopback, cloud metadata).
- **M31 – M37 (Guarded Active Recon Foundations)**: Safe HTTP header inspection, opt-in network execution seams, safe document metadata.
- **M38 (Document Probe Runner)**: Sondas documentales (`http.robots.inspect`, `http.security_txt.inspect`).
- **M39 (Active Recon Origin Run)**: Two-pass atomic batch preflight (if any probe in a batch fails, abort with 0 side effects).
- **M40 – M42 (Persisted Origin Run & Execution Persistence)**: Closed-world persistence validation, defensive persistence reload verification.
- **M43 – M44 (Read Model & Application Use Cases)**: Read model query segregation, initial application use case boundary.

### Evidence & Candidate Era (M45 – M55)
> [!IMPORTANT]
> **INTELLIGENCE LAYER STATUS**: The automated Intelligence Layer correlation engine has **NOT** yet been built.
> Milestones M45–M55 strictly establish **human-reviewed evidence custody**, differential observation comparison, candidate drafting, and explicit human triage promotion. Findings cannot be correlated, escalated, or reported autonomously without human authorization.

- **M45 (Evidence Boundary)**: `EvidenceRecord`, `IndicatorRecord`, explicit non-claim classification flags.
- **M46 (Authorized Scope Policy Refinement)**: `AuthorizedScopeGrant`, `ScopeActionRequest`, explicit permission sets and boundary matching.
- **M47 (Response Comparator)**: `SafeResponseSnapshot`, differential HTTP signal comparison.
- **M48 (Comparison Evidence Mapping)**: Differential signals mapped to non-persisted drafts (`EvidenceDraftEnvelope`).
- **M49 (Authorized Comparison Validation)**: Scope-gated differential validation.
- **M50 (Human-Reviewed Evidence Promotion)**: Reviewer gate (`approve_evidence`, `reject`, `needs_more_review`), producing un-persisted `EvidenceRecord`.
- **M51 (Reviewed Evidence Store & Read Model)**: Mutation-safe in-memory repository for reviewed evidence records.
- **M52 (Reviewed Evidence Query & Selection)**: Query and selection sets over reviewed evidence.
- **M53 (Finding Candidate Draft Boundary)**: Grouping reviewed evidence into non-persisted candidate drafts.
- **M54 (Human-Triaged Finding Candidate Promotion)**: Explicit human triage gate producing `ReviewedEvidenceFormalFindingCandidate`.
- **M55 (Core Candidate Pipeline Reality Check)**: Comprehensive end-to-end diagnostic proving ID and metadata continuity across M51 $\rightarrow$ M54.


### Continuity & Vertical Composition Era (M56A – M58)
- **M56A (Verified Authorization Boundary)**: Runtime-established `VerifiedAuthorizationDecision` using module-private `WeakSet<object>` brand. Forgery resistance against spread, structuredClone, and JSON round-trips. Strict exact-key persistence validation. ADR-001 sealed.
- **M56B (Lineage & Comparison Continuity)**: Integrated verified authorization and lineage references (`assessmentId`, `scanId`, `authorizationGrantId`, `authorizationDecisionId`, `actorId`) into M49 comparison validation.
- **M57 (Real Recon-to-Reviewed-Evidence Vertical Slice)**: Implemented `ReconToReviewedEvidenceApplicationService` unifying the 7-step flow from authorized URL to reviewed evidence store.
- **M58 (Evidence Substance & Canonical Candidate Semantics)**: Defined discriminated unions for substantive evidence payloads (`EvidenceSubstancePayload`), mandatory unbroken `ExecutionLineage`, canonical status for `ReviewedEvidenceFormalFindingCandidate` (M54), deprecated legacy M45 candidate model, exact-key closed-world rejection of injected severities/remediations, and single consolidated smoke test with 100% pass rate.
- **M59 (Persistence Readiness for Candidates & Evidence Store)**: Designed and implemented hybrid PostgreSQL tables (`v2_reviewed_evidence_records`, `v2_formal_finding_candidates`) using isolated `drizzle.v2.config.ts`, composite indexes `(scan_id, evidence_type)`, DB-agnostic error translation (PG 23505 $\rightarrow$ `PersistenceConflictError`, PG 23503 $\rightarrow$ `SessionNotFoundError`), defensive deserialization against domain exact-key validation, relational cross-column consistency checks, and fail-closed adversarial audit tests (detecting SQL injection of `severity: "CRITICAL"` or desync tampering).
- **M60 (Defensive Report Readiness Gate)**: Created Layer 9 (`reporting-boundary`) with `DefensiveAssessmentReport` DTO. Enforced mandatory human-in-the-loop signature (`operatorAttestation.operatorSignatureId`), immutable audit limitations (`auditLimitations`), explicit non-claims, unmutated candidate preservation, and strict gatekeeper rejection (`ReportGenerationError`) against missing signatures, hollow candidates (`selectedCount: 0`), or corrupted candidates carrying speculative claims (`severity`, `risk_score`, `cvss`, `remediation_advice`).
- **M61 (V2 Application Gateway & Unified Presentation Layer)**: Implemented dedicated Express 5 REST API Gateway under `worker/src/v2/api/` completely isolated from V1 monolith (`worker/src/index.ts`). Orchestrated static dependency injection via `V2CompositionRoot` (DB-free in-memory defaults, supporting Postgres adapters). Thin controllers (`AssessmentController`, `ReportController`, `AuthorizationController`) translating HTTP requests to pure domain commands with zero business logic. Centralized `v2ErrorHandler` mapping domain errors (`PersistenceConflictError` $\rightarrow$ 409, `SessionNotFoundError`/`RecordNotFoundError` $\rightarrow$ 404, `ReportGenerationError`/`RecordCorruptedError` $\rightarrow$ 400/403, unhandled errors $\rightarrow$ sanitized 500 with zero leaks of stack traces or database topologies). Runtime-branded authorization (ADR-001) instantiated at request perimeter via `POST /api/v2/auth/decisions`. Single consolidated smoke test (`milestone61_v2_api_gateway_smoke.ts`) with 10 assertions passing 100%.
- **M61.1 (Triage & Candidate Promotion Gateway Endpoints — Patch 61.1-P1)**: Patched `worker/src/v2/api/` and `worker/src/v2/finding-candidate-draft/` to expose Human-in-the-Loop endpoints (`GET /api/v2/scans/:scanId/evidence-drafts`, `POST /candidates/promote`, `POST /assessments/:sessionId/recommendations/approve`) needed for Milestone 62 frontend integration. Strictly enforced Anti-Fabrication Boundary: `POST /candidates/promote` rejects client-supplied `draft` payloads fail-closed with HTTP 400 Bad Request, strictly retrieving authentic drafts from backend storage. Preserved Clean Domain Layering by placing `EvidenceDraftRepository` and `InMemoryEvidenceDraftRepository` in Layer 8 domain (`finding-candidate-draft`), aligned draft querying with `scanId` independence (`sessionId !== scanId`), keeping `TriageController` completely thin and linear. Consolidated smoke test (`milestone61_1_triage_api_smoke.ts`) with all assertions passing 100%.
- **M62 (Visual Minimum Viable Product — Web Frontend MVP)**: Built the Next.js 16 user interface under `web/src/app/v2/` and `web/src/lib/v2/` consuming the V2 Express 5 Gateway. Developed typed API client (`FixGuardV2ApiClient`) mapping all 6 gateway endpoints, preserving the Anti-Fabrication Boundary (submitting strictly safe IDs and human authorization, zero draft object fabrication). Implemented 4-stage interactive lifecycle dashboard: Stage 1 (Target Launch & Scope), Stage 2 (Session Metrics & Active Recon Execution), Stage 3 (Evidence Triage Board with `scanId` resolution and HITL candidate promotion), and Stage 4 (Defensive Report Gatekeeper with mandatory operator signature, &ge;10 char attestation, 11-key report viewer, and JSON export). Resolved baseline build blockers in `web/` without modifying `worker/**` or legacy V1 frontend views (`npm run build` exits with code 0).

---

- **M63 (V1 Monolith Decommissioning & Workspace Cleanup)**: Decoupled and decommissioned legacy V1 monolith endpoints in `worker/src/index.ts` returning HTTP 410 Gone with descriptive redirect payloads. Hardened standalone V2 gateway (`createV2App.ts`) with dedicated CORS and Express JSON body-parsing. Safely uninstalled 51 unused packages from `worker/package.json` (`@ai-sdk/google`, `ai`, `@upstash/redis`, `axios`, `cheerio`, `playwright`, `wappalyzer`, `wappalyzer-core`). Purged tracked `worker/node_modules/` from Git tracking and enforced `.gitignore` (`node_modules/`, `dist/`, `.next/`).
- **M64 (Subdomain Discovery Tool Adapter — Subfinder)**: Implemented typed port `SubdomainDiscoveryTool` and adapter `SubfinderAdapter` under `worker/src/v2/recon/adapters/` using Ports & Adapters pattern. Command invocation strictly executes via `ProcessRunner.execute()` with `shell: false` and isolated argument array (`['-d', targetDomain, '-silent', '-json']`). Enforces two-pass atomic preflight (M39) validating runtime-branded authorization decisions and scope grant boundaries before spawning processes. Enforces SSRF egress gate (M30) filtering out RFC-1918 private subnets, loopback (`127.0.0.0/8`), and cloud metadata (`169.254.169.254`). Implements fail-closed streaming parsing resilient to corrupted lines. Strictly produces factual observation DTOs with explicit non-claims (`severity: 'info'`, zero speculative vulnerability claims or CVSS ratings). Consolidated smoke test (`milestone64_subfinder_adapter_smoke.ts`) verifying all 8 assertions with 100% pass rate.

---

- **M65 (Port & Service Discovery Tool Adapter — Naabu)**: Implemented typed port `PortDiscoveryTool` and adapter `NaabuPortDiscoveryAdapter` under `worker/src/v2/recon/adapters/` using the Ports & Adapters pattern. Command invocation strictly executes via `ProcessRunner.execute()` with `shell: false` and isolated argument arrays (`['-host', target, '-json', '-silent', '-rate', '1000', ...optional -p]`). Enforces 6-pass atomic preflight (target format, runtime-branded authorization check, continuous lineage verification, scope permission check, scope boundary check, and SSRF pre-check) ensuring 0 child processes spawn on denial. Enforces SSRF and loopback containment (M30) dropping any port observation resolving to RFC-1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), or cloud metadata (`169.254.169.254`). Stream-parses output line-by-line with fail-closed resilience against malformed/non-JSON lines. Returns factual observation DTOs with mandatory `PORT_DISCOVERY_NON_CLAIMS` (`severity: 'info'`, zero speculative vulnerability claims or CVE ratings). Consolidated smoke test (`milestone65_port_discovery_adapter_smoke.ts`) verifying all 8 assertions with 100% pass rate.

---

- **M66 (Web Technology & Service Inspection Adapter — Httpx)**: Implemented typed port `WebInspectionTool` and adapter `HttpxInspectionAdapter` under `worker/src/v2/recon/adapters/` using the Ports & Adapters pattern. Command invocation strictly executes via `ProcessRunner.execute()` with `shell: false` and isolated argument arrays (`['-u', targetUrl, '-json', '-silent', '-title', '-tech-detect', '-status-code', '-follow-redirects']`). Enforces 6-pass atomic preflight check (URL protocol validation, runtime-branded authorization check, continuous lineage verification, scope permission check, scope boundary check, and SSRF pre-check on target host) with 0 child processes spawned on denial. Enforces Deep SSRF Redirect Containment (M30) inspecting both the final resolved host and all IP hops in the redirection chain, strictly dropping observations redirecting to loopback (`127.0.0.0/8`), RFC-1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), or cloud metadata (`169.254.169.254`). Stream-parses output line-by-line with fail-closed resilience against malformed/non-JSON lines. Returns factual observation DTOs with mandatory `WEB_INSPECTION_NON_CLAIMS` (`severity: 'info'`, zero speculative CVE or vulnerability findings). Consolidated smoke test (`milestone66_httpx_adapter_smoke.ts`) verifying all 8 assertions with 100% pass rate.

---

- **M67 (Exhaustive URL & Endpoint Discovery Composite Adapter — Katana + Gau)**: Implemented typed port `UrlDiscoveryTool` and composite adapter `CompositeUrlDiscoveryAdapter` under `worker/src/v2/recon/adapters/` using the Ports & Adapters pattern. Coordinates dual discovery engines via `ProcessRunner` (`shell: false`): modern JavaScript crawling/SPA route extraction via `katana` (`['-u', targetUrl, '-silent', '-json', '-depth', '3', '-jc']`) and historical archive mining via `gau` (`['--json', targetHost]`). Enforces 6-pass atomic preflight check (format, authorization brand, continuous lineage, scope permissions, scope boundary, SSRF pre-check) ensuring 0 child processes spawn on denial. Enforces Strict Scope & SSRF Egress Gate (M30) evaluating the hostname of every discovered URL, dropping out-of-scope third-party URLs (CDNs, analytics) and SSRF-restricted IP spaces (loopback `127.0.0.0/8`, RFC-1918 private subnets, cloud metadata `169.254.169.254`). Merges, deduplicates, and normalizes outputs with source attribution (`sources: ['archive_legacy', 'modern_crawler']`). Returns factual observation DTOs with mandatory `URL_DISCOVERY_NON_CLAIMS` (`severity: 'info'`, zero speculative vulnerability findings). Consolidated smoke test (`milestone67_url_discovery_adapter_smoke.ts`) verifying all 8 assertions with 100% pass rate.

---

- **M68 (Secret Scanning & Exposed Credential Discovery Adapter — Trufflehog)**: Implemented typed port `SecretScannerTool` and adapter `TrufflehogAdapter` under `worker/src/v2/recon/adapters/` using the Ports & Adapters pattern. Command invocation strictly executes via `ProcessRunner.execute()` with `shell: false` and isolated argument arrays (`['git', targetUrl, '--json', '--no-verification']` or `['filesystem', targetPath, '--json']`). Enforces 6-pass atomic preflight check (target format, runtime-branded authorization check, continuous lineage verification, scope permission check, scope boundary check, and SSRF pre-check) ensuring 0 child processes spawn on denial. Enforces strict filesystem path traversal safety blocking `..` and forbidden root prefixes (`/etc`, `/root`, `/var/run`, `/proc`, `/sys`, etc.). Enforces Strict Secret Redaction (M68) using `maskSecret` ensuring raw plaintext credentials (`Raw`) are strictly wiped from memory immediately upon parsing and never returned in output DTOs or logs. Stream-parses output line-by-line with fail-closed resilience against corrupted/non-JSON lines. Produces factual observation DTOs with mandatory `SECRET_DISCOVERY_NON_CLAIMS` (`severity: 'info'`, zero speculative vulnerability claims or CVSS ratings). Consolidated smoke test (`milestone68_trufflehog_adapter_smoke.ts`) verifying all 8 assertions (including Deep Redaction Check) with 100% pass rate.

---

- **M69 (Exhaustive & Evasive Content Discovery Adapter — Ffuf)**: Implemented typed port `ContentDiscoveryTool` and adapter `FfufAdapter` under `worker/src/v2/recon/adapters/` using the Ports & Adapters pattern. Command invocation strictly executes via `ProcessRunner.execute()` with `shell: false` and isolated argument arrays (`['-u', targetUrl + '/FUZZ', '-w', safeWordlistPath, '-json', '-ac', '-p', String(delaySeconds), '-rate', String(rateLimit)]`). Enforces 6-pass atomic preflight check (URL format, runtime-branded authorization check, continuous lineage verification, scope permission check, scope boundary check, and SSRF pre-check) ensuring 0 child processes spawn on denial. Enforces strict wordlist path containment blocking `..` traversal and forbidden system directories (`/etc`, `/var`, `/root`, `/proc`, `/sys`, etc.) in the preflight phase. Enforces Deep SSRF Redirect Containment (M30) evaluating both base URLs and `redirectlocation` targets, strictly dropping observations resolving or redirecting to loopback (`127.0.0.0/8`), RFC-1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), or cloud metadata (`169.254.169.254`). Stream-parses output with fail-closed resilience against malformed/non-JSON lines. Produces factual observation DTOs with mandatory `CONTENT_DISCOVERY_NON_CLAIMS` (`severity: 'info'`, zero speculative vulnerability claims or CVSS ratings). Consolidated smoke test (`milestone69_ffuf_adapter_smoke.ts`) verifying all 8 assertions with 100% pass rate.

---

- **M70 (Exhaustive DNS & Zone Enumeration Tool Adapter — Dnsx)**: Implemented typed port `DnsResolutionTool` and adapter `DnsxAdapter` under `worker/src/v2/recon/adapters/` using the Ports & Adapters pattern. Command invocation strictly executes via `ProcessRunner.execute()` with `shell: false` and isolated argument arrays (`['-d', targetDomain, '-json', '-a', '-aaaa', '-cname', '-txt', '-mx', '-wd', targetDomain, '-r', resolvers]`). Enforces 6-pass atomic preflight check (FQDN format, target domain SSRF pre-check, runtime-branded authorization check, continuous lineage verification, scope permission check, and scope boundary check) ensuring 0 child processes spawn on denial. Enforces Resolver Containment strictly passing safe public resolvers (`-r 1.1.1.1,8.8.8.8`) to prevent internal DNS rebinding SSRF on the host. Dynamically injects wildcard filtering (`-wd <targetDomain>`) to drop catch-all zone false positives. Enforces Deep SSRF Egress Gate (M30) evaluating resolved `a` and `aaaa` records, strictly dropping any observation resolving to loopback (`127.0.0.0/8`), RFC-1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), or cloud metadata (`169.254.169.254`). Stream-parses output with fail-closed resilience against malformed/non-JSON lines. Produces factual observation DTOs with mandatory `DNS_RESOLUTION_NON_CLAIMS` (`severity: 'info'`, zero speculative vulnerability claims or Subdomain Takeover inferences). Consolidated smoke test (`milestone70_dnsx_adapter_smoke.ts`) verifying all 8 assertions with 100% pass rate.

---

- **M71 (Exhaustive TLS/SSL Inspection Adapter — Tlsx)**: Implemented typed port `TlsInspectionTool` and adapter `TlsxAdapter` under `worker/src/v2/recon/adapters/` using the Ports & Adapters pattern. Command invocation strictly executes via `ProcessRunner.execute()` with `shell: false` and isolated argument arrays (`['-u', targetHost, '-json', '-san', '-ve', ...optional -p]`). Enforces 6-pass atomic preflight check (URL/host format validation, target host SSRF pre-check, runtime-branded authorization check, continuous lineage verification, scope permission check, and scope boundary check) ensuring 0 child processes spawn on denial. Supports multi-port TLS inspection with isolated `-p` port parameter mapping. Instructs `tlsx` to perform exhaustive version enumeration (`-ve`) and Subject Alternative Name extraction (`-san`). Enforces Deep SSRF Post-Execution Gate (M30) evaluating resolved `ip` fields in the output, strictly dropping any observation resolving to loopback (`127.0.0.0/8`), RFC-1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), or cloud metadata (`169.254.169.254`). Stream-parses output with fail-closed resilience against malformed/non-JSON lines. Produces factual observation DTOs with mandatory `TLS_INSPECTION_NON_CLAIMS` (`severity: 'info'`, zero speculative vulnerability claims or CVSS ratings). Consolidated smoke test (`milestone71_tlsx_adapter_smoke.ts`) verifying all 8 assertions with 100% pass rate.

---

- **M72 (Active Parameter Discovery Tool Adapter — Arjun)**: Implemented typed port `ParameterDiscoveryTool` and adapter `ArjunAdapter` under `worker/src/v2/recon/adapters/` using the Ports & Adapters pattern. Command invocation strictly executes via `ProcessRunner.execute()` with `shell: false` and isolated argument arrays (`['-u', targetUrl, '-m', method, ...optional -c, -d, '-oJ', tempFilePath]`). Enforces 6-pass atomic preflight check (URL format validation, target host SSRF pre-check, runtime-branded authorization check, continuous lineage verification, scope permission check, and scope boundary check) ensuring 0 child processes spawn on denial. Supports multiple HTTP methods (GET, POST, JSON, XML) and evasion controls (parameter chunking `-c` and inter-request delay `-d`), omitting flags when undefined in the DTO. Handles JSON output securely using OS temp files with guaranteed deletion in `finally` blocks and fallback to stdout. Enforces Deep SSRF Egress Gate (M30) evaluating discovered URLs, strictly dropping any observation resolving to loopback (`127.0.0.0/8`), RFC-1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), or cloud metadata (`169.254.169.254`). Stream-parses output with fail-closed resilience against malformed/non-JSON lines. Produces factual observation DTOs with mandatory `PARAMETER_DISCOVERY_NON_CLAIMS` (`severity: 'info'`, zero speculative vulnerability claims or risk ratings). Consolidated smoke test (`milestone72_arjun_adapter_smoke.ts`) verifying all 8 assertions with 100% pass rate.

---

## 3. Active & Planned Milestones

### Milestone F0: Foundations Correction (ACTIVE ARCHITECTURAL PIVOT)
- **Status:** ACTIVE / COMPLETED.
- **Goal:** Resolve critical structural and trust gaps before adding any new capabilities or adapters.
- **Key Deliverables:**
  1. **API Security Enforcement**: Server explicitly bound to `127.0.0.1` (rejecting `0.0.0.0`). Strict CORS origin whitelisting (`http://localhost:3000`, `http://127.0.0.1:3000`, `http://localhost:4000`, `http://127.0.0.1:4000`). Bearer authentication middleware (`v2AuthMiddleware`) protecting `/api/v2` and human review gates (`/recommendations/approve`, `/candidates/promote`) via `FIXGUARD_API_SECRET` (failing closed with 401/403).
  2. **Single Source of Truth**: Purged redundant and conflicting `docs/ARCHITECTURE.md`. Retired outdated Symbol-brand text in `ADR-001` in favor of canonical `WeakSet<object>` brand. Consolidated `docs/ROADMAP.md` as the unified source of truth, clarifying that M1–M72 are completed and the Intelligence Layer correlation engine is pending (M45–M54 is strictly evidence custody).
  3. **Scope Boundary ADR**: Established `docs/decisions/ADR-002-scope-boundaries.md` rejecting interactive proxy parity, native SAST from scratch, and mature tool reimplementations.
  4. **Automated CI Integration**: Created `.github/workflows/ci.yml` running `typecheck:v2` and `check:v2` on push and pull requests.
  5. **Verification**: 34 of 34 consolidated smoke test suites passing 100%.

---

### Milestone F1: Unified Execution Boundary & Adapter Preflight Pipeline
- **Status:** COMPLETED.
- **Goal:** Unify preflight validation boilerplate across all Layer 6 tool adapters, remediate dynamic DNS rebinding vulnerabilities before process spawning, and eliminate duplication across CLI wrappers.
- **Key Deliverables:**
  1. **Unified Preflight Pipeline**: Implemented `worker/src/v2/recon/adapters/AdapterPreflightPipeline.ts` containing the canonical 7-pass preflight validation logic:
     - Pass 1: Target format validation (`fqdn`, `ipv4_or_fqdn`, `url`, `host_or_url`, `git_url_or_filesystem`).
     - Pass 2: Path & Wordlist containment checks (`validateWordlistOrPath`) blocking `..` traversal and forbidden root directories (`/etc`, `/root`, `/var/run`, `/proc`, `/sys`, etc.).
     - Pass 3: Runtime-branded authorization verification (`WeakSet<object>`).
     - Pass 4: Continuous lineage tuple validation (`assessmentId`, `scanId`, `authorizationGrantId`, `authorizationDecisionId`).
     - Pass 5: Scope permissions verification (`permissionCheck` / `requiredPermissions`).
     - Pass 6: Target host SSRF pre-check and dynamic DNS rebinding mitigation (`validateDnsRebinding()`).
     - Pass 7: Scope boundary containment check.
  2. **DNS Rebinding Containment**: Embedded pre-spawn DNS resolution (`validateDnsRebinding()`). Resolves target hostnames immediately prior to child process execution, strictly failing closed with `reasonCode: 'ssrf_target_blocked'` and 0 child processes spawned if target resolves to loopback (`127.0.0.0/8`, `::1`), RFC-1918 private subnets, or cloud metadata (`169.254.169.254`).
  3. **Complete Adapter Delegation**: Refactored all 9 Layer 6 tool adapters (`SubfinderAdapter`, `NaabuPortDiscoveryAdapter`, `HttpxInspectionAdapter`, `CompositeUrlDiscoveryAdapter`, `TrufflehogAdapter`, `FfufAdapter`, `DnsxAdapter`, `TlsxAdapter`, `ArjunAdapter`) to delegate preflight to `runAdapterPreflight()`, preserving exact `reasonCode` values across all denial paths.
  4. **Typing Hygiene**: Maintained strictly 0 occurrences of `as any` across all refactored adapters and the pipeline component.
  5. **Verification**: `npm run smoke:v2:unified-preflight` verified with 8 assertions passing 100%. All 35 regression test suites in `npm run check:v2` pass 100%. Next.js production build (`npm run build`) compiles cleanly.

---

### Milestone F2: First Real End-to-End Vulnerability Detection Vertical (IDOR / BOLA Differential Engine)
- **Status:** COMPLETED.
- **Goal:** Implement the first actual vulnerability detection engine in FixGuard V2, validating the complete vertical pipeline from safe dual-identity HTTP probing to formal candidate promotion and canonical `Finding` generation.
- **Key Deliverables:**
  1. **Detection Contracts**: Implemented `worker/src/v2/detection/DetectionContracts.ts` defining `ProbeAuthContext`, `IdorDifferentialDetectionRequest`, isolated probe transport contracts (`IdorHttpProbeTransport`, `HttpProbeRequest`, `HttpProbeResponse`), and `IdorDifferentialDetectionResult`.
  2. **Differential Detection Engine**: Implemented `worker/src/v2/detection/IdorDifferentialDetectionService.ts`:
     - Guarantees execution safety via `runAdapterPreflight()` (7-pass validation, WeakSet brand verification, SSRF/DNS rebinding prevention).
     - Dispatches safe, read-only dual-identity HTTP probes (Identity A authorized owner vs Identity B unauthorized or anonymous).
     - Evaluates access control enforcement: returns `secure_target_abstained` with 0 findings if Identity B receives 401/403/404.
     - Compares sanitized snapshots (`SafeResponseSnapshot`) using `ResponseComparatorService.compareResponses` with mode `'authorization_difference'`.
     - Feeds detection observations through `runAuthorizedComparisonValidation` (M49), `evaluateHumanReviewedEvidencePromotion` (M50), `saveReviewedEvidence` (M51), `selectReviewedEvidence` (M52), `createReviewedEvidenceFindingCandidateDraft` (M53), and `promoteReviewedEvidenceFindingCandidateDraft` (M54).
     - Generates canonical `Finding` DTO with `type: 'BROKEN_ACCESS_CONTROL'`, `severity: 'high'`, structural evidence diffs, confidence 0.95, and lineage metadata.
  3. **Identifier Hygiene**: Strictly avoided blacklisted terms (`"idor"`, `"bola"`, `"vulnerable"`, `"bearer"`, `"secret"`) in generated IDs (`det_*`, `snap_*`, `val_*`, `promo_*`, `ind_*`, `save_*`, `sel_*`, `draft_*`, `cand_*`, `find_*`) to ensure clean compatibility with upstream validators.
  4. **Typing Hygiene**: Maintained strictly 0 occurrences of `as any` across all detection contracts and services.
  5. **Verification**: `npm run smoke:v2:idor-detection` verified with all 4 assertions passing 100%. Full regression test suite (`npm run check:v2` across all 36 smoke suites) and Next.js web build (`npm run build`) pass 100%.

---

### Milestone F3: Cross-Cutting Scale Infrastructure (Session Lifecycle, Concurrency Coordinator & Evidence Retention)
- **Status:** COMPLETED.
- **Goal:** Implement the essential scale and stability infrastructure required before expanding reconnaissance or detection breadth: session health/token renewal, per-host concurrency & rate-limiting, and evidence retention boundaries.
- **Key Deliverables:**
  1. **Session Lifecycle in `TargetContext` & `ProbeAuthContext` (Acción 10)**:
     - Defined `TargetSessionState` (`active`, `expired`, `refreshing`, `invalid`), `TokenRefreshHook`, and `TokenRefreshResult` in `worker/src/v2/core/SessionLifecycleContracts.ts`.
     - Extended `TargetContext` and `ProbeAuthContext` with optional `sessionState` preserving 100% backward compatibility.
     - Implemented `validateSessionHealth()` in `worker/src/v2/core/SessionLifecycleService.ts`. Validates session state prior to execution; attempts `tokenRefreshHook()` on expiration; fails closed safely with `session_expired` and 0 probes dispatched if expired without successful refresh.
  2. **Shared Target Concurrency & Rate-Limit Coordinator (Acción 11)**:
     - Implemented `TargetExecutionCoordinator` in `worker/src/v2/runtime/TargetExecutionCoordinator.ts`.
     - Enforces global per-host rate limiting (tokens/second pacing) and concurrency ceiling (max active concurrent tasks) to prevent target-side WAF adaptation and self-inflicted response diff contamination.
  3. **Evidence Retention & Pruning Strategy (Acción 12)**:
     - Implemented `EvidenceRetentionService` in `worker/src/v2/evidence/EvidenceRetentionService.ts`.
     - Defines clear retention boundaries: retains full raw response bodies, headers, and diffs strictly for promoted `FindingCandidate` and verified `Finding` records.
     - Prunes transient comparison evidence on abstentions (`secure_target_abstained`), purging raw body payloads while strictly preserving cryptographic hashes (`bodyHash`), status codes, response times, and normalized shape signatures.
  4. **Detection Engine Integration**:
     - Wired pre-probe session health validation into `IdorDifferentialDetectionService.ts` before probe dispatch.
     - Wired `pruneTransientEvidence()` into `secure_target_abstained` flows.
  5. **Typing Hygiene**: Maintained strictly 0 occurrences of `as any` across all new and modified files.
  6. **Verification**: `npm run smoke:v2:scale-infrastructure` verified with all 4 assertions passing 100%. Full regression suite (`npm run check:v2` across all 37 smoke suites) and Next.js web build (`npm run build`) pass 100%.

---

### Milestone F4: Detection Coverage Expansion (CORS Exploitation & Parameter Reflection Engine)
- **Status:** COMPLETED.
- **Goal:** Expand real, high-precision vulnerability detection capabilities in FixGuard V2 using the established F2 promotion vertical and F3 scale infrastructure.
- **Key Deliverables:**
  1. **CORS Misconfiguration Detection Engine**:
     - Implemented `worker/src/v2/detection/CorsMisconfigurationDetectionService.ts`.
     - Evaluates target endpoints against arbitrary untrusted origins (`https://untrusted-cross-origin.example.com`) and null origins (`null`).
     - Detects exploitable CORS configurations where `Access-Control-Allow-Origin` reflects the untrusted origin AND `Access-Control-Allow-Credentials: true`.
     - Promotes confirmed discoveries through the canonical M49–M54 evidence pipeline, generating high-confidence `Finding` DTOs (`type: 'SECURITY_MISCONFIGURATION'`, `severity: 'high'`).
     - Cleanly abstains on secure configurations (`secure_target_abstained`), returning 0 findings and pruning transient comparison bodies via `pruneTransientEvidence()`.
  2. **Parameter Reflection / Context Breakout Engine**:
     - Implemented `worker/src/v2/detection/ParameterReflectionDetectionService.ts`.
     - Injects unique, non-destructive canary strings into target parameters and detects unencoded reflection in HTTP response bodies.
     - Compares baseline and canary responses via `ResponseComparatorService` (mode: `'http_difference'`).
     - Promotes confirmed reflection discoveries through the M49–M54 pipeline, generating canonical `Finding` DTOs (`type: 'INPUT_VALIDATION_FLAW'`, `severity: 'medium'`).
     - Cleanly abstains on non-reflecting / sanitized endpoints (`secure_target_abstained`), returning 0 findings and pruning transient bodies.
  3. **Shared Scale Infrastructure Integration**:
     - Pre-probe session health validation via `validateSessionHealth()`.
     - Coordinated execution pacing and concurrency ceiling via `TargetExecutionCoordinator`.
     - 7-pass atomic preflight protection (SSRF/DNS rebinding prevention) via `runAdapterPreflight()`.
     - Transient evidence pruning on abstention via `EvidenceRetentionService`.
  4. **Typing & Identifier Hygiene**:
     - Maintained strictly 0 occurrences of `as any` across all new contracts and services.
     - Guaranteed unbroken lineage tuple `{ assessmentId, scanId, authorizationGrantId, authorizationDecisionId, actorId }`.
     - Token-safe identifier generation avoiding blacklisted keywords.
  5. **Verification**: `npm run smoke:v2:detection-expansion` verified with all 4 assertions passing 100%. All 38 regression test suites in `npm run check:v2` and Next.js web build (`npm run build`) pass 100%.

---

### Milestone F5: Real Intelligence Layer (TargetProfileBuilder, CorrelationEngine & RecommendationEngine)
- **Status:** COMPLETED.
- **Goal:** Establish the true Intelligence Layer in FixGuard V2 (Plan Maestro Milestone 6), superseding evidence custody with factual aggregation and multi-vulnerability correlation reasoning over immutable target profiles.
- **Key Deliverables:**
  1. **Intelligence Contracts (`worker/src/v2/intelligence/IntelligenceContracts.ts`)**:
     - Contract version: `'fixguard-intelligence/v0'`.
     - Defined `TargetProfile`, `TargetProfileEndpoint`, `TargetRecommendation`, `TargetProfileBuilderInput`, and `RecommendationEngineResult`.
     - Specified categorized recommendation types: `'cross_origin_exploit_chain'`, `'access_control_verification'`, `'parameter_fuzzing'`, `'technology_hardening'`.
  2. **TargetProfileBuilder (`worker/src/v2/intelligence/TargetProfileBuilder.ts`)**:
     - Pure functional service aggregating canonical findings (F2 IDOR, F4 CORS, F4 Reflection) and infrastructure observations.
     - Deduplicates and normalizes technologies and web server banners.
     - Maps endpoint routes, parameters, auth boundary requirements, CORS configurations, and observed flaw categories.
     - Preserves backwards compatibility for legacy `LocalTargetProfileBuilder` used by Milestone 6.5 and `V2AssessmentRuntime`.
  3. **TargetRecommendationEngine (`worker/src/v2/intelligence/TargetRecommendationEngine.ts`)**:
     - Evaluates immutable `TargetProfile` across correlation rules:
       - **Cross-Origin Exploit Chain**: Correlates parameter reflection with credentialed CORS misconfiguration into high-confidence advisory recommendations (`category: 'cross_origin_exploit_chain'`, `suggestedCapability: 'cross_origin_escalation'`, `requiredPermissions: ['activeValidation', 'authenticatedTesting']`).
       - **Access Control Verification**: Correlates broken access control findings into systematic authorization boundary validation recommendations (`category: 'access_control_verification'`, `suggestedCapability: 'active_validation'`, `requiredPermissions: ['activeValidation']`).
       - **Unauthenticated Parameterized Surface Fuzzing**: Correlates unauthenticated parameterized endpoints without verified flaws into exploratory fuzzing recommendations (`category: 'parameter_fuzzing'`, `suggestedCapability: 'endpoint_discovery'`).
     - **Approval Boundary Invariant**: Emitted recommendations are non-executable advisory DTOs with mandatory human authorization before capability execution.
     - **Abstention Discipline**: Quiet, sparse, or benign target profiles cleanly return 0 recommendations (`recommendations: []`).
  4. **Lineage Preservation & Typing Hygiene**:
     - Continuous lineage tuple `{ assessmentId, scanId, authorizationGrantId, authorizationDecisionId, actorId }` strictly preserved end-to-end.
     - Maintained strictly 0 occurrences of `as any` across all production code.
     - Safe identifier generation avoiding blacklisted keywords (`"idor"`, `"vulnerable"`, `"attack"`).
  5. **Verification**: `npm run smoke:v2:intelligence` verified with all 4 assertions passing 100%. Full regression suite (`npm run check:v2` across all 39 smoke suites) and Next.js web build (`npm run build`) pass 100%.

---

### Milestone 73: Composite Active Reconnaissance Orchestrator Application Service
- **Status:** COMPLETED.
- **Goal:** Unify all 9 Layer 6 active reconnaissance tool adapters (`Subfinder`, `Dnsx`, `Naabu`, `Httpx`, `Tlsx`, `CompositeUrlDiscovery`, `Ffuf`, `Arjun`, `Trufflehog`) into a staged, coherent discovery pipeline enforcing preflight gates, rate-limiting coordination, session lifecycle, and unbroken execution lineage.
- **Key Deliverables:**
  1. **Orchestration Contracts (`worker/src/v2/recon/orchestration/ActiveReconOrchestrationContracts.ts`)**:
     - Contract version: `'fixguard-active-recon-orchestration/v0'`.
     - Defined 5 staged discovery phases (`stage_1_domain_zone`, `stage_2_port_service`, `stage_3_web_tls`, `stage_4_crawling_parameters`, `stage_5_secret_inspection`).
     - Defined explicit non-claims (`RECON_ORCHESTRATION_NON_CLAIMS`: `severity: 'info'`, `createsRealFindings: false`, `confirmsVulnerabilities: false`).
     - Structured `ReconToolAdapters` port bundle for all 9 adapters.
     - Canonical `OrchestratedReconEvidenceDraft` carrying stage provenance and continuous lineage tuple.
  2. **Composite Orchestrator Service (`worker/src/v2/recon/orchestration/CompositeActiveReconOrchestratorService.ts`)**:
     - **Stage 1 (Domain & Zone)**: Dispatches `Subfinder` + `Dnsx` for subdomain enumeration and multi-record DNS resolution.
     - **Stage 2 (Port & Service Discovery)**: Dispatches `Naabu` across discovered hosts/IPs.
     - **Stage 3 (HTTP & TLS Inspection)**: Dispatches `Httpx` on web ports + `Tlsx` on HTTPS targets.
     - **Stage 4 (Surface Crawling & Parameter Discovery)**: Dispatches `CompositeUrlDiscovery` (`Katana`/`Gau`) + `Ffuf` content discovery + `Arjun` parameter discovery.
     - **Stage 5 (Secret & Credential Inspection)**: Dispatches `Trufflehog` on discovered endpoints/scripts.
     - **Safety & Scaling Gateways**:
       - Atomic root preflight (`runAdapterPreflight`) enforcing target FQDN format, runtime-branded authorization check, scope boundary check, and SSRF/DNS rebinding defense.
       - `TargetExecutionCoordinator` per-host rate limiting and concurrency ceiling routing every child tool call.
       - `SessionLifecycleService` validation for authenticated crawling.
       - **Graceful Stage Containment**: Errors in leaf stages/tools are tracked as warnings, never aborting earlier verified discoveries.
  3. **Verification**:
     - `npm run smoke:v2:composite-active-recon` passing 4/4 assertions (100%).
     - Zero `as any` across all production code.
     - Full regression suite (`npm run check:v2` across all 40 smoke suites) and Next.js web build (`npm run build`) pass 100%.

---

### Milestone F6: V2 API Orchestrator Controller & Assessment Execution Gateway
- **Status:** COMPLETED.
- **Goal:** Bridge the core orchestration engine (M73 Composite Active Recon, F4 Detection Engines, F5 Intelligence Layer) into the authenticated HTTP API Gateway, providing REST endpoints to initiate, track, and summarize end-to-end assessments with continuous execution lineage and runtime-branded authorization.
- **Key Deliverables:**
  1. **Orchestrated Assessment Contracts & In-Memory Store (`worker/src/v2/application/OrchestratedAssessmentContracts.ts`, `worker/src/v2/storage/InMemoryOrchestratedAssessmentRepository.ts`)**:
     - Defined `OrchestratedAssessmentRecord`, `StartOrchestratedAssessmentCommand`, `OrchestratedAssessmentStatusDto`, and `OrchestratedAssessmentSummaryDto`.
     - In-memory store with deep clone protection preventing in-place mutations.
  2. **Application Service (`worker/src/v2/application/OrchestratedAssessmentApplicationService.ts`)**:
     - Enforces fail-closed SSRF egress preflight validating target domain against private/loopback IP spaces with 0 network calls dispatched.
     - Seals runtime ADR-001 `WeakSet` brand on authorization decisions.
     - Guarantees unbroken lineage `{ assessmentId, scanId, authorizationGrantId, authorizationDecisionId, actorId }`.
     - Coordinates asynchronous execution across M73 (5-stage recon), F4 (CORS & parameter reflection detection), and F5 (TargetProfileBuilder & RecommendationEngine).
  3. **Controller & Routing Gateway (`worker/src/v2/api/controllers/OrchestratedAssessmentController.ts`, `worker/src/v2/api/routes/v2Routes.ts`)**:
     - Mounted under `/api/v2/orchestrated/`:
       - `POST /assessments/start` -> returns HTTP 202 Accepted with assessment ID, scan ID, and continuous lineage.
       - `GET /assessments/:assessmentId/summary` -> returns synthesized TargetProfile, confirmed findings, and advisory recommendations.
       - `GET /assessments/:assessmentId/status` -> returns execution stage progress, timing metrics, and error/warning counts.
     - Protected by `v2AuthMiddleware` (`Authorization: Bearer <token>`).
  4. **Typed Web Frontend Client (`web/src/lib/v2Api.ts`)**:
     - Strict typed client helper for Next.js with zero `as any` occurrences.
  5. **Verification**:
     - `npm run smoke:v2:orchestrated-api` passing all 5 assertions (100%).
     - Zero `as any` in production code.
     - Full regression suite (`npm run check:v2` across all 41 smoke suites) and Next.js web build (`npm run build`) pass 100%.

---

### Milestone F7: V2 Orchestrated Assessment UI Integration
- **Status:** COMPLETED.
- **Goal:** Connect the Next.js 16 frontend application to the authenticated V2 orchestration endpoints (`/api/v2/orchestrated/`), delivering a functional real-time assessment dashboard enabling operators to launch target assessments, monitor stage progression, inspect synthesized findings, and review advisory recommendations.
- **Key Deliverables:**
  1. **Assessment Launcher Component (`web/src/app/v2/assessments/components/AssessmentLauncherCard.tsx`)**:
     - Client-side target format validation (domain syntax, scheme stripping).
     - Fail-closed SSRF preflight protection blocking loopback (`127.0.0.0/8`, `localhost`) and private RFC1918 subnets.
     - Preset authorized targets (`charmarket.vercel.app`, `example.com`).
     - Dispatches `startOrchestratedAssessment` with operator identity.
  2. **Real-Time Pipeline Tracker (`web/src/app/v2/assessments/components/PipelineStageTracker.tsx`)**:
     - Visual stepper monitoring all 5 M73 stages (`stage_1_domain_zone`, `stage_2_port_service`, `stage_3_web_tls`, `stage_4_crawling_parameters`, `stage_5_secret_inspection`).
     - Real-time observation counts, duration tracking, and error/warning counters.
     - Resilient interval polling with automatic cleanup upon completion, failure, or unmount.
     - Displays verified ADR-001 continuous lineage tuple (`assessmentId`, `scanId`, `grantId`, `decisionId`, `actorId`).
  3. **Executive Results Panel (`web/src/app/v2/assessments/components/ExecutiveResultsPanel.tsx`)**:
     - Renders synthesized `TargetProfile` (technologies, edge infrastructure, indexed endpoints table with methods, parameters, and auth requirements).
     - Confirmed findings panel (CORS misconfigurations, parameter reflections, IDOR) with hash verification.
     - Advisory recommendations panel with category, reasoning, suggested capability, required permissions, and confidence scores under defensive HITL governance.
  4. **Abstention & Error State Presentation (`web/src/app/v2/assessments/components/AbstentionAlert.tsx`)**:
     - Clean, non-alarmist presentation for `secure_target_abstained` (CORS policy enforced, parameters sanitized).
     - Fail-closed preflight denial alerts for SSRF attempts confirming 0 network probes dispatched.
  5. **Typing Hygiene & Routing Integration**:
     - Dedicated page at `/v2/assessments` (`web/src/app/v2/assessments/page.tsx`) with seamless navigation to/from `/v2`.
     - Zero occurrences of `as any` across the entire web application.
  6. **Verification**:
     - Next.js production build (`npm run build` in `web/`) compiles cleanly (14/14 static pages generated).
     - Zero `as any` across `web/src` and `worker/src/v2`.
     - Full regression suite (`npm run check:v2` across all 41 smoke suites) passes 100%.

---

### Milestone F8: Blast Radius Hardening & Target Circuit Breaker (Plan Maestro Acción 13)
- **Status:** COMPLETED.
- **Goal:** Harden the active assessment engine against causing target denial-of-service, severe latency degradation, or server distress by integrating an adaptive per-target Circuit Breaker state machine and blast radius containment across all execution layers.
- **Key Deliverables:**
  1. **Runtime State Machine & Contracts (`worker/src/v2/runtime/CircuitBreakerContracts.ts`)**:
     - States: `CLOSED` (healthy target interaction), `OPEN` (tripped due to consecutive server errors or timeouts), `HALF_OPEN` (controlled recovery probe validation).
     - Standard reasonCode: `target_instability_circuit_open`.
     - Configuration: configurable `consecutive5xxThreshold` (default 3), `consecutiveErrorThreshold` (default 3), `halfOpenSuccessThreshold` (default 2), and `openCooldownMs` (default 30,000ms).
     - Telemetry: tracks consecutive failures, successes, 5xx errors, timeouts, tripped counts, and state change timestamps.
     - `TargetInstabilityError`: structured error thrown immediately on execution attempts against an unstable target.
  2. **Integration with `TargetExecutionCoordinator` (`worker/src/v2/runtime/TargetExecutionCoordinator.ts`)**:
     - Per-host circuit breaker instances tracked and managed alongside rate limiter tokens and concurrency ceilings.
     - `recordTargetResponse()`: inspects status codes, treating 2xx, 3xx, 4xx (e.g. 404/403) as target responsiveness, while 5xx (500, 502, 503, 504) or network errors advance failure streak.
     - When transitioning to `OPEN`, pending queued tasks are drained and rejected immediately with `TargetInstabilityError` and reasonCode `'target_instability_circuit_open'`.
     - `isCircuitOpen(host)` and `getCircuitState(host)` provide non-invasive state checks before dispatching work.
  3. **Composite Reconnaissance Graceful Containment (`worker/src/v2/recon/orchestration/CompositeActiveReconOrchestratorService.ts`)**:
     - Pre-stage safety checks verify circuit state before entering each of the 5 discovery stages.
     - In-stage error containment traps `TargetInstabilityError` and halts subsequent discovery stages immediately.
     - Returns `status: 'circuit_broken'` preserving all verified discoveries, drafts, lineage tuples, and factual non-claims gathered up to the point of target distress.
  4. **Application Gateway Custody (`worker/src/v2/application/OrchestratedAssessmentApplicationService.ts`)**:
     - Transitions assessment record to `status: 'circuit_broken'` upon target distress without failing or corrupting prior observations.
     - Synthesizes partial `TargetProfile` and recommendations from verified observations gathered before tripping.
     - Halts active vulnerability probing (CORS / Parameter reflection) safely when target is in distress.
  5. **Frontend Integration & Clear Indicators (`web/src/lib/v2Api.ts`, `PipelineStageTracker.tsx`, `AbstentionAlert.tsx`, `page.tsx`)**:
     - Added `'circuit_broken'` to status types.
     - `AbstentionAlert.tsx`: renders clear, non-alarmist adaptive protection banner informing operators that execution paused safely to protect target availability.
     - `PipelineStageTracker.tsx`: visually marks status as paused/circuit broken and preserves completed stage progress.
     - `page.tsx`: stops polling and automatically retrieves partial summary and synthesized profile.
  6. **Verification**:
     - `npm run smoke:v2:circuit-breaker` passing all 4 assertions (100%).
     - Zero `as any` in `worker/src/v2` and `web/src`.
     - Next.js production build (`npm run build`) compiles cleanly.
     - Full regression suite (`npm run check:v2` across all 42 smoke suites) passes 100%.

---

### Milestone 7: Browser Automation Engine for SPA & DOM Discovery (Plan Maestro Orden Exacto)
- **Status:** COMPLETED.
- **Goal:** Implement a headless browser automation engine (Playwright) to handle JS hydration, DOM-based parameter extraction, form analysis, and dynamic route discovery in modern Single Page Applications (SPAs) with its own non-determinism model and explicit non-claims.
- **Key Deliverables:**
  1. **Contracts & Adapter Boundary (`worker/src/v2/recon/adapters/BrowserAutomationContracts.ts`, `worker/src/v2/recon/adapters/PlaywrightSpaAdapter.ts`)**:
     - Contract version: `'fixguard-browser-automation/v0'`.
     - Explicit non-claims: `BROWSER_AUTOMATION_NON_CLAIMS` enforcing `severity: 'info'`, `createsRealFindings: false`, `confirmsVulnerabilities: false`, `executesNetworkPayloads: false`.
     - Structured observations: `DiscoveredSpaObservation`, `DiscoveredSpaRouteObservation` (`dom_link`, `form_action`), and `DiscoveredDomInputObservation`.
     - Port abstraction interfaces: `PlaywrightBrowserLauncher`, `BrowserInstance`, `BrowserContextInstance`, `PageInstance`, `RouteInstance`, `ResponseInstance`.
     - Zero type bypasses (`as any`, `forceCast`, `unknown as T` strictly prohibited).
  2. **Double SSRF Gate**:
     - **Gate 1 (Preflight)**: Executes `runAdapterPreflight()` before browser context creation, verifying target FQDN/URL, WeakSet authorization decision brand, scope permissions (`endpointDiscovery`, `activeCrawling`, `technologyFingerprinting`), and DNS rebinding with 0 browser launches on denial.
     - **Gate 2 (In-Browser Subresource Interception)**: Registers `page.route('**/*')` intercepting every subresource fetch in real time, aborting requests to loopback (`127.0.0.0/8`, `localhost`), RFC1918 private subnets, and cloud metadata (`169.254.169.254`) with `'blockedbyclient'`.
  3. **Lifecycle, Circuit Breaker & Blast Radius Protections (Milestone F8 Integration)**:
     - Feeds page HTTP response status codes into `coordinator.recordTargetResponse()`.
     - Halts execution and transitions to `status: 'circuit_broken'` immediately if the circuit trips to `OPEN`.
     - Guaranteed teardown: closes page, browser context, and browser instance inside a `finally` block to prevent zombie processes.
  4. **Orchestrator & Application Service Integration**:
     - Integrated into Stage 4 (`stage_4_crawling_parameters`) of `CompositeActiveReconOrchestratorService.ts`, synthesizing `discovered_spa_observations` evidence drafts and aggregating dynamic routes into URL and parameter pools.
     - Attached `PlaywrightSpaAdapter` to default recon adapters in `OrchestratedAssessmentApplicationService.ts`.
  5. **Verification**:
     - `npm run smoke:v2:browser-automation` passing all 4 assertions (100%).
     - Zero `as any` across `worker/src/v2` and `web/src`.
     - Full regression suite (`npm run check:v2` across all 43 smoke suites) passes 100%.
     - Next.js production build (`npm run build`) compiles cleanly.

---

### Milestone 8: Controlled Active Verification & Safe PoC Engine (Plan Maestro Orden Exacto)
- **Status:** COMPLETED.
- **Goal:** Implement a controlled active verification and safe Proof of Concept (PoC) engine to definitively certify exploitability of detected candidates without causing harm, data alteration, or service disruption.
- **Key Deliverables:**
  1. **Active Verification Contracts (`worker/src/v2/verification/ActiveVerificationContracts.ts`)**:
     - Contract version: `'fixguard-active-verification/v0'`.
     - Explicit non-claims: `ACTIVE_VERIFICATION_NON_CLAIMS` enforcing `executesDestructivePayloads: false`, `modifiesTargetState: false`, `exploitsServiceDenial: false`, `causesDataLoss: false`, and `requiresHumanAuthorization: true`.
     - Safe exploitation vectors: `SafeExploitationVectorKind` (`'idor_read_differential'`, `'cors_arbitrary_origin_reflection'`, `'parameter_reflection_canary'`, `'security_header_enforcement'`).
     - Runtime-branded decision: `VerifiedExploitationAuthorizationDecision` sealed via module-private `WeakSet<object>` brand (ADR-001).
     - Execution contracts: `ActiveVerificationCommand`, `ActiveVerificationProofRecord` (SHA-256 request/response hashes, sanitized diff excerpts, canary reflection boolean), and `ActiveVerificationResult`.
     - Transport contracts: `VerificationHttpRequest`, `VerificationHttpResponse`, and `VerificationHttpTransport`.
  2. **Controlled Verification Service (`worker/src/v2/verification/ControlledActiveVerificationService.ts`)**:
     - **Human Authorization Gate**: Requires explicit, unexpired `VerifiedExploitationAuthorizationDecision` verified against runtime `WeakSet` brand; blocks forged or vector-mismatched decisions with 0 network calls.
     - **Non-Destructive Invariant**: Strictly limits payloads to inert alphanumeric tokens (`fgcanary<safeId>`) and read-only differential probing.
     - **Double SSRF & Egress Gate**: Validates target host against loopback (`127.0.0.0/8`), private subnets (RFC1918), and cloud metadata (`169.254.169.254`), augmented with pre-probe dynamic DNS rebinding resolution.
     - **Blast Radius & Circuit Breaker Containment**: Respects `TargetExecutionCoordinator` concurrency ceilings, records response status codes, and halts immediately with `status: 'circuit_broken'` if the target enters `OPEN` state.
     - **Deterministic Cryptographic Proof**: Calculates SHA-256 hashes of outgoing request and incoming response body, producing verifiable `ActiveVerificationProofRecord` and confirmed finding candidate records (`exploitConfidence: 1.0`).
  3. **Verification**:
     - `npm run smoke:v2:active-verification` passing all 4 assertions (100%).
     - Zero `as any` across `worker/src/v2` and `web/src`.
     - Full regression suite (`npm run check:v2` across all 44 smoke suites) passes 100%.
     - Next.js production build (`npm run build`) compiles cleanly.

---

### Phase 0: Foundations Correction & Binary Availability (Canonical Roadmap)

#### Milestone P0-1: Real Human Review Gate (Eradication of Synthetic Reviewers)
- **Status:** COMPLETED.
- **Goal:** Strictly enforce the core platform axiom ("Humans authorize") by eradicating synthetic auto-reviewers (`reviewer_lead_sec`) across all detection engines.
- **Key Deliverables:**
  1. Eradicated all default injection of fake reviewer IDs and auto-approval branches in production detection services (`IdorDifferentialDetectionService.ts`, `CorsMisconfigurationDetectionService.ts`, `ParameterReflectionDetectionService.ts`, `OrchestratedAssessmentApplicationService.ts`).
  2. Unattended detection runs without an explicit `humanReviewDecision` return `status: 'pending_human_review'` and an unsigned `EvidenceDraftEnvelope`.
  3. Automated assessment records collect unreviewed drafts into `pendingEvidenceDrafts` and emit strictly ZERO findings (`findings: []`).

#### Milestone P0-2: Discriminated Finding Metadata Union
- **Status:** COMPLETED.
- **Goal:** Replace dangerous untyped `metadata: Record<string, unknown>` on `Finding` with an exact, strongly-typed discriminated union.
- **Key Deliverables:**
  1. Defined `FindingMetadata` in `worker/src/v2/core/Evidence.ts` with discriminated variants: `BrokenAccessControlMetadata`, `SecurityMisconfigurationMetadata`, `InputValidationFlawMetadata`, and `DiscoveryFindingMetadata`.
  2. Updated all downstream parsers, profiler rules, `TargetProfileBuilder`, and `TargetRecommendationEngine` with compile-time exhaustion checks.

#### Milestone P0-3: Binary Availability Verification & Honest Composition
- **Status:** COMPLETED.
- **Goal:** Eliminate the "empty scan" illusion by verifying that required underlying recon CLI binaries (`subfinder`, `naabu`, `httpx`, `dnsx`, `tlsx`, `ffuf`, `gau`, `arjun`, `trufflehog`) are installed and executable on the host PATH before launching dependent stages.
- **Key Deliverables:**
  1. **Capability Status Contracts (`worker/src/v2/capabilities/CapabilityStatusContracts.ts`)**:
     - Contract version: `'fixguard-capability-status/v0'`.
     - Strict allowlist `RECON_TOOL_ALLOWLIST` and stage-to-tool mapping `STAGE_REQUIRED_TOOLS`.
     - Typed models: `SingleToolStatus`, `ToolCapabilityMatrix`, and `CapabilityStatusResponse`.
  2. **Recon Tool Availability Service (`worker/src/v2/capabilities/ReconToolAvailabilityService.ts`)**:
     - Safe non-shell execution (`which <tool>` and `<binary> --version`) via `ProcessRunner` (`shell: false`).
     - Strict allowlist rejection of arbitrary command inputs with `ApiValidationError`.
  3. **API Gateway Route (`worker/src/v2/api/controllers/CapabilityStatusController.ts`)**:
     - `GET /api/v2/capabilities/status` exposing host binary capability matrix behind `createV2AuthMiddleware`.
  4. **Honest Composition Pre-Scan Gate (`worker/src/v2/application/OrchestratedAssessmentApplicationService.ts`)**:
     - Verifies required binaries before dispatching recon stages; immediately aborts with HTTP 400 and `reasonCode: 'unavailable_tools'` if any required binary is absent, executing strictly 0 network probes.
  5. **Verification**:
     - `npm run smoke:v2:capabilities-status` passing all 4 assertions (100%).
     - Zero `as any` across `worker/src/v2` and `web/src`.
     - Full regression suite (`npm run check:v2` across all 45 smoke suites) passes 100%.

---

### Phase 1: Production Pipeline & Human Triage (Canonical Roadmap)

#### Milestone P1-1: Async Assessment HTTP API Lifecycle
- **Status:** COMPLETED.
- **Goal:** Decouple multi-stage assessment execution from the HTTP request/response thread, acknowledging launches immediately with `HTTP 202 Accepted` (< 100ms) and exposing non-blocking polling endpoints for real-time stage progress and synthesized results.
- **Key Deliverables:**
  1. **Immediate HTTP 202 Acknowledgment (`worker/src/v2/api/controllers/OrchestratedAssessmentController.ts`)**:
     - `POST /api/v2/orchestrated/assessments/start` returns `202 Accepted` in < 100ms (measured at 22-29ms) with `{ assessmentId, scanId, status: 'running', lineage }`.
     - In-process asynchronous dispatch preserving ADR-001 `WeakSet` authorization brand without external queuing overhead.
  2. **Real-Time Stage Callbacks (`worker/src/v2/recon/orchestration/CompositeActiveReconOrchestratorService.ts`)**:
     - Injected `onStageComplete` callback into the composite active recon orchestrator, incrementally updating stage status, durations, and observation counts as stages complete.
  3. **Non-Blocking Polling Endpoints**:
     - `GET /api/v2/orchestrated/assessments/:assessmentId/status` returns structured lifecycle metrics during execution.
     - `GET /api/v2/orchestrated/assessments/:assessmentId/summary` returns synthesized `TargetProfile`, `pendingEvidenceDrafts` (custody for human review), and advisory recommendations upon completion.
  4. **Web Frontend Client & Polling Integration (`web/src/lib/v2Api.ts`, `web/src/app/v2/assessments/page.tsx`)**:
     - Typed client supporting draft counts and non-blocking 2s polling loops.
  5. **Verification**:
     - `npm run smoke:v2:async-api` passing all 4 assertions (100%).
     - Zero `as any` across `worker/src/v2` and `web/src`.
     - Full regression suite (`npm run check:v2` across all 46 smoke suites) passes 100%.
     - Next.js production build (`npm run build`) compiles cleanly.

#### Milestone P1-2: First Real Integration Test Suite (Level 2 Validation)
- **Status:** COMPLETED.
- **Goal:** Validate the real execution path of FixGuard V2 by executing real reconnaissance binaries (`dnsx`, `httpx`) against authorized low-risk public targets (`example.com`, `scanme.nmap.org`) without mocks, while asserting SSRF containment in real execution contexts.
- **Key Deliverables:**
  1. **Integration Test Suite Directory & Runner (`worker/src/v2/integration/run_integration_suite.ts`)**:
     - Dedicated integration runner executing when `RUN_INTEGRATION=true`.
     - Skips cleanly when the environment flag or tool binaries are absent without breaking standard CI or `npm run check:v2`.
     - Wired npm script: `"test:v2:integration": "tsx src/v2/integration/run_integration_suite.ts"`.
  2. **Real SSRF Containment Smoke (`worker/src/v2/integration/real_ssrf_containment_smoke.ts`)**:
     - Asserts `isInternalOrSsrfTarget()` and `AdapterPreflightPipeline` strictly block loopback (`127.0.0.1`), cloud metadata (`169.254.169.254`), and private RFC1918 subnets in real process execution contexts with 0 child processes spawned.
  3. **Real DNS Smoke (`worker/src/v2/integration/real_target_dns_smoke.ts`)**:
     - Executes real `dnsx` against `example.com` via `LocalProcessRunner` (`shell: false`).
     - Parses live A records into typed `DiscoveredDnsRecordObservation` DTOs, falling back cleanly to Node.js native DNS resolution when `dnsx` is absent.
  4. **Real HTTPX Smoke (`worker/src/v2/integration/real_target_httpx_smoke.ts`)**:
     - Executes real `httpx` against public authorized host `http://scanme.nmap.org`.
     - Parses live HTTP response (`status: 200`, title, web server banner) with factual non-claim classifications (`WEB_INSPECTION_NON_CLAIMS`).
  5. **Typing & Policy Hygiene**:
     - Maintained strictly 0 occurrences of `as any` across all integration test files.
     - Enforced strictly read-only reconnaissance (zero detection probes, zero fuzzing, zero exploitation).
  6. **Verification**:
     - `RUN_INTEGRATION=true npm run test:v2:integration` passes 100%.
     - `npm run test:v2:integration` cleanly skips without error when flag is unset.
     - `npm run typecheck:v2` exits 0.
     - All 46 smoke test suites in `npm run check:v2` pass 100%.
     - Next.js production build (`npm run build`) compiles cleanly.

---

#### Milestone P1-3: Human Review UI Flow & Real HITL Triage
- **Status:** COMPLETED.
- **Goal:** Close the loop on the Human-in-the-Loop invariant by delivering API triage endpoints and a Next.js UI allowing operators to inspect differential HTTP evidence, enforce Server-Side Anti-Bypass gates, and formally approve/promote evidence drafts into strongly-typed `Finding` records.
- **Key Deliverables:**
  1. **API Gateway Review & Differential Endpoints (`worker/src/v2/api/controllers/OrchestratedAssessmentController.ts`)**:
     - `GET /api/v2/orchestrated/assessments/:assessmentId/evidence-drafts`: returns pending evidence drafts with complete differential context (baseline vs probe status codes, body hashes, reflected origins, canary parameters).
     - `POST /api/v2/orchestrated/assessments/:assessmentId/evidence/:draftId/review`: accepts `{ decision, reviewerId, reviewedAt, notes }`.
  2. **Server-Side Anti-Bypass Gate (`worker/src/v2/api/validation/ApiRequestValidators.ts`)**:
     - `parseReviewEvidenceDraftBody()` and `isForbiddenSyntheticReviewerId()` strictly reject mock/synthetic identities (e.g. `'reviewer_lead_sec'`, `'synthetic_*'`, `'mock_*'`, `'auto_*'`, `'bot_*'`) with HTTP 400 Bad Request.
  3. **Domain Finding Promotion & Clean Rejection (`worker/src/v2/application/OrchestratedAssessmentApplicationService.ts`)**:
     - On `'approve_evidence'`: converts the draft into a formal `Finding` using the strongly-typed `FindingMetadata` union (`SecurityMisconfigurationMetadata`, `InputValidationFlawMetadata`, `BrokenAccessControlMetadata`), adds it to `record.findings`, and dequeues the draft from `pendingEvidenceDrafts`.
     - On `'reject_evidence'`: cleans the draft from the queue with strictly ZERO findings created and ZERO evidence persisted.
  4. **Next.js HITL Triage & Review UI (`web/src/app/v2/review/page.tsx`)**:
     - Interactive differential viewer with side-by-side control baseline and probe response metrics.
     - Specific observation callouts (reflected origins with credentials, reflected parameter canaries).
     - Action buttons: "Aprobar y Promover a Hallazgo" and "Rechazar Evidencia".
     - Real-time feedback and navigation link integration from `/v2/assessments` executive panel.
  5. **Verification**:
     - Dedicated smoke test `worker/src/v2/smoke/milestoneP1_3_human_review_smoke.ts` passes 100%.
     - `npm run typecheck:v2` exits 0.
     - Full regression suite (`npm run check:v2` across all 47 smoke suites) passes 100%.
     - Next.js production build (`npm run build`) compiles cleanly with route `/v2/review`.

---

### Phase 2: Expanded Detection Coverage (DAST Active Probes & Advanced Differential Analyzers)

#### Milestone P2-1: Security Header Detection Engine
- **Status:** COMPLETED.
- **Goal:** Expand vulnerability detection coverage to passive/light inspection of HTTP security headers (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`), strictly enforcing the invariant that missing headers are hardening gaps (`status: 'potential_weakness'`), NEVER confirmed exploits.
- **Key Deliverables:**
  1. **Domain Contracts & Typed Metadata (`worker/src/v2/core/Evidence.ts`, `worker/src/v2/detection/DetectionContracts.ts`)**:
     - Added `MissingSecurityHeadersMetadata` interface to `FindingMetadata` discriminated union: `{ kind: 'missing_security_headers_metadata', missingHeaders: string[], presentHeaders: string[], observedAt: string }`.
     - Defined `SecurityHeaderDetectionRequest`, `SecurityHeaderDetectionResult`, and `SecurityHeaderDetectionStatus` (`'potential_weakness' | 'secure_target_abstained' | 'pending_human_review' | 'preflight_denied' | 'unexpected_failure'`).
  2. **Security Header Detection Service (`worker/src/v2/detection/SecurityHeaderDetectionService.ts`)**:
     - Performs 7-pass preflight validation (`runAdapterPreflight`) including SSRF / DNS rebinding prevention and session health validation.
     - Dispatches safe HTTP probe and evaluates response headers against standard security headers.
     - Full hardening: returns `status: 'secure_target_abstained'` (0 findings, 0 drafts).
     - Missing headers (unreviewed): returns `status: 'pending_human_review'` with `evidenceDraft` envelope.
     - Missing headers (approved): returns `status: 'potential_weakness'` with strongly-typed `Finding` carrying `MissingSecurityHeadersMetadata`.
  3. **Orchestrated Assessment Integration (`worker/src/v2/application/OrchestratedAssessmentApplicationService.ts`)**:
     - Integrated `runSecurityHeaderDetection` into `runPipeline()`.
     - Added triage review handling for `'missing_security_headers'` drafts, promoting approved drafts to `potential_weakness` finding records with `MissingSecurityHeadersMetadata`.
  4. **Verification**:
     - Dedicated smoke test `worker/src/v2/smoke/milestoneP2_1_security_headers_smoke.ts` passes 100%.
     - `npm run typecheck:v2` exits 0.
     - Full regression suite (`npm run check:v2` across all 48 smoke suites) passes 100%.
     - Next.js production build (`npm run build`) compiles cleanly.

---

#### Milestone P2-2: Open Redirect Detection Engine
- **Status:** COMPLETED.
- **Goal:** Implement high-precision active probing for unvalidated URL redirection vulnerabilities using safe canary targets (`https://canary.fixguard.internal/`), enforcing SSRF egress gates on redirect destinations, routing unreviewed detections to `pendingEvidenceDrafts`, and promoting approved drafts to formal `Finding` records with `OpenRedirectMetadata`.
- **Key Deliverables:**
  1. **Domain Contracts & Typed Metadata (`worker/src/v2/core/Evidence.ts`, `worker/src/v2/detection/DetectionContracts.ts`)**:
     - Added `OpenRedirectMetadata` interface to `FindingMetadata` discriminated union: `{ kind: 'open_redirect_metadata', parameterName: string, injectedCanary: string, finalDestination: string, redirectChain: readonly string[], observedAt: string }`.
     - Defined `OpenRedirectDetectionRequest`, `OpenRedirectDetectionResult`, and `OpenRedirectDetectionStatus` (`'exploit_confirmed' | 'potential_weakness' | 'secure_target_abstained' | 'pending_human_review' | 'preflight_denied' | 'unexpected_failure'`).
  2. **Open Redirect Detection Service (`worker/src/v2/detection/OpenRedirectDetectionService.ts`)**:
     - Probes candidate parameters (`redirect`, `next`, `url`, `return`, `dest`, `return_to`, `redirect_uri`, `continue`, `target`, `to`) with safe canary destination (`https://canary.fixguard.internal/`).
     - Analyzes HTTP 301/302/303/307/308 responses: detects unvalidated redirection to the injected canary.
     - Egress SSRF Gate: Inspects redirect destination hostnames, strictly failing closed (`status: 'preflight_denied'`, `reasonCode: 'ssrf_destination_blocked'`) if the redirect destination points to private IP spaces, loopback, or cloud metadata.
     - Clean Abstention: If target sanitizes to relative paths or validates against internal allowlists, returns `status: 'secure_target_abstained'` with 0 findings and 0 drafts.
     - Human-in-the-Loop: Routes unreviewed candidates to `pendingEvidenceDrafts` (`status: 'pending_human_review'`).
  3. **Orchestrated Assessment Integration & Web UI Triage (`worker/src/v2/application/OrchestratedAssessmentApplicationService.ts`, `web/src/app/v2/review/page.tsx`)**:
     - Wired `runOpenRedirectDetection` into `runPipeline()`.
     - Extended `reviewEvidenceDraft()` to promote approved `open_redirect` drafts into formal `Finding` records with `OpenRedirectMetadata`.
     - Updated web triage UI to display redirect destination, injected canary, and differential context.
  4. **Verification**:
     - Dedicated smoke test `worker/src/v2/smoke/milestoneP2_2_open_redirect_smoke.ts` passes 100%.
     - `npm run typecheck:v2` exits 0.
     - Full regression suite (`npm run check:v2` across all 49 smoke suites) passes 100%.
     - Next.js production build (`npm run build`) compiles cleanly.

---

#### Milestone P2-3: Information Disclosure Detection Engine
- **Status:** COMPLETED.
- **Goal:** Implement passive and non-destructive active probing for information disclosures (stack traces, server banners, internal filesystem paths, and framework versions), enforcing sensitive credential redaction, clean error page abstention, and the invariant that information disclosures represent hardening gaps (`status: 'potential_weakness'`, severity: `'low'` or `'info'`).
- **Key Deliverables:**
  1. **Domain Contracts & Typed Metadata (`worker/src/v2/core/Evidence.ts`, `worker/src/v2/detection/DetectionContracts.ts`)**:
     - Added `InformationDisclosureMetadata` interface to `FindingMetadata` discriminated union: `{ kind: 'information_disclosure_metadata', disclosureKind: 'stack_trace' | 'framework_version' | 'server_banner' | 'internal_path', disclosedFragment: string, trigger: string, observedAt: string }`.
     - Defined `InformationDisclosureDetectionRequest`, `InformationDisclosureDetectionResult`, and `InformationDisclosureDetectionStatus` (`'potential_weakness' | 'secure_target_abstained' | 'pending_human_review' | 'preflight_denied' | 'unexpected_failure'`).
  2. **Information Disclosure Detection Service (`worker/src/v2/detection/InformationDisclosureDetectionService.ts`)**:
     - Pattern matchers for stack traces (Java, Node.js, Python, PHP, ASP.NET), server banners (`Server: Apache/2.4.41`, `X-Powered-By: PHP/7.4.3`), and internal paths (`C:\inetpub`, `/var/www/`, `/home/app/`).
     - Sensitive Data Redaction: `sanitizeDisclosedExcerpt()` strips plaintext tokens, authorization bearer tokens, and secrets from captured excerpts before persistence or DTO creation.
     - Clean Abstention: Standard hardened error pages (generic 404/400) return `status: 'secure_target_abstained'` with 0 findings and 0 drafts.
     - Human Review Routing: Unattended detections route to `pendingEvidenceDrafts` (`status: 'pending_human_review'`). Upon approval, promotes to `status: 'potential_weakness'`.
  3. **Orchestrated Assessment Integration & Web UI Triage (`worker/src/v2/application/OrchestratedAssessmentApplicationService.ts`, `web/src/app/v2/review/page.tsx`)**:
     - Wired `runInformationDisclosureDetection` into `runPipeline()`.
     - Extended `reviewEvidenceDraft()` to promote approved `information_disclosure` drafts into formal `Finding` records with `InformationDisclosureMetadata`.
     - Updated web review UI with dedicated cards for `disclosureKind`, `trigger`, and sanitized `disclosedFragment`.
  4. **Verification**:
     - Dedicated smoke test `worker/src/v2/smoke/milestoneP2_3_information_disclosure_smoke.ts` passes 100%.
     - `npm run typecheck:v2` exits 0.
     - Full regression suite (`npm run check:v2` across all 50 smoke suites) passes 100%.
     - Next.js production build (`npm run build`) compiles cleanly.

---

#### Milestone P2-4: Subdomain Takeover Detection Engine
- **Status:** COMPLETED.
- **Goal:** Implement cross-recon active verification probing for dangling CNAME DNS records pointing to unclaimed cloud hosting providers (GitHub Pages, Heroku, AWS S3, Azure, Netlify, Fastly, Shopify), enforcing the crucial invariant that a cloud CNAME alone is NOT vulnerable until actively verified against provider error fingerprints, while cleanly abstaining on active/claimed services.
- **Key Deliverables:**
  1. **Domain Contracts & Typed Metadata (`worker/src/v2/core/Evidence.ts`, `worker/src/v2/detection/DetectionContracts.ts`)**:
     - Added `SubdomainTakeoverMetadata` interface to `FindingMetadata` discriminated union: `{ kind: 'subdomain_takeover_metadata', subdomain: string, cnameTarget: string, hostingProvider: 'github_pages' | 'heroku' | 'aws_s3' | 'azure' | 'fastly' | 'netlify' | 'shopify' | 'unknown', fingerprintMatch: string, observedAt: string }`.
     - Defined `SubdomainTakeoverDetectionRequest`, `SubdomainTakeoverDetectionResult`, `SubdomainTakeoverHostingProvider`, and `SubdomainTakeoverDetectionStatus` (`'vulnerability_detected' | 'potential_weakness' | 'secure_target_abstained' | 'pending_human_review' | 'preflight_denied' | 'unexpected_failure'`).
  2. **Subdomain Takeover Detection Service (`worker/src/v2/detection/SubdomainTakeoverDetectionService.ts`)**:
     - Fingerprint catalog mapping cloud hosting targets to unclaimed error signatures:
       - GitHub Pages: `*.github.io` $\rightarrow$ `"There isn't a GitHub Pages site here."`
       - Heroku: `*.herokudns.com` / `*.herokuapp.com` $\rightarrow$ `"There's nothing here, yet."` / `"No such app"`
       - AWS S3: `*.s3.amazonaws.com` / `*.s3-website-*.amazonaws.com` $\rightarrow$ `"<Code>NoSuchBucket</Code>"`
       - Azure: `*.azurewebsites.net` $\rightarrow$ `"404 Web Site not found"`
       - Netlify: `*.netlify.app` $\rightarrow$ `"Not Found - Request ID"`
       - Fastly: `*.fastly.net` $\rightarrow$ `"Fastly error: unknown domain"`
       - Shopify: `*.myshopify.com` $\rightarrow$ `"Sorry, this shop is currently unavailable."`
     - Targeted Verification Probe: Performs safe HTTP GET probe through `TargetExecutionCoordinator` and SSRF preflight gates.
     - Clean Abstention: Active services or valid responses (200 OK without unclaimed error signatures) cleanly return `status: 'secure_target_abstained'` with 0 findings and 0 drafts.
     - Human-in-the-Loop Routing: Unattended runs return `status: 'pending_human_review'` routing to `pendingEvidenceDrafts`. Upon approval, promotes to `status: 'vulnerability_detected'` with `severity: 'high'`.
  3. **Orchestrated Assessment Integration & Web Review UI (`worker/src/v2/application/OrchestratedAssessmentApplicationService.ts`, `web/src/app/v2/review/page.tsx`)**:
     - Consumes CNAME records collected in Stage 1/Stage 2 recon and automatically dispatches `runSubdomainTakeoverDetection`.
     - Extended `reviewEvidenceDraft()` to promote approved `subdomain_takeover` drafts into formal `Finding` records with `SubdomainTakeoverMetadata`.
     - Updated web triage UI to display dangling subdomain, CNAME target, matched hosting provider, and unclaimed fingerprint.
  4. **Verification**:
     - Dedicated smoke test `worker/src/v2/smoke/milestoneP2_4_subdomain_takeover_smoke.ts` passes 100%.
     - `npm run typecheck:v2` exits 0.
     - Full regression suite (`npm run check:v2` across all 51 smoke suites) passes 100%.
     - Next.js production build (`npm run build`) compiles cleanly.

---

#### Milestone P2-5: TLS Configuration Analysis Engine
- **Status:** COMPLETED.
- **Goal:** Implement a pure analytical engine over Stage 3 `tlsx` reconnaissance observations to evaluate SSL/TLS configuration security, detecting insecure protocols (SSLv2, SSLv3), deprecated protocols (TLS 1.0, TLS 1.1), weak cipher suites (RC4, 3DES, DES, NULL, EXPORT, MD5), and certificate anomalies (expired, self-signed, SAN mismatch) with strictly ZERO additional network requests.
- **Key Deliverables:**
  1. **Domain Contracts & Typed Metadata (`worker/src/v2/core/Evidence.ts`, `worker/src/v2/detection/DetectionContracts.ts`)**:
     - Added `WeakTlsMetadata` interface to `FindingMetadata` discriminated union: `{ kind: 'weak_tls_metadata', targetHost: string, port: number, weakProtocols: string[], weakCiphers: string[], certificateIssues: ('expired' | 'self_signed' | 'invalid_san')[], supportedTlsVersions: string[], observedAt: string }`.
     - Defined `TlsConfigurationAnalysisRequest`, `TlsConfigurationAnalysisResult`, `TlsCertificateIssue`, and `TlsAnalysisStatus` (`'vulnerability_detected' | 'potential_weakness' | 'secure_target_abstained' | 'pending_human_review' | 'unexpected_failure'`).
  2. **TLS Configuration Analysis Service (`worker/src/v2/detection/TlsConfigurationAnalysisService.ts`)**:
     - Purely analytical evaluation over existing `DiscoveredTlsObservation` records from Stage 3 active recon with 0 network calls dispatched.
     - Evaluation & Severity Rules:
       - Insecure protocols: `SSLv2`, `SSLv3` $\rightarrow$ `status: 'vulnerability_detected'`, `severity: 'high'`.
       - Deprecated protocols: `TLS 1.0`, `TLS 1.1` $\rightarrow$ `status: 'potential_weakness'`, `severity: 'medium'`.
       - Weak ciphers: `RC4`, `3DES`, `DES`, `NULL`, `EXPORT`, `MD5` $\rightarrow$ `status: 'potential_weakness'`.
       - Certificate health: `expired`, `self_signed`, `invalid_san` $\rightarrow$ `status: 'potential_weakness'`, `severity: 'medium'`.
     - Clean Abstention: Targets enforcing modern TLS 1.2+ / TLS 1.3 with secure ciphers and valid certificates cleanly return `status: 'secure_target_abstained'` (0 findings, 0 drafts).
     - Human-in-the-Loop Routing: Unattended runs route to `pendingEvidenceDrafts` (`status: 'pending_human_review'`).
  3. **Orchestrated Assessment Integration & Web Review UI (`worker/src/v2/application/OrchestratedAssessmentApplicationService.ts`, `web/src/app/v2/review/page.tsx`)**:
     - Automatically processes all TLS observations gathered in Stage 3 and evaluates them through `analyzeTlsConfiguration()`.
     - Extended `reviewEvidenceDraft()` to promote approved `weak_tls_configuration` drafts into formal `Finding` records with `WeakTlsMetadata`.
     - Updated web triage UI with cards displaying weak protocols, weak cipher suites, certificate health anomalies, and supported TLS versions.
  4. **Verification**:
     - Dedicated smoke test `worker/src/v2/smoke/milestoneP2_5_tls_configuration_smoke.ts` passes 100%.
     - `npm run typecheck:v2` exits 0.
     - Full regression suite (`npm run check:v2` across all 52 smoke suites) passes 100%.
     - Next.js production build (`npm run build`) compiles cleanly.

---

#### Milestone P2-6: HTML Report Generation & Operator Attestation (Phase 2 Finale)
- **Status:** COMPLETED.
- **Goal:** Implement the authoritative defensive HTML report generator with signed operator attestation, concluding Phase 2 of the canonical roadmap.
- **Key Deliverables:**
  1. **Self-Contained Report Builder (`worker/src/v2/reporting-boundary/ReportSectionBuilders.ts`)**:
     - Modern, dependency-free CSS design with dark/neutral aesthetics.
     - Six comprehensive report sections:
       1. Header & Target Metadata (Target domain, execution dates, scan scope, lineage tuple).
       2. Executive Summary (Severity breakdown badges, total confirmed findings count).
       3. Mandatory Audit Limitations (Point-in-Time constraints, defensive execution principles, unassessed vectors, abstention guarantees).
       4. Confirmed Findings (Title, severity badge, description, proof of evidence excerpt, typed differential metadata, continuous lineage chain).
       5. Advisory Recommendations (Rule-correlated advisory guidance derived from profile observations).
       6. Signed Operator Attestation (Operator identity, verification timestamp, signed attestation statement).
  2. **Report Generator Service (`worker/src/v2/reporting-boundary/ReportGeneratorService.ts`)**:
     - Strict validation: Requires valid operator identity and an explicit attestation statement of at least 10 characters.
     - Fail-Closed: Rejects empty statements, synthetic reviewer IDs, and forbidden speculation terms with `ReportGenerationError`.
     - Anti-Leak Invariant: Renders only confirmed `findings` promoted via HITL triage; strictly excludes unreviewed drafts.
  3. **Application Service & Gateway Controller (`worker/src/v2/application/OrchestratedAssessmentApplicationService.ts`, `worker/src/v2/api/controllers/OrchestratedAssessmentController.ts`, `worker/src/v2/api/routes/v2Routes.ts`)**:
     - Added `generateHtmlReport()` to `OrchestratedAssessmentApplicationService`.
     - Exposed `POST /api/v2/orchestrated/assessments/:assessmentId/report/html` returning `Content-Type: text/html; charset=utf-8`.
     - Validated request payloads using exact-key closed-world validator `parseGenerateHtmlReportHttpBody()`.
  4. **Next.js Web UI Integration (`web/src/lib/v2Api.ts`, `web/src/app/v2/assessments/components/ExecutiveResultsPanel.tsx`)**:
     - Integrated "Generar Informe Defensivo (HTML)" button in the Executive Assessment Results toolbar.
     - Modal dialog enabling operator identification, minimum 10-char attestation entry, and automated HTML report blob download.
  5. **Verification**:
     - Dedicated smoke test `worker/src/v2/smoke/milestoneP2_6_report_generation_smoke.ts` passes 100%.
     - `npm run typecheck:v2` exits 0.
     - Full regression suite (`npm run check:v2` across all 53 smoke suites) passes 100%.
     - Next.js production build (`npm run build`) compiles cleanly.

---

### Milestone P3-1: BYOT Session Injection Contract & Anti-Leak Boundary
- **Status:** COMPLETED.
- **Goal:** Establish the Bring Your Own Token (BYOT) ingestion boundary for operator-provided headers/cookies, replacing automated credential logins with strictly ephemeral, memory-only session tokens and enforcing anti-leak invariants (BYOT-SI-01 through BYOT-SI-06).
- **Key Deliverables:**
  1. **Anti-Leak Evidence Sanitizer (`worker/src/v2/core/EvidenceSanitizer.ts`)**:
     - Implemented `sanitizeEvidenceFragment(raw: string, maxLength?: number): string`.
     - Automatically redacts JWTs (`eyJ...`), Bearer tokens, Basic authorization credentials, session cookies, and API key patterns before storing free-text excerpts in evidence, finding metadata, or HTML reports.
     - Extended `SENSITIVE_HEADER_NAMES` in `IdorDifferentialDetectionService.ts` with `'x-auth-token'`, `'x-session-id'`, `'x-csrf-token'`, `'www-authenticate'`.
  2. **Domain Contracts & Anti-Persistence Invariant (`worker/src/v2/detection/DetectionContracts.ts`, `worker/src/v2/application/OrchestratedAssessmentContracts.ts`)**:
     - Declared `ByotIdentity` (`identityId`, `injectHeaders`, `injectCookies`) and `ByotSessionIdentityBundle` (`identityA`, optional `identityB`).
     - Extended `StartOrchestratedAssessmentCommand` with optional `sessionIdentities?: ByotSessionIdentityBundle`.
     - Invariant: `ByotIdentity` is strictly ephemeral and NEVER persisted or serialized to `OrchestratedAssessmentRecord`.
  3. **Closed-World API Validation Boundary (`worker/src/v2/api/validation/ApiRequestValidators.ts`)**:
     - Implemented `parseByotIdentity()` and `parseByotSessionIdentityBundle()`.
     - Enforces exact-key closed-world checking, safe identifier validation via `isStrictSafeId()`, and bounds limits (max 20 entries per map, max 4096 chars per value).
     - Added optional "Sesión Autenticada (BYOT)" collapsible panel with password-masked inputs (`type="password"`) for Identity A and Identity B.
     - Displayed explicit UX anti-leak invariant disclaimer: *"Las credenciales son efímeras: residen solo en memoria durante el escaneo y nunca se persisten."*
  6. **Verification**:
     - Dedicated smoke test `worker/src/v2/smoke/milestoneP3_1_byot_smoke.ts` passes 100%.
     - `npm run typecheck:v2` exits 0.
     - Full regression suite `npm run check:v2` (54 suites) passes 100%.
     - Next.js production build (`npm run build`) compiles cleanly.

---

### Milestone P3-3: Multi-Identity Differential IDOR with BYOT (Phase 3 Complete)
- **Status:** COMPLETED.
- **Goal:** Operationalize the multi-identity differential access control engine (`IdorDifferentialDetectionService`) inside `OrchestratedAssessmentApplicationService` using operator-injected BYOT session contexts (`ByotSessionIdentityBundle`), closing Phase 3.
- **Key Deliverables:**
  1. **Orchestration Pipeline Wiring (`worker/src/v2/application/OrchestratedAssessmentApplicationService.ts`)**:
     - Derived `identityAContext` from `command.sessionIdentities?.identityA` with fallback to `identity_anon_a`.
     - Derived `identityBContext` from `command.sessionIdentities?.identityB` with automatic fallback to `buildAnonymousProbeContext('identity_anon_b')` for single-identity or unauthenticated checks.
     - Parameter Candidate Discovery: Evaluated resource candidates discovered during Stage 4/5 (`id`, `user_id`, `userid`, `account_id`, `order_id`, `doc_id`, `item_id`, and RESTful `/users/1`, `/api/orders/123` patterns) plus default fallback origin candidates.
     - Executed `runIdorDifferentialDetection()` feeding dual probe contexts through the 7-pass preflight, HTTP differential probe transport, response comparator (M47), and evidence promotion pipeline (M49–M54).
  2. **HITL Triage Lifecycle Integration**:
     - Unattended runs generate non-persisted `EnrichedEvidenceDraft` with `status: 'pending_human_review'` carrying `BrokenAccessControlMetadata` and `DifferentialEvidenceContext`.
     - Operator review via `reviewEvidenceDraft()` approves draft into canonical `Finding` with `type: 'BROKEN_ACCESS_CONTROL'`, `severity: 'high'`, confidence `0.95`, and lineage chain.
  3. **Anti-Leak Invariant & Snapshot Sanitization**:
     - Redacted all sensitive session headers (`authorization`, `cookie`, `set-cookie`, `x-api-key`, `x-auth-token`, etc.) via `SENSITIVE_HEADER_NAMES` from response snapshots.
     - Sanitized body excerpts and differential fragments via `sanitizeEvidenceFragment()`.
     - Maintained 0 credentials persisted to storage.
  4. **Typing & Reviewer Discipline**:
     - Strictly 0 occurrences of `as any` across all production code.
     - Strict human review gate (zero synthetic reviewer IDs).
  5. **Verification**:
     - Dedicated smoke test `worker/src/v2/smoke/milestoneP3_3_idor_byot_smoke.ts` passes 100%.
     - `npm run typecheck:v2` exits 0.
     - Full regression suite `npm run check:v2` (55 suites) passes 100%.
     - Next.js production build (`npm run build`) compiles cleanly.

---

### Milestone P4-1: Authentication Bypass Detection Engine (COMPLETED)
- **Status:** COMPLETED.
- **Goal:** Implement the defensive Authentication Bypass Detection Engine testing whether protected endpoints accessible with credentials (Identity A) can be accessed anonymously without credentials (`header_stripping`, `cookie_omission`, `verb_tampering`) leaking identical or sensitive data ($\ge 0.85$ structural body similarity).
- **Key Deliverables:**
  1. **Domain Contracts & Finding Metadata (`worker/src/v2/core/Evidence.ts`)**:
     - Added `AuthBypassMetadata` to the `FindingMetadata` discriminated union (`kind: 'auth_bypass_metadata'`, `category: 'BROKEN_AUTHENTICATION'`, `bypassMechanism`, `bodySimilarityRatio`, `authenticatedStatusCode`, `anonymousStatusCode`).
     - Extended `DifferentialEvidenceContext` in `OrchestratedAssessmentContracts.ts` and `DifferentialEvidenceContextDto` in `web/src/lib/v2Api.ts` supporting `'auth_bypass'`.
  2. **Detection Engine (`worker/src/v2/detection/AuthBypassDetectionService.ts`)**:
     - 7-pass atomic preflight check validating targets, scope, runtime brands, and SSRF containment.
     - Dual-probe HTTP dispatch: Baseline probe with Identity A credentials vs Anonymous probe with all authentication headers and cookies completely stripped.
     - Target abstention: When unauthenticated response returns 401, 403, or 302 login redirect, cleanly abstains with `status: 'secure_target_abstained'`.
     - Structural similarity analysis: Flags authentication bypass when anonymous probe returns 200 OK and matches baseline ($\ge 0.85$ similarity ratio).
     - Full custody and promotion flow (M47, M49, M50, M51, M52, M53, M54).
  3. **Orchestrated Assessment Pipeline & Review UI**:
     - Wired into `OrchestratedAssessmentApplicationService.ts` when `sessionIdentities?.identityA` is provided.
     - Unattended runs route to `pendingEvidenceDrafts` for HITL review.
     - Operator review promotes draft to formal canonical `Finding` (`type: 'BROKEN_AUTHENTICATION'`, `severity: 'high'`).
     - Review dashboard (`web/src/app/v2/review/page.tsx`) renders Auth Bypass diff cards with bypass mechanism and similarity scores.
  4. **Verification & Hygiene**:
     - Dedicated smoke test `worker/src/v2/smoke/milestoneP4_1_auth_bypass_smoke.ts` passes 100% (4/4 assertions).
     - `npm run typecheck:v2` exits with code 0.
     - Full regression suite `npm run check:v2` (56/56 smoke suites) passes 100%.
     - `cd web && npm run build` compiles cleanly with zero errors.
     - 0 occurrences of `as any` across all production code.

---

### Milestone P4-2: Technology Fingerprint Engine (COMPLETED)
- **Status:** COMPLETED.
- **Goal:** Implement the deterministic, passive Technology Fingerprint Engine extracting typed technology profiles (with exact versions, categories, confidence, and signals) and synthesizing a `TechEcosystemProfile` without generating redundant network traffic.
- **Key Deliverables:**
  1. **Domain Contracts & Technology Types (`worker/src/v2/core/TechnologyContracts.ts`)**:
     - Defined `TechnologyCategory` union (`'cms' | 'framework' | 'frontend' | 'runtime' | 'server' | 'cdn' | 'database' | 'security' | 'unknown'`).
     - Defined `DetectedTechnology` model (`name`, `version`, `category`, `confidence`, `detectionSignal`, `cpeIdentifier`).
     - Defined `TechEcosystemProfile` (`hasSpa`, `spaFramework`, `hasCms`, `cmsType`, `hasGraphQL`, `hasPhpLegacy`, `hasExposedSourcemaps`).
  2. **Analytical Fingerprinting Service (`worker/src/v2/recon/analysis/TechnologyFingerprintService.ts`)**:
     - Consumes already captured HTTP responses (headers + HTML body) and reconnaissance observations.
     - Purely analytical (zero additional network calls).
     - Exhaustive signal extraction:
       - Server/Powered-By headers: Nginx, Apache, IIS, Gunicorn, Werkzeug, PHP, Express, Next.js, ASP.NET, Cloudflare, Vercel.
       - Session cookies: `PHPSESSID` (PHP), `laravel_session` (Laravel), `ASP.NET_SessionId` (ASP.NET), `JSESSIONID` (Java), `csrftoken` (Django), `connect.sid` (Express).
       - HTML Meta generators: WordPress, Drupal, Joomla, Gatsby, Hugo.
       - Asset & Plugin paths: WordPress core (`/wp-includes/`) and plugins (`/wp-content/plugins/<slug>/...?ver=X.Y.Z`), Drupal (`/sites/default/files/`, `/core/misc/`).
       - DOM & SPA markers: Next.js (`__NEXT_DATA__`, `/_next/static/`), Nuxt.js (`window.__nuxt__`), React (`data-reactroot`), Angular (`ng-version`), Vue (`id="__vue-app"`, `data-v-`), SvelteKit (`__sveltekit`).
       - Frontend libraries: jQuery, Bootstrap, Tailwind CSS.
       - Structural ecosystem signals: GraphQL detection, Legacy PHP (v5.x/v7.x), Exposed Sourcemaps (`sourceMappingURL=`).
  3. **Intelligence Layer & Presentation Integration**:
     - Updated `TargetProfileBuilder.ts` to enrich `TargetProfile` with `detectedTechnologies` and `ecosystemProfile` while preserving backward-compatible `technologies: string[]`.
     - Extended `web/src/lib/v2Api.ts` (`DetectedTechnologyDto`, `TechEcosystemProfileDto`).
     - Enhanced `ExecutiveResultsPanel.tsx` in Next.js UI to render technology version badges, category badges, and ecosystem tags.
  4. **Verification & Hygiene**:
     - Dedicated smoke test `worker/src/v2/smoke/milestoneP4_2_tech_fingerprint_smoke.ts` passes 100% (4/4 assertions).
     - `npm run typecheck:v2` exits with code 0.
     - Full regression suite `npm run check:v2` (58/58 smoke suites) passes 100%.
     - `cd web && npm run build` compiles cleanly with zero errors.
     - 0 occurrences of `as any` across all production code.

---

### Milestone P4-3: Sourcemap Exposure Detection Engine
- **Status:** COMPLETED.
- **Goal:** Implement the Sourcemap Exposure Detection Engine targeting SPA architectures and modern frontend bundles, verifying accessible `.js.map` files that expose full source code and internal API surfaces with strict abstention and human review promotion.
- **Key Deliverables:**
  1. **Domain Contracts & Typed Metadata (`SourcemapExposureMetadata`)**:
     - Defined `SourcemapExposureMetadata` in `worker/src/v2/core/Evidence.ts` under the `FindingMetadata` discriminated union (`kind: 'sourcemap_exposure_metadata'`, `category: 'INFORMATION_DISCLOSURE'`, `detectionSignal: 'sourcemapping_url_comment' | 'sourcemap_header' | 'deterministic_path_probe'`).
     - Extended `DifferentialEvidenceContext` and `DifferentialEvidenceContextDto` with `detectionKind: 'sourcemap_exposure'`, `exposedMapUrl`, `sourceJsUrl`, `sampleSourcesCount`, and `mapFileSizeBytes`.
  2. **Detection Service (`SourcemapExposureDetectionService.ts`)**:
     - Implemented `runSourcemapExposureDetection()` and helper `extractSourcemapUrlAndSignal()`.
     - Extracts `.js.map` URLs from `//# sourceMappingURL=` comments, `SourceMap:` / `X-SourceMap:` HTTP response headers, or deterministic `.map` paths.
     - Enforces 7-pass SSRF preflight protection blocking internal IP and loopback addresses.
     - Dispatches targeted GET probes and validates authentic JSON sourcemap structure (`version`, `sources`, `mappings`).
     - Reports confirmed exposures as `status: 'potential_weakness'`, `category: 'INFORMATION_DISCLOSURE'`, `severity: 'medium'`.
     - Cleanly abstains (`status: 'secure_target_abstained'`) on 404, 403, non-JSON error pages, or non-sourcemap payloads.
  3. **Pipeline & Review UI Integration**:
     - Integrated `runSourcemapExposureDetection` into `OrchestratedAssessmentApplicationService.ts` across discovered JavaScript assets.
     - Added human-in-the-loop review promotion in `reviewEvidenceDraft()` promoting unreviewed drafts to formal `Finding` records.
     - Enhanced `web/src/app/v2/review/page.tsx` to render exposed map URLs, source JavaScript bundles, exposed source file counts, and map file sizes.
  4. **Verification & Hygiene**:
     - Dedicated smoke test `worker/src/v2/smoke/milestoneP4_3_sourcemap_exposure_smoke.ts` passes 100% across all 5 assertions.
     - `npm run typecheck:v2` exits with code 0.
     - Full regression suite `npm run check:v2` (59/59 smoke suites) passes 100%.
     - `cd web && npm run build` compiles cleanly with zero errors.
     - 0 occurrences of `as any` across all production code.

---

### Milestone P4-4: WordPress XML-RPC and User Enumeration Probes
- **Status:** COMPLETED.
- **Goal:** Implement non-brute-force CMS detection for WordPress surfaces: XML-RPC capability probing (`system.listMethods` and `system.multicall` amplification support) and REST API user identity enumeration (`/wp-json/wp/v2/users`).
- **Key Deliverables:**
  1. **Domain Contracts & Typed Metadata (`WordPressSurfaceMetadata`)**:
     - Defined `WordPressSurfaceMetadata` in `worker/src/v2/core/Evidence.ts` under the `FindingMetadata` discriminated union (`kind: 'wordpress_surface_metadata'`, `category: 'SECURITY_MISCONFIGURATION' | 'INFORMATION_DISCLOSURE'`, `probeKind: 'xmlrpc_capabilities' | 'rest_user_enumeration'`).
     - Extended `DifferentialEvidenceContext` and `DifferentialEvidenceContextDto` with `detectionKind: 'wordpress_surface'`, `wpProbeKind`, `xmlRpcMethodsExposed`, `multicallSupported`, `exposedUsersCount`, and `sampleUserSlugs`.
     - Extended `HttpProbeRequest` in `DetectionContracts.ts` to support `POST` and body payloads.
  2. **Detection Service (`WordPressSurfaceDetectionService.ts`)**:
     - Implemented `runWordPressSurfaceDetection()`.
     - **Probe 1 (XML-RPC)**: Safely dispatches `POST /xmlrpc.php` with `system.listMethods` payload. Parses returned method list and checks for `system.multicall` presence. Classifies as `SECURITY_MISCONFIGURATION` (`medium` severity with multicall amplification, `low` without).
     - **Probe 2 (REST Users)**: Dispatches `GET /wp-json/wp/v2/users`. Parses JSON user objects, extracting author slugs and public user counts. Classifies as `INFORMATION_DISCLOSURE` (`medium` severity).
     - **Strict Non-Brute-Force & Abstention Discipline**: Never tests credentials or sends high-volume traffic. Cleanly returns `status: 'secure_target_abstained'` on 401, 403, 404, or `rest_cannot_view` responses.
     - **SSRF Safety**: 7-pass preflight protection blocks internal IP and metadata probing.
  3. **Pipeline & Review UI Integration**:
     - Wired `runWordPressSurfaceDetection` into `executePipelineStages` in `OrchestratedAssessmentApplicationService.ts`.
     - Added `reviewEvidenceDraft` handler for `'wordpress_surface'` promoting unreviewed drafts to formal `Finding` records.
     - Updated `web/src/app/v2/review/page.tsx` to render WordPress surface cards displaying probe kind, `system.multicall` risk badges, callable XML-RPC method lists, exposed user counts, and disclosed author usernames.
  4. **Verification & Hygiene**:
     - Dedicated smoke test `worker/src/v2/smoke/milestoneP4_4_wordpress_surface_smoke.ts` passes 100% across all 5 assertions.
     - `npm run typecheck:v2` exits with code 0.
     - Full regression suite `npm run check:v2` (60/60 smoke suites) passes 100%.
     - `cd web && npm run build` compiles cleanly with zero errors.
     - 0 occurrences of `as any` across all production code.

---

### Milestone P4-5: SQL Error Oracle Detection Engine
- **Status:** COMPLETED.
- **Goal:** Implement the SQL Error Oracle Detection Engine targeting data-access and legacy layers, safely detecting unhandled database error disclosure across MySQL, MSSQL, PostgreSQL, Oracle, and SQLite via inert syntax canary probes with zero boolean timing or data dumping exploitation.
- **Key Deliverables:**
  1. **Domain Contracts & Typed Metadata (`SqlErrorOracleMetadata`)**:
     - Defined `SqlErrorOracleMetadata` in `worker/src/v2/core/Evidence.ts` under the `FindingMetadata` discriminated union (`kind: 'sql_error_oracle_metadata'`, `category: 'INFORMATION_DISCLOSURE'`, `databaseEngine: 'mysql' | 'mssql' | 'postgresql' | 'oracle' | 'sqlite' | 'unknown'`, `parameterName`, `injectedProbe`, `errorFragment`).
     - Extended `DifferentialEvidenceContext` and `DifferentialEvidenceContextDto` with `detectionKind: 'sql_error_oracle'`, `databaseEngine`, `sqlErrorFragment`, and `injectedProbe`.
  2. **Detection Service (`SqlErrorOracleDetectionService.ts`)**:
     - Implemented `runSqlErrorOracleDetection()`.
     - Injects safe, inert syntax-testing canary token (`'FixGuard_Oracle_<seed>`) into candidate parameters.
     - Detects database syntax and runtime error signatures across MySQL (`/You have an error in your SQL syntax/i`), MSSQL (`/Unclosed quotation mark/i`, `/Microsoft OLE DB Provider for SQL Server/i`), PostgreSQL (`/syntax error at or near/i`), Oracle (`/ORA-01756/i`), and SQLite (`/SQLite3::prepare/i`, `/unrecognized token/i`).
     - Sanitizes error excerpts via `sanitizeEvidenceFragment()` and truncates to a strict maximum of 128 characters.
     - Enforces 7-pass SSRF preflight protection blocking internal IP and metadata probing.
     - Cleanly abstains (`status: 'secure_target_abstained'`) when the target sanitizes parameters, returns clean responses, or responds with generic 400/404 templates.
  3. **Pipeline & Review UI Integration**:
     - Wired `runSqlErrorOracleDetection` into `executePipelineStages` in `OrchestratedAssessmentApplicationService.ts`.
     - Added `reviewEvidenceDraft` handler for `'sql_error_oracle'` promoting drafts to formal `Finding` records with `SqlErrorOracleMetadata`.
     - Updated `web/src/app/v2/review/page.tsx` to render SQL Error Oracle cards displaying database engine badges, vulnerable parameter names, and sanitized error fragments.
  4. **Verification & Hygiene**:
     - Dedicated smoke test `worker/src/v2/smoke/milestoneP4_5_sql_error_oracle_smoke.ts` passes 100% across all 4 assertions.
     - `npm run typecheck:v2` exits with code 0.
     - Full regression suite `npm run check:v2` (61/61 smoke suites) passes 100%.
     - `cd web && npm run build` compiles cleanly with zero errors.
     - 0 occurrences of `as any` across all production code.

---

### Milestone P4-6: GraphQL Surface Mapper
- **Status:** COMPLETED.
- **Goal:** Implement the GraphQL Surface Mapper for modern API interfaces, safely detecting exposed schema introspection, field suggestion leakages, and query batching capabilities using strictly read-only queries with zero mutations or state-altering operations.
- **Key Deliverables:**
  1. **Domain Contracts & Typed Metadata (`GraphQLSurfaceMetadata`)**:
     - Defined `GraphQLSurfaceMetadata` in `worker/src/v2/core/Evidence.ts` under the `FindingMetadata` discriminated union (`kind: 'graphql_surface_metadata'`, `category: 'SECURITY_MISCONFIGURATION' | 'INFORMATION_DISCLOSURE'`, `endpointUrl`, `introspectionEnabled`, `batchingEnabled`, `fieldSuggestionsEnabled`, `discoveredRootTypes`, `suggestionLeak`).
     - Extended `DifferentialEvidenceContext` and `DifferentialEvidenceContextDto` with `detectionKind: 'graphql_surface'`, `introspectionEnabled`, `batchingEnabled`, `fieldSuggestionsEnabled`, `discoveredRootTypes`, and `suggestionLeak`.
  2. **Detection Service (`GraphQLSurfaceDetectionService.ts`)**:
     - Implemented `runGraphQLSurfaceDetection()`.
     - Probes candidate GraphQL endpoints (`/graphql`, `/api/graphql`, `/v1/graphql`, `/query`, or custom paths).
     - **Probe 1 (Introspection)**: Dispatches `POST` with `{"query":"{ __schema { types { name } } }"}`. On success, extracts up to 20 root/user-defined type names as proof of data model disclosure.
     - **Probe 2 (Field Suggestion Leakage)**: Dispatches `POST` with `{"query":"{ fixguard_invalid_probe }"}`. Detects suggestion patterns (`Did you mean`, `Cannot query field`, `Unknown field`) and extracts a sanitized leak excerpt (max 128 chars).
     - **Probe 3 (Batching Capability)**: Dispatches array payload `[{"query":"{ __typename }"},{"query":"{ __typename }"}]` to verify batch query execution support.
     - **SSRF Containment**: Passes all requests through `runAdapterPreflight()` enforcing 7-pass SSRF/DNS rebinding prevention.
     - **Abstention Discipline**: Cleanly returns `status: 'secure_target_abstained'` when endpoints are absent (404), disabled (403), or reject GraphQL queries without schema or suggestion leaks.
  3. **Pipeline & Review UI Integration**:
     - Wired `runGraphQLSurfaceDetection` into `executePipelineStages` in `OrchestratedAssessmentApplicationService.ts`.
     - Added `reviewEvidenceDraft` handler for `'graphql_surface'` promoting drafts to formal `Finding` records with `GraphQLSurfaceMetadata`.
     - Updated `web/src/app/v2/review/page.tsx` to render GraphQL surface cards displaying introspection status, batching support badges, field suggestion alerts, and exposed root types.
  4. **Verification & Hygiene**:
     - Dedicated smoke test `worker/src/v2/smoke/milestoneP4_6_graphql_surface_smoke.ts` passes 100% across all 5 assertions.
     - `npm run typecheck:v2` exits with code 0.
     - Full regression suite `npm run check:v2` (61/61 smoke suites) passes 100%.
     - `cd web && npm run build` compiles cleanly with zero errors.
     - 0 occurrences of `as any` across all production code.

---

## 5. Architectural Proposals (`PROPOSED` — NOT YET DECIDED)

> [!NOTE]
> The following items are technical proposals identified during the architectural audit. They represent recommendations for future consideration and **HAVE NOT BEEN DECIDED OR APPROVED YET**.

### Proposal A: V2 Unified API Gateway / HTTP Controller Layer (COMPLETED in M61)
- **Status**: Completed in M61 (`worker/src/v2/api/`). Standalone Express 5 gateway exposing V2 application services.

### Proposal B: Deprecation and Decommissioning Plan for V1 Monolith
- **Problem**: The codebase carries legacy V1 code (`worker/src/scanner/`, `worker/src/recon/`, `worker/src/index.ts`) with unredacted SQL persistence and direct binary execution.
- **Proposal**: Identify salvageable parsers or tool logic, re-implement them as clean V2 adapters (`worker/src/v2/adapters/`), and systematically decommission the V1 Express server.

### Proposal C: Dependency Hygiene & Pruning
- **Problem**: `worker/package.json` contains dependencies that are completely unused in V2 (e.g. `@upstash/redis`, `@ai-sdk/google`, `playwright`, `wappalyzer`).
- **Proposal**: Once V1 is formally retired, prune unused packages from `worker/package.json` to reduce attack surface and dependency bloat.

### Proposal D: Distributed Authorization Token Provider (Cross-Process Scaling)
- **Problem**: ADR-001 enforces authorization branding via an in-memory `WeakSet<object>`, which is process-local. It cannot cross process or worker node boundaries.
- **Proposal**: If FixGuard evolves from a single-node system into a distributed cluster, introduce an asymmetric cryptographic signing port (e.g. Ed25519) to verify decisions across process boundaries without sacrificing non-forgery guarantees.

---

## 6. Problems, Risks & Technical Debt

### 6.1. Known Issues (`CONFIRMED`)
1. **Evidence Substance Gap (Addressed in M58)**: Prior to M58, `EvidenceRecord`s could be constructed with empty snapshot and difference fields, satisfying TypeScript contracts but carrying zero substantive proof.
2. **ADR-001 Documentation Inconsistency**: The text in `ADR-001-verified-authorization.md` states that a Symbol brand is used; the actual code uses a module-private `WeakSet<object>` (a superior implementation that resists reflection).
3. **Dead Dependency in Worker**: `@upstash/redis` is installed in `worker/package.json` and listed in `.env.example`, but has zero imports across the entire repository.
4. **Web Frontend Disconnected from V2**: The Next.js frontend (`web/`) queries the V1 database schema (`scans`, `recon_profiles`, `findings`) and knows nothing about `v2_` tables.

### 6.2. Architectural Risks (`CONFIRMED`)
1. **Dual System Confusion**: Having both V1 and V2 in the same repository creates cognitive load and the risk that a future agent or engineer accidentally modifies V1 files or imports V1 patterns into V2.
2. **Process-Local Authorization Constraint**: `VerifiedAuthorizationDecision` is bound to the Node.js memory space. Any architectural decision requiring background worker queues (like BullMQ or Celery) would break runtime brand validation unless all execution remains in-process.

### 6.3. Technical Debt (`CONFIRMED`)
1. **Dual Configurations**:
   - `tsconfig.json` (V1) vs `tsconfig.v2.json` (V2).
   - `drizzle.config.ts` (V1) vs `drizzle.v2.config.ts` (V2).
   - `drizzle/` migrations (V1) vs `drizzle-v2/` migrations (V2).
2. **Legacy HTML Reports**: A static artifact `FixGuard_Report_https___balbuenabarber_vercel_app__137.html` sits in the root directory reflecting unvalidated V1 severity outputs.

---

## 7. Open Questions for External Lead Architect

The following questions should be submitted to the senior architect for strategic direction:

1. **API Integration Strategy**:
   *Should V2 be exposed to the Next.js frontend via an Express 5 REST API, a Fastify service, or directly via Next.js Route Handlers / Server Actions calling the V2 application service as an in-process library?*
2. **Execution Environment / Worker Architecture**:
   *Is FixGuard intended to remain an in-process single-instance application (where in-memory `WeakSet` authorization is sufficient), or will workers be distributed across multiple containers/machines (requiring cryptographic authorization tokens)?*
3. **Legacy V1 Retirement Timeline**:
   *Should V1 be removed immediately once V2 has its own API/UI, or should it be archived in a separate git branch?*
