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
```

---

## 2. Completed Milestones (`CONFIRMED`)

All completed milestones are verified via active TypeScript contracts and the regression test suite (`npm run check:v2` with 42 passing smoke suites, 100% pass rate).

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
