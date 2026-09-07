# AGENTS.md — FixGuard V2 Developer & Coding Agent Guidelines

> **Permanent Directive for AI Agents and Engineers:**
> "Tools execute. Intelligence decides. Humans authorize."
> 
> *FixGuard is a defensive security assessment platform. It prioritizes real evidence over finding count, abstention over speculation, and human consent over autonomous exploitation.*

---

## 1. Project Context & Purpose

FixGuard is an authorized web security assessment platform (DAST / Attack Surface Management) designed for defensive auditing of authorized targets.

### The Dual-System Reality
- **FixGuard V1 (Legacy / Monolith)**:
  - Located in `worker/src/` (excluding `v2/`) and `web/`.
  - An Express 5 + Next.js 16 monolith connecting directly to Postgres via Drizzle ORM.
  - Executes binaries (`subfinder`, `httpx`, `gau`, `trufflehog`) directly via `child_process.exec`, writing unvalidated findings and severities ("Critical", "High") directly to SQL tables.
  - **Status: FROZEN / DEPRECATED.** Do NOT add features to V1. Do NOT refactor V1 unless specifically instructed.
- **FixGuard V2 (Current Production Core)**:
  - Located strictly under `worker/src/v2/`.
  - Built under **DDD (Domain-Driven Design), Clean Architecture, and Ports & Adapters**.
  - Enforces strict trust boundaries, runtime-branded authorization, atomic preflights, egress gates, and human review boundaries.
  - **Status: ACTIVE CANONICAL CORE.** All new development belongs here.

---

## 2. Inviolable Working Rules

1. **Understand Before Modifying**: Read the relevant contracts (`*Contracts.ts`) and ADRs (`worker/src/v2/architecture/adr/`) before opening or editing services.
2. **Inspect Live Code**: Never assume that markdown documentation or historical comments reflect the working tree. Always verify against active TypeScript code.
3. **No Fabricated Data / No Hallucinated Claims**:
   - Never generate synthetic or simulated target data and present it as real findings.
   - Never assign automatic severities ("Critical", "High", "Medium") or automated remediation recipes without human authorization and real target validation.
   - Discipline of claims:
     - `OBSERVED`: What actually occurred on the target (e.g., HTTP 200, header present, body hash).
     - `INFERRED`: Hypotheses derived from observations (must be marked as unconfirmed).
     - `RECOMMENDED`: Actions proposed for human authorization.
4. **No Type Bypasses in Production**:
   - `as any` is **STRICTLY PROHIBITED** in production code (`worker/src/v2/**`).
   - `forceCast<T>()`, `unknown as T`, and `@ts-ignore` are **PROHIBITED** as shortcuts.
   - Adversarial test fixtures may construct malformed objects strictly at the test perimeter, but never in production services.
5. **No Self-Authorization**:
   - Authorization can never be established by a caller passing `confirmed: true` or supplying their own `authorizedScope`.
   - Authority must flow through `establishVerifiedAuthorizationDecision()` and carry a valid runtime brand.
6. **Closed-World / Exact-Key Validation**:
   - External inputs, persistence models, and trust boundaries use exact-key validation.
   - Unknown keys, missing keys, or forbidden executable payload keys must cause an immediate, safe fail-closed rejection.
7. **Two-Pass Atomic Batch Preflight**:
   - In active reconnaissance, all requested probes in a batch must be validated before any execution starts.
   - If any probe in a batch is unsupported or denied, the entire batch is aborted (`preflight_denied`) with **zero network requests, zero persistence writes, and zero side effects**.
8. **Double Gate on Network Execution**:
   - Every network action must pass:
     1. `VerifiedAuthorizationDecision` (human authorization & actor identity).
     2. `AuthorizedScopeGrant` (target, method, path boundaries).
     3. `evaluateEgressPolicy` (SSRF gate blocking loopback, private RFC1918, cloud metadata).
   - Egress policy is the final network safety gate, NOT the authorization source.
9. **Preserve Lineage & Identity**:
   - Every step of the pipeline must preserve the continuous lineage tuple:
     `{ assessmentId, scanId, authorizationGrantId, authorizationDecisionId, actorId }`.
10. **Single Consolidated Smoke Suite per Milestone**:
    - Avoid fragmenting tests into dozens of micro-scripts.
    - Each milestone must have 1 robust, consolidated smoke test verifying happy path, denials, malformed inputs, and corruption resistance.
    - Tests must terminate with a non-zero exit code on failure (`process.exit(1)`), never hiding rejected promises.

---

## 3. Mandatory Agent Workflow

Every task performed in FixGuard must follow these 7 steps:

```text
1. UNDERSTAND ──> 2. INSPECT ──> 3. PLAN ──> 4. IMPLEMENT ──> 5. VALIDATE ──> 6. AUDIT ──> 7. REPORT
```

1. **Understand**:
   - Identify which layer is being modified: Execution Core, Intelligence, Approval, Active Recon, Evidence, Candidate, Application, or Storage.
   - Identify upstream producers and downstream consumers.
2. **Inspect**:
   - View active contract files and verify existing types.
   - Check if similar patterns already exist (e.g. read models, validators, repository adapters).
3. **Plan**:
   - Explicitly define: Invariants (`MUST` and `MUST NOT`), Non-Goals, affected contracts.
   - If the task requires architectural changes, write/update `implementation_plan.md` and await user approval.
4. **Implement**:
   - Write clean, minimal code conforming to Clean Architecture.
   - Keep production code free of `any`.
   - Preserve existing docstrings and comments unrelated to the change.
5. **Validate**:
   - Run the isolated smoke test for the affected milestone.
   - Run TypeScript typechecking: `npm run typecheck:v2` (must exit 0).
   - Run the full regression smoke suite: `npm run check:v2` (must pass 100%).
6. **Audit (Adversarial Check)**:
   - Check fail-closed behavior: What happens on null input? Extra keys? Malformed timestamps? Mismatched scan IDs?
   - Ensure mutation safety (records must not be mutated in-place).
7. **Report**:
   - Deliver a clear, honest summary explaining what was implemented, how it works, and what was verified.
   - Never use hype, jargon, or claim that something is complete without test execution proof.

---

## 4. Definition of Done (DoD)

A task in FixGuard V2 is considered **DONE** only when all of the following criteria are met:

- [ ] **Contract Correctness**: Types are exact, discriminated unions are used, and no executable or sensitive fields leak through DTOs.
- [ ] **Security Correctness**: Verified authorization is enforced; scope policy and egress SSRF policies pass; batch preflights are atomic; no self-authorization.
- [ ] **Lineage Correctness**: `assessmentId`, `scanId`, `grantId`, `decisionId`, and `actorId` remain continuous from start to finish.
- [ ] **Data Authenticity**: All evidence and observations are grounded in actual target responses; zero fabricated findings or speculative severities.
- [ ] **Verification**:
  - `npm run typecheck:v2` exits with code `0`.
  - `npm run check:v2` runs all smoke suites and exits with code `0`.
- [ ] **Documentation**: Any newly introduced contracts, architectural decisions, or invariants are documented in `docs/` and tracked in `docs/ROADMAP.md`.
