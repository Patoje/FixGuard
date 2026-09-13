# ADR-002: Scope Boundaries and Strategic Non-Goals

- **ID:** ADR-002 (Decisions Series) / ADR-SCOPE-001
- **Status:** `ACCEPTED`
- **Context:**
  FixGuard V2 is an authorized, defensive web security assessment platform (DAST / Attack Surface Management). As the platform expands across reconnaissance and assessment layers, clear architectural boundaries are required to prevent feature sprawl, domain dilution, and wasteful reimplementation of solved problems.

---

## 1. Rejection of Interactive Real-Time Proxy Parity

### Decision
FixGuard explicitly **rejects** pursuing interactive, real-time HTTP interception proxy parity with mature manual pentesting tools such as Burp Suite Professional or OWASP ZAP.

### Motive
1. **Model Mismatch**: Interactive interception requires in-line, sub-millisecond proxying of human-driven browser traffic with stateful GUI manipulation and dynamic request tampering. FixGuard's architecture is fundamentally built upon **deferred, authorized batch evaluation** with atomic preflight validation, continuous execution lineage, and asynchronous human authorization gates.
2. **Defensive ASM Focus**: FixGuard is designed for automated, reproducible, defensive Attack Surface Management and differential observation. Live traffic interception introduces massive runtime complexity without contributing to verifiable evidence custody or differential signal comparison.

### Consequences
- FixGuard does not implement a local interception HTTP proxy daemon or browser certificate injection system for real-time manual tampering.
- Assessments operate on explicitly authorized targets via scheduled or requested batches passing the two-pass atomic preflight.

---

## 2. Rejection of Native SAST Built From Scratch

### Decision
FixGuard explicitly **rejects** building a proprietary Static Application Security Testing (SAST) engine, AST parser, or taint-analysis framework from scratch.

### Motive
1. **Engine Maturity**: High-quality static analysis requires abstract syntax tree (AST) construction, control-flow graphing, data-flow analysis, and constantly maintained rule sets across dozens of programming languages. Recreating this from scratch requires hundreds of engineer-years and is wholly outside FixGuard's mission.
2. **Ports & Adapters Alignment**: In alignment with FixGuard's Clean Architecture, code-level static analysis will be integrated strictly by wrapping mature, industry-standard, audited open-source tools (such as Semgrep, TruffleHog, or Gitleaks) behind typed port interfaces (`*Tool` ports).

### Consequences
- FixGuard focuses solely on orchestration, input sanitization, process isolation (`ProcessRunner` with `shell: false`), output normalization, secret redaction, and human review custody.
- No native rule compilers or AST engines will be authored in the FixGuard codebase.

---

## 3. Rejection of Mature Tool Reimplementation

### Decision
FixGuard explicitly **rejects** reimplementing mature network discovery, DNS resolution, port scanning, directory fuzzing, or parameter discovery utilities in native TypeScript or Node.js.

### Motive
1. **Battle-Tested Reliability**: Tools like `subfinder`, `naabu`, `httpx`, `ffuf`, `dnsx`, `tlsx`, and `arjun` represent years of community hardening against edge cases, network timeouts, protocol variations, and edge-server quirks.
2. **Core Value Proposition**: FixGuard's value lies in **trust, authority, and evidence**:
   - Runtime-established authorization branding (`VerifiedAuthorizationDecision`).
   - Atomic preflight safety gates (aborting unauthorized batches with zero packets transmitted).
   - SSRF and private network egress containment (`PassiveEgressPolicy`).
   - Factual non-claims and anti-speculation enforcement.
   - Human-in-the-loop review and formal candidate promotion.
   The underlying CLI tools are execution primitives ("Tools execute. Intelligence decides. Humans authorize.").

### Consequences
- All reconnaissance tools are wrapped as thin, isolated adapters consuming `ProcessRunner.execute({ shell: false })`.
- Adapters enforce strict parameter array construction, safe path containment, SSRF egress validation, and fail-closed JSON stream parsing.

---

## 4. Summary Matrix

| Capability Area | Native Reimplementation? | Strategy in FixGuard V2 |
|---|---|---|
| **Interactive Proxy (Burp/ZAP)** | **REJECTED** | Deferred, authorized batch validation with atomic preflight. |
| **Static Code Analysis (SAST)** | **REJECTED** | Wrap mature engines (e.g. Semgrep) via typed tool adapters. |
| **Network & Web Discovery Tools** | **REJECTED** | Wrap proven binaries (`subfinder`, `naabu`, `httpx`, etc.) via `ProcessRunner`. |
| **Authority & Evidence Custody** | **CORE NATIVE** | Native DDD domain models, WeakSet branding, and human review gates. |
