# FixGuard V2 — Forward Roadmap

> **Companion to** `docs/CURRENT_STATE.md` (read that first for the grounded picture of what exists today).
>
> **Permanent Axiom:** *"Tools execute. Intelligence decides. Humans authorize."*
>
> **Product direction (ADR-013):** depth of reconnaissance, application modeling, and classification — not breadth of automated exploitation.

**Last reconciled:** 2026-11-09 · **Branch:** `v2` · **HEAD:** `a059c7e`

---

## 0. Where We Stand (One Paragraph)

The recon → session → challenge-continuation → intelligence → human-review → advisory-planning pipeline is **real and working in-memory**. The last several weeks hardened the security spine: recon-health observability, cross-finding integrity, and a deep credential-isolation pass (redirects, ports, cookie fidelity) proven with real integration tests. The two things holding the system back from being a durable, trustworthy product are **(a) no durable persistence in the live path** and **(b) a large amount of dormant/frozen detection code and a frozen V1 still in the tree**. The natural next phase is consolidation and durability, not new features.

---

## 1. The Five Deficits (Fix These)

1. **No durable persistence in the live path.** Everything runs on `InMemory*Repository`; a restart loses every assessment, finding, plan, and evidence record. Postgres repositories + schema exist but are unwired. *This is the single highest-leverage fix.*
2. **Dead / frozen detection code at scale.** ~34 `detection/` services plus their smoke suites exist, but most are unreachable from production (ADR-013). This is thousands of lines of maintenance burden, confusing to new agents, and makes "what does FixGuard actually do?" hard to answer honestly.
3. **V1 monolith still in the tree.** Frozen and deprecated, but physically present under `worker/src/` and legacy `web/`. It inflates the codebase, confuses navigation, and risks accidental edits.
4. **Incomplete authenticated recon coverage.** Katana, gau, and trufflehog remain session-blind because their redirect/credential behavior was never verified safe. A resolved session does not reach the deepest crawl, URL-history, and secret-scan surfaces — the exact places authenticated depth matters most.
5. **No re-entry / scheduling for unresolved challenges.** Interactive challenges (no automated solver) and exhausted time-based challenges are reported as degraded, with no mechanism to revisit them later. Authenticated coverage behind such a challenge is simply lost for that run.

---

## 2. The Five Strengths (Build On These)

1. **Provably-correct credential isolation.** Cross-origin/cross-port confinement across httpx, ffuf, arjun, and Playwright is now backed by a real two-origin + real-Chromium + real-binary integration test — not mocks. This is a rare, trustworthy foundation to extend to the remaining transports.
2. **A mature recon + session + challenge spine.** The orchestrator, Session Sanctuary, and automatic bounded challenge continuation are a strong base; adding authenticated SPA/crawl depth is incremental, not architectural.
3. **A disciplined human-review / HITL boundary with continuous lineage.** Observations → reviewed evidence → findings, and advisory → authorized → executed plans, with the `{assessmentId, scanId, grantId, decisionId, actorId}` tuple intact. This is exactly the structure a durable store should persist.
4. **A deep smoke-test culture (178 suites).** Behavior is pinned by executable tests. Turning these into a CI gate (and pruning the dead ones) converts a strength-in-waiting into enforced quality.
5. **An advisory, non-executing attack-planning layer with real authorization/execution scaffolding.** The additive, never-auto-executing plan generator plus the `attack-authorization` / `attack-execution` subsystems are the right shape to mature into operator-authorized, lineage-tracked execution — safely.

---

## 3. Forward Roadmap (Natural Next Steps, In Order)

### Phase A — Consolidate & Make Durable *(highest priority; mostly closing gaps, not new features)*

- **A1. Wire Postgres into the live composition root.** Replace `InMemory*Repository` in `V2CompositionRoot.ts` with the existing Postgres repositories behind a config flag; keep in-memory for tests. Verify assessments, findings, evidence, and plans survive a restart. *Closes Deficit 1. Uses existing code.*
- **A2. Prune or quarantine dead detection code.** For each `detection/` service, confirm via call-site trace whether it is live. Move unreachable detectors (and their smoke scripts) into an explicit `detection/frozen/` quarantine or delete them, documented against ADR-013. *Closes Deficit 2.*
- **A3. Physically retire V1.** Remove or archive `worker/src/` (non-v2) and legacy `web/` surfaces that V2 has superseded. *Closes Deficit 3.*
- **A4. Make `check:v2` a CI gate.** Ensure the full suite runs in CI on every change to `worker/src/v2/**`, with non-zero exit on failure. *Builds on Strength 4.*

### Phase B — Deepen Authenticated Recon *(the product's core value per ADR-013)*

- **B1. Verify and thread session credentials into Katana** using the same real-integration-test method already proven for httpx/ffuf/arjun (two origins, capture headers, assert no cross-origin/port leak). *Closes part of Deficit 4. Uses Strength 1's test pattern.*
- **B2. Decide gau and trufflehog explicitly** — either verify-and-thread, or document them as permanently session-blind with the reason. No silent gaps.
- **B3. Authenticated SPA depth** — extend Playwright discovery to exercise authenticated routes the anonymous pass can't reach, using the confined-credential loop already built. *Builds on Strength 2.*

### Phase C — Challenge Recovery Beyond The In-Run Budget

- **C1. Owner-controlled challenge bypass as a first-class, authorized capability** — a reuse of the existing `CredentialVaultService` pattern so an operator can supply an owner-approved bypass (e.g., a scanner allowlist token) **through the authorization boundary**, not a manual cookie paste. *Addresses Deficit 5 for interactive challenges.*
- **C2. Scheduled re-entry** for time-based challenges — a bounded, authorized mechanism to revisit a `degraded_blocked` assessment later. *Addresses the rest of Deficit 5.*

### Phase D — Mature The Finding & Planning Layers

- **D1. Durable evidence + finding lifecycle** on top of Phase A's Postgres store — reviewed-evidence history, finding provenance, and dossier regeneration from persisted state. *Builds on Strength 3.*
- **D2. Operator-authorized attack execution** — graduate the advisory plan → authorization → execution path into a real, lineage-tracked, human-authorized flow using the existing `attack-authorization` / `attack-execution` scaffolding, one capability at a time, each behind HITL. *Builds on Strength 5, respecting ADR-013 (no automatic breadth).*

### Phase E — Reporting & Operator Experience

- **E1. Durable, regenerable Target Dossier** from persisted assessment state (not just the live in-memory snapshot).
- **E2. Honest coverage reporting** surfaced in the dossier — which challenges were detected/resolved, which transports were session-aware, and where authenticated coverage is incomplete.

---

## 4. Sequencing Rationale

Phase A comes first because every later phase is more valuable — and safer — on a durable store with a trimmed, honest codebase and a CI gate. Phase B is the product's stated core value (recon depth) and reuses the credential-isolation foundation just built. Phase C removes the last "challenge = lost coverage" gaps. Phases D and E turn a working engine into a product operators can trust over time. Nothing in this roadmap adds automated exploitation breadth, consistent with ADR-013.

---

## 5. Invariants That Must Not Regress (Any Phase)

- No self-authorization; verified decision + scope grant + egress gate on every network action.
- Credentials confined to the exact authorized origin (scheme + host + port); never cross-origin, cross-port, or to third-party subresources/redirects.
- Cookie lifetime and scope never silently broadened by FixGuard's import.
- Automatic challenge recovery stays automatic; no manual-resume UI/API reintroduced.
- Human approval mandatory for actions under the HITL model (attack-plan execution especially).
- `OBSERVED` / `INFERRED` / `RECOMMENDED` claim discipline; zero fabricated findings or severities.
- Continuous lineage end to end.
