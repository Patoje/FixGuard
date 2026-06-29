# Milestone 30: Authorized Scope / Egress Policy Boundary

This milestone introduces a pure, deterministic egress and scope policy module. It provides a formal contract for answering "is this exact outbound request authorized and safe?" before any real network execution occurs. This is a crucial foundation for M31 (which will introduce actual network fetching).

**Central FixGuard product principle for M30 Policy Posture:**
*Permissive inside authorized public scope.*
*Strict outside authorized scope.*
*Preserve everything.*
*Classify sensitive material safely.*

## User Review Required
> [!IMPORTANT]
> This milestone strictly enforces that **no network requests (fetch, http, sockets, DNS) are made**. The policy relies entirely on string analysis and built-in URL parsing to prevent SSRF and out-of-scope egress. DNS resolution for non-literal IPs is deferred to future milestones.

## Proposed Changes

---

### Egress Policy Contracts

#### [NEW] [EgressPolicyContracts.ts](file:///d:/FixGuard/worker/src/v2/recon/policy/EgressPolicyContracts.ts)
- Define the primary `AuthorizedScope` contract and the decision model:
```ts
export type EgressPolicyDecision =
  | { decision: 'allow'; normalizedTarget: NormalizedTargetUrl; reasons: string[]; sensitiveQueryKeys?: string[] }
  | { decision: 'block'; normalizedTarget?: NormalizedTargetUrl; blockReason: EgressPolicyBlockReason; safeDisplayUrl?: string }
  | { decision: 'candidate'; candidate: DiscoveredScopeCandidate; reason: string; safeDisplayUrl: string };
```
- A discovered subdomain is modeled as a candidate. It is not automatically an executable target. Future milestones may add explicit scope expansion after reconnaissance and human approval.
- Blocked policy decisions are purely deterministic decisions. They are not vulnerability findings, and not target evidence. Future runtime integration may persist them as audit/policy events.

### Target Normalization

#### [NEW] [TargetUrlNormalizer.ts](file:///d:/FixGuard/worker/src/v2/recon/policy/TargetUrlNormalizer.ts)
- Implement deterministic URL normalization using Node's built-in `URL` class.
- Enforce scheme allowlist (`http:` and `https:`).
- Normalize default ports (remove `:80` for `http:`, `:443` for `https:`).
- Reject credentials inside the URL, excessively long URLs, empty hosts, and malformed structures.
- **Sensitive Keys Classification**: Preserve the raw query string internally, but identify keys such as `token`, `access_token`, `api_key`, `apikey`, `key`, `secret`, `password`, `passwd`, `auth`, `authorization`, `session`, `jwt`.
- Produce a `safeDisplayUrl` with sensitive key values safely redacted for use in logs and output.

### Passive Egress Policy Evaluator

#### [NEW] [PassiveEgressPolicy.ts](file:///d:/FixGuard/worker/src/v2/recon/policy/PassiveEgressPolicy.ts)
- Implement `evaluate({ targetUrl, authorizedScope, capabilityId }): EgressPolicyDecision`.
- Enforce deterministic SSRF blocks based on string matching:
  - Reject `localhost`, `*.localhost`, `127.0.0.0/8`, `0.0.0.0`, `::1`
  - Reject RFC1918 private IPs (`10/8`, `172.16/12`, `192.168/16`)
  - Reject link-local and cloud metadata targets (especially `169.254.169.254`)
  - Reject IPv6 loopback, link-local, and unique local addresses.
- Evaluate the normalized URL against the provided `AuthorizedScope`:
  - Allow the exact authorized public URL/origin.
  - Allow same-host paths under the authorized origin (if `allowSameHostPaths` is true).
  - Out-of-scope public hosts are blocked.
  - Subdomains are returned as a `candidate` decision (a `DiscoveredScopeCandidate`), preventing automatic execution.

### Documentation

#### [NEW] [FIXGUARD_V2_SCOPE_EGRESS_POLICY_PLAN.md](file:///d:/FixGuard/FIXGUARD_V2_SCOPE_EGRESS_POLICY_PLAN.md)
- Document the policy rules, target normalization strategy, and the fact that M30 creates pure decisions with no persistence.
- **Redirect Policy**: Define that redirects are not followed in M30. Future real HTTP adapters must re-check egress policy on every redirect hop, and cross-host redirects are blocked by default unless authorized.

#### [MODIFY] [FIXGUARD_V2_IMPLEMENTATION_STATUS.md](file:///d:/FixGuard/FIXGUARD_V2_IMPLEMENTATION_STATUS.md)
- Update the implementation status to include M30.

### Validation and Smoke Tests

#### [NEW] [milestone30_scope_egress_policy_smoke.ts](file:///d:/FixGuard/worker/src/v2/smoke/milestone30_scope_egress_policy_smoke.ts)
- Add comprehensive smoke tests proving:
  - Authorized exact public HTTP URL is allowed.
  - Authorized exact public HTTPS URL is allowed.
  - Same-host path under authorized origin is allowed if configured.
  - Out-of-scope public host is blocked.
  - Discovered subdomain is returned as candidate, not executable target.
  - Malformed URL is blocked.
  - Unsupported scheme is blocked.
  - `localhost`, `127.0.0.1`, `::1`, private IPv4 ranges, link-local and cloud metadata targets (`169.254.169.254`) are blocked.
  - Credential-bearing URLs are blocked.
  - Query params are normalized deterministically.
  - Sensitive query keys are classified.
  - `safeDisplayUrl` redacts sensitive values.
  - **No network is performed, no DNS is performed.**
  - **No evidence/finding is created.**
  - **Blocked policy decisions are not vulnerability findings.**

#### [MODIFY] [package.json](file:///d:/FixGuard/worker/package.json)
- Add `"smoke:v2:recon": "tsx src/v2/smoke/milestone30_scope_egress_policy_smoke.ts"`
- Update `"smoke:v2"` to include `npm run smoke:v2:recon`.
- Ensure typecheck covers the new policy and smoke test files.

## Verification Plan

### Automated Tests
- Run `npm run typecheck:v2`.
- Run `npx tsx src/v2/smoke/milestone30_scope_egress_policy_smoke.ts`.
- Run `npm run smoke:v2` and `npm run check:v2`.

### Static Analysis
- Run `rg` commands to statically verify absolutely no `fetch`, `http.request`, `dns`, `child_process`, or scanner binaries exist in the new `policy` module.
- Confirm zero changes to `package-lock.json` and zero new dependencies.
