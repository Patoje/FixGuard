# M46 — Authorized Scope + Permission Policy Boundary

## Purpose

M46 defines a DB-free, pure-function boundary for representing and evaluating layered authorization and scope policy decisions.

M46 separates **authorization declaration** (what a human has permitted) from **per-action permission decisions** (whether a specific action is allowed within that scope).

## What M46 does

- Validates `AuthorizedScopeGrant` — the structured, human-declared authorization record.
- Validates `ScopeActionRequest` — a proposed action to evaluate.
- Derives the required permission for an action from `actionKind` + `intensity` (caller-sent `requiredPermission` is never trusted).
- Evaluates a `ScopePolicyDecision` deterministically using a fixed precedence order.

## What M46 does NOT do

- Does not execute tools.
- Does not touch the network.
- Does not verify domain ownership.
- Does not persist scope grants.
- Does not create findings, evidence, severity, risk or impact claims.
- Does not deny based on IP/CIDR scope (not supported in M46).
- Does not replace M30 egress policy.

## Separation from M30/M33

| Concern | Module |
|---|---|
| Authorized scope / permission per action | **M46** |
| Network egress safety / allowed URL decision | **M30/M33** |

Future active execution must pass **both** M46 and M30/M33 decisions before any tool adapter is invoked.

Expected future flow:
```
Human grant → M46 permission decision → M30/M33 egress decision → tool adapter
```

## Decision Precedence (deterministic)

1. invalid grant
2. invalid request
3. destructive operation / destructive intensity
4. expired grant
5. scan mismatch
6. target out of scope
7. denied path (deniedPathPatterns win)
8. allowed path mismatch
9. denied method (deniedMethods win)
10. allowed method mismatch
11. credentials/auth requirements
12. OOB requirements
13. state-changing restrictions
14. missing derived permission
15. allowed

## Path Matching

- `exact`: request pathTemplate must equal pattern pathTemplate exactly.
- `prefix`: request path must equal pattern OR start with `pattern + "/"` — ensuring `/api` does NOT match `/apiary`.
- No glob, no regex, no `*`.
- `deniedPathPatterns` always take priority over `allowedPathPatterns`.

## Permission Derivation

The service always derives the required permission from `actionKind` and `intensity`. The caller may send `requiredPermission` as a hint, but if it doesn't match the derived value the request is rejected (`denied_invalid_request`).

Intensity may upgrade (raise) a permission requirement but never downgrade it.

## Safety Invariants

- `destructiveOperations` is always `false` in `PermissionSet`.
- `allowThirdPartyTargets` is always `false` in `ScopeConstraints`.
- All classification flags are always `false`: `createsRealFindings`, `createsPersistedEvidence`, `confirmsVulnerabilities`, `makesRiskClaims`, `makesSeverityClaims`, `makesImpactClaims`, `executesNetwork`, `executesTools`, `persistsData`.
- Unknown fields in any object are rejected (strict allowed-key validation).
- All arrays are validated with `Array.isArray` before iteration.
- All free text is scanned for forbidden content (secrets, raw request/response, tokens, etc.).

## Future Gates

Milestones for crawler, OOB, Nuclei, ZAP, ffuf, sqlmap, authenticated testing and aggressive validation must pass through this boundary before execution.
