# Egress Policy Audit Boundary (M33)

This directory (`worker/src/v2/recon/audit/`) contains the M33 egress policy audit/control-plane event boundary for FixGuard V2.

## Purpose

Represent M30 egress policy decisions (`allow`, `block`, `candidate`) as sanitized, structured control-plane audit events — without treating blocks or candidates as findings, without leaking secrets, and without adding persistence, Postgres, or runtime integration.

These events answer:

> Can FixGuard represent allow/block/candidate egress policy decisions as sanitized audit/control-plane events, while remaining DB-free, network-free, runtime-free, and storage-free?

## Files

| File | Purpose |
|---|---|
| `EgressPolicyAuditContracts.ts` | Strict TypeScript event shape and result types. |
| `EgressPolicyAuditMapper.ts` | Pure mapper from M30 `EgressPolicyDecision` → `EgressPolicyAuditEvent`. |
| `InMemoryEgressPolicyAuditRecorder.ts` | In-memory, test-only event recorder. |

## Event Shape

Each event is of kind `egress_policy_decision` and carries:

- `decision`: `allow` | `block` | `candidate`
- `target.safeDisplayUrl`: safe-for-logs URL (credentials/secrets redacted by M30 normalizer)
- `policy`: sanitized block reason, candidate reason, or allow reason
- `scope`: optional sanitized scope metadata (credential origins stripped)
- `classification`: literal flags — `controlPlaneEvent: true`, `finding: false`, `evidence: false`, `vulnerability: false`, `riskClaim: false`
- `safety`: literal flags — `sensitiveValuesRedacted: true`, `containsRawSecret: false`, `rawRequestPersisted: false`, `executablePayloadPersisted: false`

## What These Events Are NOT

| Property | Value |
|---|---|
| Findings | ❌ Never |
| Evidence | ❌ Never |
| Vulnerabilities | ❌ Never |
| Risk claims | ❌ Never |
| Executable payloads | ❌ Never |
| Raw requests | ❌ Never |
| Raw secrets | ❌ Never |
| Raw URLs with credentials | ❌ Never |
| Scanner output | ❌ Never |

## Forbidden Event Fields

The following fields must never appear in an `EgressPolicyAuditEvent`:

```
binary, args, env, shell, command, stdin, executable, runner, adapterCommand,
rawUrl, originalUrl, rawRequest, requestBody, responseBody, headers, cookies,
authorization, token, password, secret, apiKey, setCookie, scannerOutput,
finding, riskScore, severity, impact, exploit, payload, stackTrace,
capabilityRequest, CapabilityRequest, executionRequest, ExecutionRequest
```

The `InMemoryEgressPolicyAuditRecorder` enforces this by rejecting any event containing these top-level keys.

## Mapper Strategy

The mapper:
- Accepts M30 `EgressPolicyDecision` objects.
- Always uses `safeDisplayUrl` from M30 — never reconstructs raw URLs manually.
- Strips credentials from scope origin metadata.
- Emits literal `true`/`false` classification and safety flags.
- Is pure — no side effects, no network, no DB, no runtime.

## Recorder Strategy

The `InMemoryEgressPolicyAuditRecorder`:
- Is instantiated explicitly — no global singleton.
- Reads no env/config.
- Has no persistence, no DB client, no runtime integration.
- Stores deep-cloned event objects (JSON round-trip).
- Returns deep clones on every read — external mutation cannot affect internal state.
- Preserves insertion order.
- Rejects events with forbidden fields.
- Rejects events with incorrect classification/safety literal flags.

## Milestone 33 Rules

- **DB-free**: No Drizzle, Postgres, or DB client imports.
- **Network-free**: No `node:http`, `node:https`, `node:dns`, `fetch`, or socket imports.
- **Runtime-free**: No `V2AssessmentRuntime` or runtime composition imports.
- **Storage-free**: No `AssessmentRepository` or storage imports.
- **Findings-free**: Block and candidate decisions never become findings, evidence, or vulnerability claims.
- **Secret-free**: No raw credentials, tokens, passwords, or sensitive query values in events.
- **Excluded from runtime default**: The audit boundary is not wired into `V2AssessmentRuntime` or production composition. That is a future milestone.
- **No production-readiness claim**: The in-memory recorder is not production audit storage.

## Future Work

- Persistent audit storage (separate milestone).
- Runtime default recording integration (separate milestone).
- Report rendering and audit trail UI (separate milestone).
