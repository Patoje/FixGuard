/**
 * EgressPolicyAuditMapper.ts
 *
 * Pure mapper from M30 EgressPolicyDecision → EgressPolicyAuditEvent.
 *
 * Rules:
 *  - Pure / deterministic (except eventId/observedAt which are injected or generated).
 *  - No network, no DB, no runtime, no storage, no process.env, no scanner imports.
 *  - Never echoes raw secrets, credentials, or unsupported-scheme payloads.
 *  - Block/candidate decisions do NOT become findings, evidence, or vulnerability claims.
 *  - Always uses safeDisplayUrl from the M30 decision — never reconstructs unsafe raw URLs.
 *  - If safeDisplayUrl is missing/unsafe, falls back to the static safe marker '[policy-redacted]'.
 */

import type { EgressPolicyDecision, AuthorizedScope } from '../policy/EgressPolicyContracts';
import type { EgressPolicyAuditEvent } from './EgressPolicyAuditContracts';

/** Literal constant classification block — always the same for every event. */
const CLASSIFICATION = {
  controlPlaneEvent: true,
  finding: false,
  evidence: false,
  vulnerability: false,
  riskClaim: false,
} as const;

/** Literal constant safety block — always the same for every event. */
const SAFETY = {
  sensitiveValuesRedacted: true,
  containsRawSecret: false,
  rawRequestPersisted: false,
  executablePayloadPersisted: false,
} as const;

/** Safe static marker used when a safeDisplayUrl is absent or cannot be trusted. */
const SAFE_FALLBACK_URL = '[policy-redacted]';

/**
 * Allowed URI schemes for the target.scheme field.
 * Only http and https are representable; anything else is omitted.
 */
function toSafeScheme(scheme: string | undefined): 'http' | 'https' | undefined {
  if (scheme === 'http:' || scheme === 'http') return 'http';
  if (scheme === 'https:' || scheme === 'https') return 'https';
  return undefined;
}

/**
 * Sanitize a safeDisplayUrl value from M30.
 * If the value is absent, empty, or appears to contain credentials (@ char before host)
 * it is replaced with the static safe marker.
 *
 * The M30 normalizer is expected to have already redacted sensitive values,
 * but we defensively verify here so the mapper cannot be bypassed.
 */
function sanitizeSafeDisplayUrl(raw: string | undefined): string {
  if (!raw || raw.trim() === '') return SAFE_FALLBACK_URL;

  // If it looks like a credential-bearing URL pattern, replace with safe marker
  // Pattern: scheme://user:pass@host or scheme://user@host
  try {
    const parsed = new URL(raw);
    if (parsed.username || parsed.password) return SAFE_FALLBACK_URL;
  } catch {
    // raw may be a static marker like '[unsupported-url]' — that is fine, keep it
  }

  return raw;
}

/**
 * Sanitize an allowed origin for safe inclusion in scope metadata.
 * Origins are user-supplied scope configuration; they should not contain secrets
 * but we defensively strip credentials if present.
 */
function sanitizeSafeOrigin(origin: string): string {
  try {
    const parsed = new URL(origin);
    if (parsed.username || parsed.password) {
      // Strip credentials from origin representation
      return `${parsed.protocol}//${parsed.host}`;
    }
    return `${parsed.protocol}//${parsed.host}`;
  } catch {
    return '[invalid-origin]';
  }
}

export interface MapperOptions {
  /** Provided externally for deterministic tests; otherwise crypto.randomUUID() is used. */
  eventId?: string;
  /** ISO 8601 string; defaults to new Date().toISOString() */
  observedAt?: string;
  /** Capability that triggered the policy evaluation. */
  capabilityId: string;
  /** Optional: include sanitized scope metadata in the event. */
  authorizedScope?: AuthorizedScope;
}

/**
 * Map a single M30 EgressPolicyDecision to a sanitized EgressPolicyAuditEvent.
 *
 * Pure — no side effects, no network, no DB, no runtime.
 */
export function mapDecisionToAuditEvent(
  decision: EgressPolicyDecision,
  options: MapperOptions,
): EgressPolicyAuditEvent {
  const eventId = options.eventId ?? generateEventId();
  const observedAt = options.observedAt ?? new Date().toISOString();

  const safeScope = options.authorizedScope
    ? {
        safeAllowedOrigins: options.authorizedScope.allowedOrigins.map(sanitizeSafeOrigin),
        sameHostPathsAllowed: options.authorizedScope.allowSameHostPaths,
        subdomainsAllowed: options.authorizedScope.allowSubdomains,
      }
    : undefined;

  if (decision.decision === 'allow') {
    const nt = decision.normalizedTarget;
    return {
      eventKind: 'egress_policy_decision',
      eventVersion: 1,
      eventId,
      observedAt,
      capabilityId: options.capabilityId,
      decision: 'allow',
      target: {
        safeDisplayUrl: sanitizeSafeDisplayUrl(decision.safeDisplayUrl),
        scheme: toSafeScheme(nt.scheme),
        hostname: nt.hostname,
        normalizedOrigin: `${toSafeScheme(nt.scheme) ?? ''}://${nt.hostname}`,
      },
      policy: {
        reason: decision.reasons.join('; '),
      },
      scope: safeScope,
      classification: CLASSIFICATION,
      safety: SAFETY,
    };
  }

  if (decision.decision === 'block') {
    const nt = decision.normalizedTarget;
    return {
      eventKind: 'egress_policy_decision',
      eventVersion: 1,
      eventId,
      observedAt,
      capabilityId: options.capabilityId,
      decision: 'block',
      target: {
        safeDisplayUrl: sanitizeSafeDisplayUrl(decision.safeDisplayUrl),
        scheme: nt ? toSafeScheme(nt.scheme) : undefined,
        hostname: nt?.hostname,
        normalizedOrigin: nt ? `${toSafeScheme(nt.scheme) ?? ''}://${nt.hostname}` : undefined,
      },
      policy: {
        blockReason: decision.blockReason,
      },
      scope: safeScope,
      classification: CLASSIFICATION,
      safety: SAFETY,
    };
  }

  // decision === 'candidate'
  return {
    eventKind: 'egress_policy_decision',
    eventVersion: 1,
    eventId,
    observedAt,
    capabilityId: options.capabilityId,
    decision: 'candidate',
    target: {
      safeDisplayUrl: sanitizeSafeDisplayUrl(decision.safeDisplayUrl),
    },
    policy: {
      candidateReason: decision.reason,
    },
    scope: safeScope,
    classification: CLASSIFICATION,
    safety: SAFETY,
  };
}

/**
 * Generate a simple event ID without external dependencies.
 * Uses Math.random() + timestamp — sufficient for in-memory audit records.
 */
function generateEventId(): string {
  const ts = Date.now().toString(36);
  const rand = Math.random().toString(36).slice(2, 10);
  return `epae_${ts}_${rand}`;
}
