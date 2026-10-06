/**
 * FixGuard V2 — Session Sanctuary Contracts.
 * Contract version: fixguard-session-sanctuary/v0
 *
 * Provides typed models for first-class assessment session contexts:
 * - anonymous context (isolated, pristine)
 * - authenticated context (Identity A, protected sanctuary)
 * - authenticated_secondary context (Identity B, optional peer)
 *
 * Invariants:
 * 1. Isolated contexts: anonymous and authenticated never share mutable cookies/headers.
 * 2. Secret Redaction: raw cookies, Authorization headers, and sensitive tokens are
 *    redacted at all diagnostic, logging, and reporting boundaries.
 * 3. Epistemic honesty: canary health validation classifies state; never assumes validity forever.
 */

export const SESSION_SANCTUARY_CONTRACT_VERSION = 'fixguard-session-sanctuary/v0' as const;
export type SessionSanctuaryContractVersion = typeof SESSION_SANCTUARY_CONTRACT_VERSION;

export type SessionContextKind = 'anonymous' | 'authenticated' | 'authenticated_secondary';

export type SessionHealthState =
  | 'valid'
  | 'degraded'
  | 'expired'
  | 'challenged'
  | 'rejected'
  | 'unknown';

export type SessionAuthenticationState =
  | 'anonymous'
  | 'authenticated'
  | 'auth_lost'
  | 'unauthenticated';

export type SessionChallengeState =
  | 'none'
  | 'detected'
  | 'waiting_for_operator'
  | 'operator_completed'
  | 'validation_pending'
  | 'resolved'
  | 'failed';

export interface AssessmentSessionContext {
  readonly contractVersion: SessionSanctuaryContractVersion;
  readonly contextId: string;
  readonly kind: SessionContextKind;
  readonly targetDomain: string;
  readonly originUrl: string;
  /** Raw headers held in sanctuary. Never emitted in safe descriptors. */
  readonly headers: Readonly<Record<string, string>>;
  /** Raw cookies held in sanctuary. Never emitted in safe descriptors. */
  readonly cookies: Readonly<Record<string, string>>;
  readonly healthState: SessionHealthState;
  readonly authenticationState: SessionAuthenticationState;
  readonly challengeState: SessionChallengeState;
  readonly browserStorageRef?: string;
  readonly createdAt: string;
  readonly lastValidatedAt: string;
  readonly lastHealthReason?: string;
}

/**
 * Safe, secret-free summary for logs, telemetry, and assessment records.
 */
export interface SafeSessionContextDescriptor {
  readonly contextId: string;
  readonly kind: SessionContextKind;
  readonly targetDomain: string;
  readonly headerNames: readonly string[];
  readonly cookieNames: readonly string[];
  readonly healthState: SessionHealthState;
  readonly authenticationState: SessionAuthenticationState;
  readonly challengeState: SessionChallengeState;
  readonly createdAt: string;
  readonly lastValidatedAt: string;
  readonly lastHealthReason?: string;
}

export interface SessionCanaryResult {
  readonly contextId: string;
  readonly kind: SessionContextKind;
  readonly healthState: SessionHealthState;
  readonly authenticationState: SessionAuthenticationState;
  readonly challengeState: SessionChallengeState;
  readonly reason: string;
  readonly checkedAt: string;
  readonly statusCode?: number;
  readonly responseTimeMs?: number;
}

const SENSITIVE_HEADER_PATTERN =
  /^(authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token|token|bearer|apikey|proxy-authorization)$/i;

const SENSITIVE_COOKIE_PATTERN =
  /^(session|sessionid|sess|token|jwt|auth|authtoken|access_token|refresh_token|connect\.sid|phpsessid|jsessionid|remember_token)$/i;

/** Redacts sensitive header values while keeping non-sensitive structural headers. */
export function redactSensitiveHeaders(
  headers: Readonly<Record<string, string>>
): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (SENSITIVE_HEADER_PATTERN.test(key.trim())) {
      result[key] = '[REDACTED]';
    } else {
      result[key] = value;
    }
  }
  return result;
}

/** Redacts sensitive cookie values. */
export function redactSensitiveCookies(
  cookies: Readonly<Record<string, string>>
): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(cookies)) {
    if (SENSITIVE_COOKIE_PATTERN.test(key.trim()) || value.length > 32) {
      result[key] = '[REDACTED]';
    } else {
      result[key] = '[REDACTED]';
    }
  }
  return result;
}

/** Projects an internal session context into a safe descriptor with 0 secrets. */
export function toSafeSessionDescriptor(
  context: AssessmentSessionContext
): SafeSessionContextDescriptor {
  return Object.freeze({
    contextId: context.contextId,
    kind: context.kind,
    targetDomain: context.targetDomain,
    headerNames: Object.freeze(Object.keys(context.headers)),
    cookieNames: Object.freeze(Object.keys(context.cookies)),
    healthState: context.healthState,
    authenticationState: context.authenticationState,
    challengeState: context.challengeState,
    createdAt: context.createdAt,
    lastValidatedAt: context.lastValidatedAt,
    ...(context.lastHealthReason ? { lastHealthReason: context.lastHealthReason } : {}),
  });
}
