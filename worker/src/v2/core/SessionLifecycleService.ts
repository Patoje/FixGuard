/**
 * Milestone F3 — Session Lifecycle Service
 *
 * Implements pre-execution health validation, expiration verification,
 * and token refresh hook orchestration.
 */

import type {
  TargetSessionState,
  SessionValidationResult
} from './SessionLifecycleContracts.js';

export async function validateSessionHealth(
  sessionState?: TargetSessionState,
  currentIsoTimestamp?: string
): Promise<SessionValidationResult> {
  const nowIso = currentIsoTimestamp ?? new Date().toISOString();
  const nowMs = Date.parse(nowIso);

  // If no session state is provided, default to active (backward compatibility)
  if (!sessionState) {
    return {
      ok: true,
      sessionState: {
        state: 'active',
        lastValidatedAt: nowIso
      }
    };
  }

  // Explicitly marked invalid
  if (sessionState.state === 'invalid') {
    return {
      ok: false,
      sessionState: {
        ...sessionState,
        lastValidatedAt: nowIso
      },
      reasonCode: 'session_invalid'
    };
  }

  const isExpiredByTime =
    typeof sessionState.expiresAt === 'string' &&
    !Number.isNaN(Date.parse(sessionState.expiresAt)) &&
    Date.parse(sessionState.expiresAt) <= nowMs;

  const isExpired = sessionState.state === 'expired' || isExpiredByTime;

  if (isExpired) {
    if (typeof sessionState.tokenRefreshHook === 'function') {
      try {
        const refreshResult = await sessionState.tokenRefreshHook();
        if (refreshResult.ok) {
          const refreshedSession: TargetSessionState = {
            state: 'active',
            expiresAt: refreshResult.newExpiresAt ?? sessionState.expiresAt,
            tokenRefreshHook: sessionState.tokenRefreshHook,
            lastValidatedAt: nowIso
          };
          return {
            ok: true,
            sessionState: refreshedSession,
            updatedHeaders: refreshResult.updatedHeaders
          };
        }
      } catch {
        // Refresh threw error, fail closed
      }
    }

    return {
      ok: false,
      sessionState: {
        ...sessionState,
        state: 'expired',
        lastValidatedAt: nowIso
      },
      reasonCode: 'session_expired'
    };
  }

  // Session is active and unexpired
  return {
    ok: true,
    sessionState: {
      ...sessionState,
      state: 'active',
      lastValidatedAt: nowIso
    }
  };
}
