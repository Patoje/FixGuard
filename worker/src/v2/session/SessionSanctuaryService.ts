/**
 * FixGuard V2 — Session Sanctuary Service.
 *
 * Implements isolated management of assessment session contexts:
 * - anonymous context (isolated from authenticated cookies)
 * - authenticated context (Identity A, protected sanctuary)
 * - authenticated_secondary context (Identity B, optional peer)
 *
 * Guarantees:
 * 1. Zero cookie leakage between contexts.
 * 2. Immutable state transitions.
 * 3. Canary health checks without destructive side-effects.
 * 4. Zero secrets in string representations, logs, and descriptors.
 */

import type {
  ByotIdentity,
  ByotSessionIdentityBundle,
  IdorHttpProbeTransport,
} from '../detection/DetectionContracts.js';
import {
  SESSION_SANCTUARY_CONTRACT_VERSION,
  toSafeSessionDescriptor,
  type AssessmentSessionContext,
  type SafeSessionContextDescriptor,
  type SessionCanaryResult,
  type SessionChallengeState,
  type SessionContextKind,
  type SessionHealthState,
} from './SessionSanctuaryContracts.js';
import { observeDefensesFromHttpResponse } from '../test-validity/DefenseObservationService.js';

export interface CreateSessionSanctuaryOptions {
  readonly targetDomain: string;
  readonly originUrl: string;
  readonly sessionIdentities?: ByotSessionIdentityBundle;
  readonly nowIso?: string;
}

export class SessionSanctuaryService {
  private contexts: Map<SessionContextKind, AssessmentSessionContext> = new Map();
  private readonly targetDomain: string;
  private readonly originUrl: string;

  constructor(options: CreateSessionSanctuaryOptions) {
    this.targetDomain = options.targetDomain;
    this.originUrl = options.originUrl;
    const now = options.nowIso ?? new Date().toISOString();

    // 1. Always establish an isolated anonymous context
    const anonContext: AssessmentSessionContext = Object.freeze({
      contractVersion: SESSION_SANCTUARY_CONTRACT_VERSION,
      contextId: `ctx_anon_${this.hashPrefix(this.targetDomain)}`,
      kind: 'anonymous',
      targetDomain: this.targetDomain,
      originUrl: this.originUrl,
      headers: Object.freeze({}),
      cookies: Object.freeze({}),
      healthState: 'unknown',
      authenticationState: 'anonymous',
      challengeState: 'none',
      createdAt: now,
      lastValidatedAt: now,
    });
    this.contexts.set('anonymous', anonContext);

    // 2. Establish isolated authenticated context if Identity A is supplied
    if (options.sessionIdentities?.identityA) {
      const authA = this.buildContextFromByot(
        'authenticated',
        options.sessionIdentities.identityA,
        now
      );
      this.contexts.set('authenticated', authA);
    }

    // 3. Establish secondary authenticated context if Identity B is supplied
    if (options.sessionIdentities?.identityB) {
      const authB = this.buildContextFromByot(
        'authenticated_secondary',
        options.sessionIdentities.identityB,
        now
      );
      this.contexts.set('authenticated_secondary', authB);
    }
  }

  private hashPrefix(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = (hash << 5) - hash + str.charCodeAt(i);
      hash |= 0;
    }
    return Math.abs(hash).toString(36).slice(0, 6);
  }

  private buildContextFromByot(
    kind: 'authenticated' | 'authenticated_secondary',
    identity: ByotIdentity,
    now: string
  ): AssessmentSessionContext {
    const rawHeaders: Record<string, string> = {};
    if (identity.injectHeaders) {
      for (const [k, v] of Object.entries(identity.injectHeaders)) {
        if (typeof v === 'string' && v.trim().length > 0) {
          rawHeaders[k] = v;
        }
      }
    }

    const rawCookies: Record<string, string> = {};
    if (identity.injectCookies) {
      for (const [k, v] of Object.entries(identity.injectCookies)) {
        if (typeof v === 'string' && v.trim().length > 0) {
          rawCookies[k] = v;
        }
      }
    }

    return Object.freeze({
      contractVersion: SESSION_SANCTUARY_CONTRACT_VERSION,
      contextId: `ctx_${kind}_${identity.identityId}`,
      kind,
      targetDomain: this.targetDomain,
      originUrl: this.originUrl,
      headers: Object.freeze(rawHeaders),
      cookies: Object.freeze(rawCookies),
      healthState: 'unknown',
      authenticationState: 'authenticated',
      challengeState: 'none',
      createdAt: now,
      lastValidatedAt: now,
    });
  }

  public getContext(kind: SessionContextKind): AssessmentSessionContext | undefined {
    return this.contexts.get(kind);
  }

  public hasAuthenticatedContext(): boolean {
    const ctx = this.contexts.get('authenticated');
    return ctx !== undefined && ctx.healthState !== 'expired' && ctx.healthState !== 'rejected';
  }

  public getAllContexts(): readonly AssessmentSessionContext[] {
    return Object.freeze(Array.from(this.contexts.values()));
  }

  public getSafeDescriptors(): readonly SafeSessionContextDescriptor[] {
    return Object.freeze(
      Array.from(this.contexts.values()).map((ctx) => toSafeSessionDescriptor(ctx))
    );
  }

  /**
   * Generates probe headers with cookies & auth material for a specific context.
   * Completely isolated: anonymous context never gets auth headers/cookies.
   */
  public createProbeHeaders(kind: SessionContextKind): Record<string, string> {
    const ctx = this.contexts.get(kind);
    if (!ctx) return {};

    const headers: Record<string, string> = { ...ctx.headers };

    if (Object.keys(ctx.cookies).length > 0) {
      const cookieStr = Object.entries(ctx.cookies)
        .map(([k, v]) => `${k}=${v}`)
        .join('; ');
      const existing = headers['Cookie'] ?? headers['cookie'];
      headers['Cookie'] = existing ? `${existing}; ${cookieStr}` : cookieStr;
      delete headers['cookie'];
    }

    return headers;
  }

  /**
   * Performs an isolated, non-destructive health canary check.
   */
  public async validateSessionHealth(
    kind: SessionContextKind,
    transport: IdorHttpProbeTransport,
    canaryUrl?: string
  ): Promise<SessionCanaryResult> {
    const ctx = this.contexts.get(kind);
    const checkedAt = new Date().toISOString();
    if (!ctx) {
      return {
        contextId: `ctx_${kind}_missing`,
        kind,
        healthState: 'unknown',
        authenticationState: 'unauthenticated',
        challengeState: 'none',
        reason: `Context of kind '${kind}' is not configured in this sanctuary`,
        checkedAt,
      };
    }

    const targetUrl = canaryUrl ?? ctx.originUrl;
    const probeHeaders = this.createProbeHeaders(kind);

    try {
      const startTime = Date.now();
      const res = await transport({
        url: targetUrl,
        method: 'GET',
        headers: Object.freeze(probeHeaders),
        timeoutMs: 8000,
      });
      const responseTimeMs = Date.now() - startTime;

      // 1. Check for edge defenses / bot challenge
      const defenses = observeDefensesFromHttpResponse({
        statusCode: res.statusCode,
        headerValues: res.headers,
        bodyExcerpt: res.bodyText.slice(0, 500),
        targetHost: this.targetDomain,
      });

      const isChallenged = defenses.some(
        (d) =>
          d.controlKind === 'bot' ||
          d.signalSource === 'challenge_body' ||
          d.reasonCode.includes('challenge')
      );

      if (isChallenged) {
        this.updateContext(kind, {
          healthState: 'challenged',
          challengeState: 'detected',
          lastValidatedAt: checkedAt,
          lastHealthReason: 'Edge challenge detected during health canary probe',
        });
        return {
          contextId: ctx.contextId,
          kind,
          healthState: 'challenged',
          authenticationState: ctx.authenticationState,
          challengeState: 'detected',
          reason: 'Edge bot or WAF challenge encountered',
          checkedAt,
          statusCode: res.statusCode,
          responseTimeMs,
        };
      }

      // 2. Classify status for authenticated vs anonymous
      if (kind === 'anonymous') {
        const health: SessionHealthState = res.statusCode < 500 ? 'valid' : 'degraded';
        this.updateContext(kind, {
          healthState: health,
          lastValidatedAt: checkedAt,
          lastHealthReason: `Canary probe returned HTTP ${res.statusCode}`,
        });
        return {
          contextId: ctx.contextId,
          kind,
          healthState: health,
          authenticationState: 'anonymous',
          challengeState: 'none',
          reason: `Anonymous context baseline confirmed (HTTP ${res.statusCode})`,
          checkedAt,
          statusCode: res.statusCode,
          responseTimeMs,
        };
      }

      // 3. Authenticated context classification
      if (res.statusCode === 401) {
        this.updateContext(kind, {
          healthState: 'expired',
          authenticationState: 'auth_lost',
          lastValidatedAt: checkedAt,
          lastHealthReason: 'Canary probe received 401 Unauthorized',
        });
        return {
          contextId: ctx.contextId,
          kind,
          healthState: 'expired',
          authenticationState: 'auth_lost',
          challengeState: 'none',
          reason: 'Supplied credentials received 401 Unauthorized (session expired)',
          checkedAt,
          statusCode: res.statusCode,
          responseTimeMs,
        };
      }

      if (res.statusCode === 403) {
        const bodyLower = res.bodyText.toLowerCase();
        const isAuthRejection =
          bodyLower.includes('unauthorized') ||
          bodyLower.includes('forbidden') ||
          bodyLower.includes('invalid session') ||
          bodyLower.includes('token expired');

        const nextHealth: SessionHealthState = isAuthRejection ? 'rejected' : 'degraded';
        this.updateContext(kind, {
          healthState: nextHealth,
          authenticationState: isAuthRejection ? 'auth_lost' : ctx.authenticationState,
          lastValidatedAt: checkedAt,
          lastHealthReason: `Canary probe received 403 Forbidden: ${isAuthRejection ? 'auth rejected' : 'degraded'}`,
        });
        return {
          contextId: ctx.contextId,
          kind,
          healthState: nextHealth,
          authenticationState: isAuthRejection ? 'auth_lost' : ctx.authenticationState,
          challengeState: 'none',
          reason: isAuthRejection
            ? 'Credentials rejected by application authorization layer'
            : 'Access forbidden but not conclusively expired',
          checkedAt,
          statusCode: res.statusCode,
          responseTimeMs,
        };
      }

      // Check for redirect to login page
      const location = res.headers['location'] ?? res.headers['Location'];
      if (
        (res.statusCode === 301 || res.statusCode === 302 || res.statusCode === 307) &&
        location &&
        /\/login|\/signin|\/auth/i.test(location)
      ) {
        this.updateContext(kind, {
          healthState: 'expired',
          authenticationState: 'auth_lost',
          lastValidatedAt: checkedAt,
          lastHealthReason: `Redirected to login endpoint (${location})`,
        });
        return {
          contextId: ctx.contextId,
          kind,
          healthState: 'expired',
          authenticationState: 'auth_lost',
          challengeState: 'none',
          reason: `Authenticated probe was redirected to login: ${location}`,
          checkedAt,
          statusCode: res.statusCode,
          responseTimeMs,
        };
      }

      // Valid session
      this.updateContext(kind, {
        healthState: 'valid',
        authenticationState: 'authenticated',
        lastValidatedAt: checkedAt,
        lastHealthReason: `Canary verified with HTTP ${res.statusCode}`,
      });
      return {
        contextId: ctx.contextId,
        kind,
        healthState: 'valid',
        authenticationState: 'authenticated',
        challengeState: 'none',
        reason: `Authenticated session confirmed reachable (HTTP ${res.statusCode})`,
        checkedAt,
        statusCode: res.statusCode,
        responseTimeMs,
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.updateContext(kind, {
        healthState: 'degraded',
        lastValidatedAt: checkedAt,
        lastHealthReason: `Canary probe network transport failure: ${msg}`,
      });
      return {
        contextId: ctx.contextId,
        kind,
        healthState: 'degraded',
        authenticationState: ctx.authenticationState,
        challengeState: 'none',
        reason: `Transport error during health probe: ${msg}`,
        checkedAt,
      };
    }
  }

  /**
   * Merges freshly captured session cookies after a challenge or navigation
   * without mutating old contexts in-place.
   */
  public updateChallengeState(
    kind: SessionContextKind,
    challengeState: SessionChallengeState,
    newCookies?: Readonly<Record<string, string>>
  ): void {
    const ctx = this.contexts.get(kind);
    if (!ctx) return;

    const updatedCookies = newCookies
      ? Object.freeze({ ...ctx.cookies, ...newCookies })
      : ctx.cookies;

    this.updateContext(kind, {
      challengeState,
      cookies: updatedCookies,
      healthState: challengeState === 'resolved' ? 'valid' : ctx.healthState,
      lastValidatedAt: new Date().toISOString(),
    });
  }

  private updateContext(
    kind: SessionContextKind,
    patch: Partial<AssessmentSessionContext>
  ): void {
    const existing = this.contexts.get(kind);
    if (!existing) return;
    const updated: AssessmentSessionContext = Object.freeze({
      ...existing,
      ...patch,
    });
    this.contexts.set(kind, updated);
  }
}
