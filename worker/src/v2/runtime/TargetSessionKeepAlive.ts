/**
 * FixGuard V2 — target session keep-alive (anti-idle).
 *
 * Periodically soft-pings in-scope hosts with BYOT/authenticated Identity A
 * (and B when present) so target session cookies do not idle-logout during
 * long orchestrated assessments.
 *
 * Distinct from AssessmentLivenessHeartbeat (UI liveness ~7s): this performs
 * real, gated network GETs against the authorized target.
 *
 * Safety:
 * - VerifiedAuthorizationDecision + AuthorizedScopeGrant + evaluateEgressPolicy
 *   via runAdapterPreflight (same double gate as other network actions).
 * - Fail-soft: tick errors never abort the assessment pipeline.
 * - Never fabricates findings; status hints contain no secrets/tokens.
 */

import type { VerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import type {
  ByotIdentity,
  ByotSessionIdentityBundle,
  IdorHttpProbeTransport,
  ProbeAuthContext,
} from '../detection/DetectionContracts.js';
import { runAdapterPreflight } from '../recon/adapters/AdapterPreflightPipeline.js';
import type { PreSpawnDnsResolver } from '../recon/adapters/AdapterPreflightPipeline.js';

/** Canonical keep-alive interval (~3.5 minutes). Matches V1 ~4 min intent. */
export const TARGET_SESSION_KEEPALIVE_INTERVAL_MS = 210_000;

/** Soft ping timeout — keep-alive must stay lightweight. */
export const TARGET_SESSION_KEEPALIVE_TIMEOUT_MS = 5_000;

export type TargetSessionKeepAliveIdentityStatus =
  | 'ok'
  | 'error'
  | 'preflight_denied'
  | 'skipped_no_auth';

export interface TargetSessionKeepAliveIdentityResult {
  readonly identityLabel: 'A' | 'B';
  readonly identityId: string;
  readonly status: TargetSessionKeepAliveIdentityStatus;
  readonly statusCode?: number;
  readonly reasonCode?: string;
}

export interface TargetSessionKeepAliveTick {
  readonly at: string;
  readonly targetUrl: string;
  readonly identityResults: readonly TargetSessionKeepAliveIdentityResult[];
}

export interface TargetSessionKeepAliveScheduleHandle {
  clear(): void;
}

export type TargetSessionKeepAliveScheduler = (
  handler: () => void,
  intervalMs: number
) => TargetSessionKeepAliveScheduleHandle;

const defaultScheduler: TargetSessionKeepAliveScheduler = (handler, intervalMs) => {
  const id = setInterval(handler, intervalMs);
  if (typeof id.unref === 'function') {
    id.unref();
  }
  return {
    clear(): void {
      clearInterval(id);
    },
  };
};

/** True when identity carries cookie / Authorization / custom auth headers. */
export function identityHasAuthMaterial(identity: ByotIdentity): boolean {
  if (identity.injectCookies && Object.keys(identity.injectCookies).length > 0) {
    return true;
  }
  if (!identity.injectHeaders) {
    return false;
  }
  for (const [key, value] of Object.entries(identity.injectHeaders)) {
    if (typeof value !== 'string' || value.trim().length === 0) {
      continue;
    }
    const lower = key.toLowerCase();
    if (
      lower === 'cookie' ||
      lower === 'authorization' ||
      lower.startsWith('x-') ||
      lower === 'x-api-key' ||
      lower === 'api-key'
    ) {
      return true;
    }
  }
  return false;
}

export function byotBundleHasAuthenticatedIdentity(
  bundle: ByotSessionIdentityBundle | undefined
): boolean {
  if (!bundle) {
    return false;
  }
  if (identityHasAuthMaterial(bundle.identityA)) {
    return true;
  }
  if (bundle.identityB && identityHasAuthMaterial(bundle.identityB)) {
    return true;
  }
  return false;
}

/**
 * Operator-safe hint string (no cookies/tokens). Example: "A:ok;B:error".
 */
export function formatKeepAliveHint(tick: TargetSessionKeepAliveTick): string {
  return tick.identityResults
    .map((r) => `${r.identityLabel}:${r.status}`)
    .join(';');
}

function buildProbeHeaders(context: ProbeAuthContext): Record<string, string> {
  const headers: Record<string, string> = {
    ...(context.headers ?? {}),
    Accept: 'text/html,application/json;q=0.9,*/*;q=0.8',
    'User-Agent': 'FixGuard-V2-SessionKeepAlive/1.0',
  };
  if (context.cookies && Object.keys(context.cookies).length > 0) {
    const cookieHeader = Object.entries(context.cookies)
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
    if (cookieHeader.length > 0) {
      const existing = headers['cookie'] ?? headers['Cookie'];
      headers['Cookie'] = existing ? `${existing}; ${cookieHeader}` : cookieHeader;
      delete headers['cookie'];
    }
  }
  return headers;
}

export interface TargetSessionKeepAliveOptions {
  readonly targetDomain: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly authorizedScopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly sessionIdentities: ByotSessionIdentityBundle;
  readonly buildProbeAuthContext: (identity: ByotIdentity) => ProbeAuthContext;
  readonly transport: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
  readonly onTick: (tick: TargetSessionKeepAliveTick) => void | Promise<void>;
  readonly intervalMs?: number;
  readonly pingTimeoutMs?: number;
  readonly now?: () => Date;
  readonly schedule?: TargetSessionKeepAliveScheduler;
  /** Fired after a successful soft ping (any identity ok) for activity deadline refresh. */
  readonly onActivity?: () => void;
}

/**
 * Periodic authorized soft-ping against the assessment target using BYOT identities.
 */
export class TargetSessionKeepAlive {
  private handle: TargetSessionKeepAliveScheduleHandle | null = null;
  private stopped = true;
  private readonly intervalMs: number;
  private readonly pingTimeoutMs: number;
  private readonly now: () => Date;
  private readonly schedule: TargetSessionKeepAliveScheduler;
  private readonly options: TargetSessionKeepAliveOptions;

  constructor(options: TargetSessionKeepAliveOptions) {
    this.options = options;
    this.intervalMs = options.intervalMs ?? TARGET_SESSION_KEEPALIVE_INTERVAL_MS;
    this.pingTimeoutMs = options.pingTimeoutMs ?? TARGET_SESSION_KEEPALIVE_TIMEOUT_MS;
    this.now = options.now ?? (() => new Date());
    this.schedule = options.schedule ?? defaultScheduler;
  }

  public start(): void {
    if (!this.stopped && this.handle !== null) {
      return;
    }
    if (!byotBundleHasAuthenticatedIdentity(this.options.sessionIdentities)) {
      return;
    }
    this.stopped = false;
    // First tick after one full interval (avoid competing with pipeline boot probes).
    this.handle = this.schedule(() => {
      void this.emitTick();
    }, this.intervalMs);
  }

  public stop(): void {
    this.stopped = true;
    if (this.handle !== null) {
      this.handle.clear();
      this.handle = null;
    }
  }

  /** Exposed for smoke tests — one gated soft-ping cycle (ignores stopped). */
  public async emitTickForTest(): Promise<TargetSessionKeepAliveTick> {
    const tick = await this.runTickCycle();
    return tick;
  }

  private async emitTick(): Promise<TargetSessionKeepAliveTick | null> {
    if (this.stopped) {
      return null;
    }
    return this.runTickCycle();
  }

  private async runTickCycle(): Promise<TargetSessionKeepAliveTick> {
    const targetUrl = `https://${this.options.targetDomain}/`;
    const at = this.now().toISOString();
    const identityResults: TargetSessionKeepAliveIdentityResult[] = [];

    try {
      const preflight = await runAdapterPreflight({
        target: targetUrl,
        targetKind: 'url',
        unsupportedProtocolReasonCode: 'unsupported_url_protocol',
        verifiedAuthorizationDecision: this.options.verifiedAuthorizationDecision,
        authorizedScopeGrant: this.options.authorizedScopeGrant,
        lineage: this.options.lineage,
        permissionCheck: (ps) =>
          Boolean(
            ps.authenticatedTesting ||
              ps.lightValidation ||
              ps.activeValidation ||
              ps.endpointDiscovery
          ),
        missingPermissionReason:
          'Scope grant does not permit authenticated testing or light validation for session keep-alive',
        targetOutOfScopeReason: 'Keep-alive target URL host is outside authorized scope boundaries',
        dnsResolver: this.options.dnsResolver,
      });

      if (!preflight.ok) {
        const denied: TargetSessionKeepAliveTick = {
          at,
          targetUrl,
          identityResults: [
            {
              identityLabel: 'A',
              identityId: this.options.sessionIdentities.identityA.identityId,
              status: 'preflight_denied',
              reasonCode: preflight.reasonCode,
            },
          ],
        };
        await this.safeNotify(denied);
        return denied;
      }

      const identities: Array<{ label: 'A' | 'B'; identity: ByotIdentity }> = [
        { label: 'A', identity: this.options.sessionIdentities.identityA },
      ];
      if (this.options.sessionIdentities.identityB) {
        identities.push({
          label: 'B',
          identity: this.options.sessionIdentities.identityB,
        });
      }

      let anyOk = false;
      for (const { label, identity } of identities) {
        if (!identityHasAuthMaterial(identity)) {
          identityResults.push({
            identityLabel: label,
            identityId: identity.identityId,
            status: 'skipped_no_auth',
          });
          continue;
        }
        const auth = this.options.buildProbeAuthContext(identity);
        try {
          const response = await this.options.transport({
            url: targetUrl,
            method: 'GET',
            headers: buildProbeHeaders(auth),
            timeoutMs: this.pingTimeoutMs,
          });
          identityResults.push({
            identityLabel: label,
            identityId: identity.identityId,
            status: 'ok',
            statusCode: response.statusCode,
          });
          anyOk = true;
        } catch {
          identityResults.push({
            identityLabel: label,
            identityId: identity.identityId,
            status: 'error',
            reasonCode: 'keepalive_transport_error',
          });
        }
      }

      const tick: TargetSessionKeepAliveTick = {
        at,
        targetUrl,
        identityResults: Object.freeze(identityResults),
      };
      if (anyOk) {
        try {
          this.options.onActivity?.();
        } catch {
          // Activity callback must never abort keep-alive.
        }
      }
      await this.safeNotify(tick);
      return tick;
    } catch {
      const failed: TargetSessionKeepAliveTick = {
        at,
        targetUrl,
        identityResults: Object.freeze([
          {
            identityLabel: 'A' as const,
            identityId: this.options.sessionIdentities.identityA.identityId,
            status: 'error' as const,
            reasonCode: 'keepalive_unexpected_failure',
          },
        ]),
      };
      await this.safeNotify(failed);
      return failed;
    }
  }

  private async safeNotify(tick: TargetSessionKeepAliveTick): Promise<void> {
    try {
      await this.options.onTick(tick);
    } catch {
      // Fail-soft: keep-alive must never take down the assessment pipeline.
    }
  }
}
