/**
 * Supabase RLS read confirm capability (Fase 3a).
 * Re-runs OBSERVED Data API GET limit=1 via SupabaseRlsAbuseDetectionService.
 * HITL authorize→execute only. Never writes. Never fabricates success.
 */

import type {
  AttackCapabilityExecutionResult,
  AttackCapabilityInvocationContext,
  AttackCapabilityPort,
} from '../AttackExecutionContracts.js';
import { SupabaseRlsAbuseDetectionService } from '../../supabase/SupabaseRlsAbuseDetectionService.js';
import { SUPABASE_RLS_ABUSE_DETECTION_CONTRACT_VERSION } from '../../supabase/SupabaseRlsAbuseDetectionContracts.js';
import type { IdorHttpProbeTransport } from '../../detection/DetectionContracts.js';
import type { PreSpawnDnsResolver } from '../../recon/adapters/AdapterPreflightPipeline.js';
import { classifySupabaseUrl } from '../../supabase/SupabaseSurfaceContracts.js';

function succeeded(
  reasonCode: string,
  safeMessage: string,
  evidenceId?: string
): AttackCapabilityExecutionResult {
  return {
    outcome: 'succeeded',
    reasonCode,
    safeMessage,
    ...(evidenceId ? { evidenceId } : {}),
  };
}

function refuted(reasonCode: string, safeMessage: string): AttackCapabilityExecutionResult {
  return { outcome: 'refuted', reasonCode, safeMessage };
}

function inconclusive(reasonCode: string, safeMessage: string): AttackCapabilityExecutionResult {
  return { outcome: 'inconclusive', reasonCode, safeMessage };
}

function failed(reasonCode: string, safeMessage: string): AttackCapabilityExecutionResult {
  return { outcome: 'failed', reasonCode, safeMessage };
}

function extractAnonKey(
  ctx: AttackCapabilityInvocationContext
): string | undefined {
  const candidates = [ctx.primaryIdentity, ctx.secondaryIdentity];
  for (const id of candidates) {
    if (!id?.headers) continue;
    for (const [k, v] of Object.entries(id.headers)) {
      if (k.toLowerCase() === 'apikey' && v.trim().length >= 20) {
        return v.trim();
      }
    }
  }
  return undefined;
}

function extractTableName(ctx: AttackCapabilityInvocationContext): string | undefined {
  for (const f of ctx.findings) {
    if (f.metadata.kind === 'supabase_rls_abuse_metadata') {
      return f.metadata.tableName;
    }
  }
  const classified = classifySupabaseUrl(ctx.targetUrl);
  return classified.tableName;
}

export interface SupabaseRlsReadConfirmCapabilityOptions {
  readonly service?: SupabaseRlsAbuseDetectionService;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

export function createSupabaseRlsReadConfirmCapability(
  options?: SupabaseRlsReadConfirmCapabilityOptions
): AttackCapabilityPort {
  const detectionService = options?.service ?? new SupabaseRlsAbuseDetectionService();

  return {
    capability: 'supabase_rls_read_confirm',
    async execute(
      ctx: AttackCapabilityInvocationContext
    ): Promise<AttackCapabilityExecutionResult> {
      if (!ctx.targetUrl || ctx.targetUrl.trim().length === 0) {
        return failed(
          'supabase_rls_target_missing',
          'Supabase RLS read confirm requires a Data API table URL'
        );
      }

      const verifiedAuthorizationDecision = ctx.verifiedAuthorizationDecision;
      if (!verifiedAuthorizationDecision) {
        return failed(
          'supabase_rls_authorization_missing',
          'Supabase RLS read confirm requires verifiedAuthorizationDecision'
        );
      }

      const anonApiKey = extractAnonKey(ctx);
      if (!anonApiKey) {
        return failed(
          'supabase_anon_key_missing',
          'OBSERVED anon/publishable apikey required in primaryIdentity headers'
        );
      }

      const classified = classifySupabaseUrl(ctx.targetUrl);
      const restBaseUrl =
        classified.restBaseUrl ??
        (() => {
          try {
            const u = new URL(ctx.targetUrl);
            return `${u.protocol}//${u.host}/rest/v1`;
          } catch {
            return undefined;
          }
        })();
      if (!restBaseUrl) {
        return failed(
          'supabase_rest_base_invalid',
          'Could not derive PostgREST rest base from target URL'
        );
      }

      const tableName = extractTableName(ctx);
      if (!tableName) {
        return failed(
          'supabase_table_missing',
          'Table name required (from finding metadata or /rest/v1/{table} URL)'
        );
      }

      const lineage = ctx.plan.lineage;
      const result = await detectionService.detect({
        contractVersion: SUPABASE_RLS_ABUSE_DETECTION_CONTRACT_VERSION,
        kind: 'supabase_rls_abuse_detection_request',
        detectionId: `det_sbrls_confirm_${ctx.plan.planId.slice(-12)}`,
        assessmentId: lineage.assessmentId,
        scanId: lineage.scanId,
        authorizationGrantId: lineage.authorizationGrantId,
        authorizationDecisionId: lineage.authorizationDecisionId,
        actorId: lineage.actorId,
        verifiedAuthorizationDecision,
        scopeGrant: ctx.scopeGrant,
        restBaseUrl,
        anonApiKey,
        tableNames: [tableName],
        authenticatedContext: ctx.primaryIdentity
          ? {
              identityId: ctx.primaryIdentity.identityId,
              headers: ctx.primaryIdentity.headers,
            }
          : undefined,
        transport: options?.transport ?? ctx.transport,
        dnsResolver: options?.dnsResolver ?? ctx.dnsResolver,
      });

      switch (result.status) {
        case 'pending_human_review':
        case 'vulnerability_detected': {
          const obs = result.observations.find((o) => o.tableName === tableName);
          if (
            obs &&
            obs.claimKind === 'SUPABASE_RLS_WORLD_READABLE' &&
            obs.rowCountHint !== null &&
            obs.rowCountHint > 0
          ) {
            const rawBody = obs.bodySnippet?.trim() || '[]';
            return {
              outcome: 'succeeded',
              reasonCode: result.reasonCode,
              safeMessage: `Confirmed world-readable Data API read on '${tableName}' (anon HTTP ${obs.anonStatusCode} JSON, ${obs.rowCountHint} rows observed)`,
              evidenceId: `ev_sbrls_${ctx.step.stepId}`,
              consoleLines: [
                {
                  stream: 'command' as const,
                  text: `curl -s -X GET "${obs.tableUrl}" -H "apikey: anon"`,
                  at: new Date().toISOString(),
                },
                {
                  stream: 'stdout' as const,
                  text: rawBody,
                  at: new Date().toISOString(),
                },
                {
                  stream: 'verdict' as const,
                  text: `[✔ VULNERABLE] Tabla '${tableName}' expuesta públicamente (${obs.rowCountHint} registros observados).`,
                  at: new Date().toISOString(),
                },
              ],
            };
          }
          return inconclusive(
            'supabase_rls_read_not_confirmed',
            'Detection ran but world-readable data exposure was not re-observed'
          );
        }
        case 'inconclusive_observation':
          return inconclusive(
            result.reasonCode,
            `Supabase RLS read confirm inconclusive (${result.reasonCode}) — observation is insufficient to establish exposure or protection`
          );
        case 'secure_target_abstained':
          return refuted(
            result.reasonCode,
            'Supabase RLS read confirm abstained — read boundary enforced (HTTP 401/403 observed)'
          );
        case 'preflight_denied':
        case 'prerequisite_missing':
        case 'unexpected_failure':
          return failed(
            result.reasonCode,
            result.error?.safeMessage ?? `Supabase RLS confirm status: ${result.status}`
          );
        default: {
          const _exhaustive: never = result.status;
          return failed(
            'supabase_rls_unexpected_status',
            `Unexpected status: ${String(_exhaustive)}`
          );
        }
      }
    },
  };
}
