/**
 * Supabase authz write-matrix capability (Plan A Fase 4 → Attack Mode).
 *
 * Wraps runSupabaseBolaBflaWriteExpansion. Advisory until human authorize+execute.
 * Fail-closed without BYOT A+B, anon key, or allowStateChangingRequests.
 * Never auto-runs from recommendations.
 */

import type {
  AttackCapabilityExecutionResult,
  AttackCapabilityInvocationContext,
  AttackCapabilityPort,
} from '../AttackExecutionContracts.js';
import type { IdorHttpProbeTransport } from '../../detection/DetectionContracts.js';
import type { PreSpawnDnsResolver } from '../../recon/adapters/AdapterPreflightPipeline.js';
import {
  runSupabaseBolaBflaWriteExpansion,
  SUPABASE_BOLA_BFLA_WRITE_CONTRACT_VERSION,
} from '../../detection/SupabaseBolaBflaWriteExpansionService.js';
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

function failed(reasonCode: string, safeMessage: string): AttackCapabilityExecutionResult {
  return { outcome: 'failed', reasonCode, safeMessage };
}

function extractAnonKey(ctx: AttackCapabilityInvocationContext): string | undefined {
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
  return classifySupabaseUrl(ctx.targetUrl).tableName;
}

function toProbeIdentity(
  id: NonNullable<AttackCapabilityInvocationContext['primaryIdentity']>
): { identityId: string; headers?: Readonly<Record<string, string>> } {
  return {
    identityId: id.identityId,
    ...(id.headers ? { headers: id.headers } : {}),
  };
}

export interface SupabaseAuthzWriteMatrixCapabilityOptions {
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

export function createSupabaseAuthzWriteMatrixCapability(
  options?: SupabaseAuthzWriteMatrixCapabilityOptions
): AttackCapabilityPort {
  return {
    capability: 'supabase_authz_write_matrix',
    async execute(
      ctx: AttackCapabilityInvocationContext
    ): Promise<AttackCapabilityExecutionResult> {
      if (!ctx.targetUrl || ctx.targetUrl.trim().length === 0) {
        return failed(
          'supabase_authz_write_matrix_target_missing',
          'Authz write matrix requires a Data API table URL'
        );
      }

      const verifiedAuthorizationDecision = ctx.verifiedAuthorizationDecision;
      if (!verifiedAuthorizationDecision) {
        return failed(
          'supabase_authz_write_matrix_authorization_missing',
          'Authz write matrix requires verifiedAuthorizationDecision'
        );
      }

      if (!ctx.scopeGrant.constraints.allowStateChangingRequests) {
        return failed(
          'supabase_authz_write_matrix_state_change_denied',
          'Scope grant does not allow state-changing requests (allowStateChangingRequests=false)'
        );
      }

      const primary = ctx.primaryIdentity;
      const secondary = ctx.secondaryIdentity;
      if (
        !primary ||
        typeof primary.identityId !== 'string' ||
        primary.identityId.trim().length === 0 ||
        !secondary ||
        typeof secondary.identityId !== 'string' ||
        secondary.identityId.trim().length === 0
      ) {
        return failed(
          'supabase_authz_write_matrix_byot_missing',
          'Authz write matrix requires BYOT primaryIdentity and secondaryIdentity'
        );
      }

      const anonApiKey = extractAnonKey(ctx);
      if (!anonApiKey) {
        return failed(
          'supabase_anon_key_missing',
          'OBSERVED anon/publishable apikey required in identity headers'
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
      const tableName = extractTableName(ctx) ?? classified.tableName;
      if (!restBaseUrl || !tableName) {
        return failed(
          'supabase_authz_write_matrix_table_unresolved',
          'Could not derive PostgREST table from target URL / finding metadata'
        );
      }

      const tableUrl = `${restBaseUrl.replace(/\/$/, '')}/${tableName}`;
      const lineage = ctx.plan.lineage;

      const result = await runSupabaseBolaBflaWriteExpansion({
        contractVersion: SUPABASE_BOLA_BFLA_WRITE_CONTRACT_VERSION,
        kind: 'supabase_bola_bfla_write_expansion_request',
        detectionId: `det_awm_${ctx.step.stepId}`.slice(0, 96),
        assessmentId: lineage.assessmentId,
        scanId: lineage.scanId,
        authorizationGrantId: lineage.authorizationGrantId,
        authorizationDecisionId: lineage.authorizationDecisionId,
        actorId: lineage.actorId,
        verifiedAuthorizationDecision,
        scopeGrant: ctx.scopeGrant,
        tableUrl,
        anonApiKey,
        identityA: toProbeIdentity(primary),
        identityB: toProbeIdentity(secondary),
        maxPairs: 3,
        ...(options?.transport || ctx.transport
          ? { transport: options?.transport ?? ctx.transport }
          : {}),
        ...(options?.dnsResolver || ctx.dnsResolver
          ? { dnsResolver: options?.dnsResolver ?? ctx.dnsResolver }
          : {}),
      });

      const evidenceId = `ev_awm_${ctx.step.stepId}`;

      if (result.status === 'differential_observed') {
        const diffs = result.pairObservations.filter((o) => o.writeAuthzDifferential).length;
        return succeeded(
          'supabase_authz_write_matrix_differential_observed',
          `Authz write matrix differential on '${tableName}' (${diffs}/${result.pairsExecuted} pairs)`,
          evidenceId
        );
      }

      if (result.status === 'secure_target_abstained') {
        return refuted(
          result.reasonCode,
          `Authz write matrix abstained on '${tableName}' — no write authz differential`
        );
      }

      if (
        result.status === 'scope_denied' ||
        result.status === 'preflight_denied' ||
        result.status === 'prerequisite_missing'
      ) {
        return failed(
          result.reasonCode,
          result.error?.safeMessage ?? `Authz write matrix denied (${result.status})`
        );
      }

      return failed(
        result.reasonCode,
        result.error?.safeMessage ?? 'Authz write matrix unexpected failure'
      );
    },
  };
}
