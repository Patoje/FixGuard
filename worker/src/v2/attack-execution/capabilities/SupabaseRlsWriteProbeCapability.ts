/**
 * Supabase RLS write probe capability (Fase 3b).
 *
 * HITL authorize→execute only. Canary INSERT (Prefer: return=representation)
 * then best-effort DELETE cleanup. Never auto-runs from recommendations.
 * Fail-closed without verifiedAuthorizationDecision, anon key, or mutation scope.
 *
 * Live Teclaaa: do NOT auto-execute against production — hermetic smoke only unless
 * operator explicitly authorizes with state_change_benign + allowStateChangingRequests.
 */

import type {
  AttackCapabilityExecutionResult,
  AttackCapabilityInvocationContext,
  AttackCapabilityPort,
} from '../AttackExecutionContracts.js';
import type { IdorHttpProbeTransport } from '../../detection/DetectionContracts.js';
import type { PreSpawnDnsResolver } from '../../recon/adapters/AdapterPreflightPipeline.js';
import { runAdapterPreflight } from '../../recon/adapters/AdapterPreflightPipeline.js';
import { defaultHttpProbeTransport } from '../../detection/IdorDifferentialDetectionService.js';
import { classifySupabaseUrl } from '../../supabase/SupabaseSurfaceContracts.js';
import { randomBytes } from 'node:crypto';

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

function extractBearer(ctx: AttackCapabilityInvocationContext): string | undefined {
  const id = ctx.primaryIdentity;
  if (!id?.headers) return undefined;
  for (const [k, v] of Object.entries(id.headers)) {
    if (k.toLowerCase() === 'authorization') {
      const m = /^Bearer\s+(.+)$/i.exec(v.trim());
      if (m?.[1] && m[1].length >= 20) return m[1];
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

function canaryMarker(): string {
  return `fg_canary_${randomBytes(8).toString('hex')}`;
}

export interface SupabaseRlsWriteProbeCapabilityOptions {
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

export function createSupabaseRlsWriteProbeCapability(
  options?: SupabaseRlsWriteProbeCapabilityOptions
): AttackCapabilityPort {
  const transport = options?.transport ?? defaultHttpProbeTransport;

  return {
    capability: 'supabase_rls_write_probe',
    async execute(
      ctx: AttackCapabilityInvocationContext
    ): Promise<AttackCapabilityExecutionResult> {
      if (!ctx.targetUrl || ctx.targetUrl.trim().length === 0) {
        return failed(
          'supabase_rls_write_target_missing',
          'Supabase RLS write probe requires a Data API table URL'
        );
      }

      const verifiedAuthorizationDecision = ctx.verifiedAuthorizationDecision;
      if (!verifiedAuthorizationDecision) {
        return failed(
          'supabase_rls_write_authorization_missing',
          'Supabase RLS write probe requires verifiedAuthorizationDecision'
        );
      }

      if (!ctx.scopeGrant.constraints.allowStateChangingRequests) {
        return failed(
          'supabase_rls_write_state_change_denied',
          'Scope grant does not allow state-changing requests (allowStateChangingRequests=false)'
        );
      }

      const allowedMethods = ctx.scopeGrant.boundaries.allowedMethods ?? [];
      if (!allowedMethods.includes('POST') || !allowedMethods.includes('DELETE')) {
        return failed(
          'supabase_rls_write_methods_denied',
          'Scope grant must allow POST and DELETE for canary write+cleanup'
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
      const tableName = extractTableName(ctx) ?? classified.tableName;
      if (!restBaseUrl || !tableName) {
        return failed(
          'supabase_rls_write_table_unresolved',
          'Could not derive PostgREST table from target URL / finding metadata'
        );
      }

      const tableUrl = `${restBaseUrl.replace(/\/$/, '')}/${tableName}`;
      const lineage = ctx.plan.lineage;
      const preflight = await runAdapterPreflight({
        target: tableUrl,
        targetKind: 'url',
        verifiedAuthorizationDecision,
        authorizedScopeGrant: ctx.scopeGrant,
        lineage,
        requiredPermissions: [
          'activeValidation',
          'authenticatedTesting',
          'endpointDiscovery',
        ],
        missingPermissionReason: 'Scope grant does not permit Supabase write canary probe',
        dnsResolver: options?.dnsResolver ?? ctx.dnsResolver,
      });
      if (!preflight.ok) {
        return failed(
          preflight.reasonCode ?? 'supabase_rls_write_preflight_denied',
          preflight.reason ?? 'Write probe preflight denied'
        );
      }

      const marker = canaryMarker();
      const bearer = extractBearer(ctx) ?? anonApiKey;
      const headers: Record<string, string> = {
        apikey: anonApiKey,
        Authorization: `Bearer ${bearer}`,
        Accept: 'application/json',
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
        'user-agent': 'Mozilla/5.0 (FixGuard Defensive Auditor)',
      };

      // Minimal canary body — tables vary; Prefer return=representation.
      // Use a disposable column-shaped payload; PostgREST may reject unknown cols (refute).
      const canaryBody = JSON.stringify({
        fixguard_canary: marker,
        name: marker,
      });

      let insertStatus = 0;
      let insertBody = '';
      try {
        const insertRes = await (options?.transport ?? ctx.transport ?? transport)({
          url: tableUrl,
          method: 'POST',
          headers,
          body: canaryBody,
          timeoutMs: 15_000,
        });
        insertStatus = insertRes.statusCode;
        insertBody = insertRes.bodyText ?? '';
      } catch (err: unknown) {
        return failed(
          'supabase_rls_write_transport_error',
          err instanceof Error ? err.message : 'Write probe transport error'
        );
      }

      const writable =
        insertStatus === 201 ||
        insertStatus === 200 ||
        (insertStatus === 204 && insertBody.length === 0);

      // Best-effort cleanup when we got a representation with id
      let cleanupAttempted = false;
      let cleanupStatus: number | undefined;
      if (writable) {
        cleanupAttempted = true;
        try {
          let deleteUrl = `${tableUrl}?fixguard_canary=eq.${encodeURIComponent(marker)}`;
          try {
            const parsed = JSON.parse(insertBody) as unknown;
            const row = Array.isArray(parsed) ? parsed[0] : parsed;
            if (row && typeof row === 'object' && !Array.isArray(row)) {
              const id = (row as { id?: unknown }).id;
              if (typeof id === 'string' || typeof id === 'number') {
                deleteUrl = `${tableUrl}?id=eq.${encodeURIComponent(String(id))}`;
              }
            }
          } catch {
            // keep marker filter
          }
          const del = await (options?.transport ?? ctx.transport ?? transport)({
            url: deleteUrl,
            method: 'DELETE',
            headers: {
              ...headers,
              Prefer: 'return=minimal',
            },
            timeoutMs: 10_000,
          });
          cleanupStatus = del.statusCode;
        } catch {
          cleanupStatus = undefined;
        }
      }

      const evidenceId = `ev_sbrls_w_${ctx.step.stepId}`;

      if (writable) {
        return succeeded(
          'supabase_rls_world_writable_observed',
          `Confirmed anon/auth Data API write on '${tableName}' (HTTP ${insertStatus}` +
            (cleanupAttempted ? `; cleanup HTTP ${cleanupStatus ?? 'n/a'}` : '') +
            ')',
          evidenceId
        );
      }

      if (insertStatus === 401 || insertStatus === 403) {
        return refuted(
          'supabase_rls_write_denied',
          `Write probe denied on '${tableName}' (HTTP ${insertStatus}) — RLS/authz boundary held`
        );
      }

      if (insertStatus === 404 || insertStatus === 406) {
        return refuted(
          'supabase_rls_write_table_unavailable',
          `Write probe table unavailable on '${tableName}' (HTTP ${insertStatus})`
        );
      }

      // 400 often = schema reject (unknown column) — not proof of world-writable
      if (insertStatus === 400 || insertStatus === 409 || insertStatus === 422) {
        return refuted(
          'supabase_rls_write_schema_rejected',
          `Write probe schema-rejected on '${tableName}' (HTTP ${insertStatus}) — not treated as world-writable`
        );
      }

      return failed(
        'supabase_rls_write_unexpected_status',
        `Write probe unexpected HTTP ${insertStatus} on '${tableName}'`
      );
    },
  };
}
