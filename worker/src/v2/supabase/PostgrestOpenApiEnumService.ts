/**
 * PostgREST OpenAPI enum service (Fase 1).
 * GET rest base with Accept: application/openapi+json.
 * Fail-closed preflight; never fabricates table names.
 */

import { createHash } from 'node:crypto';
import type { HttpProbeRequest } from '../detection/DetectionContracts.js';
import { runAdapterPreflight } from '../recon/adapters/AdapterPreflightPipeline.js';
import type { PostgrestExposedRelation } from './SupabaseSurfaceContracts.js';
import {
  POSTGREST_OPENAPI_ENUM_CONTRACT_VERSION,
  type PostgrestOpenApiEnumRequest,
  type PostgrestOpenApiEnumResult,
} from './PostgrestOpenApiEnumContracts.js';
import {
  buildPostgrestHeaders,
  createPostgrestHttpTransport,
} from './adapters/PostgrestHttpTransportAdapter.js';

function sanitizeRelationName(raw: string): string | undefined {
  const name = raw.trim();
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) return undefined;
  if (name.length > 128) return undefined;
  // Skip OpenAPI noise paths
  if (name.startsWith('_') && name !== '_') return undefined;
  return name;
}

function extractRelationsFromOpenApi(bodyText: string): PostgrestExposedRelation[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(bodyText);
  } catch {
    return [];
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return [];
  }
  const record = parsed as Record<string, unknown>;
  const paths = record.paths;
  if (!paths || typeof paths !== 'object' || Array.isArray(paths)) {
    return [];
  }
  const out = new Map<string, PostgrestExposedRelation>();
  for (const rawPath of Object.keys(paths as Record<string, unknown>)) {
    const path = rawPath.startsWith('/') ? rawPath.slice(1) : rawPath;
    if (!path || path.includes('/')) {
      // Nested paths like /rpc/foo
      if (path.startsWith('rpc/')) {
        const rpcName = sanitizeRelationName(path.slice(4).split('/')[0] ?? '');
        if (rpcName && !out.has(`rpc:${rpcName}`)) {
          out.set(`rpc:${rpcName}`, {
            name: rpcName,
            relationKind: 'rpc',
            epistemicStatus: 'OBSERVED',
          });
        }
      }
      continue;
    }
    const name = sanitizeRelationName(path);
    if (!name) continue;
    if (!out.has(name)) {
      out.set(name, {
        name,
        relationKind: 'table',
        epistemicStatus: 'OBSERVED',
      });
    }
  }
  return Array.from(out.values()).sort((a, b) => a.name.localeCompare(b.name));
}

function seedRelations(seedTableNames: readonly string[] | undefined): PostgrestExposedRelation[] {
  if (!seedTableNames || seedTableNames.length === 0) return [];
  const out: PostgrestExposedRelation[] = [];
  const seen = new Set<string>();
  for (const raw of seedTableNames) {
    const name = sanitizeRelationName(raw);
    if (!name || seen.has(name)) continue;
    seen.add(name);
    out.push({
      name,
      relationKind: 'table',
      epistemicStatus: 'INFERRED',
    });
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

export async function runPostgrestOpenApiEnum(
  request: PostgrestOpenApiEnumRequest
): Promise<PostgrestOpenApiEnumResult> {
  const lineage = {
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
  };

  let restBase: string;
  try {
    const u = new URL(request.restBaseUrl);
    restBase = `${u.protocol}//${u.host}${u.pathname.replace(/\/$/, '')}`;
  } catch {
    return {
      contractVersion: POSTGREST_OPENAPI_ENUM_CONTRACT_VERSION,
      kind: 'postgrest_openapi_enum_result',
      enumId: request.enumId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'unexpected_failure',
      reasonCode: 'rest_base_url_malformed',
      lineage,
      restBaseUrl: request.restBaseUrl,
      relations: [],
      inventoryEpistemicStatus: 'INFERRED',
      error: {
        code: 'rest_base_url_malformed',
        safeMessage: 'restBaseUrl is not a valid absolute URL',
      },
    };
  }

  const preflight = await runAdapterPreflight({
    target: restBase,
    targetKind: 'url',
    verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
    authorizedScopeGrant: request.scopeGrant,
    lineage,
    permissionCheck: (ps) =>
      Boolean(ps.endpointDiscovery || ps.lightValidation || ps.activeValidation),
    dnsResolver: request.dnsResolver,
  });

  if (!preflight.ok) {
    return {
      contractVersion: POSTGREST_OPENAPI_ENUM_CONTRACT_VERSION,
      kind: 'postgrest_openapi_enum_result',
      enumId: request.enumId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'preflight_denied',
      reasonCode: preflight.reasonCode,
      lineage,
      restBaseUrl: restBase,
      relations: [],
      inventoryEpistemicStatus: 'INFERRED',
      error: {
        code: preflight.reasonCode,
        safeMessage: `Preflight denied for PostgREST OpenAPI enum: ${preflight.reasonCode}`,
      },
    };
  }

  const transport = createPostgrestHttpTransport(request.transport);
  const probeReq: HttpProbeRequest = {
    url: `${restBase}/`,
    method: 'GET',
    headers: {
      ...buildPostgrestHeaders({ anonApiKey: request.anonApiKey }),
      accept: 'application/openapi+json, application/json',
    },
    timeoutMs: 8000,
  };

  try {
    const resp = await transport(probeReq);
    const fromOpenApi =
      resp.statusCode === 200 && resp.bodyText
        ? extractRelationsFromOpenApi(resp.bodyText)
        : [];

    if (fromOpenApi.length > 0) {
      return {
        contractVersion: POSTGREST_OPENAPI_ENUM_CONTRACT_VERSION,
        kind: 'postgrest_openapi_enum_result',
        enumId: request.enumId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'inventory_observed',
        reasonCode: 'openapi_paths_observed',
        lineage,
        restBaseUrl: restBase,
        relations: fromOpenApi,
        inventoryEpistemicStatus: 'OBSERVED',
        openApiStatusCode: resp.statusCode,
      };
    }

    const seeded = seedRelations(request.seedTableNames);
    return {
      contractVersion: POSTGREST_OPENAPI_ENUM_CONTRACT_VERSION,
      kind: 'postgrest_openapi_enum_result',
      enumId: request.enumId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: seeded.length > 0 ? 'inventory_observed' : 'openapi_unavailable',
      reasonCode:
        seeded.length > 0
          ? 'openapi_closed_seed_tables_used'
          : 'openapi_unavailable_no_seeds',
      lineage,
      restBaseUrl: restBase,
      relations: seeded,
      inventoryEpistemicStatus: seeded.length > 0 ? 'INFERRED' : 'INFERRED',
      openApiStatusCode: resp.statusCode,
    };
  } catch {
    const seeded = seedRelations(request.seedTableNames);
    return {
      contractVersion: POSTGREST_OPENAPI_ENUM_CONTRACT_VERSION,
      kind: 'postgrest_openapi_enum_result',
      enumId: request.enumId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: seeded.length > 0 ? 'inventory_observed' : 'unexpected_failure',
      reasonCode:
        seeded.length > 0
          ? 'openapi_transport_failed_seed_tables_used'
          : 'openapi_transport_failed',
      lineage,
      restBaseUrl: restBase,
      relations: seeded,
      inventoryEpistemicStatus: 'INFERRED',
      error:
        seeded.length > 0
          ? undefined
          : {
              code: 'openapi_transport_failed',
              safeMessage: 'OpenAPI enum transport failed',
            },
    };
  }
}

/** Stable hash helper exported for smokes — not used for secrets. */
export function hashOpenApiBody(bodyText: string): string {
  return createHash('sha256').update(bodyText).digest('hex');
}

export class PostgrestOpenApiEnumService {
  async enumerate(request: PostgrestOpenApiEnumRequest): Promise<PostgrestOpenApiEnumResult> {
    return runPostgrestOpenApiEnum(request);
  }
}
