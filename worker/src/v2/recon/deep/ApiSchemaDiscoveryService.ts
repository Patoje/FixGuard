/**
 * F1.3 — API schema discovery for the deep recon kit.
 * GET PostgREST OpenAPI and, when a GraphQL URL is already in inventory,
 * one introspection read. Related hosts are probed only when the grant
 * already allows them. No RLS confirmation, no writes, no findings.
 */

import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../../lineage/AuthorizedExecutionLineageContracts.js';
import type { IdorHttpProbeTransport } from '../../detection/DetectionContracts.js';
import type { PreSpawnDnsResolver } from '../adapters/AdapterPreflightPipeline.js';
import type { DiscoveredUrlObservation } from '../adapters/UrlDiscoveryContracts.js';
import { runAdapterPreflight } from '../adapters/AdapterPreflightPipeline.js';
import { POSTGREST_OPENAPI_ENUM_CONTRACT_VERSION } from '../../supabase/PostgrestOpenApiEnumContracts.js';
import { runPostgrestOpenApiEnum } from '../../supabase/PostgrestOpenApiEnumService.js';
import { isSupabaseHost } from '../../supabase/SupabaseSurfaceContracts.js';
import { tryBuildObservedFact } from '../../observation/ObservedFactCatalogService.js';
import type { ObservedFact } from '../../observation/ObservedFactContracts.js';
import type { DeepReconSchemaObservation } from './DeepReconContracts.js';

const RELATION_RE =
  /([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\s*(?:references|->)\s*([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)/g;

const API_SCHEMA_SOURCE = 'api_schema_discovery' as const;

export interface ApiSchemaDiscoveryRequest {
  readonly originUrl: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly authorizedScopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly inventoryUrls: readonly { readonly url: string }[];
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
  readonly timeoutMs?: number;
  /** Passed through only when recon already observed it. Never copied into results. */
  readonly observedAnonApiKey?: string;
  readonly maxTargets?: number;
  readonly observedAt?: string;
}

export interface ApiSchemaDiscoveryResult {
  readonly status: 'ran' | 'skipped' | 'preflight_denied' | 'failed';
  readonly reasonCode: string;
  readonly requestsUsed: number;
  readonly urlObservations: readonly DiscoveredUrlObservation[];
  readonly schemaObservations: readonly DeepReconSchemaObservation[];
  readonly observedFacts: readonly ObservedFact[];
  readonly skippedOutsideGrant: number;
}

function hostAllowed(host: string, grant: AuthorizedScopeGrant): boolean {
  const normalized = host.trim().toLowerCase().replace(/\.$/, '');
  const hosts = grant.boundaries.allowedHosts ?? [];
  return hosts.some((item) => item.trim().toLowerCase().replace(/\.$/, '') === normalized);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function graphqlTypeNames(bodyText: string): readonly string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(bodyText);
  } catch {
    return [];
  }
  if (!isRecord(parsed) || !isRecord(parsed.data) || !isRecord(parsed.data.__schema)) {
    return [];
  }
  const types = parsed.data.__schema.types;
  if (!Array.isArray(types)) return [];
  const names: string[] = [];
  for (const item of types) {
    if (!isRecord(item) || typeof item.name !== 'string') continue;
    const name = item.name;
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,80}$/.test(name) || name.startsWith('__')) continue;
    if (!bodyText.includes(name)) continue;
    names.push(name);
    if (names.length >= 20) break;
  }
  return names;
}

function graphqlQueryFieldNames(bodyText: string): readonly string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(bodyText);
  } catch {
    return [];
  }
  if (!isRecord(parsed) || !isRecord(parsed.data) || !isRecord(parsed.data.__schema)) {
    return [];
  }
  const queryType = parsed.data.__schema.queryType;
  if (!isRecord(queryType) || !Array.isArray(queryType.fields)) return [];
  const names: string[] = [];
  for (const item of queryType.fields) {
    if (!isRecord(item) || typeof item.name !== 'string') continue;
    const name = item.name;
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,80}$/.test(name) || name.startsWith('__')) continue;
    if (!bodyText.includes(name)) continue;
    names.push(name);
    if (names.length >= 20) break;
  }
  return names;
}

function relationFacts(input: {
  readonly bodyText: string;
  readonly sourceUrl: string;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly observedAt: string;
}): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const seen = new Set<string>();
  for (const match of input.bodyText.matchAll(RELATION_RE)) {
    const leftTable = match[1];
    const leftColumn = match[2];
    const rightTable = match[3];
    const rightColumn = match[4];
    if (!leftTable || !leftColumn || !rightTable || !rightColumn) continue;
    const value = `${leftTable}.${leftColumn}->${rightTable}.${rightColumn}`;
    if (seen.has(value)) continue;
    seen.add(value);
    const fact = tryBuildObservedFact({
      factKind: 'schema_relation',
      value,
      observationText: input.bodyText,
      sourceUrl: input.sourceUrl,
      observationKind: 'schema_document',
      lineage: input.lineage,
      observedAt: input.observedAt,
      sourceLabel: 'api_schema_discovery',
    });
    if (fact) facts.push(fact);
    if (facts.length >= 12) break;
  }
  return facts;
}

export async function runApiSchemaDiscovery(
  request: ApiSchemaDiscoveryRequest
): Promise<ApiSchemaDiscoveryResult> {
  const cap =
    typeof request.maxTargets === 'number' && request.maxTargets > 0
      ? Math.floor(request.maxTargets)
      : 6;
  const observedAt = request.observedAt ?? new Date().toISOString();
  const urlObservations: DiscoveredUrlObservation[] = [];
  const schemaObservations: DeepReconSchemaObservation[] = [];
  const observedFacts: ObservedFact[] = [];
  let requestsUsed = 0;
  let skippedOutsideGrant = 0;
  let attempted = 0;
  let denied = 0;

  const restBases: string[] = [];
  const seenBases = new Set<string>();
  const graphqlUrls: string[] = [];
  const seenGraphql = new Set<string>();

  for (const item of request.inventoryUrls) {
    let parsed: URL;
    try {
      parsed = new URL(item.url);
    } catch {
      continue;
    }
    const host = parsed.hostname.toLowerCase();
    if (!hostAllowed(host, request.authorizedScopeGrant)) {
      if (isSupabaseHost(host) || parsed.pathname.toLowerCase().includes('/graphql')) {
        skippedOutsideGrant += 1;
      }
      continue;
    }
    if (isSupabaseHost(host)) {
      const base = `${parsed.protocol}//${parsed.host}/rest/v1`;
      if (!seenBases.has(base)) {
        seenBases.add(base);
        restBases.push(base);
      }
    }
    if (parsed.pathname.toLowerCase().includes('/graphql') && !seenGraphql.has(parsed.href)) {
      seenGraphql.add(parsed.href);
      graphqlUrls.push(parsed.href);
    }
  }

  if (restBases.length === 0 && graphqlUrls.length === 0) {
    return {
      status: 'skipped',
      reasonCode:
        skippedOutsideGrant > 0 ? 'related_host_outside_grant' : 'no_schema_targets',
      requestsUsed: 0,
      urlObservations: [],
      schemaObservations: [],
      observedFacts: [],
      skippedOutsideGrant,
    };
  }

  if (!request.transport) {
    return {
      status: 'skipped',
      reasonCode: 'transport_not_configured',
      requestsUsed: 0,
      urlObservations: [],
      schemaObservations: [],
      observedFacts: [],
      skippedOutsideGrant,
    };
  }
  const inner = request.transport;
  const capturingTransport: IdorHttpProbeTransport = async (probe) => {
    const response = await inner(probe);
    if (
      probe.method === 'GET' &&
      probe.url.includes('/rest/v1') &&
      typeof response.bodyText === 'string' &&
      response.bodyText.length > 0
    ) {
      for (const fact of relationFacts({
        bodyText: response.bodyText,
        sourceUrl: probe.url,
        lineage: request.lineage,
        observedAt,
      })) {
        if (!observedFacts.some((existing) => existing.factId === fact.factId)) {
          observedFacts.push(fact);
        }
      }
    }
    return response;
  };

  for (const restBase of restBases) {
    if (attempted >= cap) break;
    attempted += 1;
    const enumerated = await runPostgrestOpenApiEnum({
      contractVersion: POSTGREST_OPENAPI_ENUM_CONTRACT_VERSION,
      kind: 'postgrest_openapi_enum_request',
      enumId: `openapi_${attempted}`,
      assessmentId: request.lineage.assessmentId,
      scanId: request.lineage.scanId,
      authorizationGrantId: request.lineage.authorizationGrantId,
      authorizationDecisionId: request.lineage.authorizationDecisionId,
      actorId: request.lineage.actorId,
      verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
      scopeGrant: request.authorizedScopeGrant,
      restBaseUrl: restBase,
      anonApiKey: request.observedAnonApiKey ?? '',
      transport: capturingTransport,
      ...(request.dnsResolver ? { dnsResolver: request.dnsResolver } : {}),
    });
    if (enumerated.status === 'preflight_denied') {
      denied += 1;
      continue;
    }
    requestsUsed += 1;
    if (enumerated.status !== 'inventory_observed') continue;
    let host = '';
    try {
      host = new URL(restBase).hostname.toLowerCase();
    } catch {
      continue;
    }
    for (const relation of enumerated.relations) {
      if (relation.epistemicStatus !== 'OBSERVED') continue;
      schemaObservations.push({
        sourceUrl: restBase,
        surfaceKind: relation.relationKind === 'rpc' ? 'postgrest_rpc' : 'postgrest_table',
        name: relation.name,
        epistemicStatus: 'OBSERVED',
      });
      if (relation.relationKind === 'table') {
        urlObservations.push({
          url: `${restBase}/${relation.name}`,
          host,
          path: `/rest/v1/${relation.name}`,
          sources: [API_SCHEMA_SOURCE],
          discoveredAt: observedAt,
          collectedAt: observedAt,
          freshness: 'live',
          sourceReliability: 'direct_observation',
        });
      }
    }
  }

  for (const graphqlUrl of graphqlUrls) {
    if (attempted >= cap) break;
    attempted += 1;
    const preflight = await runAdapterPreflight({
      target: graphqlUrl,
      targetKind: 'url',
      verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
      authorizedScopeGrant: request.authorizedScopeGrant,
      lineage: request.lineage,
      requiredPermissions: ['endpointDiscovery', 'passiveRecon'],
      missingPermissionReason: 'Scope grant does not permit GraphQL surface observation',
      dnsResolver: request.dnsResolver,
    });
    if (!preflight.ok) {
      denied += 1;
      continue;
    }
    requestsUsed += 1;
    try {
      const response = await inner({
        url: graphqlUrl,
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json',
          'user-agent': 'Mozilla/5.0 (FixGuard Defensive Auditor)',
        },
        body: JSON.stringify({
          query: '{ __schema { types { name } queryType { fields { name } } } }',
        }),
        timeoutMs: request.timeoutMs ?? 8_000,
      });
      if (response.statusCode !== 200) continue;
      for (const name of graphqlTypeNames(response.bodyText)) {
        schemaObservations.push({
          sourceUrl: graphqlUrl,
          surfaceKind: 'graphql_type',
          name,
          epistemicStatus: 'OBSERVED',
        });
      }
      for (const name of graphqlQueryFieldNames(response.bodyText)) {
        schemaObservations.push({
          sourceUrl: graphqlUrl,
          surfaceKind: 'graphql_query_field',
          name,
          epistemicStatus: 'OBSERVED',
        });
      }
    } catch {
      // Observation only — a failed read is not a finding.
    }
  }

  const status =
    requestsUsed > 0 ? 'ran' : denied > 0 ? 'preflight_denied' : 'skipped';
  const reasonCode =
    schemaObservations.length > 0
      ? 'schema_surface_observed'
      : requestsUsed > 0
        ? 'schema_probe_empty'
        : denied > 0
          ? 'preflight_denied'
          : 'no_schema_targets';

  return {
    status,
    reasonCode,
    requestsUsed,
    urlObservations: Object.freeze(urlObservations),
    schemaObservations: Object.freeze(schemaObservations),
    observedFacts: Object.freeze(observedFacts),
    skippedOutsideGrant,
  };
}

export function schemaRelationFactsFromOpenApiBody(input: {
  readonly bodyText: string;
  readonly sourceUrl: string;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly observedAt: string;
}): readonly ObservedFact[] {
  return Object.freeze(relationFacts(input));
}
