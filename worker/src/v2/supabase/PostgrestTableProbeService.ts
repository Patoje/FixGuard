/**
 * PostgREST table probe service (Fase 1).
 * Atomic two-pass batch preflight: validate ALL table URLs before any probe.
 * GET ?select=*&limit=1 for anon, then optional authenticated.
 */

import { createHash } from 'node:crypto';
import type { HttpProbeRequest } from '../detection/DetectionContracts.js';
import { runAdapterPreflight } from '../recon/adapters/AdapterPreflightPipeline.js';
import {
  POSTGREST_TABLE_PROBE_CONTRACT_VERSION,
  type PostgrestTableProbePairResult,
  type PostgrestTableProbeRequest,
  type PostgrestTableProbeResult,
  type PostgrestTableProbeSnapshot,
} from './PostgrestTableProbeContracts.js';
import {
  buildPostgrestHeaders,
  createPostgrestHttpTransport,
} from './adapters/PostgrestHttpTransportAdapter.js';

const DEFAULT_MAX_TABLES = 12;

function sanitizeTableName(raw: string): string | undefined {
  const name = raw.trim();
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) return undefined;
  if (name.length > 128) return undefined;
  return name;
}

function buildTableUrl(restBaseUrl: string, tableName: string): string {
  const base = restBaseUrl.replace(/\/$/, '');
  return `${base}/${tableName}?select=*&limit=1`;
}

function extractBearerFromContext(
  headers: Readonly<Record<string, string>> | undefined
): string | undefined {
  if (!headers) return undefined;
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() !== 'authorization') continue;
    const m = /^bearer\s+(.+)$/i.exec(v.trim());
    if (m?.[1]) return m[1].trim();
  }
  return undefined;
}

function classifyBody(bodyText: string, contentType: string): {
  isJsonBody: boolean;
  isHtmlBody: boolean;
  topLevelJsonKeys: readonly string[];
  rowCountHint: number | null;
} {
  const ct = contentType.toLowerCase();
  const trimmed = bodyText.trim();
  const looksHtml =
    ct.includes('text/html') ||
    /^<!doctype html/i.test(trimmed) ||
    /^<html[\s>]/i.test(trimmed);
  if (looksHtml) {
    return {
      isJsonBody: false,
      isHtmlBody: true,
      topLevelJsonKeys: [],
      rowCountHint: null,
    };
  }
  try {
    const parsed: unknown = JSON.parse(bodyText);
    if (Array.isArray(parsed)) {
      const first = parsed[0];
      const keys =
        first && typeof first === 'object' && !Array.isArray(first)
          ? Object.keys(first as Record<string, unknown>).sort().slice(0, 32)
          : [];
      return {
        isJsonBody: true,
        isHtmlBody: false,
        topLevelJsonKeys: keys,
        rowCountHint: parsed.length,
      };
    }
    if (parsed && typeof parsed === 'object') {
      return {
        isJsonBody: true,
        isHtmlBody: false,
        topLevelJsonKeys: Object.keys(parsed as Record<string, unknown>)
          .sort()
          .slice(0, 32),
        rowCountHint: null,
      };
    }
    return {
      isJsonBody: true,
      isHtmlBody: false,
      topLevelJsonKeys: [],
      rowCountHint: null,
    };
  } catch {
    return {
      isJsonBody: false,
      isHtmlBody: false,
      topLevelJsonKeys: [],
      rowCountHint: null,
    };
  }
}

function snapshotFromResponse(
  roleHint: 'anon' | 'authenticated',
  statusCode: number,
  headers: Readonly<Record<string, string>>,
  bodyText: string
): PostgrestTableProbeSnapshot {
  const contentType =
    headers['content-type'] ?? headers['Content-Type'] ?? '';
  const classified = classifyBody(bodyText, contentType);
  return {
    roleHint,
    statusCode,
    bodyHash: createHash('sha256').update(bodyText).digest('hex'),
    contentType: contentType.slice(0, 128),
    isJsonBody: classified.isJsonBody,
    isHtmlBody: classified.isHtmlBody,
    topLevelJsonKeys: classified.topLevelJsonKeys,
    rowCountHint: classified.rowCountHint,
  };
}

export async function runPostgrestTableProbe(
  request: PostgrestTableProbeRequest
): Promise<PostgrestTableProbeResult> {
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
      contractVersion: POSTGREST_TABLE_PROBE_CONTRACT_VERSION,
      kind: 'postgrest_table_probe_result',
      probeId: request.probeId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'unexpected_failure',
      reasonCode: 'rest_base_url_malformed',
      lineage,
      restBaseUrl: request.restBaseUrl,
      pairs: [],
      error: {
        code: 'rest_base_url_malformed',
        safeMessage: 'restBaseUrl is not a valid absolute URL',
      },
    };
  }

  const maxTables = request.maxTables ?? DEFAULT_MAX_TABLES;
  const tableNames: string[] = [];
  const seen = new Set<string>();
  for (const raw of request.tableNames) {
    const name = sanitizeTableName(raw);
    if (!name || seen.has(name)) continue;
    seen.add(name);
    tableNames.push(name);
    if (tableNames.length >= maxTables) break;
  }

  if (tableNames.length === 0) {
    return {
      contractVersion: POSTGREST_TABLE_PROBE_CONTRACT_VERSION,
      kind: 'postgrest_table_probe_result',
      probeId: request.probeId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'unexpected_failure',
      reasonCode: 'no_valid_table_names',
      lineage,
      restBaseUrl: restBase,
      pairs: [],
      error: {
        code: 'no_valid_table_names',
        safeMessage: 'No valid table names provided for PostgREST probe',
      },
    };
  }

  // Two-pass atomic batch preflight: all URLs validated before any execution.
  const tableUrls = tableNames.map((t) => ({
    tableName: t,
    tableUrl: buildTableUrl(restBase, t),
  }));

  for (const entry of tableUrls) {
    const preflight = await runAdapterPreflight({
      target: entry.tableUrl,
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
        contractVersion: POSTGREST_TABLE_PROBE_CONTRACT_VERSION,
        kind: 'postgrest_table_probe_result',
        probeId: request.probeId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'batch_preflight_denied',
        reasonCode: preflight.reasonCode,
        lineage,
        restBaseUrl: restBase,
        pairs: [],
        error: {
          code: preflight.reasonCode,
          safeMessage: `Atomic batch preflight denied for table '${entry.tableName}': ${preflight.reasonCode}`,
        },
      };
    }
  }

  const transport = createPostgrestHttpTransport(request.transport);
  const anonHeaders = buildPostgrestHeaders({ anonApiKey: request.anonApiKey });
  const authBearer = extractBearerFromContext(request.authenticatedContext?.headers);
  const authHeaders =
    authBearer && authBearer !== request.anonApiKey.trim()
      ? buildPostgrestHeaders({
          anonApiKey: request.anonApiKey,
          bearerToken: authBearer,
        })
      : undefined;

  const pairs: PostgrestTableProbePairResult[] = [];

  for (const entry of tableUrls) {
    const anonReq: HttpProbeRequest = {
      url: entry.tableUrl,
      method: 'GET',
      headers: anonHeaders,
      timeoutMs: 8000,
    };

    let anonSnap: PostgrestTableProbeSnapshot;
    try {
      const anonResp = await transport(anonReq);
      anonSnap = snapshotFromResponse(
        'anon',
        anonResp.statusCode,
        anonResp.headers,
        anonResp.bodyText
      );
    } catch {
      anonSnap = {
        roleHint: 'anon',
        statusCode: 0,
        bodyHash: createHash('sha256').update('').digest('hex'),
        contentType: '',
        isJsonBody: false,
        isHtmlBody: false,
        topLevelJsonKeys: [],
        rowCountHint: null,
      };
    }

    let authSnap: PostgrestTableProbeSnapshot | undefined;
    if (authHeaders) {
      const authReq: HttpProbeRequest = {
        url: entry.tableUrl,
        method: 'GET',
        headers: authHeaders,
        timeoutMs: 8000,
      };
      try {
        const authResp = await transport(authReq);
        authSnap = snapshotFromResponse(
          'authenticated',
          authResp.statusCode,
          authResp.headers,
          authResp.bodyText
        );
      } catch {
        authSnap = {
          roleHint: 'authenticated',
          statusCode: 0,
          bodyHash: createHash('sha256').update('').digest('hex'),
          contentType: '',
          isJsonBody: false,
          isHtmlBody: false,
          topLevelJsonKeys: [],
          rowCountHint: null,
        };
      }
    }

    pairs.push({
      tableName: entry.tableName,
      tableUrl: entry.tableUrl,
      anon: anonSnap,
      ...(authSnap ? { authenticated: authSnap } : {}),
    });
  }

  return {
    contractVersion: POSTGREST_TABLE_PROBE_CONTRACT_VERSION,
    kind: 'postgrest_table_probe_result',
    probeId: request.probeId,
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
    status: 'probe_completed',
    reasonCode: 'table_probes_completed',
    lineage,
    restBaseUrl: restBase,
    pairs,
  };
}

export class PostgrestTableProbeService {
  async probe(request: PostgrestTableProbeRequest): Promise<PostgrestTableProbeResult> {
    return runPostgrestTableProbe(request);
  }
}
