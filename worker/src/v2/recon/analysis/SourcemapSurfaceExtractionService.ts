/**
 * Deep recon P1 — Sourcemap surface extraction (discovery-only).
 *
 * Distinct from SourcemapExposureDetectionService:
 * - NEVER creates findings, severities, or Critical claims from unpack alone.
 * - When an accessible .map JSON is OBSERVED, mines sources[] + string literals
 *   for API / Supabase / auth paths and emits DiscoveredUrlObservation seeds.
 *
 * Tools execute. Intelligence decides. Humans authorize.
 */

import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../../lineage/AuthorizedExecutionLineageContracts.js';
import type { DiscoveredUrlObservation } from '../adapters/UrlDiscoveryContracts.js';
import { runAdapterPreflight } from '../adapters/AdapterPreflightPipeline.js';
import type { PreSpawnDnsResolver } from '../adapters/AdapterPreflightPipeline.js';
import { extractSourcemapUrlAndSignal } from '../../detection/SourcemapExposureDetectionService.js';
import { defaultHttpProbeTransport } from '../../detection/IdorDifferentialDetectionService.js';
import type { IdorHttpProbeTransport } from '../../detection/DetectionContracts.js';
import { isInternalOrSsrfTarget } from '../policy/PassiveEgressPolicy.js';
import { classifySupabaseUrl } from '../../supabase/SupabaseSurfaceContracts.js';

export const SOURCEMAP_SURFACE_CONTRACT_VERSION =
  'fixguard-sourcemap-surface-extraction/v0' as const;
export type SourcemapSurfaceContractVersion = typeof SOURCEMAP_SURFACE_CONTRACT_VERSION;

export const SOURCEMAP_SURFACE_SOURCE = 'sourcemap_surface' as const;

export interface SourcemapSurfaceExplicitNonClaims {
  readonly createsRealFindings: false;
  readonly createsPersistedEvidence: false;
  readonly confirmsVulnerabilities: false;
  readonly makesRiskClaims: false;
  readonly makesSeverityClaims: false;
  readonly makesImpactClaims: false;
  readonly executesNetworkPayloads: false;
  readonly severity: 'info';
}

export const SOURCEMAP_SURFACE_NON_CLAIMS: SourcemapSurfaceExplicitNonClaims = Object.freeze({
  createsRealFindings: false,
  createsPersistedEvidence: false,
  confirmsVulnerabilities: false,
  makesRiskClaims: false,
  makesSeverityClaims: false,
  makesImpactClaims: false,
  executesNetworkPayloads: false,
  severity: 'info',
});

/** Max absolute URLs + path seeds emitted per map. */
export const SOURCEMAP_SURFACE_MAX_URLS = 40;
/** Cap sources[] scanned for path hints. */
export const SOURCEMAP_SURFACE_MAX_SOURCES = 200;
/** Cap sourcesContent characters scanned for URL/path regex. */
export const SOURCEMAP_SURFACE_MAX_CONTENT_CHARS = 256_000;

export interface SourcemapSurfaceExtractionRequest {
  readonly sourceJsUrl: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly authorizedScopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly resolvePathsBase?: string;
  readonly explicitMapUrl?: string;
  readonly jsBodyText?: string;
  readonly jsHeaders?: Readonly<Record<string, string>>;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
  readonly timeoutMs?: number;
}

export type SourcemapSurfaceExtractionResult =
  | {
      readonly status: 'success';
      readonly contractVersion: SourcemapSurfaceContractVersion;
      readonly sourceJsUrl: string;
      readonly mapUrl: string;
      readonly urlObservations: readonly DiscoveredUrlObservation[];
      readonly sourcesSample: readonly string[];
      readonly sourcesCount: number;
      readonly explicitNonClaims: SourcemapSurfaceExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly durationMs: number;
    }
  | {
      readonly status: 'abstained';
      readonly contractVersion: SourcemapSurfaceContractVersion;
      readonly sourceJsUrl: string;
      readonly reasonCode: string;
      readonly mapUrl?: string;
      readonly explicitNonClaims: SourcemapSurfaceExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly durationMs: number;
    }
  | {
      readonly status: 'preflight_denied';
      readonly contractVersion: SourcemapSurfaceContractVersion;
      readonly sourceJsUrl: string;
      readonly reasonCode: string;
      readonly reason: string;
      readonly mapUrl?: string;
      readonly explicitNonClaims: SourcemapSurfaceExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly durationMs: number;
    };

const INTERESTING_PATH =
  /(?:^|["'`\s(=])((?:\/(?:api|auth|rest|v\d+|graphql|rpc|_next\/data)(?:\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)?)|(?:https?:\/\/[a-z0-9.-]+\.supabase\.co\/[^\s"'`<>]+))/gi;

function hostInScope(host: string, grant: AuthorizedScopeGrant): boolean {
  const h = host.trim().toLowerCase().replace(/\.$/, '');
  if (!h || isInternalOrSsrfTarget(h)) return false;
  const subjectDomain = grant.subject.domain?.trim().toLowerCase().replace(/\.$/, '');
  const subjectHost = grant.subject.host?.trim().toLowerCase().replace(/\.$/, '');
  const allowedDomains = (grant.boundaries.allowedDomains ?? []).map((d) =>
    d.trim().toLowerCase().replace(/\.$/, '')
  );
  const allowedHosts = (grant.boundaries.allowedHosts ?? []).map((x) =>
    x.trim().toLowerCase().replace(/\.$/, '')
  );
  if (subjectHost && (h === subjectHost || h.endsWith(`.${subjectHost}`))) return true;
  if (subjectDomain && (h === subjectDomain || h.endsWith(`.${subjectDomain}`))) return true;
  if (allowedHosts.some((a) => h === a || h.endsWith(`.${a}`))) return true;
  if (allowedDomains.some((a) => h === a || h.endsWith(`.${a}`))) return true;
  // Supabase project hosts often appear only as related allowedHosts — already covered.
  return false;
}

function tryAbsoluteUrl(
  raw: string,
  resolveBase: string | undefined
): { url: string; host: string; path: string; query?: string } | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  let absolute = trimmed;
  if (trimmed.startsWith('/') && resolveBase) {
    try {
      absolute = new URL(trimmed, resolveBase).toString();
    } catch {
      return null;
    }
  } else if (!/^https?:\/\//i.test(trimmed)) {
    return null;
  }
  try {
    const u = new URL(absolute);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return {
      url: absolute.split('#')[0] ?? absolute,
      host: u.hostname,
      path: u.pathname || '/',
      ...(u.search ? { query: u.search.slice(1) } : {}),
    };
  } catch {
    return null;
  }
}

/**
 * Hermetic: mine a parsed sourcemap object for in-scope URL / path seeds.
 * Does not create findings. Epistemic: paths from sources[] are INFERRED unless
 * they are absolute http(s) URLs already present in the map text.
 */
export function extractUrlSeedsFromSourcemapJson(args: {
  readonly mapJson: unknown;
  readonly resolvePathsBase: string;
  readonly authorizedScopeGrant: AuthorizedScopeGrant;
  readonly discoveredAt: string;
  readonly maxUrls?: number;
}): {
  readonly urlObservations: readonly DiscoveredUrlObservation[];
  readonly sourcesSample: readonly string[];
  readonly sourcesCount: number;
} {
  const maxUrls =
    typeof args.maxUrls === 'number' && args.maxUrls > 0
      ? Math.floor(args.maxUrls)
      : SOURCEMAP_SURFACE_MAX_URLS;
  const out: DiscoveredUrlObservation[] = [];
  const seen = new Set<string>();
  const sourcesSample: string[] = [];
  let sourcesCount = 0;

  const push = (
    raw: string,
    reliability: 'direct_observation' | 'inferred_relationship'
  ): void => {
    if (out.length >= maxUrls) return;
    const resolved = tryAbsoluteUrl(raw, args.resolvePathsBase);
    if (!resolved) return;
    if (!hostInScope(resolved.host, args.authorizedScopeGrant)) return;
    if (seen.has(resolved.url)) return;
    seen.add(resolved.url);
    out.push(
      Object.freeze({
        url: resolved.url,
        host: resolved.host,
        path: resolved.path,
        ...(resolved.query ? { query: resolved.query } : {}),
        sources: Object.freeze([SOURCEMAP_SURFACE_SOURCE]),
        discoveredAt: args.discoveredAt,
        collectedAt: args.discoveredAt,
        freshness: 'live' as const,
        sourceReliability: reliability,
      })
    );
  };

  if (!args.mapJson || typeof args.mapJson !== 'object' || Array.isArray(args.mapJson)) {
    return {
      urlObservations: Object.freeze([]),
      sourcesSample: Object.freeze([]),
      sourcesCount: 0,
    };
  }

  const record = args.mapJson as Record<string, unknown>;
  const sourcesRaw = Reflect.get(record, 'sources');
  if (Array.isArray(sourcesRaw)) {
    sourcesCount = sourcesRaw.length;
    for (const s of sourcesRaw.slice(0, SOURCEMAP_SURFACE_MAX_SOURCES)) {
      if (typeof s !== 'string' || s.trim().length === 0) continue;
      if (sourcesSample.length < 8) sourcesSample.push(s.trim().slice(0, 200));
      // Absolute URLs in sources[]
      if (/^https?:\/\//i.test(s.trim())) {
        push(s.trim(), 'direct_observation');
      }
      // Path-like sources that look like API / supabase client modules
      const lower = s.toLowerCase();
      if (
        /supabase|\/rest\/v1|\/auth\/v1|\/api\/|graphql|server.?action/i.test(lower)
      ) {
        // Prefer extracting embedded absolute URLs from the path string itself
        const abs = s.match(/https?:\/\/[^\s"'`]+/i);
        if (abs) push(abs[0], 'inferred_relationship');
      }
    }
  }

  const contentRaw = Reflect.get(record, 'sourcesContent');
  let contentBlob = '';
  if (Array.isArray(contentRaw)) {
    for (const chunk of contentRaw) {
      if (typeof chunk !== 'string') continue;
      contentBlob += chunk;
      if (contentBlob.length >= SOURCEMAP_SURFACE_MAX_CONTENT_CHARS) break;
    }
  }
  if (contentBlob.length > SOURCEMAP_SURFACE_MAX_CONTENT_CHARS) {
    contentBlob = contentBlob.slice(0, SOURCEMAP_SURFACE_MAX_CONTENT_CHARS);
  }

  if (contentBlob.length > 0) {
    INTERESTING_PATH.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = INTERESTING_PATH.exec(contentBlob)) !== null) {
      if (out.length >= maxUrls) break;
      const captured = match[1];
      if (!captured) continue;
      if (captured.startsWith('http')) {
        push(captured.replace(/[,;)}\]]+$/, ''), 'direct_observation');
        // Also seed rest table path if classifiable
        const classified = classifySupabaseUrl(captured);
        if (classified.tableName && classified.restBaseUrl) {
          push(
            `${classified.restBaseUrl}/${classified.tableName}`,
            'direct_observation'
          );
        }
      } else if (captured.startsWith('/')) {
        push(captured.replace(/[,;)}\]]+$/, ''), 'inferred_relationship');
      }
    }
  }

  return {
    urlObservations: Object.freeze(out),
    sourcesSample: Object.freeze(sourcesSample),
    sourcesCount,
  };
}

export async function runSourcemapSurfaceExtraction(
  request: SourcemapSurfaceExtractionRequest
): Promise<SourcemapSurfaceExtractionResult> {
  const started = Date.now();
  const lineage = request.lineage;
  const sourceJsUrl = request.sourceJsUrl.trim();
  const resolveBase =
    typeof request.resolvePathsBase === 'string' && request.resolvePathsBase.trim().length > 0
      ? request.resolvePathsBase.trim()
      : sourceJsUrl;

  const extracted = extractSourcemapUrlAndSignal(
    sourceJsUrl,
    request.explicitMapUrl,
    request.jsBodyText,
    request.jsHeaders
  );
  if (!extracted) {
    return {
      status: 'abstained',
      contractVersion: SOURCEMAP_SURFACE_CONTRACT_VERSION,
      sourceJsUrl,
      reasonCode: 'no_sourcemap_target_resolved',
      explicitNonClaims: SOURCEMAP_SURFACE_NON_CLAIMS,
      lineage,
      durationMs: Date.now() - started,
    };
  }

  const mapUrl = extracted.mapUrl;
  const preflight = await runAdapterPreflight({
    target: mapUrl,
    targetKind: 'url',
    verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
    authorizedScopeGrant: request.authorizedScopeGrant,
    lineage,
    requiredPermissions: [
      'endpointDiscovery',
      'activeCrawling',
      'passiveRecon',
      'technologyFingerprinting',
    ],
    missingPermissionReason: 'Scope grant does not permit sourcemap surface discovery',
    dnsResolver: request.dnsResolver,
  });
  if (!preflight.ok) {
    return {
      status: 'preflight_denied',
      contractVersion: SOURCEMAP_SURFACE_CONTRACT_VERSION,
      sourceJsUrl,
      reasonCode: preflight.reasonCode,
      reason: preflight.reason,
      mapUrl,
      explicitNonClaims: SOURCEMAP_SURFACE_NON_CLAIMS,
      lineage,
      durationMs: Date.now() - started,
    };
  }

  const transport = request.transport ?? defaultHttpProbeTransport;
  let bodyText = '';
  try {
    const probe = await transport({
      url: mapUrl,
      method: 'GET',
      headers: {
        accept: 'application/json, text/javascript, */*',
        'user-agent': 'Mozilla/5.0 (FixGuard Defensive Auditor)',
      },
      timeoutMs: request.timeoutMs ?? 8_000,
    });
    if (probe.statusCode < 200 || probe.statusCode >= 300 || probe.bodyText.trim().length === 0) {
      return {
        status: 'abstained',
        contractVersion: SOURCEMAP_SURFACE_CONTRACT_VERSION,
        sourceJsUrl,
        reasonCode: 'sourcemap_not_accessible',
        mapUrl,
        explicitNonClaims: SOURCEMAP_SURFACE_NON_CLAIMS,
        lineage,
        durationMs: Date.now() - started,
      };
    }
    bodyText = probe.bodyText;
  } catch {
    return {
      status: 'abstained',
      contractVersion: SOURCEMAP_SURFACE_CONTRACT_VERSION,
      sourceJsUrl,
      reasonCode: 'sourcemap_probe_failed',
      mapUrl,
      explicitNonClaims: SOURCEMAP_SURFACE_NON_CLAIMS,
      lineage,
      durationMs: Date.now() - started,
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(bodyText);
  } catch {
    return {
      status: 'abstained',
      contractVersion: SOURCEMAP_SURFACE_CONTRACT_VERSION,
      sourceJsUrl,
      reasonCode: 'invalid_sourcemap_json',
      mapUrl,
      explicitNonClaims: SOURCEMAP_SURFACE_NON_CLAIMS,
      lineage,
      durationMs: Date.now() - started,
    };
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return {
      status: 'abstained',
      contractVersion: SOURCEMAP_SURFACE_CONTRACT_VERSION,
      sourceJsUrl,
      reasonCode: 'non_sourcemap_payload',
      mapUrl,
      explicitNonClaims: SOURCEMAP_SURFACE_NON_CLAIMS,
      lineage,
      durationMs: Date.now() - started,
    };
  }

  const record = parsed as Record<string, unknown>;
  const hasVersion = typeof record.version === 'number' || typeof record.version === 'string';
  const hasSources = Array.isArray(record.sources);
  const hasMappings = typeof record.mappings === 'string';
  if (!hasVersion && !hasSources && !hasMappings) {
    return {
      status: 'abstained',
      contractVersion: SOURCEMAP_SURFACE_CONTRACT_VERSION,
      sourceJsUrl,
      reasonCode: 'non_sourcemap_payload',
      mapUrl,
      explicitNonClaims: SOURCEMAP_SURFACE_NON_CLAIMS,
      lineage,
      durationMs: Date.now() - started,
    };
  }

  const mined = extractUrlSeedsFromSourcemapJson({
    mapJson: parsed,
    resolvePathsBase: resolveBase,
    authorizedScopeGrant: request.authorizedScopeGrant,
    discoveredAt: new Date().toISOString(),
  });

  return {
    status: 'success',
    contractVersion: SOURCEMAP_SURFACE_CONTRACT_VERSION,
    sourceJsUrl,
    mapUrl,
    urlObservations: mined.urlObservations,
    sourcesSample: mined.sourcesSample,
    sourcesCount: mined.sourcesCount,
    explicitNonClaims: SOURCEMAP_SURFACE_NON_CLAIMS,
    lineage,
    durationMs: Date.now() - started,
  };
}
