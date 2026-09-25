/**
 * Deep recon P2 — robots.txt + sitemap.xml → URL inventory seeds (discovery-only).
 * Never creates findings. Caps loc/paths. Egress + scope preflight on every fetch.
 */

import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../../lineage/AuthorizedExecutionLineageContracts.js';
import type { DiscoveredUrlObservation } from '../adapters/UrlDiscoveryContracts.js';
import { runAdapterPreflight } from '../adapters/AdapterPreflightPipeline.js';
import type { PreSpawnDnsResolver } from '../adapters/AdapterPreflightPipeline.js';
import { defaultHttpProbeTransport } from '../../detection/IdorDifferentialDetectionService.js';
import type { IdorHttpProbeTransport } from '../../detection/DetectionContracts.js';

export const ROBOTS_SITEMAP_FEED_CONTRACT_VERSION =
  'fixguard-robots-sitemap-inventory-feed/v0' as const;
export type RobotsSitemapFeedContractVersion = typeof ROBOTS_SITEMAP_FEED_CONTRACT_VERSION;

export const ROBOTS_SITEMAP_FEED_SOURCE = 'robots_sitemap_feed' as const;

export const ROBOTS_SITEMAP_MAX_SITEMAPS = 3;
export const ROBOTS_SITEMAP_MAX_LOCS = 40;
export const ROBOTS_SITEMAP_MAX_PATH_SEEDS = 25;

export interface RobotsSitemapFeedRequest {
  readonly originUrl: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly authorizedScopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
  readonly timeoutMs?: number;
  readonly maxSitemaps?: number;
  readonly maxLocs?: number;
  readonly maxPathSeeds?: number;
}

export type RobotsSitemapFeedResult =
  | {
      readonly status: 'success';
      readonly contractVersion: RobotsSitemapFeedContractVersion;
      readonly originUrl: string;
      readonly robotsFetched: boolean;
      readonly sitemapUrls: readonly string[];
      readonly urlObservations: readonly DiscoveredUrlObservation[];
      readonly reasonCode: 'inventory_seeded' | 'robots_empty_or_missing';
    }
  | {
      readonly status: 'preflight_denied' | 'skipped' | 'unexpected_failure';
      readonly contractVersion: RobotsSitemapFeedContractVersion;
      readonly originUrl: string;
      readonly reasonCode: string;
      readonly urlObservations: readonly [];
      readonly reason?: string;
    };

function originRoot(originUrl: string): { origin: string; host: string } | null {
  try {
    const u = new URL(originUrl);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return { origin: u.origin, host: u.hostname.toLowerCase() };
  } catch {
    return null;
  }
}

function parseRobots(body: string): {
  readonly sitemaps: readonly string[];
  readonly pathSeeds: readonly string[];
} {
  const sitemaps: string[] = [];
  const pathSeeds: string[] = [];
  const seenSm = new Set<string>();
  const seenPath = new Set<string>();
  for (const rawLine of body.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const lower = line.toLowerCase();
    if (lower.startsWith('sitemap:')) {
      const url = line.slice(line.indexOf(':') + 1).trim();
      if (url.length > 0 && !seenSm.has(url)) {
        seenSm.add(url);
        sitemaps.push(url);
      }
      continue;
    }
    if (lower.startsWith('allow:') || lower.startsWith('disallow:')) {
      const path = line.slice(line.indexOf(':') + 1).trim();
      if (!path || path === '/') continue;
      if (!path.startsWith('/')) continue;
      // Skip wildcard-only entries
      if (path.includes('*') || path.includes('$')) continue;
      if (seenPath.has(path)) continue;
      seenPath.add(path);
      pathSeeds.push(path);
    }
  }
  return { sitemaps: Object.freeze(sitemaps), pathSeeds: Object.freeze(pathSeeds) };
}

function parseSitemapLocs(body: string, maxLocs: number): readonly string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const m of body.matchAll(/<loc>\s*([^<]+?)\s*<\/loc>/gi)) {
    if (out.length >= maxLocs) break;
    const loc = (m[1] ?? '').trim();
    if (!loc || seen.has(loc)) continue;
    seen.add(loc);
    out.push(loc);
  }
  return Object.freeze(out);
}

function toUrlObservation(
  absoluteUrl: string,
  discoveredAt: string
): DiscoveredUrlObservation | null {
  try {
    const u = new URL(absoluteUrl);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return {
      url: u.toString(),
      host: u.hostname.toLowerCase(),
      path: u.pathname || '/',
      ...(u.search ? { query: u.search.slice(1) } : {}),
      sources: Object.freeze([ROBOTS_SITEMAP_FEED_SOURCE]),
      discoveredAt,
      collectedAt: discoveredAt,
      freshness: 'live',
      sourceReliability: 'direct_observation',
    };
  } catch {
    return null;
  }
}

export async function runRobotsSitemapInventoryFeed(
  request: RobotsSitemapFeedRequest
): Promise<RobotsSitemapFeedResult> {
  const contractVersion = ROBOTS_SITEMAP_FEED_CONTRACT_VERSION;
  const root = originRoot(request.originUrl);
  if (!root) {
    return {
      status: 'skipped',
      contractVersion,
      originUrl: request.originUrl,
      reasonCode: 'invalid_origin',
      urlObservations: [],
    };
  }

  const robotsUrl = `${root.origin}/robots.txt`;
  const preflight = await runAdapterPreflight({
    target: robotsUrl,
    targetKind: 'url',
    verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
    authorizedScopeGrant: request.authorizedScopeGrant,
    lineage: request.lineage,
    requiredPermissions: [
      'endpointDiscovery',
      'passiveRecon',
      'technologyFingerprinting',
    ],
    missingPermissionReason: 'Scope grant does not permit robots/sitemap inventory feed',
    dnsResolver: request.dnsResolver,
  });
  if (!preflight.ok) {
    return {
      status: 'preflight_denied',
      contractVersion,
      originUrl: request.originUrl,
      reasonCode: preflight.reasonCode ?? 'preflight_denied',
      urlObservations: [],
      reason: preflight.reason,
    };
  }

  const transport = request.transport ?? defaultHttpProbeTransport;
  const timeoutMs = request.timeoutMs ?? 10_000;
  const maxSitemaps = request.maxSitemaps ?? ROBOTS_SITEMAP_MAX_SITEMAPS;
  const maxLocs = request.maxLocs ?? ROBOTS_SITEMAP_MAX_LOCS;
  const maxPathSeeds = request.maxPathSeeds ?? ROBOTS_SITEMAP_MAX_PATH_SEEDS;
  const nowIso = new Date().toISOString();
  const observations: DiscoveredUrlObservation[] = [];
  const seen = new Set<string>();

  const push = (absolute: string): void => {
    if (observations.length >= maxLocs + maxPathSeeds) return;
    if (seen.has(absolute)) return;
    const obs = toUrlObservation(absolute, nowIso);
    if (!obs) return;
    // Same-host preference; related hosts still need scope (preflight on fetch).
    seen.add(absolute);
    observations.push(obs);
  };

  let robotsFetched = false;
  let sitemapList: string[] = [`${root.origin}/sitemap.xml`];
  try {
    const robotsRes = await transport({
      url: robotsUrl,
      method: 'GET',
      headers: { accept: 'text/plain, */*', 'user-agent': 'Mozilla/5.0 (FixGuard Defensive Auditor)' },
      timeoutMs,
    });
    const robotsBody = robotsRes.bodyText ?? '';
    const robotsLooksHtml = /^\s*</.test(robotsBody) || /<html[\s>]/i.test(robotsBody);
    if (
      robotsRes.statusCode >= 200 &&
      robotsRes.statusCode < 300 &&
      robotsBody.length > 0 &&
      !robotsLooksHtml
    ) {
      robotsFetched = true;
      const parsed = parseRobots(robotsBody);
      if (parsed.sitemaps.length > 0) {
        sitemapList = [...parsed.sitemaps];
      }
      for (const path of parsed.pathSeeds.slice(0, maxPathSeeds)) {
        push(`${root.origin}${path}`);
      }
    }
  } catch {
    // fail-soft — still try default sitemap.xml
  }

  const fetchedSitemaps: string[] = [];
  for (const sm of sitemapList.slice(0, maxSitemaps)) {
    try {
      const smPre = await runAdapterPreflight({
        target: sm,
        targetKind: 'url',
        verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
        authorizedScopeGrant: request.authorizedScopeGrant,
        lineage: request.lineage,
        requiredPermissions: [
          'endpointDiscovery',
          'passiveRecon',
          'technologyFingerprinting',
        ],
        missingPermissionReason: 'Scope grant does not permit sitemap fetch',
        dnsResolver: request.dnsResolver,
      });
      if (!smPre.ok) continue;

      const smRes = await transport({
        url: sm,
        method: 'GET',
        headers: {
          accept: 'application/xml, text/xml, */*',
          'user-agent': 'Mozilla/5.0 (FixGuard Defensive Auditor)',
        },
        timeoutMs,
      });
      const smBody = smRes.bodyText ?? '';
      const smLooksHtml = /<html[\s>]/i.test(smBody) || (!/<loc[\s>]/i.test(smBody) && /<!DOCTYPE/i.test(smBody));
      if (
        smRes.statusCode < 200 ||
        smRes.statusCode >= 300 ||
        smBody.length === 0 ||
        smLooksHtml
      ) {
        continue;
      }
      fetchedSitemaps.push(sm);
      // sitemap index → nested sitemap locs (one level)
      const locs = parseSitemapLocs(smRes.bodyText, maxLocs);
      const nestedMaps = locs.filter((l) => /\.xml(\?|$)/i.test(l));
      const pageLocs = locs.filter((l) => !/\.xml(\?|$)/i.test(l));
      for (const loc of pageLocs) {
        push(loc);
      }
      for (const nested of nestedMaps.slice(0, Math.max(0, maxSitemaps - fetchedSitemaps.length))) {
        try {
          const nPre = await runAdapterPreflight({
            target: nested,
            targetKind: 'url',
            verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
            authorizedScopeGrant: request.authorizedScopeGrant,
            lineage: request.lineage,
            requiredPermissions: [
              'endpointDiscovery',
              'passiveRecon',
              'technologyFingerprinting',
            ],
            missingPermissionReason: 'Scope grant does not permit nested sitemap fetch',
            dnsResolver: request.dnsResolver,
          });
          if (!nPre.ok) continue;
          const nRes = await transport({
            url: nested,
            method: 'GET',
            headers: {
              accept: 'application/xml, text/xml, */*',
              'user-agent': 'Mozilla/5.0 (FixGuard Defensive Auditor)',
            },
            timeoutMs,
          });
          if (nRes.statusCode < 200 || nRes.statusCode >= 300 || !nRes.bodyText) continue;
          fetchedSitemaps.push(nested);
          for (const loc of parseSitemapLocs(nRes.bodyText, maxLocs - observations.length)) {
            if (/\.xml(\?|$)/i.test(loc)) continue;
            push(loc);
          }
        } catch {
          // fail-soft
        }
      }
    } catch {
      // fail-soft
    }
  }

  return {
    status: 'success',
    contractVersion,
    originUrl: request.originUrl,
    robotsFetched,
    sitemapUrls: Object.freeze(fetchedSitemaps),
    urlObservations: Object.freeze(observations),
    reasonCode: observations.length > 0 ? 'inventory_seeded' : 'robots_empty_or_missing',
  };
}
