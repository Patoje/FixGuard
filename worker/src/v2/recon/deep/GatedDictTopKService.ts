/**
 * Deep recon P4 — gated ffuf/arjun on top-K inventory only + WAF-aware abort.
 */

import type { DiscoveredUrlObservation } from '../adapters/UrlDiscoveryContracts.js';
import type { DiscoveredContentObservation } from '../adapters/ContentDiscoveryContracts.js';
import type { DiscoveredParameterObservation } from '../adapters/ParameterDiscoveryContracts.js';
import { resolveApiDiscoveryWordlistPath } from '../wordlists/resolveApiDiscoveryWordlist.js';
import {
  observeDefensesFromHttpResponse,
  isBlockingDefense,
} from '../../test-validity/DefenseObservationService.js';
import type { DefenseObservation } from '../../test-validity/TestValidityContracts.js';
import {
  DEEP_RECON_NON_CLAIMS,
  GATED_DICT_MAX_ARJUN_TARGETS_DEFAULT,
  GATED_DICT_MAX_FFUF_ROOTS_DEFAULT,
  GATED_DICT_TOPK_CONTRACT_VERSION,
  GATED_DICT_TOPK_SOURCE,
  type GatedDictTopKRequest,
  type GatedDictTopKResult,
} from './GatedDictTopKContracts.js';

const STATIC_BUNDLE_RE = /\/_next\/static\//i;
const MEDIA_EXT_RE = /\.(png|jpe?g|gif|svg|woff2?|css|ico|map)(\?|$)/i;

function scoreInventoryUrl(url: string): number {
  try {
    const u = new URL(url);
    const path = u.pathname.toLowerCase();
    if (STATIC_BUNDLE_RE.test(path) || MEDIA_EXT_RE.test(path)) return -100;
    let score = 0;
    if (/\/rest\/v1\//i.test(path)) score += 100;
    if (/\/auth\/v1\//i.test(path)) score += 90;
    if (/\/graphql/i.test(path)) score += 85;
    if (/\/api\//i.test(path)) score += 80;
    if (/\/v[0-9]+\//i.test(path)) score += 70;
    if (/\/(auth|login|dashboard|perfil|account|admin|rpc)\b/i.test(path)) score += 60;
    if (u.search.length > 1) score += 20;
    if (path === '/' || path === '') score += 5;
    // Prefer shorter useful paths over deep CDN assets
    if (path.split('/').filter(Boolean).length <= 4) score += 10;
    return score;
  } catch {
    return -100;
  }
}

/**
 * Rank inventory URLs for gated dict discovery. Drops static/media; prefers API shapes.
 */
export function selectTopKInventoryUrls(args: {
  readonly inventoryUrls: readonly { readonly url: string }[];
  readonly maxTargets: number;
}): readonly string[] {
  const max =
    typeof args.maxTargets === 'number' && args.maxTargets > 0
      ? Math.floor(args.maxTargets)
      : GATED_DICT_MAX_FFUF_ROOTS_DEFAULT;
  const scored: { readonly url: string; readonly score: number }[] = [];
  const seen = new Set<string>();
  for (const item of args.inventoryUrls) {
    const url = typeof item.url === 'string' ? item.url.trim() : '';
    if (!url || seen.has(url)) continue;
    const score = scoreInventoryUrl(url);
    if (score < 0) continue;
    seen.add(url);
    scored.push({ url, score });
  }
  scored.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    return a.url.localeCompare(b.url);
  });
  return Object.freeze(scored.slice(0, max).map((s) => s.url));
}

function contentToUrlObservation(
  obs: { readonly url: string; readonly path: string; readonly discoveredAt: string }
): DiscoveredUrlObservation | null {
  try {
    const u = new URL(obs.url);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return {
      url: obs.url,
      host: u.hostname.toLowerCase(),
      path: obs.path || u.pathname,
      ...(u.search ? { query: u.search.slice(1) } : {}),
      sources: Object.freeze([GATED_DICT_TOPK_SOURCE]),
      discoveredAt: obs.discoveredAt,
      collectedAt: obs.discoveredAt,
      freshness: 'live',
      sourceReliability: 'direct_observation',
    };
  } catch {
    return null;
  }
}

export async function runGatedDictTopK(
  request: GatedDictTopKRequest
): Promise<GatedDictTopKResult> {
  const empty = (
    status: GatedDictTopKResult['status'],
    reasonCode: string,
    extra?: {
      readonly defenses?: readonly DefenseObservation[];
      readonly requestsUsed?: number;
    }
  ): GatedDictTopKResult => ({
    contractVersion: GATED_DICT_TOPK_CONTRACT_VERSION,
    status,
    reasonCode,
    selectedFfufRoots: Object.freeze([]),
    selectedArjunTargets: Object.freeze([]),
    contentObservations: Object.freeze([]),
    parameterObservations: Object.freeze([]),
    urlObservations: Object.freeze([]),
    ...(extra?.defenses ? { defenses: extra.defenses } : {}),
    requestsUsed: extra?.requestsUsed ?? 0,
    nonClaims: DEEP_RECON_NON_CLAIMS,
  });

  if (!request.contentTool && !request.parameterTool) {
    return empty('tools_missing', 'content_and_parameter_tools_not_provided');
  }

  const maxFfuf =
    typeof request.maxFfufRoots === 'number' && request.maxFfufRoots > 0
      ? Math.floor(request.maxFfufRoots)
      : GATED_DICT_MAX_FFUF_ROOTS_DEFAULT;
  const maxArjun =
    typeof request.maxArjunTargets === 'number' && request.maxArjunTargets > 0
      ? Math.floor(request.maxArjunTargets)
      : GATED_DICT_MAX_ARJUN_TARGETS_DEFAULT;

  const ffufRoots = selectTopKInventoryUrls({
    inventoryUrls: request.inventoryUrls,
    maxTargets: maxFfuf,
  });
  const arjunTargets = selectTopKInventoryUrls({
    inventoryUrls: request.inventoryUrls,
    maxTargets: maxArjun,
  });

  if (ffufRoots.length === 0 && arjunTargets.length === 0) {
    return empty('empty_inventory', 'no_scorable_inventory_urls');
  }

  let requestsUsed = 0;
  const defensesAcc: DefenseObservation[] = [];

  // WAF canary on highest-ranked target before spray.
  if (request.skipWafCanary !== true && request.transport && ffufRoots[0]) {
    const canaryUrl = ffufRoots[0];
    try {
      const host = new URL(canaryUrl).hostname;
      const res = await request.transport({
        url: canaryUrl,
        method: 'GET',
        headers: { accept: 'text/html,application/json,*/*' },
        timeoutMs: request.timeoutMs ?? 8_000,
      });
      requestsUsed += 1;
      const defenses = observeDefensesFromHttpResponse(
        {
          statusCode: res.statusCode,
          headerNames: Object.keys(res.headers),
          headerValues: res.headers,
          bodyExcerpt: res.bodyText.slice(0, 240),
          responseTimeMs: res.responseTimeMs,
          targetHost: host,
        },
        { observationIdPrefix: 'gated_dict_canary' }
      );
      for (const d of defenses) defensesAcc.push(d);
      if (defenses.some(isBlockingDefense)) {
        return {
          contractVersion: GATED_DICT_TOPK_CONTRACT_VERSION,
          status: 'waf_aborted',
          reasonCode: 'blocking_defense_on_canary',
          selectedFfufRoots: ffufRoots,
          selectedArjunTargets: Object.freeze([]),
          contentObservations: Object.freeze([]),
          parameterObservations: Object.freeze([]),
          urlObservations: Object.freeze([]),
          defenses: Object.freeze(defensesAcc),
          requestsUsed,
          nonClaims: DEEP_RECON_NON_CLAIMS,
        };
      }
    } catch {
      // Canary transport errors do not abort — tools still have their own preflight.
      requestsUsed += 1;
    }
  }

  const wordlistPath =
    typeof request.wordlistPath === 'string' && request.wordlistPath.trim().length > 0
      ? request.wordlistPath.trim()
      : resolveApiDiscoveryWordlistPath();

  const contentObservations: DiscoveredContentObservation[] = [];
  const parameterObservations: DiscoveredParameterObservation[] = [];
  const urlObservations: DiscoveredUrlObservation[] = [];

  if (request.contentTool) {
    for (const targetUrl of ffufRoots) {
      const result = await request.contentTool.discoverContent({
        targetUrl,
        wordlistPath,
        verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
        authorizedScopeGrant: request.authorizedScopeGrant,
        lineage: request.lineage,
        timeoutMs: request.timeoutMs,
        // Keep shallow — no recursion on gated path.
        recursionDepth: 0,
        rateLimit: 20,
      });
      requestsUsed += 1;
      if (result.status === 'preflight_denied') {
        return {
          contractVersion: GATED_DICT_TOPK_CONTRACT_VERSION,
          status: 'preflight_denied',
          reasonCode: result.reasonCode,
          selectedFfufRoots: ffufRoots,
          selectedArjunTargets: arjunTargets,
          contentObservations: Object.freeze(contentObservations),
          parameterObservations: Object.freeze(parameterObservations),
          urlObservations: Object.freeze(urlObservations),
          ...(defensesAcc.length > 0 ? { defenses: Object.freeze(defensesAcc) } : {}),
          requestsUsed,
          nonClaims: DEEP_RECON_NON_CLAIMS,
        };
      }
      if (result.status === 'success') {
        for (const obs of result.observations) {
          contentObservations.push(obs);
          const asUrl = contentToUrlObservation(obs);
          if (asUrl) urlObservations.push(asUrl);
        }
      }
    }
  }

  if (request.parameterTool) {
    for (const targetUrl of arjunTargets) {
      const result = await request.parameterTool.discoverParameters({
        targetUrl,
        verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
        authorizedScopeGrant: request.authorizedScopeGrant,
        lineage: request.lineage,
        timeoutMs: request.timeoutMs,
      });
      requestsUsed += 1;
      if (result.status === 'preflight_denied') {
        return {
          contractVersion: GATED_DICT_TOPK_CONTRACT_VERSION,
          status: 'preflight_denied',
          reasonCode: result.reasonCode,
          selectedFfufRoots: ffufRoots,
          selectedArjunTargets: arjunTargets,
          contentObservations: Object.freeze(contentObservations),
          parameterObservations: Object.freeze(parameterObservations),
          urlObservations: Object.freeze(urlObservations),
          ...(defensesAcc.length > 0 ? { defenses: Object.freeze(defensesAcc) } : {}),
          requestsUsed,
          nonClaims: DEEP_RECON_NON_CLAIMS,
        };
      }
      if (result.status === 'success') {
        for (const obs of result.observations) {
          parameterObservations.push(obs);
        }
      }
    }
  }

  return {
    contractVersion: GATED_DICT_TOPK_CONTRACT_VERSION,
    status: 'success',
    reasonCode:
      contentObservations.length + parameterObservations.length > 0
        ? 'topk_dict_seeded'
        : 'topk_dict_ran_empty',
    selectedFfufRoots: ffufRoots,
    selectedArjunTargets: arjunTargets,
    contentObservations: Object.freeze(contentObservations),
    parameterObservations: Object.freeze(parameterObservations),
    urlObservations: Object.freeze(urlObservations),
    ...(defensesAcc.length > 0 ? { defenses: Object.freeze(defensesAcc) } : {}),
    requestsUsed,
    nonClaims: DEEP_RECON_NON_CLAIMS,
  };
}
