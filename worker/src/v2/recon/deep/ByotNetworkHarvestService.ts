/**
 * Deep recon P3 — BYOT authenticated HTTP harvest of XHR/RSC/Server Action metadata.
 * Fail-soft: skips cleanly without Identity A headers / FG_ACCESS_TOKEN.
 * Never mutates; never invents Next-Action ids; never persists credentials.
 */

import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../../lineage/AuthorizedExecutionLineageContracts.js';
import type { DiscoveredUrlObservation } from '../adapters/UrlDiscoveryContracts.js';
import {
  runAdapterPreflight,
  type PreSpawnDnsResolver,
} from '../adapters/AdapterPreflightPipeline.js';
import { defaultHttpProbeTransport } from '../../detection/IdorDifferentialDetectionService.js';
import type { IdorHttpProbeTransport } from '../../detection/DetectionContracts.js';
import { extractNextServerActionIdHintsFromText } from '../../supabase/SupabaseSurfaceContracts.js';
import { isHtmlStaticBundlePath } from '../analysis/HtmlRouteExtractionService.js';
import {
  BYOT_HARVEST_MAX_ACTION_IDS,
  BYOT_HARVEST_MAX_PAGES,
  BYOT_HARVEST_MAX_SCRIPTS,
  BYOT_HARVEST_MAX_URLS,
  BYOT_NETWORK_HARVEST_CONTRACT_VERSION,
  BYOT_NETWORK_HARVEST_NON_CLAIMS,
  BYOT_NETWORK_HARVEST_SOURCE,
  type ByotHarvestServerActionHint,
  type ByotNetworkHarvestContractVersion,
} from './ByotNetworkHarvestContracts.js';

const MIN_TOKEN_LEN = 20;

export interface ByotNetworkHarvestRequest {
  readonly originUrl: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly authorizedScopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  /** BYOT Identity A headers (Authorization / Cookie / apikey). Prefer over env. */
  readonly authHeaders?: Readonly<Record<string, string>>;
  /** Additional in-scope page URLs to harvest (capped). */
  readonly pageUrls?: readonly string[];
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
  readonly timeoutMs?: number;
  readonly maxPages?: number;
  readonly maxScripts?: number;
  readonly maxActionIds?: number;
  readonly maxUrls?: number;
}

export type ByotNetworkHarvestResult =
  | {
      readonly status: 'success';
      readonly contractVersion: ByotNetworkHarvestContractVersion;
      readonly originUrl: string;
      readonly reasonCode: 'harvested' | 'harvested_empty';
      readonly requestsUsed: number;
      readonly urlObservations: readonly DiscoveredUrlObservation[];
      readonly serverActionHints: readonly ByotHarvestServerActionHint[];
      readonly nonClaims: typeof BYOT_NETWORK_HARVEST_NON_CLAIMS;
    }
  | {
      readonly status: 'skipped' | 'preflight_denied' | 'failed';
      readonly contractVersion: ByotNetworkHarvestContractVersion;
      readonly originUrl: string;
      readonly reasonCode: string;
      readonly requestsUsed: number;
      readonly urlObservations: readonly [];
      readonly serverActionHints: readonly [];
      readonly reason?: string;
      readonly nonClaims: typeof BYOT_NETWORK_HARVEST_NON_CLAIMS;
    };

/**
 * Resolve harvest auth headers without logging secrets.
 * Prefer explicit BYOT headers; else FG_ACCESS_TOKEN as Bearer JWT.
 */
export function resolveByotHarvestAuthHeaders(
  authHeaders?: Readonly<Record<string, string>>
): Readonly<Record<string, string>> | null {
  if (authHeaders) {
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(authHeaders)) {
      if (typeof k !== 'string' || typeof v !== 'string') continue;
      const key = k.trim().toLowerCase();
      const val = v.trim();
      if (key.length === 0 || val.length === 0) continue;
      out[key] = val;
    }
    if (Object.keys(out).length > 0) {
      return Object.freeze(out);
    }
  }

  const token = process.env.FG_ACCESS_TOKEN?.trim() ?? '';
  if (token.length < MIN_TOKEN_LEN) return null;
  return Object.freeze({
    authorization: `Bearer ${token}`,
  });
}

function originRoot(originUrl: string): { origin: string; host: string } | null {
  try {
    const u = new URL(originUrl);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return { origin: u.origin, host: u.hostname.toLowerCase() };
  } catch {
    return null;
  }
}

function extractScriptSrcs(html: string, baseUrl: string, max: number): readonly string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const m of html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) {
    if (out.length >= max) break;
    const raw = m[1]?.trim();
    if (!raw) continue;
    try {
      const abs = new URL(raw, baseUrl).href;
      if (seen.has(abs)) continue;
      seen.add(abs);
      out.push(abs);
    } catch {
      // ignore
    }
  }
  return Object.freeze(out);
}

function extractInScopePathUrls(
  text: string,
  origin: string,
  host: string,
  max: number
): readonly string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const push = (href: string): void => {
    if (out.length >= max) return;
    try {
      const u = new URL(href, origin);
      if (u.hostname.toLowerCase() !== host) return;
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
      const path = u.pathname || '/';
      if (isHtmlStaticBundlePath(path) && !path.includes('/_next/data')) return;
      // Prefer API / RSC / auth-ish / rest surfaces for inventory value.
      const interesting =
        /^\/api(\/|$)/i.test(path) ||
        /\/_next\/data\//i.test(path) ||
        /[?&]_rsc=/i.test(u.search) ||
        /\/(auth|login|rest\/v1|rpc)\b/i.test(path) ||
        /\/auth\/v1\b/i.test(path);
      if (!interesting && !/^\/[a-z0-9_-]+(\/|$)/i.test(path)) return;
      const clean = `${u.origin}${path}${u.search}`;
      if (seen.has(clean)) return;
      seen.add(clean);
      out.push(clean);
    } catch {
      // ignore
    }
  };

  for (const m of text.matchAll(
    /(?:fetch|axios|XMLHttpRequest)\s*\(\s*["'`](\/[^"'`]+)["'`]/g
  )) {
    if (m[1]) push(m[1]);
  }
  for (const m of text.matchAll(/["'`](https?:\/\/[^"'`\s]+)["'`]/g)) {
    if (m[1]) push(m[1]);
  }
  for (const m of text.matchAll(/["'`](\/(?:api|_next\/data|auth|rest\/v1)[^"'`]*)["'`]/gi)) {
    if (m[1]) push(m[1]);
  }
  return Object.freeze(out);
}

export async function runByotNetworkHarvest(
  request: ByotNetworkHarvestRequest
): Promise<ByotNetworkHarvestResult> {
  const root = originRoot(request.originUrl);
  if (!root) {
    return {
      status: 'failed',
      contractVersion: BYOT_NETWORK_HARVEST_CONTRACT_VERSION,
      originUrl: request.originUrl,
      reasonCode: 'invalid_origin_url',
      requestsUsed: 0,
      urlObservations: [],
      serverActionHints: [],
      nonClaims: BYOT_NETWORK_HARVEST_NON_CLAIMS,
    };
  }

  const authHeaders = resolveByotHarvestAuthHeaders(request.authHeaders);
  if (!authHeaders) {
    return {
      status: 'skipped',
      contractVersion: BYOT_NETWORK_HARVEST_CONTRACT_VERSION,
      originUrl: request.originUrl,
      reasonCode: 'byot_harvest_token_absent',
      requestsUsed: 0,
      urlObservations: [],
      serverActionHints: [],
      nonClaims: BYOT_NETWORK_HARVEST_NON_CLAIMS,
    };
  }

  const maxPages =
    typeof request.maxPages === 'number' && request.maxPages > 0
      ? Math.floor(request.maxPages)
      : BYOT_HARVEST_MAX_PAGES;
  const maxScripts =
    typeof request.maxScripts === 'number' && request.maxScripts > 0
      ? Math.floor(request.maxScripts)
      : BYOT_HARVEST_MAX_SCRIPTS;
  const maxActionIds =
    typeof request.maxActionIds === 'number' && request.maxActionIds > 0
      ? Math.floor(request.maxActionIds)
      : BYOT_HARVEST_MAX_ACTION_IDS;
  const maxUrls =
    typeof request.maxUrls === 'number' && request.maxUrls > 0
      ? Math.floor(request.maxUrls)
      : BYOT_HARVEST_MAX_URLS;

  const transport = request.transport ?? defaultHttpProbeTransport;
  const timeoutMs = request.timeoutMs ?? 12_000;
  const nowIso = new Date().toISOString();

  const pageCandidates: string[] = [request.originUrl];
  for (const p of request.pageUrls ?? []) {
    if (pageCandidates.length >= maxPages) break;
    if (!pageCandidates.includes(p)) pageCandidates.push(p);
  }

  const urlObservations: DiscoveredUrlObservation[] = [];
  const serverActionHints: ByotHarvestServerActionHint[] = [];
  const seenUrls = new Set<string>();
  const seenActions = new Set<string>();
  let requestsUsed = 0;

  const pushUrl = (rawUrl: string): void => {
    if (urlObservations.length >= maxUrls) return;
    try {
      const parsed = new URL(rawUrl);
      if (parsed.hostname.toLowerCase() !== root.host) return;
      if (seenUrls.has(parsed.href)) return;
      seenUrls.add(parsed.href);
      urlObservations.push({
        url: parsed.href,
        host: parsed.hostname.toLowerCase(),
        path: parsed.pathname || '/',
        ...(parsed.search.length > 1 ? { query: parsed.search.slice(1) } : {}),
        sources: Object.freeze([BYOT_NETWORK_HARVEST_SOURCE]),
        discoveredAt: nowIso,
        collectedAt: nowIso,
        freshness: 'live',
        sourceReliability: 'direct_observation',
      });
    } catch {
      // ignore
    }
  };

  const pushActions = (endpointUrl: string, text: string): void => {
    for (const actionId of extractNextServerActionIdHintsFromText(text, maxActionIds)) {
      if (serverActionHints.length >= maxActionIds) return;
      const key = `${endpointUrl}:${actionId}`;
      if (seenActions.has(key)) continue;
      seenActions.add(key);
      serverActionHints.push({
        endpointUrl,
        actionId,
        source: BYOT_NETWORK_HARVEST_SOURCE,
      });
    }
  };

  const scriptQueue: string[] = [];
  const seenScripts = new Set<string>();

  for (const pageUrl of pageCandidates.slice(0, maxPages)) {
    const preflight = await runAdapterPreflight({
      target: pageUrl,
      targetKind: 'url',
      verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
      authorizedScopeGrant: request.authorizedScopeGrant,
      lineage: request.lineage,
      requiredPermissions: [
        'endpointDiscovery',
        'activeCrawling',
        'authenticatedTesting',
        'passiveRecon',
        'technologyFingerprinting',
      ],
      missingPermissionReason:
        'Scope grant does not permit authenticated BYOT network harvest',
      dnsResolver: request.dnsResolver,
    });
    if (!preflight.ok) {
      if (pageUrl === request.originUrl) {
        return {
          status: 'preflight_denied',
          contractVersion: BYOT_NETWORK_HARVEST_CONTRACT_VERSION,
          originUrl: request.originUrl,
          reasonCode: preflight.reasonCode,
          reason: preflight.reason,
          requestsUsed: 0,
          urlObservations: [],
          serverActionHints: [],
          nonClaims: BYOT_NETWORK_HARVEST_NON_CLAIMS,
        };
      }
      continue;
    }

    try {
      const probe = await transport({
        url: pageUrl,
        method: 'GET',
        headers: {
          ...authHeaders,
          accept: 'text/html, application/xhtml+xml, */*',
          'user-agent': 'Mozilla/5.0 (FixGuard Defensive Auditor)',
        },
        timeoutMs,
      });
      requestsUsed += 1;
      pushUrl(pageUrl);
      if (probe.statusCode >= 200 && probe.statusCode < 400 && probe.bodyText) {
        pushActions(pageUrl, probe.bodyText);
        for (const mined of extractInScopePathUrls(
          probe.bodyText,
          root.origin,
          root.host,
          maxUrls
        )) {
          pushUrl(mined);
        }
        for (const src of extractScriptSrcs(probe.bodyText, pageUrl, maxScripts)) {
          if (seenScripts.has(src)) continue;
          seenScripts.add(src);
          if (scriptQueue.length < maxScripts) scriptQueue.push(src);
        }
      }
    } catch {
      requestsUsed += 1;
    }
  }

  for (const scriptUrl of scriptQueue) {
    if (urlObservations.length >= maxUrls && serverActionHints.length >= maxActionIds) {
      break;
    }
    const preflight = await runAdapterPreflight({
      target: scriptUrl,
      targetKind: 'url',
      verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
      authorizedScopeGrant: request.authorizedScopeGrant,
      lineage: request.lineage,
      requiredPermissions: [
        'endpointDiscovery',
        'activeCrawling',
        'authenticatedTesting',
        'passiveRecon',
        'technologyFingerprinting',
      ],
      missingPermissionReason:
        'Scope grant does not permit authenticated BYOT script harvest',
      dnsResolver: request.dnsResolver,
    });
    if (!preflight.ok) continue;

    try {
      const probe = await transport({
        url: scriptUrl,
        method: 'GET',
        headers: {
          ...authHeaders,
          accept: 'application/javascript, text/javascript, */*',
          'user-agent': 'Mozilla/5.0 (FixGuard Defensive Auditor)',
        },
        timeoutMs,
      });
      requestsUsed += 1;
      if (probe.statusCode >= 200 && probe.statusCode < 300 && probe.bodyText) {
        pushUrl(scriptUrl);
        pushActions(request.originUrl, probe.bodyText);
        for (const mined of extractInScopePathUrls(
          probe.bodyText,
          root.origin,
          root.host,
          maxUrls
        )) {
          pushUrl(mined);
        }
      }
    } catch {
      requestsUsed += 1;
    }
  }

  const empty =
    urlObservations.length === 0 && serverActionHints.length === 0;
  return {
    status: 'success',
    contractVersion: BYOT_NETWORK_HARVEST_CONTRACT_VERSION,
    originUrl: request.originUrl,
    reasonCode: empty ? 'harvested_empty' : 'harvested',
    requestsUsed,
    urlObservations: Object.freeze(urlObservations),
    serverActionHints: Object.freeze(serverActionHints),
    nonClaims: BYOT_NETWORK_HARVEST_NON_CLAIMS,
  };
}
