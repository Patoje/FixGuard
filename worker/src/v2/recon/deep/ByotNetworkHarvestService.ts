/**
 * Deep recon P3 — BYOT authenticated network harvest.
 * Prefer Playwright + Identity A (cookies/Bearer) to capture post-login XHR/fetch/RSC
 * and OBSERVED Next-Action ids. Fall back to authenticated HTTP body mining when the
 * browser is unavailable. Fail-soft: skips cleanly without Identity A / FG_ACCESS_TOKEN.
 * Never mutates; never invents Next-Action ids; never persists credentials.
 */

import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../../lineage/AuthorizedExecutionLineageContracts.js';
import type { DiscoveredUrlObservation } from '../adapters/UrlDiscoveryContracts.js';
import type { PlaywrightBrowserLauncher } from '../adapters/BrowserAutomationContracts.js';
import {
  classifyBrowserRouteLoad,
  DefaultPlaywrightBrowserLauncher,
  isBrowserUrlAllowed,
  sanitizeDiscoveredNetworkUrl,
} from '../adapters/PlaywrightSpaAdapter.js';
import {
  runAdapterPreflight,
  type PreSpawnDnsResolver,
} from '../adapters/AdapterPreflightPipeline.js';
import { defaultHttpProbeTransport } from '../../detection/IdorDifferentialDetectionService.js';
import type { IdorHttpProbeTransport } from '../../detection/DetectionContracts.js';
import { extractNextServerActionIdHintsFromText } from '../../supabase/SupabaseSurfaceContracts.js';
import { isHtmlStaticBundlePath } from '../analysis/HtmlRouteExtractionService.js';
import type { ObservedFact } from '../../observation/ObservedFactContracts.js';
import { tryBuildObservedFact } from '../../observation/ObservedFactCatalogService.js';
import {
  defaultDocumentCopyDirectory,
  observeDownloadedDocument,
} from '../../observation/DocumentMetadataReader.js';
import {
  BYOT_HARVEST_HYDRATION_WAIT_MS,
  BYOT_HARVEST_MAX_ACTION_IDS,
  BYOT_HARVEST_MAX_PAGES,
  BYOT_HARVEST_MAX_SCRIPTS,
  BYOT_HARVEST_MAX_URLS,
  BYOT_HARVEST_NETWORKIDLE_WAIT_MS,
  BYOT_NETWORK_HARVEST_CONTRACT_VERSION,
  BYOT_NETWORK_HARVEST_NON_CLAIMS,
  BYOT_NETWORK_HARVEST_SOURCE,
  type ByotHarvestMode,
  type ByotHarvestServerActionHint,
  type ByotNetworkHarvestContractVersion,
} from './ByotNetworkHarvestContracts.js';

const MIN_TOKEN_LEN = 20;
const MINEABLE_NETWORK_RESOURCE_TYPES = Object.freeze(new Set(['xhr', 'fetch']));

export interface ByotNetworkHarvestRequest {
  readonly originUrl: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly authorizedScopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  /** BYOT Identity A headers (Authorization / Cookie / apikey). Prefer over env. */
  readonly authHeaders?: Readonly<Record<string, string>>;
  /** Additional in-scope page URLs to harvest (capped). */
  readonly pageUrls?: readonly string[];
  /** Injectable Playwright launcher (hermetic smokes / tests). */
  readonly browserLauncher?: PlaywrightBrowserLauncher;
  /** Force HTTP-only harvest (skip Playwright). Default false. */
  readonly httpOnly?: boolean;
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
      readonly harvestMode: ByotHarvestMode;
      readonly requestsUsed: number;
      readonly urlObservations: readonly DiscoveredUrlObservation[];
      readonly serverActionHints: readonly ByotHarvestServerActionHint[];
      readonly observedFacts: readonly ObservedFact[];
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

function isBrowserUnavailableError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return (
    /Executable doesn't exist/i.test(msg) ||
    /browserType\.launch/i.test(msg) ||
    /Failed to launch (chromium|chrome|browser)/i.test(msg) ||
    /Could not find (chromium|chrome|browser)/i.test(msg) ||
    /playwright.*install/i.test(msg) ||
    /chromium.*missing/i.test(msg) ||
    /ENOENT/i.test(msg)
  );
}

function isRscOrNextDataHint(pathname: string, search: string): boolean {
  const path = pathname.toLowerCase();
  if (path.includes('/_next/data/')) return true;
  if (search.includes('_rsc')) return true;
  return false;
}

function isMineableNetworkRequest(
  resourceType: string,
  pathname: string,
  search: string
): boolean {
  const rt = resourceType.trim().toLowerCase();
  if (MINEABLE_NETWORK_RESOURCE_TYPES.has(rt)) return true;
  if ((rt === 'document' || rt === 'fetch') && isRscOrNextDataHint(pathname, search)) {
    return true;
  }
  return false;
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

function buildAuthExtraHttpHeaders(
  authHeaders: Readonly<Record<string, string>>
): Readonly<Record<string, string>> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(authHeaders)) {
    if (k === 'authorization') out['Authorization'] = v;
    else if (k === 'cookie') out['Cookie'] = v;
    else if (k === 'apikey') out['apikey'] = v;
    else out[k] = v;
  }
  return Object.freeze(out);
}

interface HarvestCollectors {
  readonly urlObservations: DiscoveredUrlObservation[];
  readonly serverActionHints: ByotHarvestServerActionHint[];
  readonly observedFacts: ObservedFact[];
  readonly seenUrls: Set<string>;
  readonly seenActions: Set<string>;
  readonly seenFactIds: Set<string>;
  readonly rootHost: string;
  readonly maxUrls: number;
  readonly maxActionIds: number;
  readonly nowIso: string;
  readonly lineage: ByotNetworkHarvestRequest['lineage'];
}

function retainHarvestGet(
  request: ByotNetworkHarvestRequest,
  collectors: HarvestCollectors,
  url: string,
  probe: {
    readonly statusCode: number;
    readonly headers: Readonly<Record<string, string>>;
    readonly bodyText: string;
  },
): void {
  const retained = observeDownloadedDocument({
    downloaded: true,
    url,
    method: 'GET',
    statusCode: probe.statusCode,
    contentType: probe.headers['content-type'],
    body: probe.bodyText,
    scopeGrant: request.authorizedScopeGrant,
    lineage: request.lineage,
    observedAt: collectors.nowIso,
    directory: defaultDocumentCopyDirectory(),
  });
  if (!retained.fact || collectors.seenFactIds.has(retained.fact.factId)) return;
  collectors.seenFactIds.add(retained.fact.factId);
  collectors.observedFacts.push(retained.fact);
}

function pushUrl(collectors: HarvestCollectors, rawUrl: string): void {
  if (collectors.urlObservations.length >= collectors.maxUrls) return;
  try {
    const parsed = new URL(rawUrl);
    if (parsed.hostname.toLowerCase() !== collectors.rootHost) return;
    if (collectors.seenUrls.has(parsed.href)) return;
    collectors.seenUrls.add(parsed.href);
    collectors.urlObservations.push({
      url: parsed.href,
      host: parsed.hostname.toLowerCase(),
      path: parsed.pathname || '/',
      ...(parsed.search.length > 1 ? { query: parsed.search.slice(1) } : {}),
      sources: Object.freeze([BYOT_NETWORK_HARVEST_SOURCE]),
      discoveredAt: collectors.nowIso,
      collectedAt: collectors.nowIso,
      freshness: 'live',
      sourceReliability: 'direct_observation',
    });
    annotateAuthenticatedSurface(collectors, parsed.href);
  } catch {
    // ignore
  }
}

const HARVEST_OBJECT_PATH =
  /\/(?:api\/)?(?:users|orders|accounts|items|documents)\/([A-Za-z0-9_-]+)\/?$/i;

function annotateAuthenticatedSurface(collectors: HarvestCollectors, href: string): void {
  let parsed: URL;
  try {
    parsed = new URL(href);
  } catch {
    return;
  }
  const path = parsed.pathname;
  const xhrOrRsc =
    path.includes('/_next/data/') ||
    path.includes('/api/') ||
    parsed.search.includes('_rsc=') ||
    parsed.search.includes('_rsc&') ||
    parsed.search.endsWith('_rsc');
  if (!xhrOrRsc && !HARVEST_OBJECT_PATH.test(path)) return;

  for (const name of parsed.searchParams.keys()) {
    const fact = tryBuildObservedFact({
      factKind: 'observed_param',
      value: name,
      observationText: href,
      sourceUrl: href,
      observationKind: 'url',
      lineage: collectors.lineage,
      observedAt: collectors.nowIso,
      sourceLabel: 'byot_network_harvest',
    });
    if (!fact || collectors.seenFactIds.has(fact.factId)) continue;
    collectors.seenFactIds.add(fact.factId);
    collectors.observedFacts.push(fact);
  }

  const objectMatch = path.match(HARVEST_OBJECT_PATH);
  const objectId = objectMatch?.[1];
  if (!objectId || !href.includes(objectId)) return;
  const objectFact = tryBuildObservedFact({
    factKind: 'observed_object_id',
    value: objectId,
    observationText: href,
    sourceUrl: href,
    observationKind: 'url',
    lineage: collectors.lineage,
    observedAt: collectors.nowIso,
    sourceLabel: 'byot_network_harvest',
  });
  if (!objectFact || collectors.seenFactIds.has(objectFact.factId)) return;
  collectors.seenFactIds.add(objectFact.factId);
  collectors.observedFacts.push(objectFact);
}

function pushGroundedActionFact(
  collectors: HarvestCollectors,
  endpointUrl: string,
  actionId: string,
  observationText: string,
  observationKind: 'http_body' | 'http_header'
): void {
  const fact = tryBuildObservedFact({
    factKind: 'observed_action_id',
    value: actionId,
    observationText,
    sourceUrl: endpointUrl,
    observationKind,
    lineage: collectors.lineage,
    observedAt: collectors.nowIso,
    sourceLabel: 'byot_network_harvest',
  });
  if (!fact || collectors.seenFactIds.has(fact.factId)) return;
  collectors.seenFactIds.add(fact.factId);
  collectors.observedFacts.push(fact);
}

function pushActions(
  collectors: HarvestCollectors,
  endpointUrl: string,
  text: string
): void {
  for (const actionId of extractNextServerActionIdHintsFromText(
    text,
    collectors.maxActionIds
  )) {
    if (collectors.serverActionHints.length >= collectors.maxActionIds) return;
    const key = `${endpointUrl}:${actionId}`;
    if (collectors.seenActions.has(key)) continue;
    collectors.seenActions.add(key);
    collectors.serverActionHints.push({
      endpointUrl,
      actionId,
      source: BYOT_NETWORK_HARVEST_SOURCE,
    });
    pushGroundedActionFact(collectors, endpointUrl, actionId, text, 'http_body');
  }
}

function pushActionId(
  collectors: HarvestCollectors,
  endpointUrl: string,
  actionId: string
): void {
  const id = actionId.trim();
  if (id.length < 8) return;
  if (collectors.serverActionHints.length >= collectors.maxActionIds) return;
  const key = `${endpointUrl}:${id}`;
  if (collectors.seenActions.has(key)) return;
  collectors.seenActions.add(key);
  collectors.serverActionHints.push({
    endpointUrl,
    actionId: id,
    source: BYOT_NETWORK_HARVEST_SOURCE,
  });
  pushGroundedActionFact(collectors, endpointUrl, id, id, 'http_header');
}

async function harvestViaPlaywright(input: {
  readonly request: ByotNetworkHarvestRequest;
  readonly authHeaders: Readonly<Record<string, string>>;
  readonly root: { origin: string; host: string };
  readonly pageCandidates: readonly string[];
  readonly collectors: HarvestCollectors;
  readonly timeoutMs: number;
  readonly maxPages: number;
}): Promise<{ readonly requestsUsed: number; readonly unavailable: boolean }> {
  const launcher =
    input.request.browserLauncher ?? new DefaultPlaywrightBrowserLauncher();
  let browser: Awaited<ReturnType<PlaywrightBrowserLauncher['launch']>> | null =
    null;
  let context: Awaited<
    ReturnType<Awaited<ReturnType<PlaywrightBrowserLauncher['launch']>>['newContext']>
  > | null = null;
  let requestsUsed = 0;

  try {
    try {
      browser = await launcher.launch({ headless: true });
    } catch (launchErr: unknown) {
      if (isBrowserUnavailableError(launchErr)) {
        return { requestsUsed: 0, unavailable: true };
      }
      throw launchErr;
    }

    context = await browser.newContext({
      extraHTTPHeaders: buildAuthExtraHttpHeaders(input.authHeaders),
      userAgent: 'Mozilla/5.0 (FixGuard Defensive Auditor)',
    });

    for (const pageUrl of input.pageCandidates.slice(0, input.maxPages)) {
      const preflight = await runAdapterPreflight({
        target: pageUrl,
        targetKind: 'url',
        verifiedAuthorizationDecision: input.request.verifiedAuthorizationDecision,
        authorizedScopeGrant: input.request.authorizedScopeGrant,
        lineage: input.request.lineage,
        requiredPermissions: [
          'endpointDiscovery',
          'activeCrawling',
          'authenticatedTesting',
          'passiveRecon',
          'technologyFingerprinting',
        ],
        missingPermissionReason:
          'Scope grant does not permit authenticated BYOT network harvest',
        dnsResolver: input.request.dnsResolver,
      });
      if (!preflight.ok) {
        if (pageUrl === input.request.originUrl) {
          throw Object.assign(new Error(preflight.reason ?? preflight.reasonCode), {
            name: 'ByotHarvestPreflightDenied',
            reasonCode: preflight.reasonCode,
            reason: preflight.reason,
          });
        }
        continue;
      }

      const page = await context.newPage();
      try {
        await page.route('**/*', async (route) => {
          const req = route.request();
          const classification = classifyBrowserRouteLoad({
            url: req.url(),
            resourceType: req.resourceType(),
            authorizedScopeGrant: input.request.authorizedScopeGrant,
          });
          if (classification.decision === 'abort') {
            await route.abort('blockedbyclient');
            return;
          }
          await route.continue();
        });

        page.on('request', (networkReq) => {
          try {
            const rawUrl = networkReq.url();
            const sanitized = sanitizeDiscoveredNetworkUrl(rawUrl);
            if (!sanitized) return;
            const parsed = new URL(sanitized);
            if (
              !isMineableNetworkRequest(
                networkReq.resourceType(),
                parsed.pathname,
                parsed.search
              )
            ) {
              return;
            }
            if (!isBrowserUrlAllowed(sanitized, input.request.authorizedScopeGrant)) {
              return;
            }
            pushUrl(input.collectors, sanitized);

            const nextAction =
              typeof networkReq.headerValue === 'function'
                ? networkReq.headerValue('next-action')
                : undefined;
            if (typeof nextAction === 'string' && nextAction.trim().length >= 8) {
              pushActionId(input.collectors, sanitized, nextAction);
            }
          } catch {
            // ignore malformed network events
          }
        });

        await page.goto(pageUrl, {
          waitUntil: 'domcontentloaded',
          timeout: input.timeoutMs,
        });
        requestsUsed += 1;
        pushUrl(input.collectors, pageUrl);

        await page.waitForTimeout(BYOT_HARVEST_HYDRATION_WAIT_MS);
        try {
          await page.waitForLoadState('networkidle', {
            timeout: Math.min(BYOT_HARVEST_NETWORKIDLE_WAIT_MS, input.timeoutMs),
          });
        } catch {
          // best-effort
        }

        const pageText = await page.evaluate(() => {
          try {
            const html = document.documentElement?.innerHTML ?? '';
            return html.length > 250_000 ? html.slice(0, 250_000) : html;
          } catch {
            return '';
          }
        });
        if (typeof pageText === 'string' && pageText.length > 0) {
          pushActions(input.collectors, pageUrl, pageText);
          for (const mined of extractInScopePathUrls(
            pageText,
            input.root.origin,
            input.root.host,
            input.collectors.maxUrls
          )) {
            pushUrl(input.collectors, mined);
          }
        }
      } finally {
        await page.close().catch(() => undefined);
      }
    }

    return { requestsUsed, unavailable: false };
  } finally {
    if (context) await context.close().catch(() => undefined);
    if (browser) await browser.close().catch(() => undefined);
  }
}

async function harvestViaHttp(input: {
  readonly request: ByotNetworkHarvestRequest;
  readonly authHeaders: Readonly<Record<string, string>>;
  readonly root: { origin: string; host: string };
  readonly pageCandidates: readonly string[];
  readonly collectors: HarvestCollectors;
  readonly timeoutMs: number;
  readonly maxPages: number;
  readonly maxScripts: number;
}): Promise<{ readonly requestsUsed: number; readonly preflightDenied?: ByotNetworkHarvestResult }> {
  const transport = input.request.transport ?? defaultHttpProbeTransport;
  let requestsUsed = 0;
  const scriptQueue: string[] = [];
  const seenScripts = new Set<string>();

  for (const pageUrl of input.pageCandidates.slice(0, input.maxPages)) {
    const preflight = await runAdapterPreflight({
      target: pageUrl,
      targetKind: 'url',
      verifiedAuthorizationDecision: input.request.verifiedAuthorizationDecision,
      authorizedScopeGrant: input.request.authorizedScopeGrant,
      lineage: input.request.lineage,
      requiredPermissions: [
        'endpointDiscovery',
        'activeCrawling',
        'authenticatedTesting',
        'passiveRecon',
        'technologyFingerprinting',
      ],
      missingPermissionReason:
        'Scope grant does not permit authenticated BYOT network harvest',
      dnsResolver: input.request.dnsResolver,
    });
    if (!preflight.ok) {
      if (pageUrl === input.request.originUrl) {
        return {
          requestsUsed: 0,
          preflightDenied: {
            status: 'preflight_denied',
            contractVersion: BYOT_NETWORK_HARVEST_CONTRACT_VERSION,
            originUrl: input.request.originUrl,
            reasonCode: preflight.reasonCode,
            reason: preflight.reason,
            requestsUsed: 0,
            urlObservations: [],
            serverActionHints: [],
            nonClaims: BYOT_NETWORK_HARVEST_NON_CLAIMS,
          },
        };
      }
      continue;
    }

    try {
      const probe = await transport({
        url: pageUrl,
        method: 'GET',
        headers: {
          ...input.authHeaders,
          accept: 'text/html, application/xhtml+xml, */*',
          'user-agent': 'Mozilla/5.0 (FixGuard Defensive Auditor)',
        },
        timeoutMs: input.timeoutMs,
      });
      requestsUsed += 1;
      retainHarvestGet(input.request, input.collectors, pageUrl, probe);
      pushUrl(input.collectors, pageUrl);
      if (probe.statusCode >= 200 && probe.statusCode < 400 && probe.bodyText) {
        pushActions(input.collectors, pageUrl, probe.bodyText);
        for (const mined of extractInScopePathUrls(
          probe.bodyText,
          input.root.origin,
          input.root.host,
          input.collectors.maxUrls
        )) {
          pushUrl(input.collectors, mined);
        }
        for (const src of extractScriptSrcs(
          probe.bodyText,
          pageUrl,
          input.maxScripts
        )) {
          if (seenScripts.has(src)) continue;
          seenScripts.add(src);
          if (scriptQueue.length < input.maxScripts) scriptQueue.push(src);
        }
      }
    } catch {
      requestsUsed += 1;
    }
  }

  for (const scriptUrl of scriptQueue) {
    if (
      input.collectors.urlObservations.length >= input.collectors.maxUrls &&
      input.collectors.serverActionHints.length >= input.collectors.maxActionIds
    ) {
      break;
    }
    const preflight = await runAdapterPreflight({
      target: scriptUrl,
      targetKind: 'url',
      verifiedAuthorizationDecision: input.request.verifiedAuthorizationDecision,
      authorizedScopeGrant: input.request.authorizedScopeGrant,
      lineage: input.request.lineage,
      requiredPermissions: [
        'endpointDiscovery',
        'activeCrawling',
        'authenticatedTesting',
        'passiveRecon',
        'technologyFingerprinting',
      ],
      missingPermissionReason:
        'Scope grant does not permit authenticated BYOT script harvest',
      dnsResolver: input.request.dnsResolver,
    });
    if (!preflight.ok) continue;

    try {
      const probe = await transport({
        url: scriptUrl,
        method: 'GET',
        headers: {
          ...input.authHeaders,
          accept: 'application/javascript, text/javascript, */*',
          'user-agent': 'Mozilla/5.0 (FixGuard Defensive Auditor)',
        },
        timeoutMs: input.timeoutMs,
      });
      requestsUsed += 1;
      retainHarvestGet(input.request, input.collectors, scriptUrl, probe);
      if (probe.statusCode >= 200 && probe.statusCode < 300 && probe.bodyText) {
        pushUrl(input.collectors, scriptUrl);
        pushActions(input.collectors, input.request.originUrl, probe.bodyText);
        for (const mined of extractInScopePathUrls(
          probe.bodyText,
          input.root.origin,
          input.root.host,
          input.collectors.maxUrls
        )) {
          pushUrl(input.collectors, mined);
        }
      }
    } catch {
      requestsUsed += 1;
    }
  }

  return { requestsUsed };
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
  const timeoutMs = request.timeoutMs ?? 12_000;
  const nowIso = new Date().toISOString();

  const pageCandidates: string[] = [request.originUrl];
  for (const p of request.pageUrls ?? []) {
    if (pageCandidates.length >= maxPages) break;
    if (!pageCandidates.includes(p)) pageCandidates.push(p);
  }

  const collectors: HarvestCollectors = {
    urlObservations: [],
    serverActionHints: [],
    observedFacts: [],
    seenUrls: new Set<string>(),
    seenActions: new Set<string>(),
    seenFactIds: new Set<string>(),
    rootHost: root.host,
    maxUrls,
    maxActionIds,
    nowIso,
    lineage: request.lineage,
  };

  let harvestMode: ByotHarvestMode = 'http_fallback';
  let requestsUsed = 0;

  if (request.httpOnly !== true) {
    try {
      const pw = await harvestViaPlaywright({
        request,
        authHeaders,
        root,
        pageCandidates,
        collectors,
        timeoutMs,
        maxPages,
      });
      if (!pw.unavailable) {
        harvestMode = 'playwright';
        requestsUsed = pw.requestsUsed;
      }
    } catch (err: unknown) {
      if (
        err &&
        typeof err === 'object' &&
        'name' in err &&
        (err as { name?: string }).name === 'ByotHarvestPreflightDenied'
      ) {
        const denied = err as {
          reasonCode?: string;
          reason?: string;
        };
        return {
          status: 'preflight_denied',
          contractVersion: BYOT_NETWORK_HARVEST_CONTRACT_VERSION,
          originUrl: request.originUrl,
          reasonCode: denied.reasonCode ?? 'preflight_denied',
          reason: denied.reason,
          requestsUsed: 0,
          urlObservations: [],
          serverActionHints: [],
          nonClaims: BYOT_NETWORK_HARVEST_NON_CLAIMS,
        };
      }
      // Non-unavailable browser errors: fall through to HTTP fallback.
    }
  }

  if (harvestMode !== 'playwright') {
    const http = await harvestViaHttp({
      request,
      authHeaders,
      root,
      pageCandidates,
      collectors,
      timeoutMs,
      maxPages,
      maxScripts,
    });
    if (http.preflightDenied) return http.preflightDenied;
    requestsUsed = http.requestsUsed;
    harvestMode = 'http_fallback';
  }

  const empty =
    collectors.urlObservations.length === 0 &&
    collectors.serverActionHints.length === 0;
  return {
    status: 'success',
    contractVersion: BYOT_NETWORK_HARVEST_CONTRACT_VERSION,
    originUrl: request.originUrl,
    reasonCode: empty ? 'harvested_empty' : 'harvested',
    harvestMode,
    requestsUsed,
    urlObservations: Object.freeze(collectors.urlObservations),
    serverActionHints: Object.freeze(collectors.serverActionHints),
    observedFacts: Object.freeze(collectors.observedFacts),
    nonClaims: BYOT_NETWORK_HARVEST_NON_CLAIMS,
  };
}
