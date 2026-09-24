/**
 * Milestone 7 / Phase D1 — Browser Automation Engine for SPA & RSC Discovery (Playwright)
 *
 * Implements headless browser crawling, dynamic JavaScript hydration wait,
 * DOM/RSC route mining, SPA network (XHR/fetch) mining, and form/parameter extraction.
 *
 * Egress model (fail-closed, same gates as HTML extraction / other adapters):
 * 1. Gate 1 — runAdapterPreflight before browser launch:
 *    verified auth brand, lineage, permissions, host scope, static SSRF, DNS rebind.
 * 2. Gate 2 — page.route interceptor for EVERY navigation and subresource:
 *    isInternalOrSsrfTarget OR !isScopeAllowed OR evaluateEgressPolicy !== allow → abort.
 * 3. Gate 3 — discovered route registration (DOM + network):
 *    same scope + egress filters before emitting OBSERVED routes (OOS dropped).
 *
 * Network mining: page.on('request') captures in-scope xhr/fetch URLs while the
 * seed/app page renders — critical for SPAs where the DOM has no extra links.
 * Caps: maxRoutes / maxNetworkUrls per page. Loud degrade → browser_unavailable.
 *
 * Invariants:
 * 1. Layer 6 Tool Adapter: Observes and extracts; makes 0 vulnerability claims.
 * 2. Guaranteed Cleanup: Context and browser closed in finally (0 zombie processes).
 * 3. Strictly zero type bypass policy.
 * 4. Network mining stores path+query only; never headers/bodies; strips token-like query keys.
 */

import { chromium } from 'playwright';
import { isScopeAllowed } from '../../attack-execution/AttackExecutionContracts.js';
import { deriveM30EgressScope } from '../../authorization/VerifiedAuthorizationDecisionService.js';
import { evaluateEgressPolicy, isInternalOrSsrfTarget } from '../policy/PassiveEgressPolicy.js';
import {
  runAdapterPreflight,
  type PreSpawnDnsResolver,
} from './AdapterPreflightPipeline.js';
import {
  CIRCUIT_OPEN_REASON_CODE,
  TargetInstabilityError,
} from '../../runtime/CircuitBreakerContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type {
  BrowserAutomationRequest,
  BrowserAutomationResult,
  BrowserAutomationTool,
  BrowserInstance,
  BrowserContextInstance,
  PageInstance,
  PlaywrightBrowserLauncher,
  RouteInstance,
  ResponseInstance,
  DiscoveredSpaObservation,
  DiscoveredSpaRouteObservation,
  DiscoveredDomInputObservation,
  SpaRouteType,
} from './BrowserAutomationContracts.js';
import {
  BROWSER_AUTOMATION_CONTRACT_VERSION,
  BROWSER_AUTOMATION_NON_CLAIMS,
  PLAYWRIGHT_NETWORK_SOURCE,
  PLAYWRIGHT_SPA_SOURCE,
  RSC_DISCOVERY_SOURCE,
  SPA_DISCOVERY_DEFAULT_TIMEOUT_MS,
  SPA_DISCOVERY_MAX_NETWORK_URLS_PER_PAGE,
  SPA_DISCOVERY_MAX_ROUTES_PER_PAGE,
  type NetworkRequestInstance,
  type SpaRouteDiscoverySource,
} from './BrowserAutomationContracts.js';

/** Playwright resource types mined as OBSERVED discovery endpoints. */
const MINEABLE_NETWORK_RESOURCE_TYPES = Object.freeze(new Set(['xhr', 'fetch']));

/** Static media extensions dropped from network mining (mirrors HTML extractor). */
const REJECTED_NETWORK_MEDIA_EXTENSIONS = Object.freeze([
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.svg',
  '.webp',
  '.ico',
  '.woff',
  '.woff2',
  '.ttf',
  '.eot',
  '.css',
  '.mp4',
  '.webm',
  '.mp3',
] as const);

/** Query keys whose values must never be retained in discovered URLs. */
const SENSITIVE_QUERY_KEY_PATTERN =
  /^(?:access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?key|apikey|auth(?:orization)?|password|passwd|secret|session(?:id)?|sid|jwt|bearer|token|key|credential|sig|signature|code|otp)$/i;

class PlaywrightPageWrapper implements PageInstance {
  constructor(private readonly rawPage: import('playwright').Page) {}

  async goto(
    url: string,
    options?: { waitUntil?: 'load' | 'domcontentloaded' | 'networkidle'; timeout?: number }
  ): Promise<unknown> {
    return this.rawPage.goto(url, options);
  }

  async route(urlPattern: string, handler: (route: RouteInstance) => Promise<void>): Promise<void> {
    await this.rawPage.route(urlPattern, async (rawRoute) => {
      const routeWrapper: RouteInstance = {
        request: () => ({
          url: () => rawRoute.request().url(),
          method: () => rawRoute.request().method(),
        }),
        abort: async (errorCode?: string) => {
          await rawRoute.abort(errorCode);
        },
        continue: async () => {
          await rawRoute.continue();
        },
      };
      await handler(routeWrapper);
    });
  }

  on(
    event: 'response' | 'request',
    handler: ((response: ResponseInstance) => void) | ((request: NetworkRequestInstance) => void)
  ): void {
    if (event === 'response') {
      this.rawPage.on('response', (rawRes) => {
        (handler as (response: ResponseInstance) => void)({
          status: () => rawRes.status(),
          url: () => rawRes.url(),
        });
      });
      return;
    }
    if (event === 'request') {
      this.rawPage.on('request', (rawReq) => {
        (handler as (request: NetworkRequestInstance) => void)({
          url: () => rawReq.url(),
          method: () => rawReq.method(),
          resourceType: () => rawReq.resourceType(),
        });
      });
    }
  }

  async waitForLoadState(
    state?: 'load' | 'domcontentloaded' | 'networkidle',
    options?: { timeout?: number }
  ): Promise<void> {
    await this.rawPage.waitForLoadState(state, options);
  }

  async waitForTimeout(ms: number): Promise<void> {
    await this.rawPage.waitForTimeout(ms);
  }

  async evaluate<T>(fn: () => T | Promise<T>): Promise<T> {
    return this.rawPage.evaluate(fn);
  }

  async title(): Promise<string> {
    return this.rawPage.title();
  }

  async close(): Promise<void> {
    await this.rawPage.close();
  }
}

class PlaywrightBrowserContextWrapper implements BrowserContextInstance {
  constructor(private readonly rawContext: import('playwright').BrowserContext) {}

  async newPage(): Promise<PageInstance> {
    const rawPage = await this.rawContext.newPage();
    return new PlaywrightPageWrapper(rawPage);
  }

  async close(): Promise<void> {
    await this.rawContext.close();
  }
}

class PlaywrightBrowserWrapper implements BrowserInstance {
  constructor(private readonly rawBrowser: import('playwright').Browser) {}

  async newContext(options?: Record<string, unknown>): Promise<BrowserContextInstance> {
    const rawContext = await this.rawBrowser.newContext(options);
    return new PlaywrightBrowserContextWrapper(rawContext);
  }

  async close(): Promise<void> {
    await this.rawBrowser.close();
  }
}

export class DefaultPlaywrightBrowserLauncher implements PlaywrightBrowserLauncher {
  async launch(options?: { headless?: boolean; args?: readonly string[] }): Promise<BrowserInstance> {
    const rawBrowser = await chromium.launch({
      headless: options?.headless ?? true,
      args: options?.args
        ? [...options.args]
        : ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
    });
    return new PlaywrightBrowserWrapper(rawBrowser);
  }
}

interface RawDomEvaluationResult {
  readonly links: readonly string[];
  readonly forms: readonly {
    readonly action?: string;
    readonly method?: string;
    readonly inputs: readonly {
      readonly name: string;
      readonly type: string;
    }[];
  }[];
  readonly frameworks: readonly string[];
  readonly scripts: readonly string[];
  readonly rscPaths: readonly string[];
  readonly nextDataPage?: string;
}

/**
 * Fail-closed URL acceptance for browser navigations, subresources, and mined routes.
 * Mirrors HtmlRouteExtractionService: scope host check + evaluateEgressPolicy.
 */
export function isBrowserUrlAllowed(
  absoluteUrl: string,
  authorizedScopeGrant: AuthorizedScopeGrant
): boolean {
  let parsed: URL;
  try {
    parsed = new URL(absoluteUrl);
  } catch {
    return false;
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return false;
  }

  const host = parsed.hostname.trim().toLowerCase().replace(/\.$/, '');
  if (!host || isInternalOrSsrfTarget(host)) {
    return false;
  }

  if (!isScopeAllowed(host, authorizedScopeGrant)) {
    return false;
  }

  const egressScope = deriveM30EgressScope(authorizedScopeGrant);
  const egressDecision = evaluateEgressPolicy({
    targetUrl: absoluteUrl,
    authorizedScope: egressScope,
    capabilityId: 'recon.playwright_spa_discovery',
  });
  return egressDecision.decision === 'allow';
}

function isRejectedNetworkMediaPath(pathname: string): boolean {
  const lower = pathname.toLowerCase();
  return REJECTED_NETWORK_MEDIA_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

/**
 * Normalize URL to protocol+host+path+sanitized-query.
 * Strips hash and redacts token-like query parameter values (never retains secrets).
 */
export function sanitizeDiscoveredNetworkUrl(absoluteUrl: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(absoluteUrl);
  } catch {
    return null;
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return null;
  }

  parsed.hash = '';
  if (parsed.search.length > 1) {
    const params = new URLSearchParams(parsed.search);
    const sanitizedParams = new URLSearchParams();
    for (const [key, value] of params.entries()) {
      if (SENSITIVE_QUERY_KEY_PATTERN.test(key)) {
        sanitizedParams.append(key, '[REDACTED]');
      } else {
        sanitizedParams.append(key, value);
      }
    }
    const qs = sanitizedParams.toString();
    parsed.search = qs.length > 0 ? `?${qs}` : '';
  }

  return `${parsed.protocol}//${parsed.host}${parsed.pathname}${parsed.search}`;
}

function isMineableNetworkResourceType(resourceType: string): boolean {
  return MINEABLE_NETWORK_RESOURCE_TYPES.has(resourceType.trim().toLowerCase());
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

export class PlaywrightSpaAdapter implements BrowserAutomationTool {
  private readonly defaultLauncher: PlaywrightBrowserLauncher;

  constructor(
    private readonly launcher?: PlaywrightBrowserLauncher,
    private readonly defaultDnsResolver?: PreSpawnDnsResolver
  ) {
    this.defaultLauncher = launcher ?? new DefaultPlaywrightBrowserLauncher();
  }

  public async discoverSpa(request: BrowserAutomationRequest): Promise<BrowserAutomationResult> {
    const startTime = Date.now();
    const rawTarget = typeof request.targetUrlOrDomain === 'string' ? request.targetUrlOrDomain.trim() : '';

    // -------------------------------------------------------------------------
    // Double SSRF Gate — Pass 1: Unified Preflight Gate
    // -------------------------------------------------------------------------
    const preflight = await runAdapterPreflight({
      target: rawTarget,
      targetKind: 'host_or_url',
      verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
      authorizedScopeGrant: request.authorizedScopeGrant,
      lineage: request.lineage,
      requiredPermissions: ['endpointDiscovery', 'activeCrawling', 'technologyFingerprinting'],
      missingPermissionReason: 'Scope grant does not permit browser-based SPA endpoint or technology discovery',
      dnsResolver: request.dnsResolver ?? this.defaultDnsResolver,
    });

    if (!preflight.ok) {
      return {
        status: 'preflight_denied',
        contractVersion: BROWSER_AUTOMATION_CONTRACT_VERSION,
        targetUrlOrDomain: rawTarget,
        reasonCode: preflight.reasonCode,
        reason: preflight.reason,
        explicitNonClaims: BROWSER_AUTOMATION_NON_CLAIMS,
        lineage: { ...request.lineage },
        durationMs: Date.now() - startTime,
      };
    }

    const targetHost = preflight.targetHost!;
    const targetUrl = preflight.targetUrl ?? `https://${targetHost}/`;
    const coordinator = request.coordinator;
    const maxRoutes =
      typeof request.maxRoutes === 'number' && request.maxRoutes > 0
        ? Math.floor(request.maxRoutes)
        : SPA_DISCOVERY_MAX_ROUTES_PER_PAGE;

    // -------------------------------------------------------------------------
    // Gate 2: Circuit Breaker Pre-Launch Check
    // -------------------------------------------------------------------------
    if (coordinator && coordinator.isCircuitOpen(targetHost)) {
      return {
        status: 'circuit_broken',
        contractVersion: BROWSER_AUTOMATION_CONTRACT_VERSION,
        targetUrlOrDomain: rawTarget,
        targetHost,
        reasonCode: CIRCUIT_OPEN_REASON_CODE,
        reason: `Target circuit breaker is OPEN on '${targetHost}'. Browser execution safely paused.`,
        observations: [],
        routes: [],
        inputs: [],
        explicitNonClaims: BROWSER_AUTOMATION_NON_CLAIMS,
        lineage: { ...request.lineage },
        durationMs: Date.now() - startTime,
      };
    }

    const launcher = request.browserLauncher ?? this.defaultLauncher;
    let browser: BrowserInstance | null = null;
    let context: BrowserContextInstance | null = null;
    let page: PageInstance | null = null;

    const timeoutMs = request.timeoutMs ?? SPA_DISCOVERY_DEFAULT_TIMEOUT_MS;
    const hydrationWaitMs = request.waitForHydrationMs ?? 1_000;
    const maxNetworkUrls = SPA_DISCOVERY_MAX_NETWORK_URLS_PER_PAGE;
    const minedNetworkRoutes: DiscoveredSpaRouteObservation[] = [];
    const seenNetworkKeys = new Set<string>();

    try {
      // Launch browser — loud degrade when Chromium/Playwright missing
      try {
        browser = await launcher.launch({ headless: true });
      } catch (launchErr: unknown) {
        if (isBrowserUnavailableError(launchErr)) {
          const errorMsg = launchErr instanceof Error ? launchErr.message : String(launchErr);
          return {
            status: 'execution_failed',
            contractVersion: BROWSER_AUTOMATION_CONTRACT_VERSION,
            targetUrlOrDomain: rawTarget,
            targetHost,
            reasonCode: 'browser_unavailable',
            reason: `Playwright/Chromium unavailable: ${errorMsg}`,
            explicitNonClaims: BROWSER_AUTOMATION_NON_CLAIMS,
            lineage: { ...request.lineage },
            durationMs: Date.now() - startTime,
          };
        }
        throw launchErr;
      }

      context = await browser.newContext();
      page = await context.newPage();

      // -----------------------------------------------------------------------
      // Gate 2 — In-Browser Navigation & Subresource Interception
      // SSRF + scope + egress (fail-closed OOS). Same policy as HTML extraction.
      // -----------------------------------------------------------------------
      await page.route('**/*', async (route) => {
        const reqUrl = route.request().url();
        let isBlocked = false;

        try {
          if (!isBrowserUrlAllowed(reqUrl, request.authorizedScopeGrant)) {
            isBlocked = true;
          }
        } catch {
          isBlocked = true;
        }

        if (isBlocked) {
          await route.abort('blockedbyclient');
          return;
        }

        if (coordinator && coordinator.isCircuitOpen(targetHost)) {
          await route.abort('failed');
          return;
        }

        await route.continue();
      });

      // Telemetry only — never mine from response bodies/headers.
      page.on('response', (response) => {
        try {
          const resUrl = response.url();
          const parsed = new URL(resUrl);
          if (parsed.hostname === targetHost && coordinator) {
            coordinator.recordTargetResponse(targetHost, response.status());
          }
        } catch {
          // Ignore malformed response URLs
        }
      });

      // SPA network mining: capture in-scope xhr/fetch while the page renders.
      // Path+query only; Gate 3 scope/egress before retention; never headers/bodies.
      page.on('request', (networkReq) => {
        if (minedNetworkRoutes.length >= maxNetworkUrls) return;
        if (!isMineableNetworkResourceType(networkReq.resourceType())) return;

        try {
          const rawUrl = networkReq.url();
          const sanitized = sanitizeDiscoveredNetworkUrl(rawUrl);
          if (!sanitized) return;

          const parsed = new URL(sanitized);
          if (isRejectedNetworkMediaPath(parsed.pathname)) return;
          if (!isBrowserUrlAllowed(sanitized, request.authorizedScopeGrant)) return;

          const method = (networkReq.method() || 'GET').toUpperCase();
          const key = `${method}:${parsed.pathname}${parsed.search}`;
          if (seenNetworkKeys.has(key)) return;
          seenNetworkKeys.add(key);

          minedNetworkRoutes.push({
            url: sanitized,
            path: parsed.pathname,
            method,
            routeType: 'api_fetch',
            source: PLAYWRIGHT_NETWORK_SOURCE,
            discoveredAt: new Date().toISOString(),
          });
        } catch {
          // Ignore malformed request URLs
        }
      });

      // Navigate via coordinator concurrency gate
      if (coordinator) {
        await coordinator.execute(targetHost, async () => {
          if (page) {
            await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: timeoutMs });
          }
        });
      } else {
        await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: timeoutMs });
      }

      // Check if circuit breaker tripped during navigation
      if (coordinator && coordinator.isCircuitOpen(targetHost)) {
        return {
          status: 'circuit_broken',
          contractVersion: BROWSER_AUTOMATION_CONTRACT_VERSION,
          targetUrlOrDomain: rawTarget,
          targetHost,
          reasonCode: CIRCUIT_OPEN_REASON_CODE,
          reason: `Target circuit breaker tripped to OPEN on '${targetHost}' during navigation. Execution halted.`,
          observations: [],
          routes: [],
          inputs: [],
          explicitNonClaims: BROWSER_AUTOMATION_NON_CLAIMS,
          lineage: { ...request.lineage },
          durationMs: Date.now() - startTime,
        };
      }

      // Await DOM hydration
      if (hydrationWaitMs > 0) {
        await page.waitForTimeout(hydrationWaitMs);
      }

      const pageTitle = await page.title().catch(() => '');

      // Extract DOM + Next.js/RSC hydration artifacts
      const evalResult: RawDomEvaluationResult = await page.evaluate(() => {
        const collectedLinks: string[] = [];
        const linkNodes = document.querySelectorAll('a[href]');
        for (let i = 0; i < linkNodes.length; i++) {
          const href = linkNodes[i].getAttribute('href');
          if (href && !href.startsWith('javascript:') && !href.startsWith('#')) {
            collectedLinks.push(href);
          }
        }

        const collectedForms: {
          action?: string;
          method?: string;
          inputs: { name: string; type: string }[];
        }[] = [];

        const formNodes = document.querySelectorAll('form');
        for (let i = 0; i < formNodes.length; i++) {
          const form = formNodes[i];
          const formAction = form.getAttribute('action') || undefined;
          const formMethod = form.getAttribute('method') || 'GET';
          const inputs: { name: string; type: string }[] = [];

          const inputElements = form.querySelectorAll('input, select, textarea');
          for (let j = 0; j < inputElements.length; j++) {
            const el = inputElements[j];
            const name = el.getAttribute('name');
            if (name) {
              const type = el.getAttribute('type') || el.tagName.toLowerCase();
              inputs.push({ name, type });
            }
          }

          collectedForms.push({ action: formAction, method: formMethod, inputs });
        }

        const detectedFrameworks: string[] = [];
        const win = window as unknown as Record<string, unknown>;
        const rscPaths: string[] = [];
        let nextDataPage: string | undefined;

        if (win && typeof win === 'object') {
          if ('__NEXT_DATA__' in win) {
            detectedFrameworks.push('Next.js');
            const nextData = win.__NEXT_DATA__;
            if (nextData && typeof nextData === 'object') {
              const nd = nextData as Record<string, unknown>;
              if (typeof nd.page === 'string' && nd.page.length > 0) {
                nextDataPage = nd.page.startsWith('/') ? nd.page : `/${nd.page}`;
                rscPaths.push(nextDataPage);
              }
              if (typeof nd.buildId === 'string' && nd.buildId.length > 0 && nextDataPage) {
                rscPaths.push(`/_next/data/${nd.buildId}${nextDataPage === '/' ? '/index' : nextDataPage}.json`);
              }
            }
          }
          if ('__REACT_DEVTOOLS_GLOBAL_HOOK__' in win) detectedFrameworks.push('React');
          if ('__NUXT__' in win) detectedFrameworks.push('Nuxt');
          if ('__VUE__' in win) detectedFrameworks.push('Vue');
          if ('ng' in win) detectedFrameworks.push('Angular');
        }

        // App-router RSC markers in the DOM (self.__next_f, flight script payloads).
        const html = document.documentElement?.innerHTML ?? '';
        if (html.includes('self.__next_f') || html.includes('__next_f.push')) {
          if (!detectedFrameworks.includes('Next.js')) {
            detectedFrameworks.push('Next.js');
          }
        }

        const collectedScripts: string[] = [];
        const scriptNodes = document.querySelectorAll('script[src]');
        for (let i = 0; i < scriptNodes.length; i++) {
          const src = scriptNodes[i].getAttribute('src');
          if (src) {
            collectedScripts.push(src);
            if (src.includes('/_next/')) {
              if (!detectedFrameworks.includes('Next.js')) {
                detectedFrameworks.push('Next.js');
              }
            }
          }
        }

        // Prefetch / next/link data attributes often expose in-app routes.
        const prefetchNodes = document.querySelectorAll('[data-prefetch], link[rel="prefetch"]');
        for (let i = 0; i < prefetchNodes.length; i++) {
          const el = prefetchNodes[i];
          const href = el.getAttribute('href');
          if (href && href.startsWith('/')) {
            rscPaths.push(href);
          }
        }

        return {
          links: collectedLinks,
          forms: collectedForms,
          frameworks: detectedFrameworks,
          scripts: collectedScripts,
          rscPaths,
          nextDataPage,
        };
      });

      const nowIso = new Date().toISOString();
      const discoveredRoutes: DiscoveredSpaRouteObservation[] = [];
      const discoveredInputs: DiscoveredDomInputObservation[] = [];
      const seenRoutes = new Set<string>();

      const tryAddRoute = (
        rawHref: string,
        routeType: SpaRouteType,
        source: SpaRouteDiscoverySource,
        method: string
      ): void => {
        if (discoveredRoutes.length >= maxRoutes) return;
        try {
          const resolved = new URL(rawHref, targetUrl);
          resolved.hash = '';
          const absoluteUrl = `${resolved.protocol}//${resolved.host}${resolved.pathname}${resolved.search}`;
          if (!isBrowserUrlAllowed(absoluteUrl, request.authorizedScopeGrant)) {
            return;
          }
          const key = `${method}:${resolved.pathname}${resolved.search}`;
          if (seenRoutes.has(key)) return;
          seenRoutes.add(key);
          discoveredRoutes.push({
            url: absoluteUrl,
            path: resolved.pathname,
            method,
            routeType,
            source,
            discoveredAt: nowIso,
          });
        } catch {
          // Ignore invalid URLs
        }
      };

      // Prefer network-mined xhr/fetch first — the unblocker when DOM has no links.
      for (const networkRoute of minedNetworkRoutes) {
        if (discoveredRoutes.length >= maxRoutes) break;
        let search = '';
        try {
          search = new URL(networkRoute.url).search;
        } catch {
          search = '';
        }
        const key = `${networkRoute.method ?? 'GET'}:${networkRoute.path}${search}`;
        if (seenRoutes.has(key)) continue;
        seenRoutes.add(key);
        discoveredRoutes.push({
          ...networkRoute,
          discoveredAt: nowIso,
        });
      }

      for (const link of evalResult.links) {
        tryAddRoute(link, 'dom_link', PLAYWRIGHT_SPA_SOURCE, 'GET');
      }

      for (const form of evalResult.forms) {
        let formUrl = targetUrl;
        let formPath = '/';
        if (form.action) {
          try {
            const resolved = new URL(form.action, targetUrl);
            formUrl = resolved.href;
            formPath = resolved.pathname;
          } catch {
            formPath = form.action;
          }
        }

        const formMethod = (form.method ?? 'GET').toUpperCase();
        tryAddRoute(form.action ?? formUrl, 'form_action', PLAYWRIGHT_SPA_SOURCE, formMethod);

        for (const input of form.inputs) {
          discoveredInputs.push({
            formAction: formPath,
            inputName: input.name,
            inputType: input.type,
            method: formMethod,
            discoveredAt: nowIso,
          });
        }
      }

      for (const rscPath of evalResult.rscPaths) {
        tryAddRoute(rscPath, 'rsc_hint', RSC_DISCOVERY_SOURCE, 'GET');
      }

      if (evalResult.nextDataPage) {
        tryAddRoute(evalResult.nextDataPage, 'rsc_hint', RSC_DISCOVERY_SOURCE, 'GET');
      }

      const observation: DiscoveredSpaObservation = {
        url: targetUrl,
        targetHost,
        pageTitle: pageTitle.length > 0 ? pageTitle : undefined,
        frameworks: evalResult.frameworks,
        routes: discoveredRoutes,
        inputs: discoveredInputs,
        technologies: [...evalResult.frameworks],
        discoveredAt: nowIso,
        collectedAt: nowIso,
        freshness: 'live',
        sourceReliability: 'direct_observation',
      };

      return {
        status: 'success',
        contractVersion: BROWSER_AUTOMATION_CONTRACT_VERSION,
        targetUrlOrDomain: rawTarget,
        targetHost,
        observations: [observation],
        routes: discoveredRoutes,
        inputs: discoveredInputs,
        explicitNonClaims: BROWSER_AUTOMATION_NON_CLAIMS,
        lineage: { ...request.lineage },
        durationMs: Date.now() - startTime,
      };
    } catch (err: unknown) {
      if (
        err instanceof TargetInstabilityError ||
        (coordinator && coordinator.isCircuitOpen(targetHost))
      ) {
        return {
          status: 'circuit_broken',
          contractVersion: BROWSER_AUTOMATION_CONTRACT_VERSION,
          targetUrlOrDomain: rawTarget,
          targetHost,
          reasonCode: CIRCUIT_OPEN_REASON_CODE,
          reason: `Target circuit breaker is OPEN on '${targetHost}'. Browser execution safely paused.`,
          observations: [],
          routes: [],
          inputs: [],
          explicitNonClaims: BROWSER_AUTOMATION_NON_CLAIMS,
          lineage: { ...request.lineage },
          durationMs: Date.now() - startTime,
        };
      }

      if (isBrowserUnavailableError(err)) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        return {
          status: 'execution_failed',
          contractVersion: BROWSER_AUTOMATION_CONTRACT_VERSION,
          targetUrlOrDomain: rawTarget,
          targetHost,
          reasonCode: 'browser_unavailable',
          reason: `Playwright/Chromium unavailable: ${errorMsg}`,
          explicitNonClaims: BROWSER_AUTOMATION_NON_CLAIMS,
          lineage: { ...request.lineage },
          durationMs: Date.now() - startTime,
        };
      }

      const errorMsg = err instanceof Error ? err.message : String(err);
      return {
        status: 'execution_failed',
        contractVersion: BROWSER_AUTOMATION_CONTRACT_VERSION,
        targetUrlOrDomain: rawTarget,
        targetHost,
        reasonCode: 'browser_automation_error',
        reason: errorMsg,
        explicitNonClaims: BROWSER_AUTOMATION_NON_CLAIMS,
        lineage: { ...request.lineage },
        durationMs: Date.now() - startTime,
      };
    } finally {
      if (page) {
        await page.close().catch(() => {});
      }
      if (context) {
        await context.close().catch(() => {});
      }
      if (browser) {
        await browser.close().catch(() => {});
      }
    }
  }
}
