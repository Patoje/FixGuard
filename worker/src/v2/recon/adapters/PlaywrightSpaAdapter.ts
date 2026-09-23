/**
 * Milestone 7 — Browser Automation Engine for SPA & DOM Discovery (Playwright)
 *
 * Implements headless browser crawling, dynamic JavaScript hydration wait,
 * DOM-based parameter extraction, and route discovery.
 *
 * Invariants:
 * 1. Layer 6 Tool Adapter: Observes and extracts; makes 0 vulnerability claims.
 * 2. Double SSRF Gate: runAdapterPreflight before browser launch AND page.route() interceptor
 *    for all subresources to block private RFC1918, loopback, and cloud metadata access.
 * 3. Circuit Breaker & Concurrency Coordination: Obey TargetExecutionCoordinator ceilings and trip state.
 * 4. Guaranteed Cleanup: Context and browser closed in finally block (0 zombie processes).
 * 5. Strictly zero type bypass policy.
 */

import { chromium } from 'playwright';
import { isInternalOrSsrfTarget } from '../policy/PassiveEgressPolicy.js';
import {
  runAdapterPreflight,
  type PreSpawnDnsResolver,
} from './AdapterPreflightPipeline.js';
import {
  CIRCUIT_OPEN_REASON_CODE,
  TargetInstabilityError,
} from '../../runtime/CircuitBreakerContracts.js';
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
} from './BrowserAutomationContracts.js';
import {
  BROWSER_AUTOMATION_CONTRACT_VERSION,
  BROWSER_AUTOMATION_NON_CLAIMS,
} from './BrowserAutomationContracts.js';

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

  on(event: 'response', handler: (response: ResponseInstance) => void): void {
    if (event === 'response') {
      this.rawPage.on('response', (rawRes) => {
        handler({
          status: () => rawRes.status(),
          url: () => rawRes.url(),
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

    const timeoutMs = request.timeoutMs ?? 15_000;
    const hydrationWaitMs = request.waitForHydrationMs ?? 1_000;
    const blockedSubresources: string[] = [];

    try {
      // Launch browser
      browser = await launcher.launch({ headless: true });
      context = await browser.newContext();
      page = await context.newPage();

      // -----------------------------------------------------------------------
      // Double SSRF Gate — Pass 2: In-Browser Subresource Interception Gate
      // -----------------------------------------------------------------------
      await page.route('**/*', async (route) => {
        const reqUrl = route.request().url();
        let isBlocked = false;

        try {
          const parsed = new URL(reqUrl);
          if (isInternalOrSsrfTarget(parsed.hostname)) {
            isBlocked = true;
          }
        } catch {
          isBlocked = true;
        }

        if (isBlocked) {
          blockedSubresources.push(reqUrl);
          await route.abort('blockedbyclient');
          return;
        }

        if (coordinator && coordinator.isCircuitOpen(targetHost)) {
          await route.abort('failed');
          return;
        }

        await route.continue();
      });

      // Feed telemetry into coordinator circuit breaker
      if (coordinator) {
        page.on('response', (response) => {
          try {
            const parsed = new URL(response.url());
            if (parsed.hostname === targetHost) {
              coordinator.recordTargetResponse(targetHost, response.status());
            }
          } catch {
            // Ignore malformed response URLs
          }
        });
      }

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

      // Extract DOM-based dynamic artifacts
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

        // Detect client-side frameworks
        const detectedFrameworks: string[] = [];
        const win = window as unknown as Record<string, unknown>;

        if (win && typeof win === 'object') {
          if ('__NEXT_DATA__' in win) detectedFrameworks.push('Next.js');
          if ('__REACT_DEVTOOLS_GLOBAL_HOOK__' in win) detectedFrameworks.push('React');
          if ('__NUXT__' in win) detectedFrameworks.push('Nuxt');
          if ('__VUE__' in win) detectedFrameworks.push('Vue');
          if ('ng' in win) detectedFrameworks.push('Angular');
        }

        const collectedScripts: string[] = [];
        const scriptNodes = document.querySelectorAll('script[src]');
        for (let i = 0; i < scriptNodes.length; i++) {
          const src = scriptNodes[i].getAttribute('src');
          if (src) collectedScripts.push(src);
        }

        return {
          links: collectedLinks,
          forms: collectedForms,
          frameworks: detectedFrameworks,
          scripts: collectedScripts,
        };
      });

      const nowIso = new Date().toISOString();
      const discoveredRoutes: DiscoveredSpaRouteObservation[] = [];
      const discoveredInputs: DiscoveredDomInputObservation[] = [];
      const seenRoutes = new Set<string>();

      // Normalize extracted links
      for (const link of evalResult.links) {
        try {
          const resolved = new URL(link, targetUrl);
          // Keep only same-origin or in-scope subdomains
          if (resolved.hostname === targetHost || resolved.hostname.endsWith(`.${targetHost}`)) {
            const key = `GET:${resolved.pathname}`;
            if (!seenRoutes.has(key)) {
              seenRoutes.add(key);
              discoveredRoutes.push({
                url: resolved.href,
                path: resolved.pathname,
                method: 'GET',
                routeType: 'dom_link',
                source: 'playwright_dom_crawler',
                discoveredAt: nowIso,
              });
            }
          }
        } catch {
          // Ignore invalid URLs
        }
      }

      // Process forms and inputs
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
        const routeKey = `${formMethod}:${formPath}`;
        if (!seenRoutes.has(routeKey)) {
          seenRoutes.add(routeKey);
          discoveredRoutes.push({
            url: formUrl,
            path: formPath,
            method: formMethod,
            routeType: 'form_action',
            source: 'playwright_dom_crawler',
            discoveredAt: nowIso,
          });
        }

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
      // Guaranteed cleanup: strictly close page, context, and browser
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
