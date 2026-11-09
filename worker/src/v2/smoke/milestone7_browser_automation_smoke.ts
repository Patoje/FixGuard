/**
 * Milestone 7 — Browser Automation Engine for SPA & DOM Discovery Smoke Test Suite
 *
 * Validates:
 * 1. Dynamic DOM Extraction:
 *    - Extracts dynamic routes, forms, inputs, and detects framework signatures (Next.js, React).
 *    - Emits structured DiscoveredSpaObservation with explicit non-claims (severity: 'info').
 * 2. Target Circuit Breaker & Lifecycle Resilience:
 *    - Halts immediately when coordinator circuit breaker is OPEN with reasonCode: 'target_instability_circuit_open'.
 *    - Records HTTP status codes into coordinator.recordTargetResponse() and guarantees browser & context closure.
 * 3. Preflight SSRF Blocking Gate (Gate 1):
 *    - Denies private RFC1918, loopback, and metadata targets with ZERO browser instances spawned.
 * 4. In-Browser Subresource Interception (Gate 2):
 *    - Intercepts and aborts internal/cloud-metadata fetch attempts via page.route with 'blockedbyclient'.
 */

import assert from 'node:assert';
import { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import {
  CIRCUIT_OPEN_REASON_CODE,
  TargetInstabilityError,
} from '../runtime/CircuitBreakerContracts.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import { PlaywrightSpaAdapter } from '../recon/adapters/PlaywrightSpaAdapter.js';
import type {
  BrowserAutomationRequest,
  BrowserInstance,
  BrowserContextInstance,
  PageInstance,
  PlaywrightBrowserLauncher,
  RouteInstance,
  RouteFetchResponse,
  ResponseInstance,
  NetworkRequestInstance,
} from '../recon/adapters/BrowserAutomationContracts.js';
import { BROWSER_AUTOMATION_NON_CLAIMS } from '../recon/adapters/BrowserAutomationContracts.js';

/** fetch()/fulfill() are unused by tests that never attach session credentials. */
function unusedRouteFetchFulfillStubs() {
  return {
    fetch: async (): Promise<RouteFetchResponse> => {
      throw new Error('fetch() not exercised by this test');
    },
    fulfill: async (): Promise<void> => {
      throw new Error('fulfill() not exercised by this test');
    },
  };
}

function createScopeGrant(domain: string): AuthorizedScopeGrant {
  const now = new Date();
  const expires = new Date(now.getTime() + 86400_000);

  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: `grant_${domain.replace(/[^a-z0-9]/gi, '_')}`,
    scanId: 'scan_m7_001',
    issuedAt: now.toISOString(),
    expiresAt: expires.toISOString(),
    subject: {
      targetKind: 'domain',
      domain,
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: `Authorized Milestone 7 browser automation smoke test for ${domain}`,
    },
    permissionSet: {
      passiveRecon: true,
      technologyFingerprinting: true,
      endpointDiscovery: true,
      activeCrawling: true,
      authenticatedTesting: false,
      lightValidation: true,
      activeValidation: true,
      aggressiveValidation: false,
      oobTesting: false,
      destructiveOperations: false,
    },
    boundaries: {
      allowedDomains: [domain],
      allowedHosts: [domain, '93.184.216.34'],
      allowedOrigins: [`https://${domain}`, `http://${domain}`],
      allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
    },
    constraints: {
      allowLoginRequiredAreas: false,
      allowStateChangingRequests: false,
      allowCredentialUse: false,
      allowOobCallbacks: false,
      allowThirdPartyTargets: false,
    },
    classification: {
      createsRealFindings: false,
      createsPersistedEvidence: false,
      confirmsVulnerabilities: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      executesNetwork: false,
      executesTools: false,
      persistsData: false,
    },
  };
}

function setupAuthorizedContext(domain: string) {
  const scopeGrant = createScopeGrant(domain);
  const nowIso = new Date().toISOString();
  const decisionResult = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: 'asm_m7_001',
      scanId: 'scan_m7_001',
      authorizationDecisionId: 'dec_m7_001',
      authorizedActor: { actorId: 'operator_m7', actorType: 'human' },
      decision: 'authorized',
      decidedAt: nowIso,
      scopeGrant,
    },
    nowIso
  );

  if (decisionResult.status !== 'established') {
    throw new Error(`Failed to establish verified decision: ${decisionResult.reasonCode}`);
  }

  const lineage: AuthorizedActiveReconRequestLineage = {
    assessmentId: 'asm_m7_001',
    scanId: 'scan_m7_001',
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: decisionResult.decision.authorizationDecisionId,
    actorId: 'operator_m7',
  };

  return { scopeGrant, decision: decisionResult.decision, lineage };
}

class MockPage implements PageInstance {
  public closed = false;
  public navigatedUrl = '';
  public routeHandler?: (route: RouteInstance) => Promise<void>;
  public responseHandler?: (response: ResponseInstance) => void;
  public requestHandler?: (request: NetworkRequestInstance) => void;

  constructor(
    private readonly titleValue: string,
    private readonly domPayload: {
      links: string[];
      forms: Array<{ action?: string; method?: string; inputs: Array<{ name: string; type: string }> }>;
      frameworks: string[];
      scripts: string[];
      rscPaths?: string[];
      nextDataPage?: string;
    }
  ) {}

  async goto(
    url: string,
    _options?: { waitUntil?: 'load' | 'domcontentloaded' | 'networkidle'; timeout?: number }
  ): Promise<unknown> {
    this.navigatedUrl = url;
    return null;
  }

  async route(
    _urlPattern: string,
    handler: (route: RouteInstance) => Promise<void>
  ): Promise<void> {
    this.routeHandler = handler;
  }

  on(
    event: 'response' | 'request',
    handler: ((response: ResponseInstance) => void) | ((request: NetworkRequestInstance) => void)
  ): void {
    if (event === 'response') {
      this.responseHandler = handler as (response: ResponseInstance) => void;
    } else if (event === 'request') {
      this.requestHandler = handler as (request: NetworkRequestInstance) => void;
    }
  }

  async waitForLoadState(
    _state?: 'load' | 'domcontentloaded' | 'networkidle',
    _options?: { timeout?: number }
  ): Promise<void> {}

  async waitForTimeout(_ms: number): Promise<void> {}

  async evaluate<T>(fn: () => T | Promise<T>): Promise<T> {
    // If the caller is evaluating DOM inspection, return mock dom payload
    // Normalize optional RSC fields so adapter loops never see undefined.
    const payload = {
      ...this.domPayload,
      rscPaths: this.domPayload.rscPaths ?? [],
    };
    return payload as unknown as T;
  }

  async title(): Promise<string> {
    return this.titleValue;
  }

  async close(): Promise<void> {
    this.closed = true;
  }
}

class MockBrowserContext implements BrowserContextInstance {
  public closed = false;
  public lastCreatedPage?: MockPage;
  public addedCookies: Array<{
    name: string;
    value: string;
    domain?: string;
    path?: string;
    secure?: boolean;
  }> = [];

  constructor(
    private readonly titleValue: string,
    private readonly domPayload: {
      links: string[];
      forms: Array<{ action?: string; method?: string; inputs: Array<{ name: string; type: string }> }>;
      frameworks: string[];
      scripts: string[];
      rscPaths?: string[];
      nextDataPage?: string;
    }
  ) {}

  async newPage(): Promise<PageInstance> {
    const page = new MockPage(this.titleValue, this.domPayload);
    this.lastCreatedPage = page;
    return page;
  }

  async addCookies(
    cookies: readonly { name: string; value: string; domain?: string; path?: string; secure?: boolean }[]
  ): Promise<void> {
    this.addedCookies.push(...cookies);
  }

  async close(): Promise<void> {
    this.closed = true;
  }
}

class MockBrowser implements BrowserInstance {
  public closed = false;
  public lastCreatedContext?: MockBrowserContext;
  public lastContextOptions?: Record<string, unknown>;

  constructor(
    private readonly titleValue: string,
    private readonly domPayload: {
      links: string[];
      forms: Array<{ action?: string; method?: string; inputs: Array<{ name: string; type: string }> }>;
      frameworks: string[];
      scripts: string[];
      rscPaths?: string[];
      nextDataPage?: string;
    }
  ) {}

  async newContext(_options?: Record<string, unknown>): Promise<BrowserContextInstance> {
    this.lastContextOptions = _options;
    const ctx = new MockBrowserContext(this.titleValue, this.domPayload);
    this.lastCreatedContext = ctx;
    return ctx;
  }

  async close(): Promise<void> {
    this.closed = true;
  }
}

class MockPlaywrightLauncher implements PlaywrightBrowserLauncher {
  public launchCallCount = 0;
  public lastCreatedBrowser?: MockBrowser;

  constructor(
    private readonly titleValue: string = 'Demo Single Page Application',
    private readonly domPayload: {
      links: string[];
      forms: Array<{ action?: string; method?: string; inputs: Array<{ name: string; type: string }> }>;
      frameworks: string[];
      scripts: string[];
      rscPaths?: string[];
      nextDataPage?: string;
    } = {
      links: ['/dashboard', '/settings', 'https://example.com/api/v1/users'],
      forms: [
        {
          action: '/api/v1/auth/login',
          method: 'POST',
          inputs: [
            { name: 'username', type: 'text' },
            { name: 'password', type: 'password' },
          ],
        },
      ],
      frameworks: ['Next.js', 'React'],
      scripts: ['/_next/static/chunks/main.js'],
      rscPaths: [],
    }
  ) {}

  async launch(_options?: { headless?: boolean; args?: readonly string[] }): Promise<BrowserInstance> {
    this.launchCallCount += 1;
    const browser = new MockBrowser(this.titleValue, this.domPayload);
    this.lastCreatedBrowser = browser;
    return browser;
  }
}

async function runSmokeTests() {
  console.log('--- Milestone 7 Browser Automation Engine Smoke Suite ---');

  // =========================================================================
  // Assertion 1: Dynamic DOM Extraction & Explicit Non-Claims
  // =========================================================================
  console.log('[Assertion 1] Dynamic DOM extraction & explicit non-claims...');
  {
    const target = 'example.com';
    const { scopeGrant, decision, lineage } = setupAuthorizedContext(target);

    const launcher = new MockPlaywrightLauncher();
    const adapter = new PlaywrightSpaAdapter(launcher, async () => ['93.184.216.34']);

    const result = await adapter.discoverSpa({
      targetUrlOrDomain: `https://${target}`,
      verifiedAuthorizationDecision: decision,
      authorizedScopeGrant: scopeGrant,
      lineage,
    });

    assert.strictEqual(result.status, 'success', 'Result status must be success');
    assert.strictEqual(launcher.launchCallCount, 1, 'Browser must have been launched exactly once');
    assert.strictEqual(result.observations.length, 1, 'Must emit exactly 1 observation');

    const obs = result.observations[0];
    assert.strictEqual(obs.pageTitle, 'Demo Single Page Application');
    assert.deepStrictEqual(obs.frameworks, ['Next.js', 'React']);
    assert.strictEqual(obs.routes.length, 4, 'Must discover 4 routes (3 links + 1 form action)');
    const formRoute = obs.routes.find((r) => r.routeType === 'form_action');
    assert.ok(formRoute, 'Must discover form action route');
    assert.strictEqual(formRoute.path, '/api/v1/auth/login');
    assert.strictEqual(obs.inputs.length, 2, 'Must discover 2 form inputs');
    assert.strictEqual(obs.inputs[0].inputName, 'username');
    assert.strictEqual(obs.inputs[1].inputName, 'password');

    // Verify non-claims
    assert.strictEqual(result.explicitNonClaims.createsRealFindings, false);
    assert.strictEqual(result.explicitNonClaims.severity, 'info');

    // Verify cleanup
    assert.strictEqual(launcher.lastCreatedBrowser?.closed, true, 'Browser must be cleanly closed');
    assert.strictEqual(
      launcher.lastCreatedBrowser?.lastCreatedContext?.closed,
      true,
      'Browser context must be cleanly closed'
    );
    assert.strictEqual(
      launcher.lastCreatedBrowser?.lastCreatedContext?.lastCreatedPage?.closed,
      true,
      'Page must be cleanly closed'
    );
  }
  console.log('✓ Assertion 1 passed: Dynamic DOM extraction, framework detection & cleanup verified');

  // =========================================================================
  // Assertion 2: Target Circuit Breaker Obedience & Response Telemetry
  // =========================================================================
  console.log('[Assertion 2] Target Circuit Breaker obedience & response telemetry...');
  {
    const target = 'circuit-test.example.com';
    const { scopeGrant, decision, lineage } = setupAuthorizedContext(target);

    const coordinator = new TargetExecutionCoordinator({
      requestsPerSecond: 10,
      maxConcurrency: 2,
      circuitBreakerConfig: {
        consecutive5xxThreshold: 2,
        consecutiveErrorThreshold: 2,
        halfOpenSuccessThreshold: 1,
        openCooldownMs: 60_000,
      },
    });

    // Manually trip coordinator circuit breaker to OPEN
    coordinator.recordTargetResponse(target, 503);
    coordinator.recordTargetResponse(target, 503);
    assert.strictEqual(coordinator.isCircuitOpen(target), true, 'Circuit must be OPEN');

    const launcher = new MockPlaywrightLauncher();
    const adapter = new PlaywrightSpaAdapter(launcher, async () => ['93.184.216.34']);

    const result = await adapter.discoverSpa({
      targetUrlOrDomain: `https://${target}`,
      verifiedAuthorizationDecision: decision,
      authorizedScopeGrant: scopeGrant,
      lineage,
      coordinator,
    });

    assert.strictEqual(result.status, 'circuit_broken', 'Must return circuit_broken when circuit is tripped');
    assert.strictEqual(result.reasonCode, CIRCUIT_OPEN_REASON_CODE);
    assert.strictEqual(launcher.launchCallCount, 0, 'Must NOT launch browser when circuit is OPEN');

    // Test 2B: Circuit trips DURING page navigation responses
    const target2 = 'circuit-trip.example.com';
    const { scopeGrant: scopeGrant2, decision: decision2, lineage: lineage2 } = setupAuthorizedContext(target2);

    const coordinator2 = new TargetExecutionCoordinator({
      requestsPerSecond: 10,
      maxConcurrency: 2,
      circuitBreakerConfig: {
        consecutive5xxThreshold: 2,
        consecutiveErrorThreshold: 2,
        halfOpenSuccessThreshold: 1,
        openCooldownMs: 60_000,
      },
    });

    const launcher2 = new MockPlaywrightLauncher();
    const adapter2 = new PlaywrightSpaAdapter(launcher2, async () => ['93.184.216.34']);

    // Hook launcher to fire 500 responses when page created
    const originalLaunch = launcher2.launch.bind(launcher2);
    launcher2.launch = async (opts) => {
      const b = await originalLaunch(opts);
      const origNewContext = b.newContext.bind(b);
      b.newContext = async (cOpts) => {
        const ctx = await origNewContext(cOpts);
        const origNewPage = ctx.newPage.bind(ctx);
        ctx.newPage = async () => {
          const page = (await origNewPage()) as MockPage;
          const origGoto = page.goto.bind(page);
          page.goto = async (u, gOpts) => {
            // Simulate 500 responses arriving from server
            if (page.responseHandler) {
              page.responseHandler({ status: () => 500, url: () => u });
              page.responseHandler({ status: () => 502, url: () => u });
            }
            return origGoto(u, gOpts);
          };
          return page;
        };
        return ctx;
      };
      return b;
    };

    const tripResult = await adapter2.discoverSpa({
      targetUrlOrDomain: `https://${target2}`,
      verifiedAuthorizationDecision: decision2,
      authorizedScopeGrant: scopeGrant2,
      lineage: lineage2,
      coordinator: coordinator2,
    });

    assert.strictEqual(tripResult.status, 'circuit_broken', 'Must abort and return circuit_broken when responses trip circuit');
    assert.strictEqual(coordinator2.isCircuitOpen(target2), true, 'Coordinator circuit state must be OPEN');
    assert.strictEqual(launcher2.lastCreatedBrowser?.closed, true, 'Browser must still be cleanly closed on trip');
  }
  console.log('✓ Assertion 2 passed: Circuit breaker enforcement and safe abort verified');

  // =========================================================================
  // Assertion 3: Preflight SSRF Blocking (Gate 1)
  // =========================================================================
  console.log('[Assertion 3] Preflight SSRF blocking before browser spawn...');
  {
    const dangerousTargets = [
      '127.0.0.1',
      'http://127.0.0.1:8080',
      'http://169.254.169.254/latest/meta-data/',
      'http://10.0.0.1/admin',
      'http://192.168.1.1',
      'localhost',
    ];

    for (const dangerousTarget of dangerousTargets) {
      const { scopeGrant, decision, lineage } = setupAuthorizedContext('example.com');

      const launcher = new MockPlaywrightLauncher();
      const adapter = new PlaywrightSpaAdapter(launcher, async () => ['127.0.0.1']);

      const result = await adapter.discoverSpa({
        targetUrlOrDomain: dangerousTarget,
        verifiedAuthorizationDecision: decision,
        authorizedScopeGrant: scopeGrant,
        lineage,
      });

      assert.strictEqual(
        result.status,
        'preflight_denied',
        `Target ${dangerousTarget} must be denied at preflight`
      );
      assert.strictEqual(
        launcher.launchCallCount,
        0,
        `ZERO browser instances must be launched for SSRF target ${dangerousTarget}`
      );
    }
  }
  console.log('✓ Assertion 3 passed: Preflight SSRF gate blocked all internal/metadata targets with 0 browser launches');

  // =========================================================================
  // Assertion 4: In-Browser Subresource Interception (Gate 2)
  // =========================================================================
  console.log('[Assertion 4] In-browser subresource interception via page.route()...');
  {
    const target = 'spa.example.com';
    const { scopeGrant, decision, lineage } = setupAuthorizedContext(target);

    const launcher = new MockPlaywrightLauncher();
    const adapter = new PlaywrightSpaAdapter(launcher, async () => ['93.184.216.34']);

    // Launch discovery
    const discoveryPromise = adapter.discoverSpa({
      targetUrlOrDomain: `https://${target}`,
      verifiedAuthorizationDecision: decision,
      authorizedScopeGrant: scopeGrant,
      lineage,
    });

    const result = await discoveryPromise;
    assert.strictEqual(result.status, 'success');

    // Retrieve the installed route handler on MockPage
    const page = launcher.lastCreatedBrowser?.lastCreatedContext?.lastCreatedPage;
    assert.ok(page?.routeHandler, 'page.route() handler must have been registered');

    // Test Gate 2 against internal/cloud-metadata subresource fetches:
    const blockedUrls = [
      'http://169.254.169.254/latest/meta-data/',
      'http://127.0.0.1:3000/internal-api',
      'http://10.200.0.5/secrets.json',
      'http://192.168.1.1/router',
    ];

    for (const blockedUrl of blockedUrls) {
      let abortCalled = false;
      let abortReason = '';
      let continueCalled = false;

      const mockRoute: RouteInstance = {
        request: () => ({
          url: () => blockedUrl,
          method: () => 'GET',
          resourceType: () => 'fetch',
        }),
        abort: async (code) => {
          abortCalled = true;
          abortReason = code ?? '';
        },
        continue: async () => {
          continueCalled = true;
        },
        ...unusedRouteFetchFulfillStubs(),
      };

      await page!.routeHandler!(mockRoute);

      assert.strictEqual(abortCalled, true, `Subresource ${blockedUrl} must be aborted`);
      assert.strictEqual(abortReason, 'blockedbyclient', 'Abort reason must be blockedbyclient');
      assert.strictEqual(continueCalled, false, 'Continue must not be called for SSRF target');
    }

    // Verify legitimate same-origin subresource is permitted:
    let legitimateAbort = false;
    let legitimateContinue = false;

    const legitRoute: RouteInstance = {
      request: () => ({
        url: () => `https://${target}/_next/static/chunks/main.js`,
        method: () => 'GET',
        resourceType: () => 'script',
      }),
      abort: async () => {
        legitimateAbort = true;
      },
      continue: async () => {
        legitimateContinue = true;
      },
      ...unusedRouteFetchFulfillStubs(),
    };

    await page!.routeHandler!(legitRoute);
    assert.strictEqual(legitimateAbort, false, 'Same-origin asset must NOT be aborted');
    assert.strictEqual(legitimateContinue, true, 'Same-origin asset must continue');

    // Out-of-scope public CDN static script: allow-to-load for hydration, never mined.
    let oosCdnAbort = false;
    let oosCdnContinue = false;
    const oosCdnRoute: RouteInstance = {
      request: () => ({
        url: () => 'https://cdn.example.com/assets/app.js',
        method: () => 'GET',
        resourceType: () => 'script',
      }),
      abort: async () => {
        oosCdnAbort = true;
      },
      continue: async () => {
        oosCdnContinue = true;
      },
      ...unusedRouteFetchFulfillStubs(),
    };
    await page!.routeHandler!(oosCdnRoute);
    assert.strictEqual(oosCdnAbort, false, 'OOS CDN script must be allow-to-load (not aborted)');
    assert.strictEqual(oosCdnContinue, true, 'OOS CDN script must continue for hydration');

    // Out-of-scope API xhr/fetch must still abort-navigation.
    let oosApiAbort = false;
    let oosApiContinue = false;
    const oosApiRoute: RouteInstance = {
      request: () => ({
        url: () => 'https://api.evil.net/v1/data',
        method: () => 'GET',
        resourceType: () => 'fetch',
      }),
      abort: async () => {
        oosApiAbort = true;
      },
      continue: async () => {
        oosApiContinue = true;
      },
      ...unusedRouteFetchFulfillStubs(),
    };
    await page!.routeHandler!(oosApiRoute);
    assert.strictEqual(oosApiAbort, true, 'OOS API fetch must be aborted');
    assert.strictEqual(oosApiContinue, false, 'OOS API fetch must not continue');

    // OOS document navigation must abort.
    let oosNavAbort = false;
    const oosNavRoute: RouteInstance = {
      request: () => ({
        url: () => 'https://evil.net/login',
        method: () => 'GET',
        resourceType: () => 'document',
      }),
      abort: async () => {
        oosNavAbort = true;
      },
      continue: async () => {},
      ...unusedRouteFetchFulfillStubs(),
    };
    await page!.routeHandler!(oosNavRoute);
    assert.strictEqual(oosNavAbort, true, 'OOS document navigation must be aborted');
  }
  console.log('✓ Assertion 4 passed: Gate 2 allow-to-load CDN vs abort OOS API/nav + SSRF');

  // =========================================================================
  // Assertion 5 — Milestone: Final Playwright Redirect & Cookie Fidelity
  // Corrections. Verified directly against a real two-origin redirect
  // that page.route() fires exactly once per intercepted request —
  // fulfilling a 3xx does NOT give this handler a second interception
  // opportunity for the browser's own auto-navigation to the Location.
  // Session credentials (Cookie AND Authorization, combined into one
  // header set) are therefore attached only inside an explicit, bounded
  // redirect-following loop this handler drives itself via
  // route.fetch({url, method, maxRedirects: 0}) — never via
  // context.addCookies() (a real cookie jar has no port scoping, so a
  // cookie added for one port leaks to every other port on that
  // hostname) and never via continue({headers}) or a bare fulfilled 3xx
  // handed back to the browser mid-chain.
  // =========================================================================
  console.log('[Assertion 5] Session credentials are origin-scoped via an explicit redirect loop, never the cookie jar...');
  {
    const target = 'session-thread.example.com';
    const { scopeGrant, decision, lineage } = setupAuthorizedContext(target);

    const launcher = new MockPlaywrightLauncher();
    const adapter = new PlaywrightSpaAdapter(launcher, async () => ['93.184.216.34']);

    const result = await adapter.discoverSpa({
      targetUrlOrDomain: `https://${target}`,
      verifiedAuthorizationDecision: decision,
      authorizedScopeGrant: scopeGrant,
      lineage,
      sessionCredentials: {
        origin: `https://${target}`,
        cookies: { cf_clearance: 'operator_resolved_token' },
        headers: { authorization: 'Bearer secret_session_token' },
      },
    });

    // 7. Existing authorized SPA discovery still functions end to end.
    assert.strictEqual(result.status, 'success', 'SPA discovery must still succeed with sessionCredentials supplied');

    const context = launcher.lastCreatedBrowser?.lastCreatedContext;
    const page = context?.lastCreatedPage;
    assert.ok(page?.routeHandler, 'page.route() handler must have been registered');

    // The cookie jar is never used for session credentials — a real
    // cookie jar cannot express port-scoping, so this is the only way to
    // guarantee exact-origin isolation for both credential types alike.
    assert.deepStrictEqual(
      context!.addedCookies,
      [],
      'context.addCookies() must never be called for session credentials'
    );

    // No sensitive session header present in context-level extraHTTPHeaders.
    const contextOptions = launcher.lastCreatedBrowser?.lastContextOptions as
      | { extraHTTPHeaders?: Record<string, string> }
      | undefined;
    assert.ok(contextOptions?.extraHTTPHeaders, 'stealth must still set its own extraHTTPHeaders');
    assert.strictEqual(
      contextOptions!.extraHTTPHeaders!['Cookie'],
      undefined,
      'Cookie must never appear in context-level extraHTTPHeaders'
    );
    assert.strictEqual(
      contextOptions!.extraHTTPHeaders!['authorization'],
      undefined,
      'Authorization must never appear in context-level extraHTTPHeaders'
    );
    // Stealth fingerprint headers remain intact (unrelated to credential scoping).
    assert.ok(
      'sec-ch-ua' in contextOptions!.extraHTTPHeaders!,
      'Stealth fingerprint headers must be untouched by credential scoping'
    );

    // Case 1: a same-origin request with no redirect — both Cookie and
    // Authorization attached via fetch(), fulfilled with that one response.
    {
      let fetchCallCount = 0;
      let fetchCalledWith: { url?: string; method?: string; headers?: Record<string, string>; maxRedirects?: number } | undefined;
      let fulfillCalledWith: RouteFetchResponse | undefined;
      const mockResponse: RouteFetchResponse = { status: () => 200, headers: () => ({}) };
      const route: RouteInstance = {
        request: () => ({
          url: () => `https://${target}/api/account`,
          method: () => 'GET',
          resourceType: () => 'fetch',
          headers: () => ({ accept: '*/*' }),
        }),
        abort: async () => { throw new Error('same-origin request must not be aborted'); },
        continue: async () => { throw new Error('a session-origin-matched request must use the fetch loop, never continue({headers})'); },
        fetch: async (options) => {
          fetchCallCount += 1;
          fetchCalledWith = options;
          return mockResponse;
        },
        fulfill: async (options) => { fulfillCalledWith = options.response; },
      };
      await page!.routeHandler!(route);
      assert.strictEqual(fetchCallCount, 1, 'a non-redirecting request must fetch exactly once');
      assert.strictEqual(fetchCalledWith?.headers?.authorization, 'Bearer secret_session_token');
      assert.strictEqual(fetchCalledWith?.headers?.Cookie, 'cf_clearance=operator_resolved_token');
      assert.strictEqual(fetchCalledWith?.maxRedirects, 0);
      assert.strictEqual(fetchCalledWith?.headers?.accept, '*/*', 'the request’s own existing headers must be preserved');
      assert.strictEqual(fulfillCalledWith, mockResponse, 'the fetched response must be served via fulfill()');
      console.log('  [case 1] no redirect: Cookie + Authorization attached in one fetch() call, fulfilled directly.');
    }

    // Case 2: a same-origin redirect chain (hop1 -> hop2, both same
    // origin) — the loop must follow it itself, attaching credentials to
    // EVERY hop, and fulfill with the FINAL non-redirect response.
    {
      let fetchCallCount = 0;
      const fetchedUrls: (string | undefined)[] = [];
      const fetchedHeaders: (Record<string, string> | undefined)[] = [];
      let fulfillCalledWith: RouteFetchResponse | undefined;
      const hop2Response: RouteFetchResponse = { status: () => 200, headers: () => ({}) };
      const hop1Response: RouteFetchResponse = {
        status: () => 302,
        headers: () => ({ location: `https://${target}/dashboard` }),
      };
      const route: RouteInstance = {
        request: () => ({
          url: () => `https://${target}/login-redirect`,
          method: () => 'GET',
          resourceType: () => 'document',
          headers: () => ({}),
        }),
        abort: async () => { throw new Error('must not abort'); },
        continue: async () => { throw new Error('must not hand a same-origin redirect chain back to continue()'); },
        fetch: async (options) => {
          fetchCallCount += 1;
          fetchedUrls.push(options?.url);
          fetchedHeaders.push(options?.headers);
          return fetchCallCount === 1 ? hop1Response : hop2Response;
        },
        fulfill: async (options) => { fulfillCalledWith = options.response; },
      };
      await page!.routeHandler!(route);
      assert.strictEqual(fetchCallCount, 2, 'both hops of a same-origin redirect chain must be fetched');
      assert.strictEqual(fetchedUrls[0], undefined, 'the first hop reuses the intercepted request’s own URL');
      assert.strictEqual(fetchedUrls[1], `https://${target}/dashboard`, 'the second hop must target the redirect’s Location');
      assert.strictEqual(fetchedHeaders[0]?.authorization, 'Bearer secret_session_token', 'hop 1 must receive credentials');
      assert.strictEqual(fetchedHeaders[1]?.authorization, 'Bearer secret_session_token', 'hop 2 must also receive credentials — same origin');
      assert.strictEqual(fetchedHeaders[1]?.Cookie, 'cf_clearance=operator_resolved_token');
      assert.strictEqual(fulfillCalledWith, hop2Response, 'the FINAL (non-redirect) response must be the one fulfilled');
      console.log('  [case 2] same-origin redirect chain: both hops fetched with credentials; final response fulfilled.');
    }

    // Case 3: a redirect to a DIFFERENT origin — the loop must stop
    // immediately and must NEVER fetch the cross-origin destination
    // itself; it fulfills with the last same-origin hop's own 3xx
    // response instead (observation preserved, never requested with
    // credentials, never claimed authenticated).
    {
      let fetchCallCount = 0;
      const fetchedUrls: (string | undefined)[] = [];
      let fulfillCalledWith: RouteFetchResponse | undefined;
      const crossOriginRedirect: RouteFetchResponse = {
        status: () => 302,
        headers: () => ({ location: 'https://attacker.example.net/landing' }),
      };
      const route: RouteInstance = {
        request: () => ({
          url: () => `https://${target}/go-elsewhere`,
          method: () => 'GET',
          resourceType: () => 'document',
          headers: () => ({}),
        }),
        abort: async () => { throw new Error('must not abort'); },
        continue: async () => { throw new Error('must not hand off to continue()'); },
        fetch: async (options) => {
          fetchCallCount += 1;
          fetchedUrls.push(options?.url);
          return crossOriginRedirect;
        },
        fulfill: async (options) => { fulfillCalledWith = options.response; },
      };
      await page!.routeHandler!(route);
      assert.strictEqual(fetchCallCount, 1, 'the loop must fetch only the same-origin hop, never the cross-origin target');
      assert.strictEqual(fulfillCalledWith, crossOriginRedirect, 'the cross-origin-pointing 3xx is fulfilled as-is (observation preserved, not followed by this code)');
      console.log('  [case 3] cross-origin redirect target: never fetched by this code; the redirect itself is still observed.');
    }

    // Case 4: a redirect loop (hop points back to an already-visited URL)
    // must be detected and stopped, not followed forever.
    {
      let fetchCallCount = 0;
      let fulfillCalled = false;
      const loopingResponse: RouteFetchResponse = {
        status: () => 302,
        headers: () => ({ location: `https://${target}/loop-a` }),
      };
      const route: RouteInstance = {
        request: () => ({
          url: () => `https://${target}/loop-a`,
          method: () => 'GET',
          resourceType: () => 'document',
          headers: () => ({}),
        }),
        abort: async () => { throw new Error('must not abort'); },
        continue: async () => { throw new Error('must not hand off to continue()'); },
        fetch: async () => {
          fetchCallCount += 1;
          return loopingResponse;
        },
        fulfill: async () => { fulfillCalled = true; },
      };
      await page!.routeHandler!(route);
      assert.ok(fetchCallCount <= 11, `a redirect loop must be bounded, not infinite (got ${fetchCallCount} fetch calls)`);
      assert.strictEqual(fulfillCalled, true, 'a detected loop must still resolve the route (fulfill), never hang');
      console.log(`  [case 4] redirect loop: stopped after ${fetchCallCount} fetch call(s), route resolved.`);
    }

    // External CDN script (classification allows load, origin doesn't
    // match) — unaffected by the credential loop, still plain continue().
    let oosContinueCalled = false;
    let oosContinueOptions: { headers?: Record<string, string> } | undefined;
    let oosAbortCalled = false;
    const oosCdnRoute: RouteInstance = {
      request: () => ({
        url: () => 'https://cdn.example.com/assets/app.js',
        method: () => 'GET',
        resourceType: () => 'script',
        headers: () => ({ accept: '*/*' }),
      }),
      abort: async () => {
        oosAbortCalled = true;
      },
      continue: async (options) => {
        oosContinueCalled = true;
        oosContinueOptions = options;
      },
      ...unusedRouteFetchFulfillStubs(),
    };
    await page!.routeHandler!(oosCdnRoute);
    assert.strictEqual(oosAbortCalled, false, 'External CDN script must still be allowed to load');
    assert.strictEqual(oosContinueCalled, true, 'External CDN script must still continue');
    assert.strictEqual(
      oosContinueOptions,
      undefined,
      'External CDN script must never receive a header override carrying session credentials'
    );
    console.log('  [case 5] external CDN script: unaffected, plain continue(), no credentials.');
  }
  console.log('✓ Assertion 5 passed: Cookie + Authorization both flow only through the explicit, bounded, per-hop-validated redirect loop — never the cookie jar, never context-level headers, never a credentialed hop handed back to the browser.');

  console.log('\n--- ALL 5 MILESTONE 7 ASSERTIONS PASSED SUCCESSFULLY ---');
}

runSmokeTests().catch((err) => {
  console.error('Milestone 7 Browser Automation smoke suite failed:', err);
  process.exit(1);
});
