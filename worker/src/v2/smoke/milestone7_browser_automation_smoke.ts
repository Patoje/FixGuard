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
  ResponseInstance,
} from '../recon/adapters/BrowserAutomationContracts.js';
import { BROWSER_AUTOMATION_NON_CLAIMS } from '../recon/adapters/BrowserAutomationContracts.js';

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

  constructor(
    private readonly titleValue: string,
    private readonly domPayload: {
      links: string[];
      forms: Array<{ action?: string; method?: string; inputs: Array<{ name: string; type: string }> }>;
      frameworks: string[];
      scripts: string[];
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

  on(event: 'response', handler: (response: ResponseInstance) => void): void {
    if (event === 'response') {
      this.responseHandler = handler;
    }
  }

  async waitForLoadState(
    _state?: 'load' | 'domcontentloaded' | 'networkidle',
    _options?: { timeout?: number }
  ): Promise<void> {}

  async waitForTimeout(_ms: number): Promise<void> {}

  async evaluate<T>(fn: () => T | Promise<T>): Promise<T> {
    // If the caller is evaluating DOM inspection, return mock dom payload
    return this.domPayload as unknown as T;
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

  constructor(
    private readonly titleValue: string,
    private readonly domPayload: {
      links: string[];
      forms: Array<{ action?: string; method?: string; inputs: Array<{ name: string; type: string }> }>;
      frameworks: string[];
      scripts: string[];
    }
  ) {}

  async newPage(): Promise<PageInstance> {
    const page = new MockPage(this.titleValue, this.domPayload);
    this.lastCreatedPage = page;
    return page;
  }

  async close(): Promise<void> {
    this.closed = true;
  }
}

class MockBrowser implements BrowserInstance {
  public closed = false;
  public lastCreatedContext?: MockBrowserContext;

  constructor(
    private readonly titleValue: string,
    private readonly domPayload: {
      links: string[];
      forms: Array<{ action?: string; method?: string; inputs: Array<{ name: string; type: string }> }>;
      frameworks: string[];
      scripts: string[];
    }
  ) {}

  async newContext(_options?: Record<string, unknown>): Promise<BrowserContextInstance> {
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
        }),
        abort: async (code) => {
          abortCalled = true;
          abortReason = code ?? '';
        },
        continue: async () => {
          continueCalled = true;
        },
      };

      await page!.routeHandler!(mockRoute);

      assert.strictEqual(abortCalled, true, `Subresource ${blockedUrl} must be aborted`);
      assert.strictEqual(abortReason, 'blockedbyclient', 'Abort reason must be blockedbyclient');
      assert.strictEqual(continueCalled, false, 'Continue must not be called for SSRF target');
    }

    // Verify legitimate external subresource is permitted:
    let legitimateAbort = false;
    let legitimateContinue = false;

    const legitRoute: RouteInstance = {
      request: () => ({
        url: () => 'https://cdn.example.com/assets/app.js',
        method: () => 'GET',
      }),
      abort: async () => {
        legitimateAbort = true;
      },
      continue: async () => {
        legitimateContinue = true;
      },
    };

    await page!.routeHandler!(legitRoute);
    assert.strictEqual(legitimateAbort, false, 'Legitimate asset must NOT be aborted');
    assert.strictEqual(legitimateContinue, true, 'Legitimate asset must continue');
  }
  console.log('✓ Assertion 4 passed: In-browser subresource gate strictly aborts SSRF/metadata requests');

  console.log('\n--- ALL 4 MILESTONE 7 ASSERTIONS PASSED SUCCESSFULLY ---');
}

runSmokeTests().catch((err) => {
  console.error('Milestone 7 Browser Automation smoke suite failed:', err);
  process.exit(1);
});
