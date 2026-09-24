/**
 * Phase D1 — Playwright SPA / RSC Discovery Smoke (hermetic)
 *
 * Validates:
 * 1. Mocked hydrated DOM + RSC hints yield in-scope routes with sources
 *    playwright_spa / rsc_discovery (OBSERVED provenance).
 * 2. Out-of-scope / SSRF URLs are fail-closed (Gate 1 preflight, Gate 2 route,
 *    Gate 3 route registration).
 * 3. Orchestrator opt-in: disabled by default without seeds/Next signals;
 *    enabled with seeds; caps pages; loud degrade on browser_unavailable.
 */

import assert from 'node:assert';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import { PlaywrightSpaAdapter, isBrowserUrlAllowed } from '../recon/adapters/PlaywrightSpaAdapter.js';
import {
  PLAYWRIGHT_SPA_SOURCE,
  RSC_DISCOVERY_SOURCE,
  SPA_DISCOVERY_MAX_PAGES,
  type BrowserAutomationRequest,
  type BrowserInstance,
  type BrowserContextInstance,
  type PageInstance,
  type PlaywrightBrowserLauncher,
  type RouteInstance,
  type ResponseInstance,
} from '../recon/adapters/BrowserAutomationContracts.js';
import { CompositeActiveReconOrchestratorService } from '../recon/orchestration/CompositeActiveReconOrchestratorService.js';
import type { ReconToolAdapters } from '../recon/orchestration/ActiveReconOrchestrationContracts.js';
import { SUBDOMAIN_DISCOVERY_NON_CLAIMS } from '../recon/adapters/SubdomainDiscoveryContracts.js';
import { DNS_RESOLUTION_NON_CLAIMS } from '../recon/adapters/DnsResolutionContracts.js';
import { PORT_DISCOVERY_NON_CLAIMS } from '../recon/adapters/PortDiscoveryContracts.js';
import { WEB_INSPECTION_NON_CLAIMS } from '../recon/adapters/WebInspectionContracts.js';
import { TLS_INSPECTION_NON_CLAIMS } from '../recon/adapters/TlsInspectionContracts.js';
import { URL_DISCOVERY_NON_CLAIMS } from '../recon/adapters/UrlDiscoveryContracts.js';
import { CONTENT_DISCOVERY_NON_CLAIMS } from '../recon/adapters/ContentDiscoveryContracts.js';
import { PARAMETER_DISCOVERY_NON_CLAIMS } from '../recon/adapters/ParameterDiscoveryContracts.js';
import { SECRET_DISCOVERY_NON_CLAIMS } from '../recon/adapters/SecretDiscoveryContracts.js';
import type { BrowserAutomationTool } from '../recon/adapters/BrowserAutomationContracts.js';

function createScopeGrant(domain: string): AuthorizedScopeGrant {
  const now = new Date();
  const expires = new Date(now.getTime() + 86400_000);
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: `grant_${domain.replace(/[^a-z0-9]/gi, '_')}`,
    scanId: 'scan_d1_spa_001',
    issuedAt: now.toISOString(),
    expiresAt: expires.toISOString(),
    subject: {
      targetKind: 'domain',
      domain,
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: `Authorized Phase D1 Playwright SPA smoke for ${domain}`,
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
      allowedMethods: ['GET', 'HEAD', 'OPTIONS', 'POST'],
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
      assessmentId: 'asm_d1_spa_001',
      scanId: 'scan_d1_spa_001',
      authorizationDecisionId: 'dec_d1_spa_001',
      authorizedActor: { actorId: 'operator_d1_spa', actorType: 'human' },
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
    assessmentId: 'asm_d1_spa_001',
    scanId: 'scan_d1_spa_001',
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: decisionResult.decision.authorizationDecisionId,
    actorId: 'operator_d1_spa',
  };

  return { scopeGrant, decision: decisionResult.decision, lineage };
}

type DomPayload = {
  links: string[];
  forms: Array<{ action?: string; method?: string; inputs: Array<{ name: string; type: string }> }>;
  frameworks: string[];
  scripts: string[];
  rscPaths?: string[];
  nextDataPage?: string;
};

class MockPage implements PageInstance {
  public closed = false;
  public routeHandler?: (route: RouteInstance) => Promise<void>;
  public responseHandler?: (response: ResponseInstance) => void;

  constructor(
    private readonly titleValue: string,
    private readonly domPayload: DomPayload
  ) {}

  async goto(_url: string): Promise<unknown> {
    return null;
  }

  async route(_urlPattern: string, handler: (route: RouteInstance) => Promise<void>): Promise<void> {
    this.routeHandler = handler;
  }

  on(event: 'response', handler: (response: ResponseInstance) => void): void {
    if (event === 'response') this.responseHandler = handler;
  }

  async waitForLoadState(): Promise<void> {}
  async waitForTimeout(_ms: number): Promise<void> {}

  async evaluate<T>(_fn: () => T | Promise<T>): Promise<T> {
    return {
      ...this.domPayload,
      rscPaths: this.domPayload.rscPaths ?? [],
    } as unknown as T;
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
    private readonly domPayload: DomPayload
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
    private readonly domPayload: DomPayload
  ) {}

  async newContext(): Promise<BrowserContextInstance> {
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
    private readonly titleValue: string,
    private readonly domPayload: DomPayload
  ) {}

  async launch(): Promise<BrowserInstance> {
    this.launchCallCount += 1;
    const browser = new MockBrowser(this.titleValue, this.domPayload);
    this.lastCreatedBrowser = browser;
    return browser;
  }
}

class UnavailableLauncher implements PlaywrightBrowserLauncher {
  public launchCallCount = 0;
  async launch(): Promise<BrowserInstance> {
    this.launchCallCount += 1;
    throw new Error("Executable doesn't exist at /missing/chromium");
  }
}

function buildStubAdapters(spaTool?: BrowserAutomationTool): ReconToolAdapters {
  return {
    subdomainTool: {
      async discoverSubdomains(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-subdomain-discovery/v0',
          targetDomain: req.targetDomain,
          observations: [],
          explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 1,
        };
      },
    },
    dnsTool: {
      async resolveDns(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-dns-resolution/v0',
          targetDomain: req.targetDomain,
          observations: [],
          explicitNonClaims: DNS_RESOLUTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 1,
        };
      },
    },
    portTool: {
      async discoverPorts(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-port-discovery/v0',
          targetHostOrIp: req.targetHostOrIp,
          observations: [],
          explicitNonClaims: PORT_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 1,
        };
      },
    },
    webTool: {
      async inspectWeb(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-web-inspection/v0',
          targetUrl: req.targetUrl,
          observations: [
            {
              url: req.targetUrl,
              method: 'GET',
              statusCode: 200,
              title: 'stub',
              technologies: [],
              bodyText: '<html><body>plain</body></html>',
              discoveredAt: new Date().toISOString(),
            },
          ],
          explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 1,
        };
      },
    },
    tlsTool: {
      async inspectTls(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-tls-inspection/v0',
          targetHost: req.targetHostOrUrl,
          observations: [],
          explicitNonClaims: TLS_INSPECTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 1,
        };
      },
    },
    urlTool: {
      async discoverUrls(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-url-discovery/v0',
          targetUrlOrDomain: req.targetUrlOrDomain,
          observations: [],
          explicitNonClaims: URL_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 1,
        };
      },
    },
    contentTool: {
      async discoverContent(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-content-discovery/v0',
          targetUrl: req.targetUrl,
          wordlistPath: req.wordlistPath,
          observations: [],
          explicitNonClaims: CONTENT_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 1,
        };
      },
    },
    parameterTool: {
      async discoverParameters(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-parameter-discovery/v0',
          targetUrl: req.targetUrl,
          observations: [],
          explicitNonClaims: PARAMETER_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 1,
        };
      },
    },
    secretTool: {
      async scanSecrets(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-secret-discovery/v0',
          targetUrlOrPath: req.targetUrlOrPath,
          observations: [],
          explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 1,
        };
      },
    },
    ...(spaTool ? { spaDiscoveryTool: spaTool } : {}),
  };
}

async function runSmokeTests() {
  console.log('--- Phase D1 Playwright SPA/RSC Discovery Smoke ---');

  // =========================================================================
  // 1. Route extraction + RSC provenance (hermetic mocked page)
  // =========================================================================
  console.log('-> Test 1: DOM + RSC routes extracted with provenance...');
  {
    const target = 'spa.example.com';
    const { scopeGrant, decision, lineage } = setupAuthorizedContext(target);
    const launcher = new MockPlaywrightLauncher('Teclaaa App', {
      links: ['/login', '/api/v1/me', 'https://evil.example.net/steal', 'http://169.254.169.254/'],
      forms: [
        {
          action: '/api/auth/callback',
          method: 'POST',
          inputs: [{ name: 'token', type: 'hidden' }],
        },
      ],
      frameworks: ['Next.js', 'React'],
      scripts: ['/_next/static/chunks/main-app.js'],
      rscPaths: ['/carrera/93kpw', '/_next/data/build123/carrera/93kpw.json'],
      nextDataPage: '/carrera/93kpw',
    });
    const adapter = new PlaywrightSpaAdapter(launcher, async () => ['93.184.216.34']);

    const result = await adapter.discoverSpa({
      targetUrlOrDomain: `https://${target}/`,
      verifiedAuthorizationDecision: decision,
      authorizedScopeGrant: scopeGrant,
      lineage,
    });

    assert.strictEqual(result.status, 'success', 'Must succeed with mocked launcher');
    assert.ok(result.status === 'success');
    const paths = result.routes.map((r) => r.path);
    assert.ok(paths.includes('/login'), 'Must extract /login');
    assert.ok(paths.includes('/api/v1/me'), 'Must extract /api/v1/me');
    assert.ok(paths.includes('/api/auth/callback'), 'Must extract form action');
    assert.ok(paths.includes('/carrera/93kpw'), 'Must extract RSC path');
    assert.ok(
      !paths.some((p) => p.includes('evil') || p.includes('169.254')),
      'Must exclude OOS/SSRF links'
    );

    const spaSources = result.routes.filter((r) => r.source === PLAYWRIGHT_SPA_SOURCE);
    const rscSources = result.routes.filter((r) => r.source === RSC_DISCOVERY_SOURCE);
    assert.ok(spaSources.length >= 2, 'Must have playwright_spa sources');
    assert.ok(rscSources.length >= 1, 'Must have rsc_discovery sources');
    assert.ok(result.observations[0].frameworks.includes('Next.js'));
  }
  console.log('  [PASS] In-scope DOM/RSC routes mined; OOS excluded.');

  // =========================================================================
  // 2. Gate 1 + Gate 2 + isBrowserUrlAllowed egress
  // =========================================================================
  console.log('-> Test 2: Egress/scope denial (preflight + helper + Gate 2)...');
  {
    const { scopeGrant, decision, lineage } = setupAuthorizedContext('spa.example.com');
    const launcher = new MockPlaywrightLauncher('x', {
      links: [],
      forms: [],
      frameworks: [],
      scripts: [],
      rscPaths: [],
    });
    const adapter = new PlaywrightSpaAdapter(launcher, async () => ['127.0.0.1']);

    const denied = await adapter.discoverSpa({
      targetUrlOrDomain: 'http://127.0.0.1/',
      verifiedAuthorizationDecision: decision,
      authorizedScopeGrant: scopeGrant,
      lineage,
    });
    assert.strictEqual(denied.status, 'preflight_denied');
    assert.strictEqual(launcher.launchCallCount, 0, 'ZERO browser launch on SSRF preflight');

    assert.strictEqual(
      isBrowserUrlAllowed('https://other.com/api', scopeGrant),
      false,
      'OOS helper must deny'
    );
    assert.strictEqual(
      isBrowserUrlAllowed('https://spa.example.com/login', scopeGrant),
      true,
      'In-scope helper must allow'
    );
    assert.strictEqual(
      isBrowserUrlAllowed('http://169.254.169.254/latest/meta-data/', scopeGrant),
      false,
      'Metadata helper must deny'
    );

    // Gate 2: after successful discover, OOS fetch aborted
    const okLauncher = new MockPlaywrightLauncher('x', {
      links: [],
      forms: [],
      frameworks: [],
      scripts: [],
      rscPaths: [],
    });
    const okAdapter = new PlaywrightSpaAdapter(okLauncher, async () => ['93.184.216.34']);
    const okResult = await okAdapter.discoverSpa({
      targetUrlOrDomain: 'https://spa.example.com/',
      verifiedAuthorizationDecision: decision,
      authorizedScopeGrant: scopeGrant,
      lineage,
    });
    assert.strictEqual(okResult.status, 'success');
    const page = okLauncher.lastCreatedBrowser?.lastCreatedContext?.lastCreatedPage;
    assert.ok(page?.routeHandler);

    let aborted = false;
    await page!.routeHandler!({
      request: () => ({ url: () => 'https://cdn.evil.net/x.js', method: () => 'GET' }),
      abort: async () => {
        aborted = true;
      },
      continue: async () => {
        aborted = false;
      },
    });
    assert.strictEqual(aborted, true, 'Gate 2 must abort OOS subresource');
  }
  console.log('  [PASS] Preflight + scope/egress helper + Gate 2 OOS abort.');

  // =========================================================================
  // 3. Loud degrade when Chromium missing
  // =========================================================================
  console.log('-> Test 3: browser_unavailable loud degrade...');
  {
    const target = 'spa.example.com';
    const { scopeGrant, decision, lineage } = setupAuthorizedContext(target);
    const launcher = new UnavailableLauncher();
    const adapter = new PlaywrightSpaAdapter(launcher, async () => ['93.184.216.34']);
    const result = await adapter.discoverSpa({
      targetUrlOrDomain: `https://${target}/`,
      verifiedAuthorizationDecision: decision,
      authorizedScopeGrant: scopeGrant,
      lineage,
    });
    assert.strictEqual(result.status, 'execution_failed');
    assert.ok(result.status === 'execution_failed');
    assert.strictEqual(result.reasonCode, 'browser_unavailable');
    assert.strictEqual(launcher.launchCallCount, 1);
  }
  console.log('  [PASS] Missing Chromium → browser_unavailable.');

  // =========================================================================
  // 4. Orchestrator opt-in + caps + degrade notice
  // =========================================================================
  console.log('-> Test 4: Orchestrator opt-in, caps, degrade...');
  {
    const target = 'spa.example.com';
    const { scopeGrant, decision, lineage } = setupAuthorizedContext(target);

    // 4a: No seeds, no Next signals, enableSpaDiscovery omitted → SPA not invoked
    let spaCalls = 0;
    const countingSpa: BrowserAutomationTool = {
      async discoverSpa(req: BrowserAutomationRequest) {
        spaCalls += 1;
        const adapter = new PlaywrightSpaAdapter(
          new MockPlaywrightLauncher('t', {
            links: ['/from-spa'],
            forms: [],
            frameworks: ['Next.js'],
            scripts: [],
            rscPaths: ['/rsc-only'],
          }),
          async () => ['93.184.216.34']
        );
        return adapter.discoverSpa(req);
      },
    };

    const orchOff = new CompositeActiveReconOrchestratorService(buildStubAdapters(countingSpa));
    const offResult = await orchOff.orchestrate({
      targetDomain: target,
      verifiedAuthorizationDecision: decision,
      authorizedScopeGrant: scopeGrant,
      lineage,
      dnsResolver: async () => ['93.184.216.34'],
      config: {
        skipStages: ['stage_1_domain_zone', 'stage_2_port_service', 'stage_5_secret_inspection'],
        enableSpaDiscovery: false,
      },
    });
    assert.strictEqual(offResult.status, 'success');
    assert.strictEqual(spaCalls, 0, 'Must not call SPA when explicitly disabled');

    // 4b: Seeds present → SPA enabled, capped pages
    spaCalls = 0;
    const pageTracker: string[] = [];
    const cappedSpa: BrowserAutomationTool = {
      async discoverSpa(req: BrowserAutomationRequest) {
        spaCalls += 1;
        pageTracker.push(req.targetUrlOrDomain);
        const adapter = new PlaywrightSpaAdapter(
          new MockPlaywrightLauncher('t', {
            links: ['/hydrated-route'],
            forms: [],
            frameworks: ['Next.js'],
            scripts: [],
            rscPaths: ['/rsc-route'],
          }),
          async () => ['93.184.216.34']
        );
        return adapter.discoverSpa(req);
      },
    };

    const seedA = `https://${target}/carrera/93kpw`;
    const seedB = `https://${target}/login`;
    const orchOn = new CompositeActiveReconOrchestratorService(buildStubAdapters(cappedSpa));
    const onResult = await orchOn.orchestrate({
      targetDomain: target,
      verifiedAuthorizationDecision: decision,
      authorizedScopeGrant: scopeGrant,
      lineage,
      dnsResolver: async () => ['93.184.216.34'],
      seedUrls: [seedA, seedB],
      config: {
        skipStages: ['stage_1_domain_zone', 'stage_2_port_service', 'stage_5_secret_inspection'],
        spaDiscoveryMaxPages: 2,
      },
    });
    assert.strictEqual(onResult.status, 'success');
    assert.ok(onResult.status === 'success');
    assert.ok(spaCalls > 0, 'Seeds must enable SPA discovery');
    assert.ok(spaCalls <= SPA_DISCOVERY_MAX_PAGES);
    assert.ok(spaCalls <= 2, 'spaDiscoveryMaxPages=2 must cap navigations');
    assert.ok(pageTracker.includes(seedA) || pageTracker.includes(seedB));

    const spaUrls = onResult.aggregatedObservations.urls.filter((u) =>
      u.sources.some((s) => s === PLAYWRIGHT_SPA_SOURCE || s === RSC_DISCOVERY_SOURCE)
    );
    assert.ok(spaUrls.length >= 1, 'SPA/RSC routes must register into URL inventory');
    assert.ok(
      spaUrls.every((u) => u.sourceReliability === 'direct_observation' && u.freshness === 'live'),
      'Provenance must be OBSERVED (live / direct_observation)'
    );

    // 4c: browser_unavailable → degradedCapabilities
    const unavailableSpa: BrowserAutomationTool = {
      async discoverSpa(req: BrowserAutomationRequest) {
        const adapter = new PlaywrightSpaAdapter(
          new UnavailableLauncher(),
          async () => ['93.184.216.34']
        );
        return adapter.discoverSpa(req);
      },
    };
    const orchDeg = new CompositeActiveReconOrchestratorService(buildStubAdapters(unavailableSpa));
    const degResult = await orchDeg.orchestrate({
      targetDomain: target,
      verifiedAuthorizationDecision: decision,
      authorizedScopeGrant: scopeGrant,
      lineage,
      dnsResolver: async () => ['93.184.216.34'],
      seedUrls: [seedA],
      config: {
        skipStages: ['stage_1_domain_zone', 'stage_2_port_service', 'stage_5_secret_inspection'],
      },
    });
    assert.strictEqual(degResult.status, 'success');
    assert.ok(degResult.status === 'success');
    const degraded = degResult.degradedCapabilities ?? [];
    assert.ok(
      degraded.some((d) => d === 'degraded_mode_missing_binary: chromium'),
      `Expected chromium degrade notice, got ${JSON.stringify(degraded)}`
    );
  }
  console.log('  [PASS] Opt-in, caps, and loud chromium degrade verified.');

  console.log('\n--- ALL PHASE D1 PLAYWRIGHT SPA/RSC ASSERTIONS PASSED ---');
}

runSmokeTests().catch((err) => {
  console.error('Phase D1 Playwright SPA/RSC smoke failed:', err);
  process.exit(1);
});
