/**
 * Deep recon P3 — BYOT network harvest + Playwright Identity A + composite wiring (hermetic).
 */
import assert from 'node:assert/strict';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import type { HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';
import type {
  BrowserInstance,
  BrowserContextInstance,
  NetworkRequestInstance,
  PageInstance,
  PlaywrightBrowserLauncher,
  ResponseInstance,
  RouteInstance,
} from '../recon/adapters/BrowserAutomationContracts.js';
import { planDeepReconMethods } from '../recon/deep/DeepReconMethodPlanner.js';
import { runDeepReconOrchestrator } from '../recon/deep/DeepReconOrchestratorService.js';
import {
  resolveByotHarvestAuthHeaders,
  runByotNetworkHarvest,
} from '../recon/deep/ByotNetworkHarvestService.js';
import { BYOT_NETWORK_HARVEST_SOURCE } from '../recon/deep/ByotNetworkHarvestContracts.js';
import { CompositeActiveReconOrchestratorService } from '../recon/orchestration/CompositeActiveReconOrchestratorService.js';
import type { ReconToolAdapters } from '../recon/orchestration/ActiveReconOrchestrationContracts.js';

const ACTION_ID = 'a1b2c3d4e5f67890abcdef12';
const NETWORK_ACTION_ID = 'f9e8d7c6b5a4938271605f4e';

function createScopeGrant(opts?: {
  readonly authenticatedTesting?: boolean;
}): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_byot_harvest_001',
    scanId: 'scan_byot_harvest_001',
    issuedAt: '2026-09-25T12:00:00.000Z',
    expiresAt: '2026-09-26T12:00:00.000Z',
    subject: { targetKind: 'domain', domain: 'app.example.com' },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for BYOT harvest smoke',
    },
    permissionSet: {
      passiveRecon: true,
      technologyFingerprinting: true,
      endpointDiscovery: true,
      activeCrawling: true,
      authenticatedTesting: opts?.authenticatedTesting === true,
      lightValidation: true,
      activeValidation: false,
      aggressiveValidation: false,
      oobTesting: false,
      destructiveOperations: false,
    },
    boundaries: {
      allowedDomains: ['app.example.com'],
      allowedHosts: ['app.example.com'],
      allowedOrigins: ['https://app.example.com'],
      allowedMethods: ['GET', 'HEAD'],
    },
    constraints: {
      allowLoginRequiredAreas: true,
      allowStateChangingRequests: false,
      allowCredentialUse: true,
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

type MockNetReq = {
  readonly url: string;
  readonly method?: string;
  readonly resourceType?: string;
  readonly headers?: Readonly<Record<string, string>>;
};

class MockHarvestPage implements PageInstance {
  public routeHandler?: (route: RouteInstance) => Promise<void>;
  public requestHandler?: (request: NetworkRequestInstance) => void;
  public lastContextOptions: Record<string, unknown> | undefined;

  constructor(
    private readonly networkRequests: readonly MockNetReq[],
    private readonly html: string
  ) {}

  async goto(_url: string): Promise<unknown> {
    if (this.requestHandler) {
      for (const req of this.networkRequests) {
        const headers = req.headers ?? {};
        this.requestHandler({
          url: () => req.url,
          method: () => req.method ?? 'GET',
          resourceType: () => req.resourceType ?? 'fetch',
          headerValue: (name: string): string | undefined => {
            const wanted = name.trim().toLowerCase();
            for (const [k, v] of Object.entries(headers)) {
              if (k.toLowerCase() === wanted) return v;
            }
            return undefined;
          },
        });
      }
    }
    return null;
  }

  async route(_urlPattern: string, handler: (route: RouteInstance) => Promise<void>): Promise<void> {
    this.routeHandler = handler;
  }

  on(
    event: 'response' | 'request',
    handler: ((response: ResponseInstance) => void) | ((request: NetworkRequestInstance) => void)
  ): void {
    if (event === 'request') {
      this.requestHandler = handler as (request: NetworkRequestInstance) => void;
    }
  }

  async waitForLoadState(): Promise<void> {}
  async waitForTimeout(_ms: number): Promise<void> {}

  async evaluate<T>(_fn: () => T | Promise<T>): Promise<T> {
    return this.html as unknown as T;
  }

  async title(): Promise<string> {
    return 'BYOT harvest smoke';
  }

  async close(): Promise<void> {}
}

class MockHarvestContext implements BrowserContextInstance {
  public lastOptions: Record<string, unknown> | undefined;

  constructor(
    private readonly networkRequests: readonly MockNetReq[],
    private readonly html: string,
    options?: Record<string, unknown>
  ) {
    this.lastOptions = options;
  }

  async newPage(): Promise<PageInstance> {
    return new MockHarvestPage(this.networkRequests, this.html);
  }

  async close(): Promise<void> {}
}

class MockHarvestBrowser implements BrowserInstance {
  public lastContextOptions: Record<string, unknown> | undefined;
  public closed = false;

  constructor(
    private readonly networkRequests: readonly MockNetReq[],
    private readonly html: string
  ) {}

  async newContext(options?: Record<string, unknown>): Promise<BrowserContextInstance> {
    this.lastContextOptions = options;
    return new MockHarvestContext(this.networkRequests, this.html, options);
  }

  async close(): Promise<void> {
    this.closed = true;
  }
}

class MockHarvestLauncher implements PlaywrightBrowserLauncher {
  public launchCount = 0;
  public lastBrowser: MockHarvestBrowser | undefined;

  constructor(
    private readonly networkRequests: readonly MockNetReq[],
    private readonly html: string
  ) {}

  async launch(): Promise<BrowserInstance> {
    this.launchCount += 1;
    const browser = new MockHarvestBrowser(this.networkRequests, this.html);
    this.lastBrowser = browser;
    return browser;
  }
}

class UnavailableLauncher implements PlaywrightBrowserLauncher {
  public launchCount = 0;
  async launch(): Promise<BrowserInstance> {
    this.launchCount += 1;
    throw new Error("Executable doesn't exist at /missing/chromium");
  }
}

function createHermeticAdapters(): ReconToolAdapters {
  const deny = async () =>
    ({
      status: 'preflight_denied' as const,
      reasonCode: 'hermetic_stub',
      reason: 'hermetic stub',
      observations: [],
      contractVersion: 'fixguard-hermetic/v0',
      lineage: {
        assessmentId: 'a',
        scanId: 's',
        authorizationGrantId: 'g',
        authorizationDecisionId: 'd',
        actorId: 'u',
      },
      durationMs: 1,
      explicitNonClaims: {
        createsRealFindings: false as const,
        createsPersistedEvidence: false as const,
        confirmsVulnerabilities: false as const,
        makesRiskClaims: false as const,
        makesSeverityClaims: false as const,
        makesImpactClaims: false as const,
        executesNetworkPayloads: false as const,
        severity: 'info' as const,
      },
    }) as never;

  return {
    subdomainTool: { discoverSubdomains: deny },
    dnsTool: { resolveDns: deny },
    portTool: { discoverPorts: deny },
    webTool: {
      inspectWeb: async (req) => ({
        status: 'success' as const,
        contractVersion: 'fixguard-web-inspection/v0' as const,
        targetUrl: req.targetUrl,
        observations: [
          {
            url: req.targetUrl,
            method: 'GET',
            statusCode: 200,
            headers: { 'x-powered-by': 'Next.js' },
            technologies: ['Next.js'],
            bodyText:
              '<html><script src="/_next/static/chunks/app.js"></script><body>__NEXT_DATA__</body></html>',
            discoveredAt: '2026-09-25T12:00:00.000Z',
          },
        ],
        explicitNonClaims: {
          createsRealFindings: false as const,
          createsPersistedEvidence: false as const,
          confirmsVulnerabilities: false as const,
          makesRiskClaims: false as const,
          makesSeverityClaims: false as const,
          makesImpactClaims: false as const,
          executesNetworkPayloads: false as const,
          severity: 'info' as const,
        },
        lineage: req.lineage,
        durationMs: 1,
      }),
    },
    tlsTool: { inspectTls: deny },
    urlTool: { discoverUrls: deny },
    contentTool: { discoverContent: deny },
    parameterTool: { discoverParameters: deny },
    secretTool: { scanSecrets: deny },
  };
}

async function main(): Promise<void> {
  console.log('=== Deep recon P3 BYOT harvest + Playwright Identity A smoke ===');

  const prevToken = process.env.FG_ACCESS_TOKEN;
  delete process.env.FG_ACCESS_TOKEN;

  assert.equal(resolveByotHarvestAuthHeaders(undefined), null);
  console.log('[+] absent token/headers → null auth');

  process.env.FG_ACCESS_TOKEN =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.smoke.token.value.padding';
  const resolvedEnv = resolveByotHarvestAuthHeaders(undefined);
  assert.ok(resolvedEnv?.authorization?.startsWith('Bearer '));
  assert.equal(
    resolveByotHarvestAuthHeaders({ Authorization: 'Bearer explicit' })?.authorization,
    'Bearer explicit'
  );
  console.log('[+] FG_ACCESS_TOKEN / explicit headers resolve without leaking');

  const scopeGrant = createScopeGrant({ authenticatedTesting: true });
  const lineage: AuthorizedActiveReconRequestLineage = {
    assessmentId: 'asmt_byot_harvest_001',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'dec_byot_harvest_001',
    actorId: 'act_byot_harvest_op',
  };
  const now = '2026-09-25T12:05:00.000Z';
  const auth = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      authorizedActor: { actorId: lineage.actorId, actorType: 'human' },
      decision: 'authorized',
      decidedAt: now,
      scopeGrant,
    },
    now
  );
  assert.equal(auth.status, 'established');

  const transport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
    if (req.url.includes('/_next/static/chunks/app.js')) {
      return {
        statusCode: 200,
        headers: { 'content-type': 'application/javascript' },
        bodyText: `fetch("/api/orders"); Next-Action: "${ACTION_ID}"; $ACTION_ID_${ACTION_ID}`,
        responseTimeMs: 3,
      };
    }
    if (req.url.includes('robots.txt') || req.url.includes('sitemap')) {
      return { statusCode: 404, headers: {}, bodyText: '', responseTimeMs: 2 };
    }
    return {
      statusCode: 200,
      headers: { 'content-type': 'text/html', 'x-powered-by': 'Next.js' },
      bodyText:
        '<html><script src="/_next/static/chunks/app.js"></script><body>__NEXT_DATA__</body></html>',
      responseTimeMs: 3,
    };
  };

  // Without token: skip cleanly
  delete process.env.FG_ACCESS_TOKEN;
  const skipped = await runByotNetworkHarvest({
    originUrl: 'https://app.example.com/',
    verifiedAuthorizationDecision: auth.decision!,
    authorizedScopeGrant: scopeGrant,
    lineage,
    transport,
    dnsResolver: async () => ['93.184.216.34'],
  });
  assert.equal(skipped.status, 'skipped');
  assert.equal(skipped.reasonCode, 'byot_harvest_token_absent');
  console.log('[+] harvest skips cleanly without BYOT/token');

  // Playwright Identity A harvest (hermetic fake headers + network events)
  const pwLauncher = new MockHarvestLauncher(
    [
      {
        url: 'https://app.example.com/api/me',
        method: 'GET',
        resourceType: 'fetch',
      },
      {
        url: 'https://app.example.com/dashboard?_rsc=1abc',
        method: 'GET',
        resourceType: 'fetch',
      },
      {
        url: 'https://app.example.com/',
        method: 'POST',
        resourceType: 'fetch',
        headers: { 'next-action': NETWORK_ACTION_ID },
      },
    ],
    `<html><body>Next-Action: "${ACTION_ID}"</body></html>`
  );
  const pwHarvested = await runByotNetworkHarvest({
    originUrl: 'https://app.example.com/',
    verifiedAuthorizationDecision: auth.decision!,
    authorizedScopeGrant: scopeGrant,
    lineage,
    authHeaders: {
      authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.smoke.pad',
      cookie: 'sb-access-token=fake.smoke.jwt',
    },
    browserLauncher: pwLauncher,
    transport,
    dnsResolver: async () => ['93.184.216.34'],
  });
  assert.equal(pwHarvested.status, 'success', `pw status=${pwHarvested.status}`);
  assert.equal(pwHarvested.status === 'success' ? pwHarvested.harvestMode : null, 'playwright');
  assert.equal(pwLauncher.launchCount, 1);
  const extraHeaders = pwLauncher.lastBrowser?.lastContextOptions?.extraHTTPHeaders as
    | Record<string, string>
    | undefined;
  assert.ok(extraHeaders?.Authorization?.startsWith('Bearer '), 'Identity A Authorization injected');
  assert.ok(typeof extraHeaders?.Cookie === 'string', 'Identity A Cookie injected');
  assert.ok(
    pwHarvested.urlObservations.some(
      (u) => u.sources.includes(BYOT_NETWORK_HARVEST_SOURCE) && u.url.includes('/api/me')
    ),
    'expected XHR/fetch /api/me'
  );
  assert.ok(
    pwHarvested.urlObservations.some((u) => u.url.includes('_rsc=')),
    'expected RSC network hint'
  );
  assert.ok(
    pwHarvested.serverActionHints.some((h) => h.actionId === NETWORK_ACTION_ID),
    'expected Next-Action from network header'
  );
  assert.ok(
    pwHarvested.serverActionHints.some((h) => h.actionId === ACTION_ID),
    'expected Next-Action from DOM text'
  );
  console.log('[+] Playwright Identity A harvest mines XHR/RSC/Next-Action');

  // Browser unavailable → HTTP fallback with fake auth headers
  const unavailable = new UnavailableLauncher();
  const httpFallback = await runByotNetworkHarvest({
    originUrl: 'https://app.example.com/',
    verifiedAuthorizationDecision: auth.decision!,
    authorizedScopeGrant: scopeGrant,
    lineage,
    authHeaders: { authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.smoke.pad' },
    browserLauncher: unavailable,
    transport,
    dnsResolver: async () => ['93.184.216.34'],
  });
  assert.equal(httpFallback.status, 'success');
  assert.equal(httpFallback.status === 'success' ? httpFallback.harvestMode : null, 'http_fallback');
  assert.equal(unavailable.launchCount, 1);
  assert.ok(httpFallback.serverActionHints.some((h) => h.actionId === ACTION_ID));
  assert.ok(
    httpFallback.urlObservations.some(
      (u) => u.sources.includes(BYOT_NETWORK_HARVEST_SOURCE) && u.url.includes('/api/orders')
    )
  );
  console.log('[+] browser unavailable → authenticated HTTP fallback');

  // Explicit httpOnly path
  const httpOnly = await runByotNetworkHarvest({
    originUrl: 'https://app.example.com/',
    verifiedAuthorizationDecision: auth.decision!,
    authorizedScopeGrant: scopeGrant,
    lineage,
    authHeaders: { authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.smoke.pad' },
    httpOnly: true,
    transport,
    dnsResolver: async () => ['93.184.216.34'],
  });
  assert.equal(httpOnly.status === 'success' ? httpOnly.harvestMode : null, 'http_fallback');
  console.log('[+] httpOnly forces HTTP harvest path');

  // Planner: enableByotHarvest + jwt → byot_network_harvest planned
  delete process.env.FG_ACCESS_TOKEN;
  const planned = planDeepReconMethods({
    stack: { hasNextJs: true, hasJwtIdentity: true },
    budget: { maxRequests: 50, remainingRequests: 50 },
    enableByotHarvest: true,
  });
  assert.ok(planned.some((p) => p.method === 'byot_network_harvest'));
  console.log('[+] planner includes byot_network_harvest when JWT present');

  const orch = await runDeepReconOrchestrator({
    originUrl: 'https://app.example.com/',
    verifiedAuthorizationDecision: auth.decision!,
    authorizedScopeGrant: scopeGrant,
    lineage,
    stack: { hasNextJs: true, hasJwtIdentity: true },
    budget: { maxRequests: 50, remainingRequests: 50 },
    enableByotHarvest: true,
    byotAuthHeaders: {
      authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.smoke.pad',
    },
    byotBrowserLauncher: new MockHarvestLauncher(
      [
        {
          url: 'https://app.example.com/api/session',
          method: 'GET',
          resourceType: 'xhr',
        },
      ],
      '<html><body>ok</body></html>'
    ),
    transport,
    dnsResolver: async () => ['93.184.216.34'],
  });
  const byotResult = orch.methodResults.find((m) => m.method === 'byot_network_harvest');
  assert.equal(byotResult?.status, 'ran');
  assert.notEqual(byotResult?.reasonCode, 'byot_harvest_stub_activated');
  assert.ok(
    orch.urlObservations.some((u) => u.url.includes('/api/session')),
    'orchestrator receives Playwright-mined URL'
  );
  console.log('[+] deep recon orchestrator runs Playwright harvest (not stub)');

  // Composite wiring: stage_deep_recon present with heartbeat toolHint
  const stageHints: string[] = [];
  const composite = new CompositeActiveReconOrchestratorService(createHermeticAdapters());
  const compositeResult = await composite.orchestrate({
    targetDomain: 'app.example.com',
    verifiedAuthorizationDecision: auth.decision!,
    authorizedScopeGrant: scopeGrant,
    lineage,
    config: {
      skipStages: [
        'stage_1_domain_zone',
        'stage_2_port_service',
        'stage_5_secret_inspection',
      ],
      enableDeepRecon: true,
      enableByotHarvest: true,
      enableSpaDiscovery: false,
      deepReconMaxRequests: 30,
      timeoutMs: 5_000,
    },
    byotHarvestHeaders: {
      authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.smoke.pad',
    },
    byotHarvestHttpOnly: true,
    dnsResolver: async () => ['93.184.216.34'],
    probeTransport: transport,
    onStageStart: async (info) => {
      stageHints.push(`${info.stage}:${info.toolHint}`);
    },
  });

  assert.ok(
    compositeResult.status === 'success' || compositeResult.status === 'circuit_broken'
  );
  if (compositeResult.status === 'success' || compositeResult.status === 'circuit_broken') {
    const deepStage = compositeResult.stages.find((s) => s.stage === 'stage_deep_recon');
    assert.ok(deepStage, 'stage_deep_recon must be recorded');
    assert.ok(
      stageHints.some((h) => h.startsWith('stage_deep_recon:')),
      `expected deep_recon heartbeat, got ${stageHints.join(',')}`
    );
    const warnings = deepStage?.warnings?.join('\n') ?? '';
    assert.ok(
      warnings.includes('byot_network_harvest') || warnings.includes('deep_recon_summary'),
      warnings
    );
  }
  console.log('[+] CompositeActiveRecon records stage_deep_recon + heartbeat hints');

  if (prevToken === undefined) {
    delete process.env.FG_ACCESS_TOKEN;
  } else {
    process.env.FG_ACCESS_TOKEN = prevToken;
  }

  console.log('=== Deep recon P3 BYOT harvest smoke: ALL PASSED ===');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
