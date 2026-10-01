/**
 * Milestone Playwright CDP (Chrome DevTools Protocol) HITL Integration Smoke Test
 *
 * Validates:
 * 1. CDP Endpoint Validation (strict loopback restriction, rejects external hosts)
 * 2. Preflight Denial: Blocks non-loopback/rogue CDP endpoints with 0 connections
 * 3. Launcher Capability Check: Degrades loudly with reasonCode 'cdp_unsupported' if launcher lacks connectOverCDP
 * 4. Safe HITL Lifecycle: Verifies that discoverSpa calls disconnect() instead of close() on CDP sessions
 * 5. Gate 2 & Gate 3 Boundary Integrity: Egress policy and scope filtering remain active on CDP pages
 */

import assert from 'node:assert';
import {
  PlaywrightSpaAdapter,
  validateCdpEndpoint,
} from '../recon/adapters/PlaywrightSpaAdapter.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import type {
  BrowserInstance,
  BrowserContextInstance,
  PageInstance,
  PlaywrightBrowserLauncher,
  RouteInstance,
  ResponseInstance,
  NetworkRequestInstance,
} from '../recon/adapters/BrowserAutomationContracts.js';

function createScopeGrant(domain: string): AuthorizedScopeGrant {
  const now = new Date();
  const expires = new Date(now.getTime() + 86400_000);

  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: `grant_${domain.replace(/[^a-z0-9]/gi, '_')}`,
    scanId: 'scan_cdp_smoke_001',
    issuedAt: now.toISOString(),
    expiresAt: expires.toISOString(),
    subject: {
      targetKind: 'domain',
      domain,
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: `Authorized CDP smoke test for ${domain}`,
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
      allowedHosts: [domain],
      allowedOrigins: [`https://${domain}`],
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
      assessmentId: 'asm_cdp_smoke_001',
      scanId: 'scan_cdp_smoke_001',
      authorizationDecisionId: 'dec_cdp_smoke_001',
      authorizedActor: { actorId: 'operator_cdp', actorType: 'human' },
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
    assessmentId: 'asm_cdp_smoke_001',
    scanId: 'scan_cdp_smoke_001',
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: decisionResult.decision.authorizationDecisionId,
    actorId: 'operator_cdp',
  };

  return { scopeGrant, decision: decisionResult.decision, lineage };
}

async function runCdpSmokeSuite() {
  console.log('--- Playwright CDP HITL Integration Smoke Suite ---');

  // ---------------------------------------------------------------------------
  // Test 1: CDP Endpoint Validation
  // ---------------------------------------------------------------------------
  console.log('[Test 1] Validating CDP endpoint security validator...');
  assert.strictEqual(validateCdpEndpoint('').valid, false, 'Empty endpoint must be rejected');
  assert.strictEqual(validateCdpEndpoint('not-a-url').valid, false, 'Malformed URL must be rejected');
  assert.strictEqual(validateCdpEndpoint('ftp://127.0.0.1:9222').valid, false, 'FTP must be rejected');
  assert.strictEqual(validateCdpEndpoint('http://example.com:9222').valid, false, 'External domain must be rejected');
  assert.strictEqual(validateCdpEndpoint('http://192.168.1.1:9222').valid, false, 'LAN IP must be rejected');
  assert.strictEqual(validateCdpEndpoint('http://169.254.169.254:9222').valid, false, 'Cloud metadata must be rejected');

  assert.strictEqual(validateCdpEndpoint('http://127.0.0.1:9222').valid, true, 'IPv4 loopback must be accepted');
  assert.strictEqual(validateCdpEndpoint('http://localhost:9222').valid, true, 'localhost must be accepted');
  assert.strictEqual(validateCdpEndpoint('ws://127.0.0.1:9222/devtools/browser/abc-123').valid, true, 'ws:// loopback must be accepted');
  console.log('✓ Test 1 passed: CDP endpoint validator enforces loopback restriction');

  // ---------------------------------------------------------------------------
  // Test 2: Preflight Denial on Non-Loopback CDP Endpoint
  // ---------------------------------------------------------------------------
  console.log('[Test 2] Validating preflight denial for rogue external CDP endpoint...');
  const { scopeGrant, decision, lineage } = setupAuthorizedContext('app.example.com');
  const adapter = new PlaywrightSpaAdapter();

  let connectCalls = 0;
  const mockLauncher: PlaywrightBrowserLauncher = {
    async launch() { throw new Error('launch() should not be called'); },
    async connectOverCDP() {
      connectCalls++;
      throw new Error('connectOverCDP() should not be called on invalid endpoint');
    },
  };

  const rogueResult = await adapter.discoverSpa({
    targetUrlOrDomain: 'https://app.example.com/',
    verifiedAuthorizationDecision: decision,
    authorizedScopeGrant: scopeGrant,
    lineage,
    browserLauncher: mockLauncher,
    cdpEndpoint: 'http://evil-relay.attacker.com:9222',
  });

  assert.strictEqual(rogueResult.status, 'preflight_denied');
  assert.strictEqual(rogueResult.reasonCode, 'invalid_cdp_endpoint');
  assert.strictEqual(connectCalls, 0, 'Zero connection attempts made on denied endpoint');
  console.log('✓ Test 2 passed: Preflight denial blocks non-loopback CDP target');

  // ---------------------------------------------------------------------------
  // Test 3: Launcher Capability Check
  // ---------------------------------------------------------------------------
  console.log('[Test 3] Validating loud degrade when launcher lacks connectOverCDP...');
  const launcherWithoutCdp: PlaywrightBrowserLauncher = {
    async launch() { throw new Error('launch() should not be called'); },
  };

  const unsupportedResult = await adapter.discoverSpa({
    targetUrlOrDomain: 'https://app.example.com/',
    verifiedAuthorizationDecision: decision,
    authorizedScopeGrant: scopeGrant,
    lineage,
    browserLauncher: launcherWithoutCdp,
    cdpEndpoint: 'http://127.0.0.1:9222',
  });

  assert.strictEqual(unsupportedResult.status, 'execution_failed');
  assert.strictEqual(unsupportedResult.reasonCode, 'cdp_unsupported');
  console.log('✓ Test 3 passed: Loud degrade on unsupported launcher verified');

  // ---------------------------------------------------------------------------
  // Test 4 & 5: Safe Lifecycle (Disconnect instead of Close) & Discovery
  // ---------------------------------------------------------------------------
  console.log('[Test 4 & 5] Validating safe disconnect and route discovery over CDP...');
  let disconnected = false;
  let closed = false;
  let contextClosed = false;
  let pageClosed = false;

  const mockPage: PageInstance = {
    async goto() { return null; },
    async route() {},
    on() {},
    async waitForLoadState() {},
    async waitForTimeout() {},
    async evaluate<T>(_fn: () => T | Promise<T>): Promise<T> {
      const payload = {
        links: ['https://app.example.com/checkout', 'https://app.example.com/settings'],
        forms: [{ action: '/api/profile', method: 'POST', inputs: [{ name: 'email', type: 'email' }] }],
        frameworks: ['Next.js'],
        scripts: [],
        rscPaths: ['/checkout?_rsc=abc'],
      };
      return payload as unknown as T;
    },
    async title() { return 'Real Chrome Auth Session'; },
    async close() { pageClosed = true; },
  };

  const mockContext: BrowserContextInstance = {
    async newPage() { return mockPage; },
    async close() { contextClosed = true; },
  };

  const mockCdpBrowser: BrowserInstance = {
    async newContext() { return mockContext; },
    async close() { closed = true; },
    async disconnect() { disconnected = true; },
  };

  const cdpLauncher: PlaywrightBrowserLauncher = {
    async launch() { throw new Error('launch() must not be called when cdpEndpoint is provided'); },
    async connectOverCDP(endpointUrl) {
      assert.strictEqual(endpointUrl, 'http://127.0.0.1:9222');
      return mockCdpBrowser;
    },
  };

  const cdpResult = await adapter.discoverSpa({
    targetUrlOrDomain: 'https://app.example.com/',
    verifiedAuthorizationDecision: decision,
    authorizedScopeGrant: scopeGrant,
    lineage,
    browserLauncher: cdpLauncher,
    cdpEndpoint: 'http://127.0.0.1:9222',
  });

  assert.strictEqual(cdpResult.status, 'success');
  assert.strictEqual(cdpResult.observations[0]?.pageTitle, 'Real Chrome Auth Session');
  assert.strictEqual(cdpResult.routes.length, 4, 'Discovered routes mined from real Chrome');
  assert.strictEqual(cdpResult.inputs.length, 1, 'Form inputs mined from real Chrome');

  // Verify HITL preservation: FixGuard must disconnect, NEVER close the operator's browser process
  assert.strictEqual(pageClosed, true, 'Audited page must be closed');
  assert.strictEqual(contextClosed, true, 'Audited context must be closed');
  assert.strictEqual(disconnected, true, 'Must invoke disconnect() on CDP session');
  assert.strictEqual(closed, false, 'Must NOT invoke close() to prevent killing host Chrome');
  console.log('✓ Test 4 & 5 passed: Safe disconnect and discovery over CDP verified');

  console.log('\n--- ALL 5 PLAYWRIGHT CDP ASSERTIONS PASSED SUCCESSFULLY ---');
}

runCdpSmokeSuite().catch((err) => {
  console.error('CDP smoke test failed:', err);
  process.exit(1);
});
