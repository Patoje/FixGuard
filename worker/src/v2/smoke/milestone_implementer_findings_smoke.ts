/**
 * Milestone Implementer Findings Smoke Suite
 *
 * Consolidated verification of accepted FIX_NOW items:
 * 1. CT Transport — createEgressGuardedCtFetch strictly enforces HTTPS, crt.sh host, SSRF gate, and returns parsed subdomains
 * 2. Playwright Availability Probe — checkPlaywrightAvailability and ReconToolAvailabilityService.checkBrowserAvailability
 * 3. Actor Identity Validation — strict requirement on actorId, no silent magic string fallback
 * 4. Scope Classification Metadata — accurately reflects network and tool execution without unverified claims
 * 5. Adaptive Crawl Frontier — explores without arbitrary 25-route truncation, terminates on frontier exhaustion or budget saturation
 */

import assert from 'node:assert/strict';
import {
  CrtShAdapter,
  createEgressGuardedCtFetch,
} from '../recon/adapters/CrtShAdapter.js';
import {
  PlaywrightSpaAdapter,
  checkPlaywrightAvailability,
} from '../recon/adapters/PlaywrightSpaAdapter.js';
import { ReconToolAvailabilityService } from '../capabilities/ReconToolAvailabilityService.js';
import { parseStartOrchestratedAssessmentBody } from '../api/validation/ApiRequestValidators.js';
import { ApiValidationError } from '../api/ApiErrors.js';
import { validateAuthorizedScopeGrant } from '../scope/AuthorizedScopePolicyService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import { CompositeActiveReconOrchestratorService } from '../recon/orchestration/CompositeActiveReconOrchestratorService.js';
import type { ReconToolAdapters } from '../recon/orchestration/ActiveReconOrchestrationContracts.js';
import { SUBDOMAIN_DISCOVERY_NON_CLAIMS } from '../recon/adapters/SubdomainDiscoveryContracts.js';
import { DNS_RESOLUTION_CONTRACT_VERSION, DNS_RESOLUTION_NON_CLAIMS } from '../recon/adapters/DnsResolutionContracts.js';
import { PORT_DISCOVERY_CONTRACT_VERSION, PORT_DISCOVERY_NON_CLAIMS } from '../recon/adapters/PortDiscoveryContracts.js';
import { WEB_INSPECTION_CONTRACT_VERSION, WEB_INSPECTION_NON_CLAIMS } from '../recon/adapters/WebInspectionContracts.js';
import { TLS_INSPECTION_CONTRACT_VERSION, TLS_INSPECTION_NON_CLAIMS } from '../recon/adapters/TlsInspectionContracts.js';
import { URL_DISCOVERY_CONTRACT_VERSION, URL_DISCOVERY_NON_CLAIMS } from '../recon/adapters/UrlDiscoveryContracts.js';
import { CONTENT_DISCOVERY_CONTRACT_VERSION, CONTENT_DISCOVERY_NON_CLAIMS } from '../recon/adapters/ContentDiscoveryContracts.js';
import { PARAMETER_DISCOVERY_CONTRACT_VERSION, PARAMETER_DISCOVERY_NON_CLAIMS } from '../recon/adapters/ParameterDiscoveryContracts.js';
import { SECRET_DISCOVERY_CONTRACT_VERSION, SECRET_DISCOVERY_NON_CLAIMS } from '../recon/adapters/SecretDiscoveryContracts.js';

function fail(error: unknown): never {
  const message = error instanceof Error ? (error.stack ?? error.message) : String(error);
  process.stderr.write(`[milestone_implementer_findings_smoke] FAILED: ${message}\n`);
  process.exit(1);
}

const TARGET_HOST = 'test.example.com';

function createMockScopeGrant(classificationOverrides = {}): AuthorizedScopeGrant {
  const now = Date.now();
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_findings_smoke_001',
    scanId: 'scan_findings_smoke_001',
    issuedAt: new Date(now - 3600_000).toISOString(),
    expiresAt: new Date(now + 86400_000).toISOString(),
    subject: { targetKind: 'domain', domain: TARGET_HOST },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized test assessment',
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
      allowedDomains: [TARGET_HOST],
      allowedHosts: [TARGET_HOST],
      allowedOrigins: [`https://${TARGET_HOST}`],
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
      createsRealFindings: true,
      createsPersistedEvidence: true,
      confirmsVulnerabilities: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      executesNetwork: true,
      executesTools: true,
      persistsData: true,
      ...classificationOverrides,
    },
  };
}

async function testCtTransportEgressGuard(): Promise<void> {
  process.stdout.write('[1/5] Testing CT Transport Egress Guard...\n');

  // Verify non-HTTPS is rejected
  const customFetch = createEgressGuardedCtFetch(async () => new Response('[]'));
  await assert.rejects(
    async () => customFetch('http://crt.sh/?q=test&output=json'),
    (err: Error) => {
      assert.ok(err.message.includes('disallowed protocol or host'));
      return true;
    }
  );

  // Verify non-crt.sh domain is rejected
  await assert.rejects(
    async () => customFetch('https://evil.com/?q=test&output=json'),
    (err: Error) => {
      assert.ok(err.message.includes('disallowed protocol or host'));
      return true;
    }
  );

  // Verify localhost / SSRF targets are rejected
  await assert.rejects(
    async () => customFetch('https://127.0.0.1/?q=test&output=json'),
    (err: Error) => {
      assert.ok(err.message.includes('CT egress policy violation'));
      return true;
    }
  );

  // Verify valid crt.sh URL queries through mock and returns parsed observations
  const mockDnsResolver = async (h: string): Promise<string[]> => ['93.184.216.34']; // Public IP (example.com)
  const mockPayload = JSON.stringify([
    { name_value: 'api.test.example.com' },
    { name_value: 'admin.test.example.com\nportal.test.example.com' },
    { name_value: 'out-of-scope.other.com' }, // Out of scope domain
  ]);

  const mockFetchApi = createEgressGuardedCtFetch(async (url) => {
    assert.ok(String(url).startsWith('https://crt.sh'));
    return new Response(mockPayload, { status: 200, headers: { 'Content-Type': 'application/json' } });
  });

  const adapter = new CrtShAdapter({
    dnsResolver: mockDnsResolver,
    fetchApi: mockFetchApi,
  });

  const grant = createMockScopeGrant();
  const decisionResult = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: 'asmt_ct_001',
      scanId: grant.scanId,
      authorizationDecisionId: 'dec_ct_001',
      authorizedActor: { actorId: 'usr_operator_1', actorType: 'human' },
      decision: 'authorized',
      decidedAt: new Date().toISOString(),
      scopeGrant: grant,
    },
    new Date().toISOString()
  );
  assert.equal(decisionResult.status, 'established');

  const reconResult = await adapter.discoverSubdomains({
    targetDomain: TARGET_HOST,
    verifiedAuthorizationDecision: decisionResult.decision,
    authorizedScopeGrant: grant,
    lineage: {
      assessmentId: 'asmt_ct_001',
      scanId: grant.scanId,
      authorizationGrantId: grant.grantId,
      authorizationDecisionId: 'dec_ct_001',
      actorId: 'usr_operator_1',
    },
  });

  assert.equal(reconResult.status, 'success');
  if (reconResult.status === 'success') {
    const subs = reconResult.observations.map((o) => o.subdomain);
    assert.ok(subs.includes('api.test.example.com'));
    assert.ok(subs.includes('admin.test.example.com'));
    assert.ok(subs.includes('portal.test.example.com'));
    // Out-of-scope must be excluded by scope boundary filtering
    assert.equal(subs.includes('out-of-scope.other.com'), false);
  }

  process.stdout.write('   -> CT Transport egress guard and subdomain ingestion validated.\n');
}

async function testPlaywrightAvailabilityProbe(): Promise<void> {
  process.stdout.write('[2/5] Testing Playwright / Chromium Availability Probe...\n');

  const probe = checkPlaywrightAvailability();
  assert.equal(typeof probe.available, 'boolean');
  if (probe.available) {
    assert.equal(typeof probe.path, 'string');
    assert.ok(probe.path!.length > 0);
  }

  const availabilityService = new ReconToolAvailabilityService();
  const browserStatus = await availabilityService.checkBrowserAvailability();
  assert.equal(browserStatus.available, probe.available);

  process.stdout.write(`   -> Playwright availability probe returned available=${probe.available}.\n`);
}

async function testActorIdentityValidation(): Promise<void> {
  process.stdout.write('[3/5] Testing Actor Identity Validation & Rejection...\n');

  // Missing actorId throws ApiValidationError
  assert.throws(
    () => parseStartOrchestratedAssessmentBody({ targetDomain: 'example.com' }),
    (err: unknown) => {
      assert.ok(err instanceof ApiValidationError);
      assert.ok(err.message.includes("Field 'actorId' is required"));
      return true;
    }
  );

  // Invalid actorId format (spaces, illegal chars) throws ApiValidationError
  assert.throws(
    () => parseStartOrchestratedAssessmentBody({ targetDomain: 'example.com', actorId: 'bad actor id!' }),
    (err: unknown) => {
      assert.ok(err instanceof ApiValidationError);
      assert.ok(err.message.includes("strict identifier format"));
      return true;
    }
  );

  // Valid actorId succeeds
  const parsed = parseStartOrchestratedAssessmentBody({
    targetDomain: 'example.com',
    actorId: 'usr_audit_operator',
  });
  assert.equal(parsed.targetDomain, 'example.com');
  assert.equal(parsed.actorId, 'usr_audit_operator');

  process.stdout.write('   -> ActorId strict presence and format validation confirmed.\n');
}

async function testScopeClassificationMetadata(): Promise<void> {
  process.stdout.write('[4/5] Testing Scope Classification Metadata...\n');

  // Realistic operational flags pass validation
  const validGrant = createMockScopeGrant({
    executesNetwork: true,
    executesTools: true,
    createsRealFindings: true,
    createsPersistedEvidence: true,
    persistsData: true,
  });

  const grantValidation = validateAuthorizedScopeGrant(validGrant);
  assert.equal(grantValidation.isValid, true);

  // Speculative claim flags fail closed
  const invalidGrant = createMockScopeGrant({
    confirmsVulnerabilities: true, // speculative claim forbidden
  });
  const invalidResult = validateAuthorizedScopeGrant(invalidGrant);
  assert.equal(invalidResult.isValid, false);
  assert.ok(invalidResult.message?.includes('speculative vulnerability'));

  process.stdout.write('   -> Scope classification metadata correctly accepts execution flags while rejecting speculative claims.\n');
}

async function testAdaptiveCrawlFrontier(): Promise<void> {
  process.stdout.write('[5/5] Testing Adaptive Crawl Frontier (Depth > 25 Routes)...\n');

  // Generate 40 unique in-scope route links on page 1
  const generatedLinks = Array.from({ length: 40 }, (_, i) => `<a href="/route-endpoint-${i}">Link ${i}</a>`).join('\n');
  const mockHtml = `<html><body>${generatedLinks}</body></html>`;

  const grant = createMockScopeGrant();
  const decidedAt = new Date().toISOString();
  const established = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: 'asmt_crawl_001',
      scanId: grant.scanId,
      authorizationDecisionId: 'dec_crawl_001',
      authorizedActor: { actorId: 'usr_crawler', actorType: 'human' },
      decision: 'authorized',
      decidedAt,
      scopeGrant: grant,
    },
    decidedAt
  );
  assert.equal(established.status, 'established');

  let inspectCallCount = 0;
  const mockTools: ReconToolAdapters = {
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
          contractVersion: DNS_RESOLUTION_CONTRACT_VERSION,
          targetDomain: req.targetDomain,
          observations: [
            { domain: req.targetDomain, recordType: 'A', values: ['93.184.216.34'], discoveredAt: decidedAt },
          ],
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
          contractVersion: PORT_DISCOVERY_CONTRACT_VERSION,
          targetHostOrIp: req.targetHostOrIp,
          observations: [
            { host: req.targetHostOrIp, ip: '93.184.216.34', port: 443, protocol: 'tcp', service: 'https', state: 'open', discoveredAt: decidedAt },
          ],
          explicitNonClaims: PORT_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 1,
        };
      },
    },
    webTool: {
      async inspectWeb(req) {
        inspectCallCount++;
        return {
          status: 'success',
          contractVersion: WEB_INSPECTION_CONTRACT_VERSION,
          targetUrl: req.targetUrl,
          observations: [
            {
              url: req.targetUrl,
              method: 'GET',
              statusCode: 200,
              headers: { 'content-type': 'text/html' },
              technologies: [],
              bodyText: req.targetUrl.endsWith('/route-endpoint-0') ? '<html><body><a href="/nested-subpage">Nested</a></body></html>' : mockHtml,
              discoveredAt: decidedAt,
            },
          ],
          explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 2,
        };
      },
    },
    tlsTool: {
      async inspectTls(req) {
        return {
          status: 'preflight_denied',
          contractVersion: TLS_INSPECTION_CONTRACT_VERSION,
          targetHost: req.targetHostOrUrl,
          reasonCode: 'skipped',
          reason: 'test',
          explicitNonClaims: TLS_INSPECTION_NON_CLAIMS,
          lineage: req.lineage,
        };
      },
    },
    urlTool: {
      async discoverUrls(req) {
        return {
          status: 'preflight_denied',
          contractVersion: URL_DISCOVERY_CONTRACT_VERSION,
          targetUrlOrDomain: req.targetUrlOrDomain,
          reasonCode: 'skipped',
          reason: 'test',
          explicitNonClaims: URL_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
        };
      },
    },
    contentTool: {
      async discoverContent(req) {
        return {
          status: 'preflight_denied',
          contractVersion: CONTENT_DISCOVERY_CONTRACT_VERSION,
          targetUrl: req.targetUrl,
          wordlistPath: req.wordlistPath,
          reasonCode: 'skipped',
          reason: 'test',
          explicitNonClaims: CONTENT_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
        };
      },
    },
    parameterTool: {
      async discoverParameters(req) {
        return {
          status: 'preflight_denied',
          contractVersion: PARAMETER_DISCOVERY_CONTRACT_VERSION,
          targetUrl: req.targetUrl,
          reasonCode: 'skipped',
          reason: 'test',
          explicitNonClaims: PARAMETER_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
        };
      },
    },
    secretTool: {
      async scanSecrets(req) {
        return {
          status: 'preflight_denied',
          contractVersion: SECRET_DISCOVERY_CONTRACT_VERSION,
          targetUrlOrPath: req.targetUrlOrPath,
          reasonCode: 'skipped',
          reason: 'test',
          explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
        };
      },
    },
  };

  const reconOrchestrator = new CompositeActiveReconOrchestratorService(mockTools);
  const result = await reconOrchestrator.orchestrate({
    targetDomain: TARGET_HOST,
    verifiedAuthorizationDecision: established.decision,
    authorizedScopeGrant: grant,
    lineage: {
      assessmentId: 'asmt_crawl_001',
      scanId: grant.scanId,
      authorizationGrantId: grant.grantId,
      authorizationDecisionId: 'dec_crawl_001',
      actorId: 'usr_crawler',
    },
    dnsResolver: async () => ['93.184.216.34'],
    config: {
      skipStages: [
        'stage_4_crawling_parameters',
        'stage_deep_recon',
        'stage_5_secret_inspection',
      ],
      enableDeepRecon: false,
      enableSpaDiscovery: false,
      crawlRequestBudget: 50,
      crawlDuplicateSaturationThreshold: 5,
    },
  });

  assert.equal(result.status, 'success');
  if (result.status === 'success') {
    const urls = result.aggregatedObservations.urls.map((u) => u.url);
    // The previous rigid cap was 25. With adaptive crawling, all 40 links + nested are discovered!
    assert.ok(
      urls.length >= 40,
      `Expected discovery to exceed old 25-route cap; got ${urls.length} routes`
    );
    assert.ok(urls.some((u) => u.includes('route-endpoint-39')));
    assert.ok(urls.some((u) => u.includes('nested-subpage')));
  }

  process.stdout.write(`   -> Adaptive crawl frontier discovered ${result.status === 'success' ? result.aggregatedObservations.urls.length : 0} routes (exceeding old 25 limit without truncation).\n`);
}

async function main(): Promise<void> {
  process.stdout.write('=== [MILESTONE IMPLEMENTER FINDINGS SMOKE] ===\n');
  await testCtTransportEgressGuard();
  await testPlaywrightAvailabilityProbe();
  await testActorIdentityValidation();
  await testScopeClassificationMetadata();
  await testAdaptiveCrawlFrontier();
  process.stdout.write('=== ALL AUDIT FINDINGS VALIDATIONS PASSED ===\n');
}

main().catch(fail);
