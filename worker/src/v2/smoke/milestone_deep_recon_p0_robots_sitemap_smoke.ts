/**
 * Deep recon P0 + robots/sitemap feed smoke (hermetic).
 */
import assert from 'node:assert/strict';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import type { HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';
import {
  ROBOTS_SITEMAP_FEED_SOURCE,
  runRobotsSitemapInventoryFeed,
} from '../recon/analysis/RobotsSitemapInventoryFeedService.js';
import { planDeepReconMethods } from '../recon/deep/DeepReconMethodPlanner.js';
import { runDeepReconOrchestrator } from '../recon/deep/DeepReconOrchestratorService.js';

function createScopeGrant(): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_deep_p0_001',
    scanId: 'scan_deep_p0_001',
    issuedAt: '2026-09-24T12:00:00.000Z',
    expiresAt: '2026-09-25T12:00:00.000Z',
    subject: { targetKind: 'domain', domain: 'app.example.com' },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for deep recon P0 smoke',
    },
    permissionSet: {
      passiveRecon: true,
      technologyFingerprinting: true,
      endpointDiscovery: true,
      activeCrawling: true,
      authenticatedTesting: false,
      lightValidation: false,
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

async function main(): Promise<void> {
  console.log('=== Deep recon P0 + robots/sitemap feed smoke ===');
  const scopeGrant = createScopeGrant();
  const lineage: AuthorizedActiveReconRequestLineage = {
    assessmentId: 'asmt_deep_p0_001',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'dec_deep_p0_001',
    actorId: 'act_deep_p0_op',
  };
  const now = '2026-09-24T12:05:00.000Z';
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
  assert.ok(auth.decision);

  // Planner: Next/Vercel stack → robots first, then JS/maps
  const planned = planDeepReconMethods({
    stack: { hasNextJs: true, hasVercel: true, hasSupabase: true },
    budget: { maxRequests: 50, remainingRequests: 50 },
  });
  assert.ok(planned.length >= 2);
  assert.equal(planned[0]?.method, 'robots_sitemap_feed');
  console.log('[+] method planner orders robots_sitemap_feed first');

  // Budget zero → empty plan
  const empty = planDeepReconMethods({
    stack: { hasNextJs: true },
    budget: { maxRequests: 0, remainingRequests: 0 },
  });
  assert.equal(empty.length, 0);

  // Hermetic robots + sitemap feed
  const transport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
    if (req.url.endsWith('/robots.txt')) {
      return {
        statusCode: 200,
        headers: { 'content-type': 'text/plain' },
        bodyText:
          'User-agent: *\nAllow: /api/\nDisallow: /admin\nSitemap: https://app.example.com/sitemap.xml\n',
        responseTimeMs: 5,
      };
    }
    if (req.url.endsWith('/sitemap.xml')) {
      return {
        statusCode: 200,
        headers: { 'content-type': 'application/xml' },
        bodyText:
          '<?xml version="1.0"?><urlset><url><loc>https://app.example.com/api/v1/items</loc></url><url><loc>https://app.example.com/perfil</loc></url></urlset>',
        responseTimeMs: 5,
      };
    }
    return {
      statusCode: 404,
      headers: {},
      bodyText: '',
      responseTimeMs: 5,
    };
  };

  const feed = await runRobotsSitemapInventoryFeed({
    originUrl: 'https://app.example.com/',
    verifiedAuthorizationDecision: auth.decision!,
    authorizedScopeGrant: scopeGrant,
    lineage,
    transport,
    dnsResolver: async () => ['93.184.216.34'],
  });
  assert.equal(
    feed.status,
    'success',
    `feed status=${feed.status} reason=${'reasonCode' in feed ? feed.reasonCode : ''} ${'reason' in feed ? feed.reason : ''}`
  );
  if (feed.status === 'success') {
    assert.ok(feed.robotsFetched);
    const urls = feed.urlObservations.map((u) => u.url);
    assert.ok(urls.some((u) => u.includes('/api/v1/items')));
    assert.ok(urls.some((u) => u.includes('/perfil') || u.includes('/api/')));
    assert.ok(
      feed.urlObservations.every((u) => u.sources.includes(ROBOTS_SITEMAP_FEED_SOURCE))
    );
  }
  console.log('[+] robots/sitemap feed seeds inventory');

  // Loopback / private denied
  const denied = await runRobotsSitemapInventoryFeed({
    originUrl: 'https://127.0.0.1/',
    verifiedAuthorizationDecision: auth.decision!,
    authorizedScopeGrant: {
      ...scopeGrant,
      boundaries: {
        ...scopeGrant.boundaries,
        allowedHosts: ['127.0.0.1'],
        allowedDomains: ['127.0.0.1'],
        allowedOrigins: ['https://127.0.0.1'],
      },
      subject: { targetKind: 'domain', domain: '127.0.0.1' },
    },
    lineage,
    transport,
    dnsResolver: async () => ['127.0.0.1'],
  });
  assert.equal(denied.status, 'preflight_denied');
  console.log('[+] loopback robots feed preflight denied');

  const orch = await runDeepReconOrchestrator({
    originUrl: 'https://app.example.com/',
    verifiedAuthorizationDecision: auth.decision!,
    authorizedScopeGrant: scopeGrant,
    lineage,
    stack: { hasNextJs: true, hasVercel: true, hasSupabase: true },
    budget: { maxRequests: 50, remainingRequests: 50 },
    transport,
    dnsResolver: async () => ['93.184.216.34'],
  });
  assert.equal(orch.status, 'completed');
  assert.ok(orch.urlObservations.length >= 1);
  const robotsResult = orch.methodResults.find((m) => m.method === 'robots_sitemap_feed');
  assert.equal(robotsResult?.status, 'ran');
  const skippedJs = orch.methodResults.find((m) => m.method === 'js_surface_mining');
  assert.equal(skippedJs?.status, 'skipped');
  assert.equal(skippedJs?.reasonCode, 'jsluice_tool_not_configured');
  console.log('[+] deep recon orchestrator P0 runs robots feed; js mining waits for a tool');

  console.log('=== Deep recon P0 smoke: ALL PASSED ===');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
